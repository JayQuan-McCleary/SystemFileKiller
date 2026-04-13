namespace SystemFileKiller.Core;

public record FileUnlockResult(
    string FilePath,
    int HandlesFound,
    int HandlesClosed,
    List<(int Pid, string? ProcessName)> LockingProcesses);

public enum DeleteResult
{
    Success,
    NotFound,
    UnlockFailed,
    DeleteFailed,
    ScheduledForReboot
}

public static class FileDestroyer
{
    /// <summary>
    /// Unlock a file by finding and closing all handles to it.
    /// </summary>
    public static FileUnlockResult UnlockFile(string filePath)
    {
        var fullPath = Path.GetFullPath(filePath);
        var handles = HandleUtils.FindHandlesForFile(fullPath);
        int closed = 0;
        var lockingProcesses = new List<(int, string?)>();

        foreach (var (pid, handle) in handles)
        {
            string? procName = null;
            try
            {
                procName = System.Diagnostics.Process.GetProcessById(pid).ProcessName;
            }
            catch { }
            lockingProcesses.Add((pid, procName));

            if (HandleUtils.CloseRemoteHandle(pid, handle))
                closed++;
        }

        return new FileUnlockResult(fullPath, handles.Count, closed, lockingProcesses);
    }

    /// <summary>
    /// Force-delete a file. Tries multiple strategies in escalation order.
    /// </summary>
    public static (DeleteResult Result, string Message) ForceDelete(string filePath)
    {
        var fullPath = Path.GetFullPath(filePath);

        if (!File.Exists(fullPath))
            return (DeleteResult.NotFound, $"File not found: {fullPath}");

        // Strategy 1: Direct delete
        try
        {
            File.Delete(fullPath);
            return (DeleteResult.Success, $"Deleted: {fullPath}");
        }
        catch { }

        // Strategy 2: Unlock handles, then delete
        var unlockResult = UnlockFile(fullPath);
        if (unlockResult.HandlesFound > 0)
        {
            // Brief pause for handles to fully release
            Thread.Sleep(100);
            try
            {
                File.Delete(fullPath);
                return (DeleteResult.Success,
                    $"Deleted after unlocking {unlockResult.HandlesClosed}/{unlockResult.HandlesFound} handles: {fullPath}");
            }
            catch { }
        }

        // Strategy 3: Rename to random name, then delete (bypasses some protections)
        try
        {
            var dir = Path.GetDirectoryName(fullPath)!;
            var tempName = Path.Combine(dir, $".del_{Guid.NewGuid():N}");
            File.Move(fullPath, tempName);
            File.Delete(tempName);
            return (DeleteResult.Success, $"Deleted via rename: {fullPath}");
        }
        catch { }

        // Strategy 4: Schedule for reboot deletion
        return ScheduleRebootDelete(fullPath);
    }

    /// <summary>
    /// Force-delete an entire directory tree.
    /// </summary>
    public static (DeleteResult Result, string Message) ForceDeleteDirectory(string dirPath)
    {
        var fullPath = Path.GetFullPath(dirPath);

        if (!Directory.Exists(fullPath))
            return (DeleteResult.NotFound, $"Directory not found: {fullPath}");

        var failures = new List<string>();
        int deleted = 0;
        int rebootScheduled = 0;

        // Delete files bottom-up
        foreach (var file in Directory.EnumerateFiles(fullPath, "*", SearchOption.AllDirectories))
        {
            var (result, _) = ForceDelete(file);
            if (result == DeleteResult.Success)
                deleted++;
            else if (result == DeleteResult.ScheduledForReboot)
                rebootScheduled++;
            else
                failures.Add(file);
        }

        // Remove empty directories bottom-up
        foreach (var dir in Directory.EnumerateDirectories(fullPath, "*", SearchOption.AllDirectories)
            .OrderByDescending(d => d.Length))
        {
            try { Directory.Delete(dir); }
            catch { }
        }

        // Remove root directory
        try
        {
            Directory.Delete(fullPath);
        }
        catch
        {
            // Schedule the directory itself for reboot deletion
            NativeMethods.MoveFileEx(fullPath, null, NativeMethods.MOVEFILE_DELAY_UNTIL_REBOOT);
        }

        if (failures.Count == 0 && rebootScheduled == 0)
            return (DeleteResult.Success, $"Deleted directory with {deleted} files: {fullPath}");
        else if (failures.Count == 0)
            return (DeleteResult.ScheduledForReboot,
                $"Deleted {deleted} files, {rebootScheduled} scheduled for reboot: {fullPath}");
        else
            return (DeleteResult.DeleteFailed,
                $"Deleted {deleted}, reboot {rebootScheduled}, failed {failures.Count}: {fullPath}");
    }

    /// <summary>
    /// Schedule a file for deletion on next system reboot.
    /// </summary>
    public static (DeleteResult Result, string Message) ScheduleRebootDelete(string filePath)
    {
        var fullPath = Path.GetFullPath(filePath);

        bool success = NativeMethods.MoveFileEx(
            fullPath,
            null,
            NativeMethods.MOVEFILE_DELAY_UNTIL_REBOOT);

        return success
            ? (DeleteResult.ScheduledForReboot, $"Scheduled for deletion on reboot: {fullPath}")
            : (DeleteResult.DeleteFailed, $"Failed to schedule reboot deletion: {fullPath}");
    }
}
