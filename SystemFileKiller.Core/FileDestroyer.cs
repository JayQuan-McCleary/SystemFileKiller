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

/// <summary>
/// Per-call options + trace for the FileDestroyer escalation ladder.
/// Mirrors the shape of <see cref="KillEscalation"/>.
/// </summary>
public class ForceDeleteEscalation
{
    /// <summary>Stage 2: scan for handles holding the file open and close them. Only fires on sharing-violation IOExceptions.</summary>
    public bool AllowHandleUnlock { get; init; } = true;
    /// <summary>Stage 4: forward to the LocalSystem helper service via named pipe. Handles ACL-protected paths without UAC.</summary>
    public bool AllowPipeService { get; init; } = true;
    /// <summary>Stage 5: re-launch the host exe under UAC. Off by default — UAC mid-tool-call is jarring.</summary>
    public bool AllowUacElevation { get; init; } = false;
    /// <summary>Per-stage breadcrumbs.</summary>
    public List<string> Trace { get; } = new();
    internal void Note(string entry) => Trace.Add(entry);
}

public static class FileDestroyer
{
    /// <summary>
    /// Unlock a file by finding and closing all handles to it.
    /// </summary>
    public static FileUnlockResult UnlockFile(string filePath)
        => UnlockFileInternal(filePath, null);

    internal static FileUnlockResult UnlockFileInternal(
        string filePath,
        IReadOnlyList<NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>? cachedHandles)
    {
        var fullPath = Path.GetFullPath(filePath);
        var handles = HandleUtils.FindHandlesForFile(fullPath, cachedHandles);
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
        => ForceDeleteInternal(filePath, new ForceDeleteEscalation(), null);

    public static (DeleteResult Result, string Message) ForceDelete(string filePath, ForceDeleteEscalation esc)
        => ForceDeleteInternal(filePath, esc, null);

    /// <summary>
    /// Batch entry point — accepts a pre-enumerated handle table so we don't re-scan
    /// 100k+ system handles once per file when bulk-deleting directories.
    /// </summary>
    internal static (DeleteResult Result, string Message) ForceDeleteInternal(
        string filePath,
        ForceDeleteEscalation esc,
        IReadOnlyList<NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>? cachedHandles)
    {
        var fullPath = Path.GetFullPath(filePath);

        if (!File.Exists(fullPath))
            return (DeleteResult.NotFound, $"File not found: {fullPath}");

        // Stage 1: Direct delete
        try
        {
            File.Delete(fullPath);
            esc.Note("Stage1:Direct:Success");
            return (DeleteResult.Success, $"Deleted: {fullPath}");
        }
        catch (UnauthorizedAccessException)
        {
            // ACL or read-only. NOT a locking issue — skip handle scan entirely.
            esc.Note("Stage1:Direct:Unauthorized");

            // Stage 1b: clear read-only attribute if that's the cause
            try
            {
                var attrs = File.GetAttributes(fullPath);
                if ((attrs & FileAttributes.ReadOnly) != 0)
                {
                    File.SetAttributes(fullPath, attrs & ~FileAttributes.ReadOnly);
                    File.Delete(fullPath);
                    esc.Note("Stage1b:ClearReadOnly:Success");
                    return (DeleteResult.Success, $"Deleted after clearing read-only: {fullPath}");
                }
            }
            catch (Exception ex)
            {
                esc.Note($"Stage1b:ClearReadOnly:{ex.GetType().Name}");
            }
            return Escalate(fullPath, esc, isDirectory: false);
        }
        catch (IOException ioEx)
        {
            // 0x20 = ERROR_SHARING_VIOLATION, 0x21 = ERROR_LOCK_VIOLATION (file actually in use)
            int hr = ioEx.HResult & 0xFFFF;
            esc.Note($"Stage1:Direct:IO:0x{hr:X}");

            if (esc.AllowHandleUnlock && (hr == 0x20 || hr == 0x21))
            {
                var unlock = UnlockFileInternal(fullPath, cachedHandles);
                esc.Note($"Stage2:Unlock:found={unlock.HandlesFound},closed={unlock.HandlesClosed}");
                if (unlock.HandlesFound > 0)
                {
                    Thread.Sleep(100);
                    try
                    {
                        File.Delete(fullPath);
                        return (DeleteResult.Success,
                            $"Deleted after unlocking {unlock.HandlesClosed}/{unlock.HandlesFound} handles: {fullPath}");
                    }
                    catch (Exception retryEx)
                    {
                        esc.Note($"Stage2:RetryDelete:{retryEx.GetType().Name}");
                    }
                }
            }

            // Stage 3: Rename trick — bypasses some sharing-mode restrictions
            try
            {
                var dir = Path.GetDirectoryName(fullPath)!;
                var tempName = Path.Combine(dir, $".del_{Guid.NewGuid():N}");
                File.Move(fullPath, tempName);
                File.Delete(tempName);
                esc.Note("Stage3:Rename:Success");
                return (DeleteResult.Success, $"Deleted via rename: {fullPath}");
            }
            catch (Exception ex)
            {
                esc.Note($"Stage3:Rename:{ex.GetType().Name}");
            }

            return Escalate(fullPath, esc, isDirectory: false);
        }
        catch (Exception ex)
        {
            esc.Note($"Stage1:Direct:Exception:{ex.GetType().Name}");
            return Escalate(fullPath, esc, isDirectory: false);
        }
    }

    /// <summary>
    /// Stage 4–5: escalate via LocalSystem service, then fall back to reboot deletion.
    /// </summary>
    private static (DeleteResult Result, string Message) Escalate(
        string fullPath, ForceDeleteEscalation esc, bool isDirectory)
    {
        // Stage 4: Pipe service (LocalSystem). Bypasses both ACL and most locks.
        if (esc.AllowPipeService)
        {
            if (PipeClient.IsServiceAvailable())
            {
                var resp = PipeClient.Send(new PipeRequest
                {
                    Cmd = isDirectory ? PipeProtocol.Commands.DeleteDir : PipeProtocol.Commands.DeleteFile,
                    Path = fullPath
                }, timeoutMs: isDirectory ? 120000 : 15000);
                esc.Note($"Stage4:PipeService:{(resp.Ok ? "ok" : resp.Error ?? "failed")}");

                bool gone = isDirectory ? !Directory.Exists(fullPath) : !File.Exists(fullPath);
                if (resp.Ok && gone)
                    return (DeleteResult.Success, $"Deleted via LocalSystem service: {fullPath}");
            }
            else
            {
                esc.Note("Stage4:PipeService:unavailable");
            }
        }

        // Stage 5: schedule for reboot deletion (works for files; directories must be empty)
        if (!isDirectory)
        {
            var (r, m) = ScheduleRebootDelete(fullPath);
            esc.Note($"Stage5:Reboot:{r}");
            return (r, m);
        }

        return (DeleteResult.DeleteFailed, $"All stages failed for: {fullPath} ({string.Join(" | ", esc.Trace)})");
    }

    /// <summary>
    /// Force-delete an entire directory tree.
    /// </summary>
    public static (DeleteResult Result, string Message) ForceDeleteDirectory(string dirPath)
        => ForceDeleteDirectory(dirPath, new ForceDeleteEscalation());

    public static (DeleteResult Result, string Message) ForceDeleteDirectory(string dirPath, ForceDeleteEscalation esc)
    {
        var fullPath = Path.GetFullPath(dirPath);

        if (!Directory.Exists(fullPath))
            return (DeleteResult.NotFound, $"Directory not found: {fullPath}");

        // Eagerly snapshot the file list — Directory.EnumerateFiles is lazy and gets
        // confused when files disappear under it. If enumeration itself fails (ACL on the
        // root), escalate the whole tree to the service.
        List<string> files;
        try
        {
            var options = new EnumerationOptions
            {
                IgnoreInaccessible = true,
                RecurseSubdirectories = true,
                AttributesToSkip = 0,
            };
            files = Directory.EnumerateFiles(fullPath, "*", options).ToList();
        }
        catch (UnauthorizedAccessException)
        {
            esc.Note("Enumerate:Unauthorized");
            return Escalate(fullPath, esc, isDirectory: true);
        }
        catch (Exception ex)
        {
            esc.Note($"Enumerate:{ex.GetType().Name}");
            return Escalate(fullPath, esc, isDirectory: true);
        }

        // Cache the handle table lazily — only built if we hit a sharing violation that
        // actually needs it. Avoids the 100k-handle scan when (as in most batch deletes)
        // there are no locks at all.
        IReadOnlyList<NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>? cached = null;
        bool sawUnauthorized = false;
        var failures = new List<string>();
        int deleted = 0;
        int rebootScheduled = 0;
        int serviceDeleted = 0;

        foreach (var file in files)
        {
            // If we already saw one ACL-denied file in this dir, don't waste time per-file
            // calling File.Delete on the rest — they'll all fail the same way. Just jump
            // straight to the dir-level service escalation after the loop.
            if (sawUnauthorized)
            {
                failures.Add(file);
                continue;
            }

            var fileEsc = new ForceDeleteEscalation
            {
                AllowHandleUnlock = esc.AllowHandleUnlock,
                AllowPipeService = false, // suppressed — we'll do one bulk dir-level service call
                AllowUacElevation = false,
            };

            var (result, _) = ForceDeleteInternal(file, fileEsc, cached);
            switch (result)
            {
                case DeleteResult.Success: deleted++; break;
                case DeleteResult.ScheduledForReboot: rebootScheduled++; break;
                default: failures.Add(file); break;
            }

            // Detect first sharing violation -> build the cache for subsequent files
            if (cached == null && fileEsc.Trace.Any(t => t.StartsWith("Stage2:Unlock")))
            {
                cached = HandleUtils.EnumerateAllHandles();
                esc.Note($"Cache:Built:{cached.Count}");
            }

            // Detect ACL -> abort per-file iteration, jump to bulk service escalation
            if (fileEsc.Trace.Any(t => t == "Stage1:Direct:Unauthorized"))
            {
                sawUnauthorized = true;
            }
        }

        // If any file was ACL-blocked, hand the whole remaining tree to the service.
        if (sawUnauthorized && esc.AllowPipeService && PipeClient.IsServiceAvailable())
        {
            var resp = PipeClient.Send(new PipeRequest
            {
                Cmd = PipeProtocol.Commands.DeleteDir,
                Path = fullPath
            }, timeoutMs: 120000);
            esc.Note($"BulkEscalate:PipeService:{(resp.Ok ? "ok" : resp.Error ?? "failed")}");
            if (resp.Ok && !Directory.Exists(fullPath))
            {
                serviceDeleted = failures.Count;
                failures.Clear();
                return (DeleteResult.Success,
                    $"Deleted directory via LocalSystem service ({deleted} user-deletable + {serviceDeleted} system-deletable files): {fullPath}");
            }
        }

        // Strip empty leaf dirs bottom-up
        try
        {
            foreach (var dir in Directory.EnumerateDirectories(fullPath, "*", SearchOption.AllDirectories)
                .OrderByDescending(d => d.Length))
            {
                try { Directory.Delete(dir); } catch { }
            }
        }
        catch { }

        // Remove root directory
        bool rootDeleted = false;
        try
        {
            Directory.Delete(fullPath, recursive: true);
            rootDeleted = true;
        }
        catch (UnauthorizedAccessException)
        {
            if (esc.AllowPipeService && PipeClient.IsServiceAvailable())
            {
                var resp = PipeClient.Send(new PipeRequest
                {
                    Cmd = PipeProtocol.Commands.DeleteDir,
                    Path = fullPath
                }, timeoutMs: 30000);
                rootDeleted = resp.Ok && !Directory.Exists(fullPath);
                esc.Note($"RootEscalate:PipeService:{(resp.Ok ? "ok" : resp.Error ?? "failed")}");
            }
            if (!rootDeleted)
                NativeMethods.MoveFileEx(fullPath, null, NativeMethods.MOVEFILE_DELAY_UNTIL_REBOOT);
        }
        catch
        {
            NativeMethods.MoveFileEx(fullPath, null, NativeMethods.MOVEFILE_DELAY_UNTIL_REBOOT);
        }

        if (failures.Count == 0 && rebootScheduled == 0 && rootDeleted)
            return (DeleteResult.Success, $"Deleted directory with {deleted} files: {fullPath}");
        else if (failures.Count == 0)
            return (DeleteResult.ScheduledForReboot,
                $"Deleted {deleted} files, {rebootScheduled} scheduled for reboot, root deleted={rootDeleted}: {fullPath}");
        else
            return (DeleteResult.DeleteFailed,
                $"Deleted {deleted}, reboot {rebootScheduled}, failed {failures.Count}, root deleted={rootDeleted}: {fullPath}");
    }

    /// <summary>
    /// Batch-delete N paths in one call. Each path may be a file or directory — auto-detected.
    /// When the LocalSystem helper service is reachable, sends a single <c>delete_paths</c> pipe
    /// request so the whole batch costs one connect/round-trip instead of N. Otherwise falls
    /// back to iterating <see cref="ForceDelete"/> / <see cref="ForceDeleteDirectory"/> locally.
    /// </summary>
    public static List<(string Path, DeleteResult Result, string Message)> ForceDeletePaths(IEnumerable<string> paths)
    {
        var list = paths?.ToList() ?? new List<string>();
        var results = new List<(string, DeleteResult, string)>(list.Count);
        if (list.Count == 0) return results;

        if (PipeClient.IsServiceAvailable())
        {
            // 30 min ceiling — bulk deletes of multi-GB game folders can take a couple minutes.
            var resp = PipeClient.Send(new PipeRequest
            {
                Cmd = PipeProtocol.Commands.DeletePaths,
                Paths = list.ToArray()
            }, timeoutMs: 30 * 60 * 1000);

            if (resp.Results is { Count: > 0 } items)
            {
                foreach (var item in items)
                {
                    DeleteResult r;
                    string msg;
                    if (item.Result == "AlreadyAbsent")
                    {
                        r = DeleteResult.Success;
                        msg = "Already absent";
                    }
                    else if (!Enum.TryParse<DeleteResult>(item.Result, out r))
                    {
                        r = item.Ok ? DeleteResult.Success : DeleteResult.DeleteFailed;
                        msg = item.Error ?? item.Result ?? "";
                    }
                    else
                    {
                        msg = item.Error ?? item.Result ?? "";
                    }
                    results.Add((item.Path, r, msg));
                }
                return results;
            }

            // Pipe reachable but came back without per-path results — propagate the error
            // for every path and fall through to local-iteration is overkill; surface the failure.
            foreach (var p in list)
                results.Add((p, DeleteResult.DeleteFailed, resp.Error ?? "pipe returned no per-path results"));
            return results;
        }

        // Local fallback: iterate, auto-detecting file vs directory per path.
        foreach (var p in list)
        {
            try
            {
                if (Directory.Exists(p))
                {
                    var (r, m) = ForceDeleteDirectory(p);
                    results.Add((p, r, m));
                }
                else if (File.Exists(p))
                {
                    var (r, m) = ForceDelete(p);
                    results.Add((p, r, m));
                }
                else
                {
                    results.Add((p, DeleteResult.Success, "Already absent"));
                }
            }
            catch (Exception ex)
            {
                results.Add((p, DeleteResult.DeleteFailed, ex.Message));
            }
        }
        return results;
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
