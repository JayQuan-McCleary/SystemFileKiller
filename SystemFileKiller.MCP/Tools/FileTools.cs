using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;
using SystemFileKiller.Core;

namespace SystemFileKiller.MCP.Tools;

[McpServerToolType]
public class FileTools
{
    [McpServerTool(Name = "sfk_file_delete")]
    [Description("Force-delete a file using escalating strategies: direct delete, unlock file handles then delete, rename trick, and finally schedule for reboot deletion. Requires admin for locked/protected files.")]
    public static string ForceDeleteFile(
        [Description("Full path to the file to delete")] string path)
    {
        var (result, message) = FileDestroyer.ForceDelete(path);
        return JsonSerializer.Serialize(new
        {
            result = result.ToString(),
            message,
            success = result is DeleteResult.Success or DeleteResult.ScheduledForReboot
        });
    }

    [McpServerTool(Name = "sfk_file_delete_dir")]
    [Description("Force-delete an entire directory tree. Recursively unlocks and deletes all files, then removes directories. Files that can't be deleted are scheduled for reboot deletion.")]
    public static string ForceDeleteDirectory(
        [Description("Full path to the directory to delete")] string path)
    {
        var (result, message) = FileDestroyer.ForceDeleteDirectory(path);
        return JsonSerializer.Serialize(new
        {
            result = result.ToString(),
            message,
            success = result is DeleteResult.Success or DeleteResult.ScheduledForReboot
        });
    }

    [McpServerTool(Name = "sfk_file_delete_paths")]
    [Description("Batch-delete N files/directories in one call. Each path is auto-detected as file or directory and processed via the LocalSystem helper service with full escalation (handle unlock, rename trick, schedule-for-reboot). Significantly faster than calling sfk_file_delete or sfk_file_delete_dir N times — single pipe round-trip instead of N. Use this whenever you have more than one path to remove.")]
    public static string ForceDeletePaths(
        [Description("Array of full paths to delete. Each may be a file or a directory; type is auto-detected per entry.")] string[] paths)
    {
        var results = FileDestroyer.ForceDeletePaths(paths ?? Array.Empty<string>());
        int succeeded = results.Count(r => r.Result is DeleteResult.Success or DeleteResult.ScheduledForReboot);
        return JsonSerializer.Serialize(new
        {
            total = results.Count,
            succeeded,
            failed = results.Count - succeeded,
            allSucceeded = succeeded == results.Count,
            results = results.Select(r => new
            {
                path = r.Path,
                result = r.Result.ToString(),
                message = r.Message,
                success = r.Result is DeleteResult.Success or DeleteResult.ScheduledForReboot
            })
        }, new JsonSerializerOptions { WriteIndented = true });
    }

    [McpServerTool(Name = "sfk_file_unlock")]
    [Description("Find and close all file handles locking a file. Shows which processes were holding the file. Does NOT delete the file - only unlocks it.")]
    public static string UnlockFile(
        [Description("Full path to the locked file")] string path)
    {
        var result = FileDestroyer.UnlockFile(path);
        return JsonSerializer.Serialize(new
        {
            filePath = result.FilePath,
            handlesFound = result.HandlesFound,
            handlesClosed = result.HandlesClosed,
            lockingProcesses = result.LockingProcesses.Select(p => new
            {
                pid = p.Pid,
                processName = p.ProcessName
            }),
            fullyUnlocked = result.HandlesClosed == result.HandlesFound
        }, new JsonSerializerOptions { WriteIndented = true });
    }

    [McpServerTool(Name = "sfk_file_reboot_delete")]
    [Description("Schedule a file for deletion on the next system reboot using MoveFileEx API. Use this as a last resort when a file absolutely cannot be deleted while Windows is running.")]
    public static string ScheduleRebootDelete(
        [Description("Full path to the file to delete on reboot")] string path)
    {
        var (result, message) = FileDestroyer.ScheduleRebootDelete(path);
        return JsonSerializer.Serialize(new
        {
            result = result.ToString(),
            message,
            success = result == DeleteResult.ScheduledForReboot
        });
    }
}
