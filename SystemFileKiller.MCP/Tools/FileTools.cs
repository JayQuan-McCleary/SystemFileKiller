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
