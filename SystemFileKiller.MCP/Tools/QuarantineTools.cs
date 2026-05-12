using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;
using SystemFileKiller.Core;

namespace SystemFileKiller.MCP.Tools;

[McpServerToolType]
public class QuarantineTools
{
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    [McpServerTool(Name = "sfk_quarantine_file")]
    [Description("REVERSIBLE delete: zip the file/directory into %ProgramData%\\SFK\\Quarantine\\<id>\\content.zip with metadata, then remove the original. Use this instead of sfk_file_delete when you want an undo path. Returns the quarantine id needed for restore.")]
    public static string QuarantineFile([Description("Full path to file or directory to quarantine")] string path)
    {
        var (r, msg, item) = QuarantineManager.Quarantine(path);
        return JsonSerializer.Serialize(new
        {
            path,
            result = r.ToString(),
            success = r == QuarantineResult.Success,
            message = msg,
            quarantineId = item?.Id,
            archivePath = item?.ArchivePath,
            originalSizeBytes = item?.OriginalSizeBytes
        }, Indented);
    }

    [McpServerTool(Name = "sfk_quarantine_list")]
    [Description("List every item currently in the SFK quarantine. Returns id, original path, when quarantined, archive path, and original size. Use the id with sfk_quarantine_restore.")]
    public static string ListQuarantine()
    {
        var items = QuarantineManager.ListItems();
        return JsonSerializer.Serialize(new
        {
            count = items.Count,
            items = items.Select(i => new
            {
                id = i.Id,
                originalPath = i.OriginalPath,
                quarantinedAt = i.QuarantinedAt,
                originalSizeBytes = i.OriginalSizeBytes,
                wasDirectory = i.WasDirectory,
                archivePath = i.ArchivePath
            })
        }, Indented);
    }

    [McpServerTool(Name = "sfk_quarantine_restore")]
    [Description("Restore a quarantined item back to its original location. Pass the id from sfk_quarantine_list. Overwrites if the destination exists.")]
    public static string Restore([Description("Quarantine bucket id (timestamp_guid)")] string quarantineId)
    {
        var (r, msg) = QuarantineManager.Restore(quarantineId);
        return JsonSerializer.Serialize(new { quarantineId, result = r.ToString(),
            success = r == QuarantineResult.Success, message = msg });
    }

    [McpServerTool(Name = "sfk_quarantine_purge")]
    [Description("Permanently delete quarantine buckets. Set olderThanDays > 0 to keep recent items as a safety window; 0 (default) wipes all. Irreversible.")]
    public static string Purge([Description("Only purge items older than this many days. 0 = purge everything.")] int olderThanDays = 0)
    {
        var (r, msg, removed) = QuarantineManager.Purge(olderThanDays);
        return JsonSerializer.Serialize(new { result = r.ToString(),
            success = r == QuarantineResult.Success, removed, message = msg });
    }
}
