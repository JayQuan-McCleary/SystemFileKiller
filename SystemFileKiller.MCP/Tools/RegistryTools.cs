using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;
using SystemFileKiller.Core;

namespace SystemFileKiller.MCP.Tools;

[McpServerToolType]
public class RegistryTools
{
    [McpServerTool(Name = "sfk_registry_scan")]
    [Description("Scan all known malware persistence registry locations (Run, RunOnce, Services, Winlogon, Shell Folders, etc). Returns every entry found with suspicious ones flagged with a reason.")]
    public static string ScanAll()
    {
        var entries = RegistryCleaner.ScanPersistenceLocations();
        var suspicious = entries.Count(e => e.Reason != null);

        return JsonSerializer.Serialize(new
        {
            totalEntries = entries.Count,
            suspiciousCount = suspicious,
            entries = entries.Select((e, i) => new
            {
                index = i,
                hivePath = e.HivePath,
                valueName = e.ValueName,
                valueData = e.ValueData,
                reason = e.Reason,
                isSuspicious = e.Reason != null
            })
        }, new JsonSerializerOptions { WriteIndented = true });
    }

    [McpServerTool(Name = "sfk_registry_scan_suspicious")]
    [Description("Scan registry persistence locations and return ONLY entries flagged as suspicious. Flags include: executables in temp folders, encoded PowerShell, script host execution, missing executables, and more.")]
    public static string ScanSuspicious()
    {
        var entries = RegistryCleaner.ScanSuspicious();

        return JsonSerializer.Serialize(new
        {
            suspiciousCount = entries.Count,
            entries = entries.Select((e, i) => new
            {
                index = i,
                hivePath = e.HivePath,
                valueName = e.ValueName,
                valueData = e.ValueData,
                reason = e.Reason
            })
        }, new JsonSerializerOptions { WriteIndented = true });
    }

    [McpServerTool(Name = "sfk_registry_remove")]
    [Description("Remove a specific registry persistence entry by its hive path and value name. Use sfk_registry_scan first to identify entries to remove.")]
    public static string RemoveEntry(
        [Description("Full registry hive path (e.g. 'HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run')")] string hivePath,
        [Description("Registry value name to remove")] string valueName)
    {
        var entry = new RegistryEntry(hivePath, valueName, null, null);
        var success = RegistryCleaner.RemoveEntry(entry);

        return JsonSerializer.Serialize(new
        {
            hivePath,
            valueName,
            removed = success,
            message = success
                ? $"Removed: {hivePath}\\{valueName}"
                : $"Failed to remove: {hivePath}\\{valueName} (may need admin privileges)"
        });
    }
}
