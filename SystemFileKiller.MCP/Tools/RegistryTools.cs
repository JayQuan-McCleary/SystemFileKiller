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

    [McpServerTool(Name = "sfk_registry_remove_key")]
    [Description("Delete an entire registry key (and its subtree) at any hive path — HKLM, HKCU, HKCR, HKU, HKCC. Use for uninstall stubs (HKLM\\SOFTWARE\\...\\Uninstall\\<guid>), service registrations (HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>), or malware persistence containers. Refuses to touch system-critical roots (SAM, SECURITY, HARDWARE, LSA, Setup). Requires admin for HKLM. Hive path uses standard short prefixes: HKLM\\, HKCU\\, etc.")]
    public static string RemoveKey([Description("Full hive path, e.g. 'HKLM\\\\SOFTWARE\\\\WOW6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\{GUID}'")] string hivePath)
    {
        var (ok, msg) = RegistryCleaner.RemoveKey(hivePath);
        return JsonSerializer.Serialize(new { hivePath, success = ok, message = msg });
    }

    [McpServerTool(Name = "sfk_registry_remove_value")]
    [Description("Delete a single value under any registry key without removing the key itself. Use for surgical removal — e.g. one entry from HKCU\\...\\Run without nuking the whole Run key. Pass empty string for the (Default) value.")]
    public static string RemoveValue(
        [Description("Full hive path of the parent key")] string hivePath,
        [Description("Value name (empty string targets the (Default) value)")] string valueName)
    {
        var (ok, msg) = RegistryCleaner.RemoveValue(hivePath, valueName);
        return JsonSerializer.Serialize(new { hivePath, valueName, success = ok, message = msg });
    }

    [McpServerTool(Name = "sfk_registry_set_value")]
    [Description("Write a registry value, creating the key if missing. Use to NEUTRALIZE hijacks by overwriting a malicious entry with the legitimate one (e.g. restoring HKLM\\...\\Winlogon\\Shell to 'explorer.exe') rather than deleting it and breaking the system. Kind: 'String' (default), 'ExpandString', 'DWord', 'QWord', 'Binary' (hex string), 'MultiString' (newline-separated).")]
    public static string SetValue(
        [Description("Full hive path of the parent key")] string hivePath,
        [Description("Value name (empty string for (Default))")] string valueName,
        [Description("Value data as string — converted per Kind")] string value,
        [Description("Registry value kind: String|ExpandString|DWord|QWord|Binary|MultiString")] string kind = "String")
    {
        var k = Enum.TryParse<Microsoft.Win32.RegistryValueKind>(kind, true, out var parsed)
            ? parsed : Microsoft.Win32.RegistryValueKind.String;
        var (ok, msg) = RegistryCleaner.SetValue(hivePath, valueName, value, k);
        return JsonSerializer.Serialize(new { hivePath, valueName, value, kind = k.ToString(), success = ok, message = msg });
    }
}
