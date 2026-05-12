using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;
using SystemFileKiller.Core;

namespace SystemFileKiller.MCP.Tools;

[McpServerToolType]
public class HostsTools
{
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    [McpServerTool(Name = "sfk_hosts_list")]
    [Description("List all non-comment, non-blank entries in C:\\Windows\\System32\\drivers\\etc\\hosts. Default Windows ships an all-comment file — any data line is worth eyeballing. Common adware patterns: redirecting ad-network domains to 127.0.0.1, or pointing competitor sites at attacker-controlled IPs.")]
    public static string ListEntries()
    {
        var entries = HostsFileUtil.ReadEntries();
        return JsonSerializer.Serialize(new
        {
            count = entries.Count,
            entries = entries.Select(e => new
            {
                e.LineNumber, e.Address, e.Hostname, e.Comment, e.RawLine
            })
        }, Indented);
    }

    [McpServerTool(Name = "sfk_hosts_remove_pattern")]
    [Description("Remove every hosts file entry whose hostname matches the given .NET regex (case-insensitive). Atomic write via .new + replace, original kept as .sfk-bak. Requires admin.")]
    public static string RemoveMatching([Description(".NET regex pattern matched against the hostname column")] string pattern)
    {
        var (ok, msg, removed) = HostsFileUtil.RemoveMatching(pattern);
        return JsonSerializer.Serialize(new { pattern, success = ok, removed, message = msg });
    }
}
