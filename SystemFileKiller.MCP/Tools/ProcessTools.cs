using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;
using SystemFileKiller.Core;

namespace SystemFileKiller.MCP.Tools;

[McpServerToolType]
public class ProcessTools
{
    [McpServerTool(Name = "sfk_process_list")]
    [Description("List all running processes with PID, name, file path, and memory usage in MB.")]
    public static string ListProcesses()
    {
        var processes = ProcessKiller.ListProcesses();
        var result = processes.Select(p => new
        {
            p.Pid,
            p.Name,
            p.FilePath,
            p.MemoryMB,
            p.Description
        });
        return JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
    }

    [McpServerTool(Name = "sfk_process_search")]
    [Description("Search for running processes by name or path substring. Returns matching processes with PID, name, path, and memory.")]
    public static string SearchProcesses(
        [Description("Search filter - matches against process name or file path (case-insensitive)")] string filter)
    {
        var processes = ProcessKiller.ListProcesses()
            .Where(p => p.Name.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                        (p.FilePath?.Contains(filter, StringComparison.OrdinalIgnoreCase) == true))
            .ToList();

        return JsonSerializer.Serialize(new
        {
            matchCount = processes.Count,
            processes = processes.Select(p => new
            {
                p.Pid,
                p.Name,
                p.FilePath,
                p.MemoryMB,
                p.Description
            })
        }, new JsonSerializerOptions { WriteIndented = true });
    }

    [McpServerTool(Name = "sfk_process_kill")]
    [Description("Force-kill a process by PID or name. Escalates through multiple termination methods: normal kill, then suspend + NtTerminateProcess. Set killTree=true to also kill all child processes.")]
    public static string KillProcess(
        [Description("Process PID (number) or process name (string)")] string target,
        [Description("If true, kill the process and all its child processes")] bool killTree = false)
    {
        if (int.TryParse(target, out int pid))
        {
            var result = ProcessKiller.ForceKill(pid, killTree);
            return JsonSerializer.Serialize(new
            {
                pid,
                result = result.ToString(),
                success = result == KillResult.Success
            });
        }
        else
        {
            var results = ProcessKiller.ForceKillByName(target, killTree);
            if (results.Count == 0)
                return JsonSerializer.Serialize(new { error = $"No processes found with name: {target}" });

            return JsonSerializer.Serialize(new
            {
                targetName = target,
                results = results.Select(r => new
                {
                    pid = r.Pid,
                    result = r.Result.ToString(),
                    success = r.Result == KillResult.Success
                }),
                allSucceeded = results.All(r => r.Result == KillResult.Success)
            }, new JsonSerializerOptions { WriteIndented = true });
        }
    }
}
