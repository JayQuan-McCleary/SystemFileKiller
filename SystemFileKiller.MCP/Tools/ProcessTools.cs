using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json;
using ModelContextProtocol.Server;
using SystemFileKiller.Core;

namespace SystemFileKiller.MCP.Tools;

[McpServerToolType]
public class ProcessTools
{
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

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
        return JsonSerializer.Serialize(result, Indented);
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
        }, Indented);
    }

    [McpServerTool(Name = "sfk_process_kill")]
    [Description("Force-kill a process by PID or name. Walks an escalation ladder: Process.Kill → NtTerminate (suspend+terminate) → SCM service stop → LocalSystem helper service via named pipe (if installed) → optional UAC self-elevate. Each call returns a `trace` array of which stages were tried and their outcomes.")]
    public static string KillProcess(
        [Description("Process PID (number) or process name (string)")] string target,
        [Description("If true, kill the process and all its child processes")] bool killTree = false,
        [Description("If true, allow Stage 5 (UAC self-elevate via 'runas') as a final fallback. Off by default — UAC mid-call is jarring; opt-in per call.")] bool useElevation = false)
    {
        if (int.TryParse(target, out int pid))
        {
            var esc = new KillEscalation { AllowUacElevation = useElevation };
            var result = ProcessKiller.ForceKill(pid, killTree, esc);
            return JsonSerializer.Serialize(new
            {
                pid,
                result = result.ToString(),
                success = IsSuccess(result),
                trace = esc.Trace,
                lastError = (string?)null
            }, Indented);
        }

        var processes = Process.GetProcessesByName(target);
        if (processes.Length == 0)
            processes = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(target));

        if (processes.Length == 0)
            return JsonSerializer.Serialize(new { error = $"No processes found with name: {target}" });

        var perPid = new List<object>();
        bool allOk = true;
        foreach (var p in processes)
        {
            var pidNum = p.Id;
            p.Dispose();
            var subEsc = new KillEscalation { AllowUacElevation = useElevation };
            var result = ProcessKiller.ForceKill(pidNum, killTree, subEsc);
            var ok = IsSuccess(result);
            allOk = allOk && ok;
            perPid.Add(new
            {
                pid = pidNum,
                result = result.ToString(),
                success = ok,
                trace = subEsc.Trace
            });
        }

        return JsonSerializer.Serialize(new
        {
            targetName = target,
            results = perPid,
            allSucceeded = allOk
        }, Indented);
    }

    private static bool IsSuccess(KillResult r) =>
        r is KillResult.Success
            or KillResult.StoppedViaService
            or KillResult.StoppedViaPipeService
            or KillResult.StoppedViaUac;
}
