using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;
using SystemFileKiller.Core;

namespace SystemFileKiller.MCP.Tools;

[McpServerToolType]
public class TaskTools
{
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    [McpServerTool(Name = "sfk_task_list")]
    [Description("List all Windows scheduled tasks. Each entry includes task path, run target, status, author, and a suspicion flag (heuristics: targets in user-writable paths, base64-encoded PowerShell, missing binaries, Microsoft-author claim outside system paths). Set suspiciousOnly=true to filter to flagged entries — the cleanup-relevant subset.")]
    public static string ListTasks(
        [Description("Return only entries flagged by suspicion heuristics")] bool suspiciousOnly = false)
    {
        var tasks = TaskManager.ListTasks(suspiciousOnly);
        return JsonSerializer.Serialize(new
        {
            count = tasks.Count,
            suspiciousCount = tasks.Count(t => t.IsSuspicious),
            tasks = tasks.Select(t => new
            {
                path = t.TaskPath,
                name = t.TaskName,
                status = t.Status,
                author = t.Author,
                taskRun = t.TaskRun,
                lastRunTime = t.LastRunTime,
                lastResult = t.LastResult,
                nextRunTime = t.NextRunTime,
                isSuspicious = t.IsSuspicious,
                suspicionReason = t.SuspicionReason,
            })
        }, Indented);
    }

    [McpServerTool(Name = "sfk_task_disable")]
    [Description("Disable a scheduled task by full task path (e.g. '\\Microsoft\\Windows\\UpdateOrchestrator\\Reboot'). Disabled tasks stay registered but won't fire. Reversible via sfk_task_enable. Requires admin.")]
    public static string DisableTask([Description("Full task path including leading backslash")] string taskPath)
    {
        var r = TaskManager.DisableTask(taskPath);
        return JsonSerializer.Serialize(new { taskPath, result = r.ToString(),
            success = r is ServiceOpResult.Success or ServiceOpResult.AlreadyInTargetState });
    }

    [McpServerTool(Name = "sfk_task_enable")]
    [Description("Re-enable a previously disabled scheduled task. Use to undo sfk_task_disable.")]
    public static string EnableTask([Description("Full task path")] string taskPath)
    {
        var r = TaskManager.EnableTask(taskPath);
        return JsonSerializer.Serialize(new { taskPath, result = r.ToString(),
            success = r is ServiceOpResult.Success or ServiceOpResult.AlreadyInTargetState });
    }

    [McpServerTool(Name = "sfk_task_delete")]
    [Description("Permanently delete a scheduled task by full path. Irreversible — prefer sfk_task_disable for triage. Requires admin.")]
    public static string DeleteTask([Description("Full task path")] string taskPath)
    {
        var r = TaskManager.DeleteTask(taskPath);
        return JsonSerializer.Serialize(new { taskPath, result = r.ToString(),
            success = r == ServiceOpResult.Success });
    }
}
