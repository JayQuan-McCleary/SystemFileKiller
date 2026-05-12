using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;
using SystemFileKiller.Core;

namespace SystemFileKiller.MCP.Tools;

/// <summary>
/// One MCP operation inside a batch. <see cref="Op"/> picks the dispatch; the other fields are
/// the parameters for that op (only the relevant ones are read).
/// </summary>
public class BatchOpInput
{
    /// <summary>The op identifier — see BatchTools.Batch description for the full list.</summary>
    public string? Op { get; set; }
    public int? Pid { get; set; }
    public string? Name { get; set; }
    public string? Path { get; set; }
    public string[]? Paths { get; set; }
    public bool? KillTree { get; set; }
    public string? Hive { get; set; }
    public string? ValueName { get; set; }
    public string? ValueData { get; set; }
    public string? ValueKind { get; set; }
    public string? QuarantineId { get; set; }
    public int? OlderThanDays { get; set; }
    public string? Pattern { get; set; }
    public string? Description { get; set; }
}

[McpServerToolType]
public class BatchTools
{
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    [McpServerTool(Name = "sfk_batch")]
    [Description(
        "Execute a sequence of SFK operations in ONE pipe round-trip. Use this for any multi-step cleanup. " +
        "Operations run sequentially in the order given. Set dryRun=true to preview what each op would do " +
        "without performing destructive actions — recommended for AI-driven cleanups before committing.\n\n" +
        "Supported ops (set 'op' plus the relevant parameter fields):\n" +
        "  PROCESSES\n" +
        "    kill_process              (pid, killTree?)\n" +
        "    kill_process_by_name      (name, killTree?)              — kills every process with that name\n" +
        "  SERVICES\n" +
        "    stop_service              (name)                          — service short name\n" +
        "    disable_service           (name)                          — set StartType=Disabled (no auto-start at boot)\n" +
        "    delete_service            (name)                          — sc delete after stopping\n" +
        "  FILES\n" +
        "    delete_file               (path)\n" +
        "    delete_dir                (path)\n" +
        "    delete_paths              (paths[])                       — mixed file/dir, auto-detected\n" +
        "    quarantine_file           (path)                          — REVERSIBLE: zip → quarantine → delete original\n" +
        "    quarantine_restore        (quarantineId)                  — undo a quarantine\n" +
        "    quarantine_purge          (olderThanDays?)                — finalize quarantine (irreversible)\n" +
        "  SCHEDULED TASKS\n" +
        "    task_disable              (name = full task path)\n" +
        "    task_enable               (name)\n" +
        "    task_delete               (name)\n" +
        "  REGISTRY (refuses SAM/SECURITY/HARDWARE/LSA/Setup)\n" +
        "    registry_remove_key       (hive)                          — delete subtree at hive path\n" +
        "    registry_remove_value     (hive, valueName)\n" +
        "    registry_set_value        (hive, valueName, valueData, valueKind?)\n" +
        "  HOSTS / WMI / SYSTEM\n" +
        "    hosts_remove_pattern      (pattern)                       — regex against hostname column\n" +
        "    wmi_persistence_remove    (name = consumer name)\n" +
        "    restore_point_create      (description?)                  — System Restore checkpoint\n\n" +
        "Returns top-level ok/summary plus 'results' array (one per input op). Each result includes the op's " +
        "inner result, error (if any), pathResults (for delete_paths), and inner (for kill_process_by_name).\n" +
        "Default: continue past per-op failures. Pass stopOnError=true to abort early.")]
    public static string Batch(
        [Description("Array of operations to run sequentially")] BatchOpInput[] ops,
        [Description("Stop at first failed op instead of continuing")] bool stopOnError = false,
        [Description("Preview only: report what each op WOULD do without executing destructive actions. Recommended before any cleanup batch.")] bool dryRun = false)
    {
        if (ops is null || ops.Length == 0)
        {
            return JsonSerializer.Serialize(new { ok = false, error = "ops array is empty" }, Indented);
        }

        var pipeOps = ops.Select(o => new PipeRequest
        {
            Id = Guid.NewGuid().ToString("N"),
            Cmd = o.Op ?? "",
            Pid = o.Pid,
            Name = o.Name,
            Path = o.Path,
            Paths = o.Paths,
            KillTree = o.KillTree ?? false,
            Hive = o.Hive,
            ValueName = o.ValueName,
            ValueData = o.ValueData,
            ValueKind = o.ValueKind,
            QuarantineId = o.QuarantineId,
            OlderThanDays = o.OlderThanDays,
            Pattern = o.Pattern,
            Description = o.Description,
        }).ToArray();

        var req = new PipeRequest
        {
            Cmd = PipeProtocol.Commands.Batch,
            Ops = pipeOps,
            StopOnError = stopOnError,
            DryRun = dryRun,
        };

        // 30-minute ceiling: a batch may include multi-GB directory deletes.
        var resp = PipeClient.Send(req, timeoutMs: 30 * 60 * 1000);

        return JsonSerializer.Serialize(new
        {
            ok = resp.Ok,
            summary = resp.Result,
            error = resp.Error,
            results = (resp.BatchResults ?? new List<PipeResponse>()).Select((r, idx) => new
            {
                index = idx,
                op = idx < ops.Length ? ops[idx].Op : null,
                ok = r.Ok,
                result = r.Result,
                error = r.Error,
                pathResults = r.Results?.Select(p => new { path = p.Path, ok = p.Ok, result = p.Result, error = p.Error }),
                inner = r.BatchResults?.Select(b => new { ok = b.Ok, result = b.Result, error = b.Error })
            })
        }, Indented);
    }
}
