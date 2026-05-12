using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;
using SystemFileKiller.Core;

namespace SystemFileKiller.MCP.Tools;

[McpServerToolType]
public class NukeTools
{
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    [McpServerTool(Name = "sfk_nuke")]
    [Description(
        "ONE-CALL APP/MALWARE REMOVAL. Pass an identifier (process short name, install path, or " +
        "display-name fragment) and the orchestrator discovers everything related — running " +
        "processes, services hosted by those PIDs, services with matching name/ImagePath, " +
        "scheduled tasks running the target, uninstall registry stubs, install folders, on-disk " +
        "binaries, Run-key persistence values — and assembles a single batch in shutdown-then-" +
        "cleanup order: kill → stop → disable → delete services/tasks → wipe files → strip " +
        "registry persistence → drop uninstall stubs.\n\n" +
        "RECOMMENDED FLOW:\n" +
        "  1. First call with default args (executePlan=false): returns the discovery (findings) " +
        "and the planned op sequence WITHOUT executing. Review it.\n" +
        "  2. Optional second call with executePlan=true and dryRun=true: server simulates each " +
        "op, returning per-op 'would do X' messages.\n" +
        "  3. Final call with executePlan=true and dryRun=false: actually performs the cleanup.\n\n" +
        "Refuses identifiers in the never-touch list (csrss, lsass, winlogon, services, system, " +
        "explorer, svchost, dwm, windows, microsoft, etc). Individual ops still pass through the " +
        "protected-path / protected-key / critical-process blocklists in the dispatcher, so even " +
        "a permitted identifier can't drag along forbidden side effects.")]
    public static string Nuke(
        [Description("Target identifier — short process name (e.g. 'badexe'), install path (e.g. 'C:\\\\Program Files\\\\BadApp'), or display-name fragment matching uninstall stubs (e.g. 'BadApp Pro 2024')")] string identifier,
        [Description("If true, dispatch the plan via pipe. If false (default), return the plan only — caller reviews first.")] bool executePlan = false,
        [Description("Only meaningful when executePlan=true. If true, server simulates each op (no destructive action). If false, performs the cleanup for real.")] bool dryRun = false)
    {
        var plan = NukeOrchestrator.Plan(identifier);

        if (plan.Refused)
        {
            return JsonSerializer.Serialize(new
            {
                identifier,
                refused = true,
                reason = plan.RefusedReason,
            }, Indented);
        }

        var planView = new
        {
            identifier = plan.Identifier,
            findings = plan.Findings.Select(f => new { f.Kind, f.Detail, f.Path, f.AssociatedHive }),
            opCount = plan.Ops.Length,
            ops = plan.Ops.Select(o => Summarize(o)),
        };

        if (!executePlan)
        {
            return JsonSerializer.Serialize(new
            {
                mode = "plan-only",
                executed = false,
                plan = planView,
                hint = "call again with executePlan=true and dryRun=true to simulate, or executePlan=true and dryRun=false to commit",
            }, Indented);
        }

        if (plan.Ops.Length == 0)
        {
            return JsonSerializer.Serialize(new
            {
                identifier,
                executed = false,
                noOpsToRun = true,
                plan = planView,
            }, Indented);
        }

        var (_, resp) = NukeOrchestrator.Execute(identifier, dryRun);
        return JsonSerializer.Serialize(new
        {
            mode = dryRun ? "dryrun" : "execute",
            executed = true,
            ok = resp?.Ok,
            summary = resp?.Result,
            error = resp?.Error,
            plan = planView,
            results = (resp?.BatchResults ?? new List<PipeResponse>()).Select((r, idx) => new
            {
                index = idx,
                op = idx < plan.Ops.Length ? plan.Ops[idx].Cmd : null,
                ok = r.Ok,
                result = r.Result,
                error = r.Error,
            }),
        }, Indented);
    }

    private static object Summarize(PipeRequest op) => op.Cmd switch
    {
        PipeProtocol.Commands.KillProcess => new { op = op.Cmd, op.Pid, op.KillTree },
        PipeProtocol.Commands.KillProcessByName => new { op = op.Cmd, op.Name, op.KillTree },
        PipeProtocol.Commands.StopService or
            PipeProtocol.Commands.DisableService or
            PipeProtocol.Commands.DeleteService => new { op = op.Cmd, op.Name },
        PipeProtocol.Commands.TaskDisable or
            PipeProtocol.Commands.TaskEnable or
            PipeProtocol.Commands.TaskDelete => new { op = op.Cmd, taskPath = op.Name },
        PipeProtocol.Commands.DeleteFile or PipeProtocol.Commands.DeleteDir => new { op = op.Cmd, op.Path },
        PipeProtocol.Commands.DeletePaths => new { op = op.Cmd, pathCount = op.Paths?.Length ?? 0, sample = op.Paths?.Take(5) },
        PipeProtocol.Commands.RegistryRemoveKey => new { op = op.Cmd, op.Hive },
        PipeProtocol.Commands.RegistryRemoveValue => new { op = op.Cmd, op.Hive, op.ValueName },
        _ => new { op = op.Cmd },
    };
}
