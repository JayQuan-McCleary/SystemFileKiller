using System.Diagnostics;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using SystemFileKiller.Core;

namespace SystemFileKiller.Service;

/// <summary>
/// Listens on \\.\pipe\sfk and dispatches requests to <see cref="ProcessKiller"/> /
/// <see cref="ServiceManager"/> / <see cref="FileDestroyer"/> as LocalSystem. Refuses to
/// touch the critical-process blocklist (csrss, lsass, etc.) and refuses to delete inside
/// protected system paths.
/// </summary>
public class PipeServer
{
    private static readonly HashSet<string> CriticalProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "csrss", "wininit", "services", "lsass", "smss", "winlogon", "system", "registry"
    };

    // Protected roots — refuse to delete inside these even as LocalSystem.
    // The service has full power; the guardrail is this list.
    private static readonly string[] ProtectedRoots = new[]
    {
        @"C:\Windows",
        @"C:\Program Files\Windows",
        @"C:\Program Files\WindowsApps",
        @"C:\Program Files (x86)\Windows",
        @"C:\System Volume Information",
        @"C:\Recovery",
        @"C:\Boot",
        @"C:\EFI",
    };

    private readonly ILogger _logger;

    public PipeServer(ILogger logger) { _logger = logger; }

    public async Task RunAsync(CancellationToken ct)
    {
        var security = BuildPipeSecurity();

        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? server = null;
            try
            {
                server = NamedPipeServerStreamAcl.Create(
                    PipeProtocol.PipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,
                    inBufferSize: 4096,
                    outBufferSize: 4096,
                    pipeSecurity: security);

                await server.WaitForConnectionAsync(ct);

                var owned = server;
                server = null; // Ownership transferred to handler task
                _ = Task.Run(() => HandleConnection(owned, ct), ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Pipe server loop error");
                server?.Dispose();
                try { await Task.Delay(500, ct); } catch (OperationCanceledException) { break; }
            }
        }
    }

    private async Task HandleConnection(NamedPipeServerStream server, CancellationToken ct)
    {
        try
        {
            using (server)
            {
                var requestStr = await ReadLineAsync(server, ct);
                if (string.IsNullOrEmpty(requestStr)) return;

                PipeRequest? req = null;
                PipeResponse resp;
                try
                {
                    req = JsonSerializer.Deserialize<PipeRequest>(requestStr);
                    resp = req == null
                        ? new PipeResponse { Id = "", Ok = false, Error = "Invalid request" }
                        : Dispatch(req);
                }
                catch (Exception ex)
                {
                    resp = new PipeResponse { Id = req?.Id ?? "", Ok = false, Error = ex.Message };
                }

                var json = JsonSerializer.Serialize(resp);
                var bytes = Encoding.UTF8.GetBytes(json + "\n");
                await server.WriteAsync(bytes, ct);
                await server.FlushAsync(ct);
            }
        }
        catch (OperationCanceledException) { /* shutting down */ }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Pipe connection handler error");
        }
    }

    private PipeResponse Dispatch(PipeRequest req)
    {
        var resp = new PipeResponse { Id = req.Id };
        try
        {
            switch (req.Cmd)
            {
                case PipeProtocol.Commands.Ping:
                    resp.Ok = true;
                    resp.Result = "pong";
                    return resp;

                case PipeProtocol.Commands.KillProcess:
                    return DispatchKill(req, resp);

                case PipeProtocol.Commands.StopService:
                    return DispatchStopService(req, resp);

                case PipeProtocol.Commands.DeleteFile:
                    return DispatchDeleteFile(req, resp);

                case PipeProtocol.Commands.DeleteDir:
                    return DispatchDeleteDir(req, resp);

                case PipeProtocol.Commands.DeletePaths:
                    return DispatchDeletePaths(req, resp);

                case PipeProtocol.Commands.KillProcessByName:
                    return DispatchKillByName(req, resp);

                case PipeProtocol.Commands.DisableService:
                    return DispatchDisableService(req, resp);

                case PipeProtocol.Commands.DeleteService:
                    return DispatchDeleteService(req, resp);

                case PipeProtocol.Commands.TaskDisable:
                    return DispatchTaskOp(req, resp, TaskManager.DisableTask, "task_disable");

                case PipeProtocol.Commands.TaskEnable:
                    return DispatchTaskOp(req, resp, TaskManager.EnableTask, "task_enable");

                case PipeProtocol.Commands.TaskDelete:
                    return DispatchTaskOp(req, resp, TaskManager.DeleteTask, "task_delete");

                case PipeProtocol.Commands.RegistryRemoveKey:
                    return DispatchRegistryRemoveKey(req, resp);

                case PipeProtocol.Commands.RegistryRemoveValue:
                    return DispatchRegistryRemoveValue(req, resp);

                case PipeProtocol.Commands.RegistrySetValue:
                    return DispatchRegistrySetValue(req, resp);

                case PipeProtocol.Commands.QuarantineFile:
                    return DispatchQuarantineFile(req, resp);

                case PipeProtocol.Commands.QuarantineRestore:
                    return DispatchQuarantineRestore(req, resp);

                case PipeProtocol.Commands.QuarantinePurge:
                    return DispatchQuarantinePurge(req, resp);

                case PipeProtocol.Commands.HostsRemovePattern:
                    return DispatchHostsRemovePattern(req, resp);

                case PipeProtocol.Commands.WmiPersistenceRemove:
                    return DispatchWmiPersistenceRemove(req, resp);

                case PipeProtocol.Commands.RestorePointCreate:
                    return DispatchRestorePointCreate(req, resp);

                case PipeProtocol.Commands.Batch:
                    return DispatchBatch(req, resp);

                default:
                    resp.Error = $"Unknown command: {req.Cmd}";
                    return resp;
            }
        }
        catch (Exception ex)
        {
            resp.Ok = false;
            resp.Error = ex.Message;
            return resp;
        }
    }

    private PipeResponse DispatchKill(PipeRequest req, PipeResponse resp)
    {
        if (!req.Pid.HasValue)
        {
            resp.Error = "kill_process requires Pid";
            return resp;
        }

        if (IsCriticalProcess(req.Pid.Value, out var critName))
        {
            _logger.LogWarning("Refused kill of critical process: PID {Pid} ({Name})", req.Pid, critName);
            resp.Error = $"Refused: critical system process ({critName})";
            return resp;
        }

        // Terminal authority — don't loop back to ourselves or to UAC.
        var esc = new KillEscalation { AllowPipeService = false, AllowUacElevation = false };
        var result = ProcessKiller.ForceKill(req.Pid.Value, req.KillTree, esc);
        bool ok = result is KillResult.Success
            or KillResult.StoppedViaService
            or KillResult.StoppedViaPipeService
            or KillResult.StoppedViaUac;

        resp.Ok = ok;
        resp.Result = result.ToString();
        if (!ok) resp.Error = string.Join(" | ", esc.Trace);
        _logger.LogInformation("kill_process pid={Pid} tree={Tree} → {Result}", req.Pid, req.KillTree, result);
        return resp;
    }

    private PipeResponse DispatchStopService(PipeRequest req, PipeResponse resp)
    {
        if (string.IsNullOrEmpty(req.Name))
        {
            resp.Error = "stop_service requires Name";
            return resp;
        }
        var sr = ServiceManager.StopService(req.Name);
        bool ok = sr is ServiceOpResult.Success or ServiceOpResult.AlreadyInTargetState;
        resp.Ok = ok;
        resp.Result = sr.ToString();
        if (!ok) resp.Error = sr.ToString();
        _logger.LogInformation("stop_service name={Name} → {Result}", req.Name, sr);
        return resp;
    }

    private PipeResponse DispatchDeleteFile(PipeRequest req, PipeResponse resp)
    {
        if (string.IsNullOrEmpty(req.Path))
        {
            resp.Error = "delete_file requires Path";
            return resp;
        }
        if (IsProtectedPath(req.Path, out var reason))
        {
            _logger.LogWarning("Refused delete_file in protected path: {Path} ({Reason})", req.Path, reason);
            resp.Error = $"Refused: {reason}";
            return resp;
        }

        // Terminal authority — don't loop back to ourselves.
        var esc = new ForceDeleteEscalation { AllowPipeService = false, AllowUacElevation = false };
        var (result, message) = FileDestroyer.ForceDelete(req.Path, esc);
        bool ok = result is DeleteResult.Success or DeleteResult.ScheduledForReboot;

        resp.Ok = ok;
        resp.Result = result.ToString();
        if (!ok) resp.Error = $"{message} | {string.Join(" | ", esc.Trace)}";
        _logger.LogInformation("delete_file path={Path} → {Result}", req.Path, result);
        return resp;
    }

    private PipeResponse DispatchDeleteDir(PipeRequest req, PipeResponse resp)
    {
        if (string.IsNullOrEmpty(req.Path))
        {
            resp.Error = "delete_dir requires Path";
            return resp;
        }
        if (IsProtectedPath(req.Path, out var reason))
        {
            _logger.LogWarning("Refused delete_dir in protected path: {Path} ({Reason})", req.Path, reason);
            resp.Error = $"Refused: {reason}";
            return resp;
        }

        // Terminal authority — don't loop back to ourselves.
        var esc = new ForceDeleteEscalation { AllowPipeService = false, AllowUacElevation = false };
        var (result, message) = FileDestroyer.ForceDeleteDirectory(req.Path, esc);
        bool ok = result is DeleteResult.Success or DeleteResult.ScheduledForReboot;

        resp.Ok = ok;
        resp.Result = result.ToString();
        if (!ok) resp.Error = $"{message} | {string.Join(" | ", esc.Trace)}";
        _logger.LogInformation("delete_dir path={Path} → {Result}", req.Path, result);
        return resp;
    }

    /// <summary>
    /// Batch delete: one request with N paths. Auto-detects file vs directory per path. Always
    /// processes the full list; per-path outcome is returned in <see cref="PipeResponse.Results"/>.
    /// Top-level Ok=true only if every path succeeded (Success / ScheduledForReboot / AlreadyAbsent).
    /// </summary>
    private PipeResponse DispatchDeletePaths(PipeRequest req, PipeResponse resp)
    {
        if (req.Paths is null || req.Paths.Length == 0)
        {
            resp.Error = "delete_paths requires Paths";
            return resp;
        }

        var items = new List<PipePathResult>(req.Paths.Length);
        int okCount = 0;

        foreach (var path in req.Paths)
        {
            var item = new PipePathResult { Path = path ?? "" };
            try
            {
                if (string.IsNullOrEmpty(path))
                {
                    item.Error = "empty path";
                }
                else if (IsProtectedPath(path, out var reason))
                {
                    _logger.LogWarning("Refused delete_paths entry: {Path} ({Reason})", path, reason);
                    item.Error = $"Refused: {reason}";
                }
                else if (Directory.Exists(path))
                {
                    var esc = new ForceDeleteEscalation { AllowPipeService = false, AllowUacElevation = false };
                    var (result, message) = FileDestroyer.ForceDeleteDirectory(path, esc);
                    bool ok = result is DeleteResult.Success or DeleteResult.ScheduledForReboot;
                    item.Ok = ok;
                    item.Result = result.ToString();
                    if (!ok) item.Error = $"{message} | {string.Join(" | ", esc.Trace)}";
                    if (ok) okCount++;
                }
                else if (File.Exists(path))
                {
                    var esc = new ForceDeleteEscalation { AllowPipeService = false, AllowUacElevation = false };
                    var (result, message) = FileDestroyer.ForceDelete(path, esc);
                    bool ok = result is DeleteResult.Success or DeleteResult.ScheduledForReboot;
                    item.Ok = ok;
                    item.Result = result.ToString();
                    if (!ok) item.Error = $"{message} | {string.Join(" | ", esc.Trace)}";
                    if (ok) okCount++;
                }
                else
                {
                    item.Ok = true;
                    item.Result = "AlreadyAbsent";
                    okCount++;
                }
            }
            catch (Exception ex)
            {
                item.Error = ex.Message;
            }
            items.Add(item);
        }

        resp.Results = items;
        resp.Ok = okCount == req.Paths.Length;
        resp.Result = $"{okCount}/{req.Paths.Length} succeeded";
        _logger.LogInformation("delete_paths count={N} succeeded={K}", req.Paths.Length, okCount);
        return resp;
    }

    /// <summary>
    /// Kill all processes matching a name. Resolves name → PIDs locally, then dispatches a
    /// <c>kill_process</c> per PID through the existing <see cref="DispatchKill"/> (which
    /// applies the critical-process filter and the no-loop escalation policy).
    /// </summary>
    private PipeResponse DispatchKillByName(PipeRequest req, PipeResponse resp)
    {
        if (string.IsNullOrEmpty(req.Name))
        {
            resp.Error = "kill_process_by_name requires Name";
            return resp;
        }

        var processes = Process.GetProcessesByName(req.Name);
        if (processes.Length == 0)
            processes = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(req.Name));

        if (processes.Length == 0)
        {
            resp.Ok = true;
            resp.Result = "0/0 (no matching processes)";
            return resp;
        }

        var per = new List<PipeResponse>(processes.Length);
        int ok = 0;
        foreach (var proc in processes)
        {
            int pid = proc.Id;
            proc.Dispose();
            var subReq = new PipeRequest
            {
                Id = Guid.NewGuid().ToString("N"),
                Cmd = PipeProtocol.Commands.KillProcess,
                Pid = pid,
                KillTree = req.KillTree
            };
            var subResp = Dispatch(subReq);
            per.Add(subResp);
            if (subResp.Ok) ok++;
        }

        resp.Ok = ok == processes.Length;
        resp.Result = $"{ok}/{processes.Length} processes killed";
        resp.BatchResults = per;
        _logger.LogInformation("kill_process_by_name name={Name} matched={N} killed={K}", req.Name, processes.Length, ok);
        return resp;
    }

    /// <summary>
    /// Universal batch: takes <see cref="PipeRequest.Ops"/> (an array of nested PipeRequests) and
    /// dispatches each through <see cref="Dispatch"/> in order. One pipe call → N operations.
    /// Continues on per-op failure by default; set <see cref="PipeRequest.StopOnError"/> to abort early.
    /// Set <see cref="PipeRequest.DryRun"/> for a preview without performing destructive actions.
    /// Nested <c>batch</c> ops are rejected to prevent unbounded recursion.
    /// </summary>
    private PipeResponse DispatchBatch(PipeRequest req, PipeResponse resp)
    {
        if (req.Ops is null || req.Ops.Length == 0)
        {
            resp.Error = "batch requires Ops";
            return resp;
        }

        var per = new List<PipeResponse>(req.Ops.Length);
        int ok = 0;
        int executed = 0;
        foreach (var op in req.Ops)
        {
            executed++;
            PipeResponse subResp;
            if (op is null)
            {
                subResp = new PipeResponse { Id = "", Ok = false, Error = "Null op in batch" };
            }
            else if (op.Cmd == PipeProtocol.Commands.Batch)
            {
                subResp = new PipeResponse { Id = op.Id, Ok = false, Error = "Nested batch not allowed" };
            }
            else if (req.DryRun)
            {
                subResp = SimulateOp(op);
            }
            else
            {
                try
                {
                    subResp = Dispatch(op);
                }
                catch (Exception ex)
                {
                    subResp = new PipeResponse { Id = op.Id, Ok = false, Error = ex.Message };
                }
            }

            per.Add(subResp);
            if (subResp.Ok) ok++;
            else if (req.StopOnError) break;
        }

        resp.Ok = ok == req.Ops.Length;
        resp.Result = (req.DryRun ? "[DRYRUN] " : "") + $"{ok}/{req.Ops.Length} ops succeeded"
            + (executed < req.Ops.Length ? $" (stopped after {executed})" : "");
        resp.BatchResults = per;
        _logger.LogInformation("batch ops={N} succeeded={K} executed={E} dryRun={D}",
            req.Ops.Length, ok, executed, req.DryRun);
        return resp;
    }

    // ─── Tier 1: services ────────────────────────────────────────────────────────

    private PipeResponse DispatchDisableService(PipeRequest req, PipeResponse resp)
    {
        if (string.IsNullOrEmpty(req.Name)) { resp.Error = "disable_service requires Name"; return resp; }
        var r = ServiceManager.DisableService(req.Name);
        resp.Ok = r is ServiceOpResult.Success or ServiceOpResult.AlreadyInTargetState;
        resp.Result = r.ToString();
        if (!resp.Ok) resp.Error = r.ToString();
        _logger.LogInformation("disable_service name={Name} -> {Result}", req.Name, r);
        return resp;
    }

    private PipeResponse DispatchDeleteService(PipeRequest req, PipeResponse resp)
    {
        if (string.IsNullOrEmpty(req.Name)) { resp.Error = "delete_service requires Name"; return resp; }
        var r = ServiceManager.DeleteService(req.Name);
        resp.Ok = r is ServiceOpResult.Success or ServiceOpResult.AlreadyInTargetState;
        resp.Result = r.ToString();
        if (!resp.Ok) resp.Error = r.ToString();
        _logger.LogInformation("delete_service name={Name} -> {Result}", req.Name, r);
        return resp;
    }

    // ─── Tier 1: scheduled tasks ─────────────────────────────────────────────────

    private PipeResponse DispatchTaskOp(PipeRequest req, PipeResponse resp, Func<string, ServiceOpResult> op, string label)
    {
        if (string.IsNullOrEmpty(req.Name)) { resp.Error = $"{label} requires Name (full task path)"; return resp; }
        var r = op(req.Name);
        resp.Ok = r is ServiceOpResult.Success or ServiceOpResult.AlreadyInTargetState;
        resp.Result = r.ToString();
        if (!resp.Ok) resp.Error = r.ToString();
        _logger.LogInformation("{Label} name={Name} -> {Result}", label, req.Name, r);
        return resp;
    }

    // ─── Tier 1: generic registry ────────────────────────────────────────────────

    private PipeResponse DispatchRegistryRemoveKey(PipeRequest req, PipeResponse resp)
    {
        if (string.IsNullOrEmpty(req.Hive)) { resp.Error = "registry_remove_key requires Hive"; return resp; }
        var (ok, msg) = RegistryCleaner.RemoveKey(req.Hive);
        resp.Ok = ok; resp.Result = msg; if (!ok) resp.Error = msg;
        _logger.LogInformation("registry_remove_key hive={Hive} -> {Ok} {Msg}", req.Hive, ok, msg);
        return resp;
    }

    private PipeResponse DispatchRegistryRemoveValue(PipeRequest req, PipeResponse resp)
    {
        if (string.IsNullOrEmpty(req.Hive)) { resp.Error = "registry_remove_value requires Hive"; return resp; }
        if (req.ValueName is null) { resp.Error = "registry_remove_value requires ValueName"; return resp; }
        var (ok, msg) = RegistryCleaner.RemoveValue(req.Hive, req.ValueName);
        resp.Ok = ok; resp.Result = msg; if (!ok) resp.Error = msg;
        _logger.LogInformation("registry_remove_value hive={Hive} value={Value} -> {Ok}", req.Hive, req.ValueName, ok);
        return resp;
    }

    private PipeResponse DispatchRegistrySetValue(PipeRequest req, PipeResponse resp)
    {
        if (string.IsNullOrEmpty(req.Hive)) { resp.Error = "registry_set_value requires Hive"; return resp; }
        if (req.ValueName is null) { resp.Error = "registry_set_value requires ValueName"; return resp; }
        if (req.ValueData is null) { resp.Error = "registry_set_value requires ValueData"; return resp; }
        var kind = Enum.TryParse<Microsoft.Win32.RegistryValueKind>(req.ValueKind ?? "String", true, out var k)
            ? k : Microsoft.Win32.RegistryValueKind.String;
        var (ok, msg) = RegistryCleaner.SetValue(req.Hive, req.ValueName, req.ValueData, kind);
        resp.Ok = ok; resp.Result = msg; if (!ok) resp.Error = msg;
        _logger.LogInformation("registry_set_value hive={Hive} value={Value} kind={Kind} -> {Ok}",
            req.Hive, req.ValueName, kind, ok);
        return resp;
    }

    // ─── Tier 2: quarantine ──────────────────────────────────────────────────────

    private PipeResponse DispatchQuarantineFile(PipeRequest req, PipeResponse resp)
    {
        if (string.IsNullOrEmpty(req.Path)) { resp.Error = "quarantine_file requires Path"; return resp; }
        if (IsProtectedPath(req.Path, out var reason)) { resp.Error = $"Refused: {reason}"; return resp; }
        var (r, msg, item) = QuarantineManager.Quarantine(req.Path);
        resp.Ok = r == QuarantineResult.Success;
        resp.Result = item is null ? r.ToString() : $"{r}|id={item.Id}";
        if (!resp.Ok) resp.Error = msg;
        _logger.LogInformation("quarantine_file path={Path} -> {Result}", req.Path, r);
        return resp;
    }

    private PipeResponse DispatchQuarantineRestore(PipeRequest req, PipeResponse resp)
    {
        if (string.IsNullOrEmpty(req.QuarantineId)) { resp.Error = "quarantine_restore requires QuarantineId"; return resp; }
        var (r, msg) = QuarantineManager.Restore(req.QuarantineId);
        resp.Ok = r == QuarantineResult.Success;
        resp.Result = r.ToString();
        if (!resp.Ok) resp.Error = msg;
        return resp;
    }

    private PipeResponse DispatchQuarantinePurge(PipeRequest req, PipeResponse resp)
    {
        var (r, msg, removed) = QuarantineManager.Purge(req.OlderThanDays ?? 0);
        resp.Ok = r == QuarantineResult.Success;
        resp.Result = $"removed={removed}|{msg}";
        if (!resp.Ok) resp.Error = msg;
        return resp;
    }

    // ─── Tier 3: hosts ───────────────────────────────────────────────────────────

    private PipeResponse DispatchHostsRemovePattern(PipeRequest req, PipeResponse resp)
    {
        if (string.IsNullOrEmpty(req.Pattern)) { resp.Error = "hosts_remove_pattern requires Pattern"; return resp; }
        var (ok, msg, removed) = HostsFileUtil.RemoveMatching(req.Pattern);
        resp.Ok = ok;
        resp.Result = $"removed={removed}|{msg}";
        if (!ok) resp.Error = msg;
        return resp;
    }

    // ─── Tier 3: WMI persistence ────────────────────────────────────────────────

    private PipeResponse DispatchWmiPersistenceRemove(PipeRequest req, PipeResponse resp)
    {
        if (string.IsNullOrEmpty(req.Name)) { resp.Error = "wmi_persistence_remove requires Name (consumer)"; return resp; }
        var (ok, msg) = WmiPersistenceUtil.RemoveByConsumerName(req.Name);
        resp.Ok = ok; resp.Result = msg; if (!ok) resp.Error = msg;
        return resp;
    }

    // ─── Tier 3: restore point ──────────────────────────────────────────────────

    private PipeResponse DispatchRestorePointCreate(PipeRequest req, PipeResponse resp)
    {
        var (r, msg) = RestorePointUtil.Create(req.Description ?? "SFK checkpoint");
        resp.Ok = r == RestorePointResult.Success;
        resp.Result = r.ToString();
        if (!resp.Ok) resp.Error = msg;
        return resp;
    }

    // ─── Dry-run synthesizer ────────────────────────────────────────────────────

    private PipeResponse SimulateOp(PipeRequest op)
    {
        var r = new PipeResponse { Id = op.Id, Ok = true };
        r.Result = op.Cmd switch
        {
            PipeProtocol.Commands.KillProcess => $"would kill PID {op.Pid} (KillTree={op.KillTree})",
            PipeProtocol.Commands.KillProcessByName =>
                $"would kill {Process.GetProcessesByName(op.Name ?? "").Length} process(es) named '{op.Name}'",
            PipeProtocol.Commands.StopService => $"would stop service '{op.Name}'",
            PipeProtocol.Commands.DisableService => $"would set service '{op.Name}' StartType=Disabled",
            PipeProtocol.Commands.DeleteService => $"would delete service '{op.Name}'",
            PipeProtocol.Commands.DeleteFile => $"would delete file '{op.Path}'" + (op.Path is not null && File.Exists(op.Path) ? "" : " (not found)"),
            PipeProtocol.Commands.DeleteDir => $"would delete directory tree '{op.Path}'" + (op.Path is not null && Directory.Exists(op.Path) ? "" : " (not found)"),
            PipeProtocol.Commands.DeletePaths => $"would delete {op.Paths?.Length ?? 0} path(s)",
            PipeProtocol.Commands.TaskDisable => $"would disable task '{op.Name}'",
            PipeProtocol.Commands.TaskEnable => $"would enable task '{op.Name}'",
            PipeProtocol.Commands.TaskDelete => $"would delete task '{op.Name}'",
            PipeProtocol.Commands.RegistryRemoveKey => $"would remove key '{op.Hive}'",
            PipeProtocol.Commands.RegistryRemoveValue => $"would remove value '{op.Hive}\\{op.ValueName}'",
            PipeProtocol.Commands.RegistrySetValue => $"would set '{op.Hive}\\{op.ValueName}' = {op.ValueData} ({op.ValueKind ?? "String"})",
            PipeProtocol.Commands.QuarantineFile => $"would quarantine '{op.Path}'",
            PipeProtocol.Commands.QuarantineRestore => $"would restore quarantine id '{op.QuarantineId}'",
            PipeProtocol.Commands.QuarantinePurge => $"would purge quarantine items older than {op.OlderThanDays ?? 0} day(s)",
            PipeProtocol.Commands.HostsRemovePattern => $"would remove hosts entries matching /{op.Pattern}/",
            PipeProtocol.Commands.WmiPersistenceRemove => $"would remove WMI subscription consumer '{op.Name}'",
            PipeProtocol.Commands.RestorePointCreate => $"would create restore point: {op.Description ?? "SFK checkpoint"}",
            PipeProtocol.Commands.Ping => "would ping",
            _ => $"unknown op: {op.Cmd}"
        };
        return r;
    }

    private static bool IsCriticalProcess(int pid, out string name)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            name = proc.ProcessName;
            return CriticalProcesses.Contains(proc.ProcessName);
        }
        catch
        {
            name = "";
            return false;
        }
    }

    /// <summary>
    /// Refuse to operate on system-critical roots. We have LocalSystem power; without this
    /// the service could brick the OS on bad input.
    /// </summary>
    private static bool IsProtectedPath(string path, out string reason)
    {
        reason = "";
        string full;
        try { full = Path.GetFullPath(path); }
        catch { reason = "invalid path"; return true; }

        // Drive root by itself is always protected
        var trimmed = full.TrimEnd('\\', '/');
        if (trimmed.Length <= 2 || trimmed.EndsWith(":"))
        {
            reason = "drive root";
            return true;
        }

        foreach (var root in ProtectedRoots)
        {
            if (full.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            {
                // Allow if the path is a subfolder under e.g. C:\Windows\Temp — actually no, even
                // that's risky. Keep it strict; deny everything under these roots.
                reason = $"under {root}";
                return true;
            }
        }
        return false;
    }

    private static async Task<string?> ReadLineAsync(NamedPipeServerStream stream, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        var buf = new byte[4096];
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            int n = await stream.ReadAsync(buf, ct);
            if (n == 0) break;
            ms.Write(buf, 0, n);
            var data = ms.GetBuffer();
            for (int i = 0; i < ms.Length; i++)
            {
                if (data[i] == (byte)'\n')
                {
                    var s = Encoding.UTF8.GetString(ms.ToArray()).TrimEnd('\n', '\r', '\0');
                    return string.IsNullOrEmpty(s) ? null : s;
                }
            }
        }
        var tail = Encoding.UTF8.GetString(ms.ToArray()).TrimEnd('\n', '\r', '\0');
        return string.IsNullOrEmpty(tail) ? null : tail;
    }

    /// <summary>
    /// LocalSystem + Admins: full control. Interactive: read+write+sync (personal-machine ACL;
    /// tighten to a specific user SID for multi-user boxes).
    /// </summary>
    private static PipeSecurity BuildPipeSecurity()
    {
        var sec = new PipeSecurity();
        sec.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
            PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));
        return sec;
    }
}
