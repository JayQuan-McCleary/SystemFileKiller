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
/// <see cref="ServiceManager"/> as LocalSystem. Refuses to touch the critical-process blocklist
/// (csrss, lsass, etc.) — killing those bluescreens the box.
/// </summary>
public class PipeServer
{
    private static readonly HashSet<string> CriticalProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "csrss", "wininit", "services", "lsass", "smss", "winlogon", "system", "registry"
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
