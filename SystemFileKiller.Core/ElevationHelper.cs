using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json;

namespace SystemFileKiller.Core;

public record ElevationResult(bool Ok, string? Error = null);

/// <summary>
/// Stage 5 of the kill ladder: re-launch the host exe under UAC and run a single privileged op,
/// then read its result from a temp file. Used opt-in only — UAC mid-tool-call is jarring.
/// </summary>
public static class ElevationHelper
{
    public const string ArgElevateAndKill = "--elevate-and-kill";
    public const string ArgElevateAndStopService = "--elevate-and-stop-service";
    public const string ArgResult = "--result";

    public static ElevationResult ElevateAndKill(int pid, bool killTree)
    {
        return RunElevated(new[] { ArgElevateAndKill, pid.ToString(), killTree ? "1" : "0" });
    }

    public static ElevationResult ElevateAndStopService(string serviceName)
    {
        if (string.IsNullOrEmpty(serviceName))
            return new ElevationResult(false, "Service name required");
        return RunElevated(new[] { ArgElevateAndStopService, serviceName });
    }

    private static ElevationResult RunElevated(string[] opArgs)
    {
        var exe = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exe))
            return new ElevationResult(false, "Cannot determine current process path");

        var resultFile = Path.Combine(Path.GetTempPath(), $"sfk_elev_{Guid.NewGuid():N}.json");
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                UseShellExecute = true,
                Verb = "runas",
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            foreach (var a in opArgs) psi.ArgumentList.Add(a);
            psi.ArgumentList.Add(ArgResult);
            psi.ArgumentList.Add(resultFile);

            using var proc = Process.Start(psi);
            if (proc == null) return new ElevationResult(false, "Failed to start elevated process");

            if (!proc.WaitForExit(30000))
            {
                try { proc.Kill(); } catch { /* best-effort */ }
                return new ElevationResult(false, "Elevated process timed out");
            }

            if (File.Exists(resultFile))
            {
                var json = File.ReadAllText(resultFile);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                bool ok = root.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();
                string? error = root.TryGetProperty("error", out var errEl) ? errEl.GetString() : null;
                return new ElevationResult(ok, error);
            }

            return new ElevationResult(
                proc.ExitCode == 0,
                proc.ExitCode == 0 ? null : $"Exit code {proc.ExitCode}, no result file");
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return new ElevationResult(false, "User declined UAC prompt");
        }
        catch (Exception ex)
        {
            return new ElevationResult(false, ex.Message);
        }
        finally
        {
            try { if (File.Exists(resultFile)) File.Delete(resultFile); } catch { /* swallow */ }
        }
    }

    /// <summary>
    /// Called by entry-point exes (MCP host) at the top of Main. If the args indicate this is a UAC
    /// re-launch, the op runs and the process exits with a code; the caller returns that code.
    /// Otherwise returns null and normal startup continues.
    /// </summary>
    public static int? TryHandleElevatedArgs(string[] args)
    {
        if (args.Length < 1) return null;

        switch (args[0])
        {
            case ArgElevateAndKill: return HandleKill(args);
            case ArgElevateAndStopService: return HandleStopService(args);
            default: return null;
        }
    }

    private static int HandleKill(string[] args)
    {
        // --elevate-and-kill <pid> <killTree:0|1> --result <file>
        var resultFile = ExtractResult(args);
        try
        {
            if (args.Length < 3)
            {
                WriteResult(resultFile, false, "Missing pid/killTree");
                return 1;
            }
            if (!int.TryParse(args[1], out int pid))
            {
                WriteResult(resultFile, false, "Invalid pid");
                return 1;
            }
            bool killTree = args[2] == "1";

            // Don't loop back to UAC or pipe service — we're already elevated.
            var esc = new KillEscalation { AllowPipeService = false, AllowUacElevation = false };
            var result = ProcessKiller.ForceKill(pid, killTree, esc);
            bool ok = result is KillResult.Success
                or KillResult.StoppedViaService
                or KillResult.StoppedViaPipeService
                or KillResult.StoppedViaUac;

            WriteResult(resultFile, ok, ok ? null : $"{result}: {string.Join(" | ", esc.Trace)}");
            return ok ? 0 : 1;
        }
        catch (Exception ex)
        {
            WriteResult(resultFile, false, ex.Message);
            return 1;
        }
    }

    private static int HandleStopService(string[] args)
    {
        // --elevate-and-stop-service <name> --result <file>
        var resultFile = ExtractResult(args);
        try
        {
            if (args.Length < 2)
            {
                WriteResult(resultFile, false, "Missing service name");
                return 1;
            }
            var r = ServiceManager.StopService(args[1]);
            bool ok = r is ServiceOpResult.Success or ServiceOpResult.AlreadyInTargetState;
            WriteResult(resultFile, ok, ok ? null : r.ToString());
            return ok ? 0 : 1;
        }
        catch (Exception ex)
        {
            WriteResult(resultFile, false, ex.Message);
            return 1;
        }
    }

    private static string? ExtractResult(string[] args)
    {
        for (int i = 0; i < args.Length - 1; i++)
            if (args[i] == ArgResult) return args[i + 1];
        return null;
    }

    private static void WriteResult(string? resultFile, bool ok, string? error)
    {
        if (string.IsNullOrEmpty(resultFile)) return;
        try
        {
            var json = JsonSerializer.Serialize(new { ok, error });
            File.WriteAllText(resultFile, json);
        }
        catch { /* swallow — parent will treat absent file as failure */ }
    }
}
