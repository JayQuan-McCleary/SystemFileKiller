using System.Diagnostics;
using System.Management;

namespace SystemFileKiller.Core;

public record ProcessInfo(
    int Pid,
    string Name,
    string? FilePath,
    long MemoryMB,
    string? Description);

public enum KillResult
{
    Success,
    StoppedViaService,
    StoppedViaPipeService,
    StoppedViaUac,
    NotFound,
    AccessDenied,
    Failed
}

public static class ProcessKiller
{
    static ProcessKiller()
    {
        // Best-effort: enable SeDebugPrivilege when elevated. No-op when running as a standard user.
        PrivilegeManager.TryEnableDebugPrivilege();
    }

    /// <summary>
    /// Lists all running processes with relevant details.
    /// </summary>
    public static List<ProcessInfo> ListProcesses()
    {
        var list = new List<ProcessInfo>();
        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                string? path = null;
                string? desc = null;
                try
                {
                    path = proc.MainModule?.FileName;
                    desc = proc.MainModule?.FileVersionInfo.FileDescription;
                }
                catch { /* Access denied for some system processes */ }

                list.Add(new ProcessInfo(
                    proc.Id,
                    proc.ProcessName,
                    path,
                    proc.WorkingSet64 / (1024 * 1024),
                    desc));
            }
            catch
            {
                list.Add(new ProcessInfo(proc.Id, proc.ProcessName, null, 0, null));
            }
            finally
            {
                proc.Dispose();
            }
        }
        return list.OrderBy(p => p.Name).ToList();
    }

    /// <summary>
    /// Force-kills a process by PID. Walks the escalation ladder: Process.Kill → NtTerminate →
    /// service stop → pipe service → UAC. Returns on first success.
    /// </summary>
    public static KillResult ForceKill(int pid, bool killTree = false)
        => ForceKill(pid, killTree, new KillEscalation());

    /// <summary>
    /// Force-kills a process with caller-supplied escalation options. The same instance receives
    /// per-stage trace breadcrumbs.
    /// </summary>
    public static KillResult ForceKill(int pid, bool killTree, KillEscalation esc)
    {
        if (killTree)
        {
            // Snapshot liveness before walking children. If the target was alive going in but
            // dies as a side effect of the tree walk (e.g. a shell that was blocked waiting on
            // its child), that's Success — not NotFound. Without this short-circuit, Stage 1
            // would hit ArgumentException on the now-dead target and return NotFound.
            bool wasAlive = IsAlive(pid);
            KillProcessTree(pid, esc);
            if (wasAlive && !IsAlive(pid))
            {
                esc.Note("TreeKill:TargetDiedWithChildren");
                return KillResult.Success;
            }
        }

        // Stage 1: Normal Process.Kill()
        try
        {
            var proc = Process.GetProcessById(pid);
            proc.Kill();
            proc.WaitForExit(3000);
            if (proc.HasExited)
            {
                esc.Note("Stage1:Process.Kill:Success");
                return KillResult.Success;
            }
            esc.Note("Stage1:Process.Kill:DidNotExit");
        }
        catch (ArgumentException)
        {
            esc.Note("Stage1:Process.Kill:NotFound");
            return KillResult.NotFound;
        }
        catch (Exception ex)
        {
            esc.Note($"Stage1:Process.Kill:Exception:{ex.GetType().Name}");
        }

        // Stage 2: Suspend all threads, then NtTerminateProcess
        var ntResult = NtForceKill(pid);
        esc.Note($"Stage2:NtTerminate:{ntResult}");
        if (ntResult == KillResult.Success || !IsAlive(pid)) return KillResult.Success;

        // Stage 3: Service stop via SCM. Catches the entire Dell/Adobe/Razer wall — SCM uses the
        // *service* DACL, not the *process* DACL.
        foreach (var svc in ServiceManager.GetServicesByPid(pid))
        {
            var sr = ServiceManager.StopService(svc);
            esc.Note($"Stage3:StopService:{svc}:{sr}");
            if ((sr == ServiceOpResult.Success || sr == ServiceOpResult.AlreadyInTargetState) && !IsAlive(pid))
                return KillResult.StoppedViaService;
        }

        // Stage 4: Forward to LocalSystem helper service via named pipe (no UAC prompt path)
        if (esc.AllowPipeService)
        {
            if (PipeClient.IsServiceAvailable())
            {
                var resp = PipeClient.Send(new PipeRequest
                {
                    Cmd = PipeProtocol.Commands.KillProcess,
                    Pid = pid,
                    KillTree = killTree
                });
                esc.Note($"Stage4:PipeService:{(resp.Ok ? "ok" : resp.Error ?? "failed")}");
                if (resp.Ok && !IsAlive(pid)) return KillResult.StoppedViaPipeService;
            }
            else
            {
                esc.Note("Stage4:PipeService:unavailable");
            }
        }

        // Stage 5: UAC self-elevate (opt-in)
        if (esc.AllowUacElevation && !PrivilegeManager.IsElevated)
        {
            var er = ElevationHelper.ElevateAndKill(pid, killTree);
            esc.Note($"Stage5:UacElevate:{(er.Ok ? "ok" : er.Error ?? "failed")}");
            if (er.Ok && !IsAlive(pid)) return KillResult.StoppedViaUac;
        }
        else if (esc.AllowUacElevation)
        {
            esc.Note("Stage5:UacElevate:alreadyElevated");
        }

        // If something else outside our visibility took it down, count that.
        if (!IsAlive(pid))
        {
            esc.Note("Final:VerifiedDead");
            return KillResult.Success;
        }

        return KillResult.AccessDenied;
    }

    /// <summary>
    /// Force-kills a process by name. Kills all processes with that name.
    /// </summary>
    public static List<(int Pid, KillResult Result)> ForceKillByName(string name, bool killTree = false)
    {
        var results = new List<(int, KillResult)>();
        var processes = Process.GetProcessesByName(name);
        if (processes.Length == 0)
        {
            // Try without .exe extension
            processes = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(name));
        }

        foreach (var proc in processes)
        {
            results.Add((proc.Id, ForceKill(proc.Id, killTree)));
            proc.Dispose();
        }

        return results;
    }

    /// <summary>
    /// True if a process with the given PID is still running. Errs on the side of "alive" when
    /// uncertain — otherwise the ladder would short-circuit to Success on AccessDenied during
    /// status queries.
    /// </summary>
    private static bool IsAlive(int pid)
    {
        // Ground truth that doesn't need a process handle: enumerate all PIDs.
        try
        {
            foreach (var p in Process.GetProcesses())
            {
                bool match = p.Id == pid;
                p.Dispose();
                if (match) return true;
            }
            return false;
        }
        catch
        {
            // If even the enumeration fails, assume alive.
            return true;
        }
    }

    /// <summary>
    /// Suspend + NtTerminateProcess for stubborn processes.
    /// </summary>
    private static KillResult NtForceKill(int pid)
    {
        IntPtr hProcess = IntPtr.Zero;
        try
        {
            hProcess = NativeMethods.OpenProcess(
                NativeMethods.PROCESS_TERMINATE | NativeMethods.PROCESS_SUSPEND_RESUME,
                false, pid);

            if (hProcess == IntPtr.Zero)
                return KillResult.AccessDenied;

            // Suspend first to prevent respawn/watchdog
            NativeMethods.NtSuspendProcess(hProcess);

            // Terminate with NT API
            var status = NativeMethods.NtTerminateProcess(hProcess, -1);

            return status == NativeMethods.STATUS_SUCCESS
                ? KillResult.Success
                : KillResult.Failed;
        }
        catch
        {
            return KillResult.Failed;
        }
        finally
        {
            if (hProcess != IntPtr.Zero)
                NativeMethods.CloseHandle(hProcess);
        }
    }

    /// <summary>
    /// Kill all child processes of the given PID (bottom-up), then the parent.
    /// </summary>
    private static void KillProcessTree(int parentPid, KillEscalation esc)
    {
        try
        {
            // Use WMI to find child processes
            using var searcher = new ManagementObjectSearcher(
                $"SELECT ProcessId FROM Win32_Process WHERE ParentProcessId = {parentPid}");

            foreach (ManagementObject obj in searcher.Get())
            {
                var childPid = Convert.ToInt32(obj["ProcessId"]);
                KillProcessTree(childPid, esc); // Recurse into children first
                ForceKill(childPid, false, esc); // Then kill this child (share trace + flags)
            }
        }
        catch
        {
            // WMI may fail - not critical, we still kill the parent
        }
    }
}
