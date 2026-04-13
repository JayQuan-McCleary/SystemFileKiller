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
    NotFound,
    AccessDenied,
    Failed
}

public static class ProcessKiller
{
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
    /// Force-kills a process by PID. Escalates through multiple termination methods.
    /// </summary>
    public static KillResult ForceKill(int pid, bool killTree = false)
    {
        if (killTree)
        {
            KillProcessTree(pid);
        }

        // Stage 1: Normal Process.Kill()
        try
        {
            var proc = Process.GetProcessById(pid);
            proc.Kill();
            proc.WaitForExit(3000);
            if (proc.HasExited) return KillResult.Success;
        }
        catch (ArgumentException) { return KillResult.NotFound; }
        catch { /* Escalate */ }

        // Stage 2: Suspend all threads, then NtTerminateProcess
        return NtForceKill(pid);
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
    private static void KillProcessTree(int parentPid)
    {
        try
        {
            // Use WMI to find child processes
            using var searcher = new ManagementObjectSearcher(
                $"SELECT ProcessId FROM Win32_Process WHERE ParentProcessId = {parentPid}");

            foreach (ManagementObject obj in searcher.Get())
            {
                var childPid = Convert.ToInt32(obj["ProcessId"]);
                KillProcessTree(childPid); // Recurse into children first
                ForceKill(childPid, false); // Then kill this child
            }
        }
        catch
        {
            // WMI may fail - not critical, we still kill the parent
        }
    }
}
