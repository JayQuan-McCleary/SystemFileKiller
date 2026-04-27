using System.ComponentModel;
using System.Management;
using System.ServiceProcess;

namespace SystemFileKiller.Core;

public record ServiceInfo(string Name, string DisplayName, string Status, int ProcessId);

public enum ServiceOpResult
{
    Success,
    AlreadyInTargetState,
    NotFound,
    AccessDenied,
    Timeout,
    Failed
}

/// <summary>
/// Service Control Manager wrapper. SCM checks the *service* DACL (which grants SERVICE_STOP to admins),
/// not the *process* DACL — so admins can usually stop service-hosted processes that OpenProcess
/// would refuse with AccessDenied.
/// </summary>
public static class ServiceManager
{
    /// <summary>
    /// Returns service short-names hosted by the given PID. Empty list if the process isn't service-managed
    /// or WMI is unavailable. Win32_Service exposes ProcessId directly so no extra P/Invoke needed.
    /// </summary>
    public static List<string> GetServicesByPid(int pid)
    {
        var names = new List<string>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT Name FROM Win32_Service WHERE ProcessId = {pid}");
            foreach (ManagementObject obj in searcher.Get())
            {
                if (obj["Name"] is string name && !string.IsNullOrEmpty(name))
                    names.Add(name);
                obj.Dispose();
            }
        }
        catch
        {
            // WMI may fail under low-rights or service-host scenarios — return what we have.
        }
        return names;
    }

    public static List<ServiceInfo> ListServices(bool runningOnly)
    {
        var list = new List<ServiceInfo>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, DisplayName, State, ProcessId FROM Win32_Service");
            foreach (ManagementObject obj in searcher.Get())
            {
                var name = obj["Name"] as string ?? "";
                var display = obj["DisplayName"] as string ?? "";
                var state = obj["State"] as string ?? "";
                int processId = obj["ProcessId"] switch
                {
                    uint u => (int)u,
                    int i => i,
                    _ => 0
                };

                obj.Dispose();

                if (runningOnly && !state.Equals("Running", StringComparison.OrdinalIgnoreCase))
                    continue;

                list.Add(new ServiceInfo(name, display, state, processId));
            }
        }
        catch
        {
            // Empty list on WMI failure
        }
        return list.OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static ServiceOpResult StopService(string name, int timeoutSec = 15)
    {
        try
        {
            using var sc = new ServiceController(name);
            var status = sc.Status;
            if (status == ServiceControllerStatus.Stopped) return ServiceOpResult.AlreadyInTargetState;
            if (status == ServiceControllerStatus.StopPending)
            {
                sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(timeoutSec));
                return ServiceOpResult.Success;
            }

            sc.Stop();
            sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(timeoutSec));
            return ServiceOpResult.Success;
        }
        catch (System.ServiceProcess.TimeoutException) { return ServiceOpResult.Timeout; }
        catch (InvalidOperationException ex) when (ex.InnerException is Win32Exception w && w.NativeErrorCode == 5)
        {
            return ServiceOpResult.AccessDenied;
        }
        catch (InvalidOperationException ex) when (ex.InnerException is Win32Exception w && w.NativeErrorCode == 1060)
        {
            // ERROR_SERVICE_DOES_NOT_EXIST
            return ServiceOpResult.NotFound;
        }
        catch (InvalidOperationException) { return ServiceOpResult.NotFound; }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 5) { return ServiceOpResult.AccessDenied; }
        catch { return ServiceOpResult.Failed; }
    }

    public static ServiceOpResult StartService(string name, int timeoutSec = 15)
    {
        try
        {
            using var sc = new ServiceController(name);
            var status = sc.Status;
            if (status == ServiceControllerStatus.Running) return ServiceOpResult.AlreadyInTargetState;
            if (status == ServiceControllerStatus.StartPending)
            {
                sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(timeoutSec));
                return ServiceOpResult.Success;
            }

            sc.Start();
            sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(timeoutSec));
            return ServiceOpResult.Success;
        }
        catch (System.ServiceProcess.TimeoutException) { return ServiceOpResult.Timeout; }
        catch (InvalidOperationException ex) when (ex.InnerException is Win32Exception w && w.NativeErrorCode == 5)
        {
            return ServiceOpResult.AccessDenied;
        }
        catch (InvalidOperationException ex) when (ex.InnerException is Win32Exception w && w.NativeErrorCode == 1060)
        {
            return ServiceOpResult.NotFound;
        }
        catch (InvalidOperationException) { return ServiceOpResult.NotFound; }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 5) { return ServiceOpResult.AccessDenied; }
        catch { return ServiceOpResult.Failed; }
    }
}
