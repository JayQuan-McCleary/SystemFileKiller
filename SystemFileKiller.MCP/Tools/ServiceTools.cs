using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;
using SystemFileKiller.Core;

namespace SystemFileKiller.MCP.Tools;

[McpServerToolType]
public class ServiceTools
{
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    [McpServerTool(Name = "sfk_service_list")]
    [Description("List Windows services with name, display name, status, and PID. Set runningOnly=true to filter to running services only.")]
    public static string ListServices(
        [Description("If true, only show services in 'Running' state")] bool runningOnly = false)
    {
        var services = ServiceManager.ListServices(runningOnly);
        return JsonSerializer.Serialize(new
        {
            count = services.Count,
            services = services.Select(s => new { s.Name, s.DisplayName, s.Status, s.ProcessId })
        }, Indented);
    }

    [McpServerTool(Name = "sfk_service_stop")]
    [Description("Stop a Windows service by short name (e.g. 'CloudflareWARP', not 'Cloudflare WARP'). Uses SCM, which checks the service DACL — admins can stop services even when OpenProcess on the host PID would return AccessDenied. Requires admin to actually stop.")]
    public static string StopService(
        [Description("The service short name (Win32_Service.Name), not display name")] string name,
        [Description("Stop wait timeout in seconds")] int timeoutSec = 15)
    {
        var result = ServiceManager.StopService(name, timeoutSec);
        return JsonSerializer.Serialize(new
        {
            name,
            result = result.ToString(),
            success = result is ServiceOpResult.Success or ServiceOpResult.AlreadyInTargetState
        });
    }

    [McpServerTool(Name = "sfk_service_for_pid")]
    [Description("Find Windows services hosted by a given PID. Useful when sfk_process_kill returns AccessDenied — many of those processes are service-managed; stop the service instead.")]
    public static string ServiceForPid(
        [Description("Process ID to look up")] int pid)
    {
        var names = ServiceManager.GetServicesByPid(pid);
        return JsonSerializer.Serialize(new
        {
            pid,
            serviceCount = names.Count,
            services = names
        });
    }
}
