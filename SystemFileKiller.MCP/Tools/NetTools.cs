using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;
using SystemFileKiller.Core;

namespace SystemFileKiller.MCP.Tools;

[McpServerToolType]
public class NetTools
{
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    [McpServerTool(Name = "sfk_netconn_list")]
    [Description("List active TCPv4 connections with their owning PIDs and process names. Functionally equivalent to 'netstat -ano' but returned as structured JSON. Use to spot processes that shouldn't be on the network making outbound ESTABLISHED connections.")]
    public static string ListTcp()
    {
        var conns = NetConnUtil.ListTcp();
        return JsonSerializer.Serialize(new
        {
            count = conns.Count,
            connections = conns.Select(Project)
        }, Indented);
    }

    [McpServerTool(Name = "sfk_netconn_for_pid")]
    [Description("List active TCPv4 connections owned by a specific PID. Use after sfk_process_kill returns AccessDenied to triage what the process is doing on the network before deciding whether to escalate.")]
    public static string ListForPid([Description("Process ID to filter on")] int pid)
    {
        var conns = NetConnUtil.ListTcpForPid(pid);
        return JsonSerializer.Serialize(new
        {
            pid,
            count = conns.Count,
            connections = conns.Select(Project)
        }, Indented);
    }

    private static object Project(NetConnection c) => new
    {
        c.OwningPid, c.OwningProcessName,
        c.LocalAddress, c.LocalPort,
        c.RemoteAddress, c.RemotePort,
        c.State, c.Protocol
    };
}
