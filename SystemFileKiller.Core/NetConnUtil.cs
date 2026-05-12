using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace SystemFileKiller.Core;

public record NetConnection(
    int OwningPid,
    string? OwningProcessName,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    string State,
    string Protocol);

/// <summary>
/// Active TCP connections with owning PID — the "who is talking to the internet" view. Uses
/// <c>GetExtendedTcpTable</c> from iphlpapi.dll, the same source <c>netstat -ano</c> reads.
/// Flags useful for spotting C2 callbacks: a process that shouldn't be on the network making
/// outbound ESTABLISHED connections to unfamiliar IPs.
/// </summary>
public static class NetConnUtil
{
    public static List<NetConnection> ListTcp() => ListTcpInternal(filterPid: null);

    public static List<NetConnection> ListTcpForPid(int pid) => ListTcpInternal(filterPid: pid);

    private static List<NetConnection> ListTcpInternal(int? filterPid)
    {
        var list = new List<NetConnection>();
        var procNames = new Dictionary<int, string>();
        try
        {
            foreach (var p in Process.GetProcesses())
            {
                try { procNames[p.Id] = p.ProcessName; } catch { }
                p.Dispose();
            }
        }
        catch { }

        // IPv4
        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, 2 /*AF_INET*/, TCP_TABLE_OWNER_PID_ALL, 0);
        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            if (GetExtendedTcpTable(buffer, ref bufferSize, true, 2, TCP_TABLE_OWNER_PID_ALL, 0) == 0)
            {
                int rowCount = Marshal.ReadInt32(buffer);
                IntPtr rowPtr = IntPtr.Add(buffer, 4);
                int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                for (int i = 0; i < rowCount; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                    rowPtr = IntPtr.Add(rowPtr, rowSize);
                    int pid = (int)row.owningPid;
                    if (filterPid.HasValue && pid != filterPid.Value) continue;
                    var localPort = ((row.localPort1 & 0xFF) << 8) | (row.localPort2 & 0xFF);
                    var remotePort = ((row.remotePort1 & 0xFF) << 8) | (row.remotePort2 & 0xFF);
                    list.Add(new NetConnection(
                        OwningPid: pid,
                        OwningProcessName: procNames.GetValueOrDefault(pid),
                        LocalAddress: new IPAddress(row.localAddr).ToString(),
                        LocalPort: localPort,
                        RemoteAddress: new IPAddress(row.remoteAddr).ToString(),
                        RemotePort: remotePort,
                        State: StateName(row.state),
                        Protocol: "TCPv4"));
                }
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }
        return list;
    }

    private static string StateName(uint state) => state switch
    {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => $"UNKNOWN({state})"
    };

    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public byte localPort1;
        public byte localPort2;
        public byte localPortPad1;
        public byte localPortPad2;
        public uint remoteAddr;
        public byte remotePort1;
        public byte remotePort2;
        public byte remotePortPad1;
        public byte remotePortPad2;
        public uint owningPid;
    }
}
