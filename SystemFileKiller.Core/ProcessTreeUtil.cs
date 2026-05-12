using System.Diagnostics;
using System.Management;

namespace SystemFileKiller.Core;

public record ProcessNode(
    int Pid,
    int ParentPid,
    string Name,
    string? Path,
    DateTime? StartTime,
    long MemoryMB,
    List<ProcessNode> Children);

public record ProcessAncestor(int Pid, string Name, string? Path);

/// <summary>
/// Process relationship views — descendants down (a tree) and ancestors up (a chain). Useful
/// for forensic triage: "what spawned this?" or "what's this process's whole tree?". Backed by
/// the WMI Win32_Process table — the same source PowerShell's Get-CimInstance uses.
/// </summary>
public static class ProcessTreeUtil
{
    public static ProcessNode? GetTree(int rootPid)
    {
        var all = SnapshotAll();
        return BuildSubtree(rootPid, all);
    }

    public static List<ProcessAncestor> GetAncestry(int startPid, int maxDepth = 32)
    {
        var all = SnapshotAll();
        var chain = new List<ProcessAncestor>();
        int current = startPid;
        var seen = new HashSet<int>();

        for (int i = 0; i < maxDepth; i++)
        {
            if (!all.TryGetValue(current, out var node)) break;
            if (!seen.Add(node.Pid)) break;
            chain.Add(new ProcessAncestor(node.Pid, node.Name, node.Path));
            if (node.ParentPid == 0 || node.ParentPid == node.Pid) break;
            current = node.ParentPid;
        }
        return chain;
    }

    private static ProcessNode? BuildSubtree(int rootPid, Dictionary<int, ProcessNode> all)
    {
        if (!all.TryGetValue(rootPid, out var root)) return null;

        var queue = new Queue<ProcessNode>();
        queue.Enqueue(root);
        while (queue.Count > 0)
        {
            var parent = queue.Dequeue();
            var children = all.Values.Where(p => p.ParentPid == parent.Pid && p.Pid != parent.Pid).ToList();
            foreach (var c in children) { parent.Children.Add(c); queue.Enqueue(c); }
        }
        return root;
    }

    private static Dictionary<int, ProcessNode> SnapshotAll()
    {
        var dict = new Dictionary<int, ProcessNode>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CreationDate, WorkingSetSize FROM Win32_Process");
            foreach (ManagementObject obj in searcher.Get())
            {
                int pid = Convert.ToInt32(obj["ProcessId"]);
                int ppid = Convert.ToInt32(obj["ParentProcessId"]);
                var name = obj["Name"] as string ?? "";
                var path = obj["ExecutablePath"] as string;
                DateTime? start = null;
                if (obj["CreationDate"] is string cd && cd.Length >= 14)
                {
                    try { start = ManagementDateTimeConverter.ToDateTime(cd); } catch { }
                }
                long mb = 0;
                try { mb = Convert.ToInt64(obj["WorkingSetSize"]) / (1024 * 1024); } catch { }
                dict[pid] = new ProcessNode(pid, ppid, name, path, start, mb, new List<ProcessNode>());
                obj.Dispose();
            }
        }
        catch
        {
            // WMI may fail under low-rights — fallback to Process.GetProcesses without parent info
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    dict[p.Id] = new ProcessNode(p.Id, 0, p.ProcessName, p.MainModule?.FileName,
                        p.StartTime, p.WorkingSet64 / (1024 * 1024), new List<ProcessNode>());
                }
                catch { }
                p.Dispose();
            }
        }
        return dict;
    }
}
