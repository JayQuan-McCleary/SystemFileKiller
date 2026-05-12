using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;
using SystemFileKiller.Core;

namespace SystemFileKiller.MCP.Tools;

[McpServerToolType]
public class AnalysisTools
{
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    [McpServerTool(Name = "sfk_file_hash")]
    [Description("Compute SHA256 + MD5 hashes of a file. Use the SHA256 to look up reputation on VirusTotal/Hybrid Analysis; MD5 is provided for legacy IOC matching.")]
    public static string FileHash([Description("Full file path")] string path)
    {
        var h = HashUtil.ComputeHash(path);
        if (h is null) return JsonSerializer.Serialize(new { path, error = "file not found" });
        return JsonSerializer.Serialize(new { h.Path, h.SizeBytes, h.Sha256, h.Md5 }, Indented);
    }

    [McpServerTool(Name = "sfk_file_signature")]
    [Description("Verify the Authenticode signature on a file. Returns Status (Valid/Invalid/NotSigned/Expired/NotTrusted/Unknown), signer subject + issuer, certificate validity window, and thumbprint. An unsigned binary in user-writable space (AppData, Temp, Downloads) is a major triage signal.")]
    public static string FileSignature([Description("Full file path (typically .exe/.dll/.sys)")] string path)
    {
        var s = HashUtil.VerifySignature(path);
        return JsonSerializer.Serialize(new
        {
            s.Path,
            status = s.Status.ToString(),
            isSigned = s.Status != SignatureStatus.NotSigned && s.Status != SignatureStatus.Unknown,
            isValid = s.Status == SignatureStatus.Valid,
            s.Subject,
            s.Issuer,
            s.NotBefore,
            s.NotAfter,
            s.Thumbprint,
            s.Detail
        }, Indented);
    }

    [McpServerTool(Name = "sfk_process_tree")]
    [Description("Get the full descendant tree of a process — children, grandchildren, etc. — with PID, name, path, start time, memory. Use to see what a suspicious process spawned.")]
    public static string ProcessTree([Description("Root PID to expand")] int pid)
    {
        var tree = ProcessTreeUtil.GetTree(pid);
        if (tree is null) return JsonSerializer.Serialize(new { error = $"PID {pid} not found" });
        return JsonSerializer.Serialize(Project(tree), Indented);

        static object Project(ProcessNode n) => new
        {
            pid = n.Pid,
            parentPid = n.ParentPid,
            name = n.Name,
            path = n.Path,
            startTime = n.StartTime,
            memoryMB = n.MemoryMB,
            children = n.Children.Select(Project)
        };
    }

    [McpServerTool(Name = "sfk_process_ancestry")]
    [Description("Walk parent processes upward from a given PID, returning the chain of ancestors. Catches cases like 'this exe was spawned by powershell.exe -enc, which was spawned by wmic.exe' — the spawning chain often reveals the initial access vector.")]
    public static string ProcessAncestry([Description("Starting PID")] int pid,
        [Description("Maximum walk depth (default 32)")] int maxDepth = 32)
    {
        var chain = ProcessTreeUtil.GetAncestry(pid, maxDepth);
        return JsonSerializer.Serialize(new
        {
            count = chain.Count,
            chain = chain.Select(a => new { a.Pid, a.Name, a.Path })
        }, Indented);
    }
}
