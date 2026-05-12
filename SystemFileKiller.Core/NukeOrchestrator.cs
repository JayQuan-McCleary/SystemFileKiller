using System.Diagnostics;
using Microsoft.Win32;

namespace SystemFileKiller.Core;

public record NukeFinding(
    string Kind,
    string Detail,
    string? Path,
    string? AssociatedHive);

public record NukeTargetPlan(
    string Identifier,
    List<NukeFinding> Findings,
    PipeRequest[] Ops,
    bool Refused,
    string? RefusedReason);

/// <summary>
/// One-shot "remove this thing" orchestrator. Given a target identifier (process name, install
/// path, or display-name fragment), discovers every related artifact across processes, services,
/// scheduled tasks, registry persistence entries, and on-disk files — then assembles a single
/// <see cref="PipeProtocol.Commands.Batch"/> in a sane shutdown-then-cleanup order.
///
/// Order: kill processes → stop services → disable services → disable tasks → delete services →
/// delete tasks → quarantine binaries → delete remaining files → remove uninstall stubs →
/// remove Run-key persistence values. Each op goes through the existing dispatchers (which
/// honor the critical-process / protected-path / protected-key blocklists), so even a malicious
/// or wildly-typed target can't ask the planner to do something the dispatcher would refuse.
///
/// Use <see cref="Plan"/> to inspect what would happen, or wrap with the batch's
/// <see cref="PipeRequest.DryRun"/> flag for a no-op preview. Use <see cref="Execute"/> to
/// run the assembled batch.
/// </summary>
public static class NukeOrchestrator
{
    private static readonly HashSet<string> RefuseTargets = new(StringComparer.OrdinalIgnoreCase)
    {
        "csrss", "lsass", "winlogon", "wininit", "smss", "services", "system", "registry",
        "explorer", "svchost", "dwm", "windowsdefender", "msmpeng",
        "windows", "microsoft",
    };

    // The pipe service runs as LocalSystem, which has its own HKCU at C:\Windows\System32\config\
    // systemprofile\ — different from the interactive user's HKCU. When the planner discovers
    // entries in the *interactive user's* HKCU and we want the service to act on those same
    // entries, we translate HKCU\... → HKU\<interactive-user-sid>\... so the service hits the
    // right hive instead of failing with "key absent".
    private static readonly string CurrentUserSid =
        System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value ?? "";

    private static string NormalizeHiveForServiceContext(string hive)
    {
        if (string.IsNullOrEmpty(hive)) return hive;
        if (string.IsNullOrEmpty(CurrentUserSid)) return hive;
        const string prefix = "HKCU\\";
        if (hive.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return $"HKU\\{CurrentUserSid}\\{hive[prefix.Length..]}";
        return hive;
    }

    public static NukeTargetPlan Plan(string identifier)
    {
        if (string.IsNullOrWhiteSpace(identifier))
            return new NukeTargetPlan("", new List<NukeFinding>(), Array.Empty<PipeRequest>(), true, "empty identifier");

        var bareTarget = Path.GetFileNameWithoutExtension(identifier).Trim();
        if (RefuseTargets.Contains(bareTarget) || RefuseTargets.Contains(identifier.ToLowerInvariant()))
        {
            return new NukeTargetPlan(identifier, new List<NukeFinding>(),
                Array.Empty<PipeRequest>(), true, $"refused: '{identifier}' is in the never-touch list");
        }

        var findings = new List<NukeFinding>();
        var ops = new List<PipeRequest>();

        // ── 1. Processes ────────────────────────────────────────────────────────
        var matchedPids = new HashSet<int>();
        try
        {
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    bool match = p.ProcessName.Contains(bareTarget, StringComparison.OrdinalIgnoreCase);
                    if (!match)
                    {
                        var path = TryGetProcessPath(p);
                        if (path is not null && path.Contains(identifier, StringComparison.OrdinalIgnoreCase))
                            match = true;
                    }
                    if (match)
                    {
                        matchedPids.Add(p.Id);
                        findings.Add(new NukeFinding("Process", $"PID {p.Id} '{p.ProcessName}'", TryGetProcessPath(p), null));
                    }
                }
                catch { }
                p.Dispose();
            }
        }
        catch { }

        foreach (var pid in matchedPids)
        {
            ops.Add(new PipeRequest
            {
                Id = Guid.NewGuid().ToString("N"),
                Cmd = PipeProtocol.Commands.KillProcess,
                Pid = pid,
                KillTree = true,
            });
        }

        // ── 2. Services ─────────────────────────────────────────────────────────
        var matchedServices = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // 2a. Services hosted by matched PIDs
        foreach (var pid in matchedPids)
        {
            foreach (var svc in ServiceManager.GetServicesByPid(pid))
                matchedServices.Add(svc);
        }
        // 2b. Services with matching name / display / image path
        foreach (var svc in ServiceManager.ListServices(runningOnly: false))
        {
            if (svc.Name.Contains(bareTarget, StringComparison.OrdinalIgnoreCase)
                || svc.DisplayName.Contains(bareTarget, StringComparison.OrdinalIgnoreCase))
            {
                matchedServices.Add(svc.Name);
            }
            else
            {
                // Check ImagePath via registry
                try
                {
                    using var k = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{svc.Name}");
                    var img = k?.GetValue("ImagePath") as string;
                    if (img is not null && img.Contains(identifier, StringComparison.OrdinalIgnoreCase))
                        matchedServices.Add(svc.Name);
                }
                catch { }
            }
        }
        foreach (var name in matchedServices)
        {
            findings.Add(new NukeFinding("Service", name, null, null));
        }
        // Stop, then disable, then delete (in that order)
        foreach (var name in matchedServices)
            ops.Add(new PipeRequest { Id = Guid.NewGuid().ToString("N"), Cmd = PipeProtocol.Commands.StopService, Name = name });
        foreach (var name in matchedServices)
            ops.Add(new PipeRequest { Id = Guid.NewGuid().ToString("N"), Cmd = PipeProtocol.Commands.DisableService, Name = name });

        // ── 3. Scheduled tasks ──────────────────────────────────────────────────
        var matchedTasks = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var t in TaskManager.ListTasks(suspiciousOnly: false))
            {
                if (t.TaskRun.Contains(identifier, StringComparison.OrdinalIgnoreCase)
                    || t.TaskRun.Contains(bareTarget, StringComparison.OrdinalIgnoreCase)
                    || t.TaskPath.Contains(bareTarget, StringComparison.OrdinalIgnoreCase))
                {
                    matchedTasks.Add(t.TaskPath);
                    findings.Add(new NukeFinding("Task", t.TaskPath, t.TaskRun, null));
                }
            }
        }
        catch { }
        foreach (var tp in matchedTasks)
            ops.Add(new PipeRequest { Id = Guid.NewGuid().ToString("N"), Cmd = PipeProtocol.Commands.TaskDisable, Name = tp });

        // ── Now the order continues with deletes (services, tasks) after disables apply ──
        foreach (var name in matchedServices)
            ops.Add(new PipeRequest { Id = Guid.NewGuid().ToString("N"), Cmd = PipeProtocol.Commands.DeleteService, Name = name });
        foreach (var tp in matchedTasks)
            ops.Add(new PipeRequest { Id = Guid.NewGuid().ToString("N"), Cmd = PipeProtocol.Commands.TaskDelete, Name = tp });

        // ── 4. Uninstall stubs + paths ──────────────────────────────────────────
        var registryStubsToRemove = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var pathsToWipe = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (hive, sub, label) in new[]
        {
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM"),
            (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM\\WOW6432Node"),
            (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKCU"),
        })
        {
            try
            {
                using var root = hive.OpenSubKey(sub);
                if (root is null) continue;
                foreach (var subName in root.GetSubKeyNames())
                {
                    try
                    {
                        using var k = root.OpenSubKey(subName);
                        if (k is null) continue;
                        var dn = k.GetValue("DisplayName") as string ?? "";
                        var loc = k.GetValue("InstallLocation") as string ?? "";
                        bool match = dn.Contains(bareTarget, StringComparison.OrdinalIgnoreCase)
                                  || dn.Contains(identifier, StringComparison.OrdinalIgnoreCase)
                                  || (!string.IsNullOrEmpty(loc) && (loc.Contains(identifier, StringComparison.OrdinalIgnoreCase) || loc.Contains(bareTarget, StringComparison.OrdinalIgnoreCase)));
                        if (match)
                        {
                            var hiveName = hive == Registry.LocalMachine ? "HKLM" : "HKCU";
                            var stubPath = $@"{hiveName}\{sub}\{subName}";
                            registryStubsToRemove.Add(stubPath);
                            findings.Add(new NukeFinding("UninstallStub", $"{dn} (key: {subName})", loc, stubPath));
                            if (!string.IsNullOrWhiteSpace(loc) && Directory.Exists(loc))
                                pathsToWipe.Add(loc.TrimEnd('\\'));
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        // ── 5. Files: matched-process binaries + their parent folders ──────────
        foreach (var pid in matchedPids)
        {
            try
            {
                using var p = Process.GetProcessById(pid);
                var binary = TryGetProcessPath(p);
                if (binary is not null && File.Exists(binary))
                {
                    pathsToWipe.Add(binary);
                    var parent = Path.GetDirectoryName(binary);
                    if (parent is not null && Directory.Exists(parent)
                        && parent.Contains(bareTarget, StringComparison.OrdinalIgnoreCase))
                        pathsToWipe.Add(parent);
                }
            }
            catch { }
        }
        // If identifier itself is a path, include it
        if (Directory.Exists(identifier) || File.Exists(identifier))
            pathsToWipe.Add(Path.GetFullPath(identifier));

        foreach (var p in pathsToWipe)
            findings.Add(new NukeFinding("FileOrDir", p, p, null));

        if (pathsToWipe.Count > 0)
        {
            ops.Add(new PipeRequest
            {
                Id = Guid.NewGuid().ToString("N"),
                Cmd = PipeProtocol.Commands.DeletePaths,
                Paths = pathsToWipe.ToArray(),
            });
        }

        // ── 6. Run-key persistence values referencing the target ───────────────
        try
        {
            foreach (var entry in RegistryCleaner.ScanPersistenceLocations())
            {
                if (string.IsNullOrEmpty(entry.ValueData)) continue;
                if (entry.ValueData.Contains(identifier, StringComparison.OrdinalIgnoreCase)
                    || entry.ValueData.Contains(bareTarget, StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new NukeFinding("RunKey", $"{entry.HivePath}\\{entry.ValueName} = {entry.ValueData}", null, entry.HivePath));
                    ops.Add(new PipeRequest
                    {
                        Id = Guid.NewGuid().ToString("N"),
                        Cmd = PipeProtocol.Commands.RegistryRemoveValue,
                        Hive = NormalizeHiveForServiceContext(entry.HivePath),
                        ValueName = entry.ValueName,
                    });
                }
            }
        }
        catch { }

        // ── 7. Uninstall stub keys (last — after files they pointed at are gone) ──
        foreach (var stub in registryStubsToRemove)
        {
            ops.Add(new PipeRequest
            {
                Id = Guid.NewGuid().ToString("N"),
                Cmd = PipeProtocol.Commands.RegistryRemoveKey,
                Hive = NormalizeHiveForServiceContext(stub),
            });
        }

        return new NukeTargetPlan(identifier, findings, ops.ToArray(), false, null);
    }

    /// <summary>
    /// Plan + dispatch in one shot. Split routing: user-hive (HKU\&lt;current-user-sid&gt;\…) registry
    /// ops execute client-side because the service runs as LocalSystem and the .NET RegistryKey
    /// API can't reliably get write access to interactive-user hives without backup-restore
    /// privilege juggling. Everything else (process kills, file deletes, HKLM registry, services,
    /// scheduled tasks, hosts, restore points) batches through the pipe service.
    /// </summary>
    public static (NukeTargetPlan Plan, PipeResponse? Response) Execute(string identifier, bool dryRun = false)
    {
        var plan = Plan(identifier);
        if (plan.Refused || plan.Ops.Length == 0)
            return (plan, null);

        // Pass 1: classify each op
        var classification = new List<(int Index, bool IsLocal)>();
        var pipeOps = new List<PipeRequest>();
        var pipeOpIndices = new List<int>();
        for (int i = 0; i < plan.Ops.Length; i++)
        {
            var op = plan.Ops[i];
            if (IsUserHiveRegistryOp(op))
            {
                classification.Add((i, true));
            }
            else
            {
                classification.Add((i, false));
                pipeOps.Add(op);
                pipeOpIndices.Add(i);
            }
        }

        // Pass 2: send the pipe batch (if any non-local ops)
        PipeResponse? pipeResp = null;
        if (pipeOps.Count > 0)
        {
            pipeResp = PipeClient.Send(new PipeRequest
            {
                Cmd = PipeProtocol.Commands.Batch,
                Ops = pipeOps.ToArray(),
                StopOnError = false,
                DryRun = dryRun,
            }, timeoutMs: 30 * 60 * 1000);
        }

        // Pass 3: execute (or simulate) local user-hive registry ops in our own process
        var merged = new PipeResponse[plan.Ops.Length];
        for (int j = 0; j < pipeOpIndices.Count; j++)
        {
            int origIndex = pipeOpIndices[j];
            merged[origIndex] = (pipeResp?.BatchResults is { } list && j < list.Count)
                ? list[j]
                : new PipeResponse { Id = plan.Ops[origIndex].Id, Ok = false, Error = "no pipe result" };
        }
        foreach (var (i, isLocal) in classification.Where(c => c.IsLocal))
        {
            merged[i] = dryRun ? SimulateLocally(plan.Ops[i]) : ExecuteLocallyRegistry(plan.Ops[i]);
        }

        int okCount = merged.Count(r => r?.Ok == true);
        var unified = new PipeResponse
        {
            Id = Guid.NewGuid().ToString("N"),
            Ok = okCount == merged.Length,
            Result = (dryRun ? "[DRYRUN] " : "") + $"{okCount}/{merged.Length} ops succeeded "
                   + $"(local:{classification.Count(c => c.IsLocal)} pipe:{pipeOps.Count})",
            BatchResults = merged.ToList(),
        };
        return (plan, unified);
    }

    private static bool IsUserHiveRegistryOp(PipeRequest op)
    {
        if (op.Cmd != PipeProtocol.Commands.RegistryRemoveKey
            && op.Cmd != PipeProtocol.Commands.RegistryRemoveValue
            && op.Cmd != PipeProtocol.Commands.RegistrySetValue) return false;
        if (string.IsNullOrEmpty(op.Hive)) return false;
        if (op.Hive.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase)) return true;
        if (!string.IsNullOrEmpty(CurrentUserSid)
            && op.Hive.StartsWith($"HKU\\{CurrentUserSid}\\", StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    private static PipeResponse ExecuteLocallyRegistry(PipeRequest op)
    {
        var resp = new PipeResponse { Id = op.Id };
        switch (op.Cmd)
        {
            case PipeProtocol.Commands.RegistryRemoveKey:
            {
                var (ok, msg) = RegistryCleaner.RemoveKey(op.Hive!);
                resp.Ok = ok; resp.Result = msg; if (!ok) resp.Error = msg;
                break;
            }
            case PipeProtocol.Commands.RegistryRemoveValue:
            {
                var (ok, msg) = RegistryCleaner.RemoveValue(op.Hive!, op.ValueName ?? "");
                resp.Ok = ok; resp.Result = msg; if (!ok) resp.Error = msg;
                break;
            }
            case PipeProtocol.Commands.RegistrySetValue:
            {
                var kind = Enum.TryParse<Microsoft.Win32.RegistryValueKind>(op.ValueKind ?? "String", true, out var k)
                    ? k : Microsoft.Win32.RegistryValueKind.String;
                var (ok, msg) = RegistryCleaner.SetValue(op.Hive!, op.ValueName ?? "", op.ValueData ?? "", kind);
                resp.Ok = ok; resp.Result = msg; if (!ok) resp.Error = msg;
                break;
            }
            default:
                resp.Error = "not a local-eligible op";
                break;
        }
        return resp;
    }

    private static PipeResponse SimulateLocally(PipeRequest op) => new()
    {
        Id = op.Id,
        Ok = true,
        Result = op.Cmd switch
        {
            PipeProtocol.Commands.RegistryRemoveKey => $"would remove key '{op.Hive}' (local)",
            PipeProtocol.Commands.RegistryRemoveValue => $"would remove value '{op.Hive}\\{op.ValueName}' (local)",
            PipeProtocol.Commands.RegistrySetValue => $"would set '{op.Hive}\\{op.ValueName}' (local)",
            _ => $"would execute {op.Cmd}",
        }
    };

    private static string? TryGetProcessPath(Process p)
    {
        try { return p.MainModule?.FileName; }
        catch { return null; }
    }
}
