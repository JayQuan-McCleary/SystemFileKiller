using SystemFileKiller.Core;

namespace SystemFileKiller.CLI;

class Program
{
    static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            PrintUsage();
            return 0;
        }

        var command = args[0].ToLowerInvariant();
        var subCommand = args.Length > 1 ? args[1].ToLowerInvariant() : "";
        var target = args.Length > 2 ? string.Join(" ", args[2..]) : "";

        try
        {
            return (command, subCommand) switch
            {
                ("process", "list") => ProcessList(),
                ("process", "kill") => ProcessKill(target, false),
                ("process", "kill-tree") => ProcessKill(target, true),
                ("file", "delete") => FileDelete(target),
                ("file", "delete-dir") => FileDeleteDir(target),
                ("file", "delete-paths") => FileDeletePaths(args.Length > 2 ? args[2..] : Array.Empty<string>()),
                ("file", "unlock") => FileUnlock(target),
                ("file", "reboot-delete") => FileRebootDelete(target),
                ("registry", "scan") => RegistryScan(false),
                ("registry", "scan-suspicious") => RegistryScan(true),
                ("registry", "clean") => RegistryClean(target),
                ("registry", "clean-all") => RegistryCleanAll(),
                ("nuke", _) => NukeTarget(args.Length > 1 ? args[1] : "", args.Length > 2 ? args[2].ToLowerInvariant() : "plan"),
                ("help", _) => Help(),
                _ => Unknown(command, subCommand)
            };
        }
        catch (Exception ex)
        {
            Error($"Unhandled error: {ex.Message}");
            return 1;
        }
    }

    // ── Process Commands ──

    static int ProcessList()
    {
        var processes = ProcessKiller.ListProcesses();
        Console.WriteLine($"{"PID",-8} {"Name",-30} {"Memory (MB)",-12} {"Path"}");
        Console.WriteLine(new string('-', 100));
        foreach (var p in processes)
        {
            Console.WriteLine($"{p.Pid,-8} {p.Name,-30} {p.MemoryMB,-12} {p.FilePath ?? ""}");
        }
        Console.WriteLine($"\nTotal: {processes.Count} processes");
        return 0;
    }

    static int ProcessKill(string target, bool tree)
    {
        if (string.IsNullOrEmpty(target))
        {
            Error("Usage: sfk process kill <pid|name>");
            return 1;
        }

        if (int.TryParse(target, out int pid))
        {
            var result = ProcessKiller.ForceKill(pid, tree);
            PrintKillResult(pid, result);
            return result == KillResult.Success ? 0 : 1;
        }
        else
        {
            var results = ProcessKiller.ForceKillByName(target, tree);
            if (results.Count == 0)
            {
                Warn($"No processes found with name: {target}");
                return 1;
            }
            foreach (var (p, r) in results)
                PrintKillResult(p, r);
            return results.All(r => r.Result == KillResult.Success) ? 0 : 1;
        }
    }

    static void PrintKillResult(int pid, KillResult result)
    {
        switch (result)
        {
            case KillResult.Success:
                Success($"Killed process {pid}");
                break;
            case KillResult.NotFound:
                Warn($"Process {pid} not found");
                break;
            case KillResult.AccessDenied:
                Error($"Access denied for process {pid} (try running as Administrator)");
                break;
            case KillResult.Failed:
                Error($"Failed to kill process {pid}");
                break;
        }
    }

    // ── File Commands ──

    static int FileDelete(string target)
    {
        if (string.IsNullOrEmpty(target))
        {
            Error("Usage: sfk file delete <path>");
            return 1;
        }

        var (result, message) = FileDestroyer.ForceDelete(target);
        PrintFileResult(result, message);
        return result is DeleteResult.Success or DeleteResult.ScheduledForReboot ? 0 : 1;
    }

    static int FileDeleteDir(string target)
    {
        if (string.IsNullOrEmpty(target))
        {
            Error("Usage: sfk file delete-dir <path>");
            return 1;
        }

        var (result, message) = FileDestroyer.ForceDeleteDirectory(target);
        PrintFileResult(result, message);
        return result is DeleteResult.Success or DeleteResult.ScheduledForReboot ? 0 : 1;
    }

    static int FileUnlock(string target)
    {
        if (string.IsNullOrEmpty(target))
        {
            Error("Usage: sfk file unlock <path>");
            return 1;
        }

        Info($"Scanning for handles to: {target}");
        var result = FileDestroyer.UnlockFile(target);

        if (result.HandlesFound == 0)
        {
            Info("No locking handles found.");
            return 0;
        }

        Console.WriteLine($"Found {result.HandlesFound} handle(s):");
        foreach (var (pid, procName) in result.LockingProcesses)
            Console.WriteLine($"  PID {pid} ({procName ?? "unknown"})");

        Console.WriteLine($"Closed: {result.HandlesClosed}/{result.HandlesFound}");
        return result.HandlesClosed == result.HandlesFound ? 0 : 1;
    }

    static int FileRebootDelete(string target)
    {
        if (string.IsNullOrEmpty(target))
        {
            Error("Usage: sfk file reboot-delete <path>");
            return 1;
        }

        var (result, message) = FileDestroyer.ScheduleRebootDelete(target);
        PrintFileResult(result, message);
        return result == DeleteResult.ScheduledForReboot ? 0 : 1;
    }

    static int NukeTarget(string identifier, string mode)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            Error("Usage: sfk nuke <identifier> [plan|dryrun|execute]");
            Info("  plan    (default) — show discovery + planned ops, do nothing");
            Info("  dryrun           — send batch with dry-run flag (server simulates each op)");
            Info("  execute          — actually perform the cleanup (destructive)");
            return 1;
        }

        var plan = NukeOrchestrator.Plan(identifier);
        if (plan.Refused)
        {
            Error($"Refused: {plan.RefusedReason}");
            return 1;
        }

        Info($"Target: {identifier}   Findings: {plan.Findings.Count}   Ops: {plan.Ops.Length}");
        Console.WriteLine();
        Console.WriteLine("FINDINGS:");
        foreach (var f in plan.Findings)
        {
            Console.ForegroundColor = f.Kind switch
            {
                "Process" => ConsoleColor.Yellow,
                "Service" => ConsoleColor.Magenta,
                "Task" => ConsoleColor.Cyan,
                "UninstallStub" => ConsoleColor.DarkGray,
                "FileOrDir" => ConsoleColor.Gray,
                "RunKey" => ConsoleColor.DarkYellow,
                _ => ConsoleColor.White,
            };
            Console.WriteLine($"  [{f.Kind,-13}] {f.Detail}");
            if (!string.IsNullOrEmpty(f.Path) && f.Path != f.Detail)
                Console.WriteLine($"                   path: {f.Path}");
            Console.ResetColor();
        }
        Console.WriteLine();
        Console.WriteLine("PLANNED OPS (in order):");
        for (int i = 0; i < plan.Ops.Length; i++)
        {
            var o = plan.Ops[i];
            string detail = o.Cmd switch
            {
                _ when !string.IsNullOrEmpty(o.Path) => o.Path!,
                _ when !string.IsNullOrEmpty(o.Name) => o.Name!,
                _ when !string.IsNullOrEmpty(o.Hive) => o.Hive + (o.ValueName is { Length: > 0 } ? $"\\{o.ValueName}" : ""),
                _ when o.Pid is int pid => $"PID {pid}" + (o.KillTree ? " (tree)" : ""),
                _ when o.Paths is string[] arr => $"{arr.Length} paths",
                _ => "",
            };
            Console.WriteLine($"  [{i:00}] {o.Cmd,-25} {detail}");
        }

        if (mode == "plan")
        {
            Console.WriteLine();
            Info("plan-only mode — nothing executed. Re-run with 'dryrun' or 'execute' as 3rd arg to dispatch.");
            return 0;
        }

        bool dryRun = mode == "dryrun";
        if (mode == "execute")
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write($"About to EXECUTE {plan.Ops.Length} destructive op(s) for '{identifier}'. Continue? [y/N] ");
            Console.ResetColor();
            if (Console.ReadLine()?.Trim().ToLowerInvariant() != "y")
            {
                Info("Cancelled.");
                return 0;
            }
        }

        var (_, resp) = NukeOrchestrator.Execute(identifier, dryRun);
        Console.WriteLine();
        Console.WriteLine($"RESULT: Ok={resp?.Ok}  Summary='{resp?.Result}'");
        if (resp?.BatchResults is not null)
        {
            for (int i = 0; i < resp.BatchResults.Count; i++)
            {
                var r = resp.BatchResults[i];
                var op = i < plan.Ops.Length ? plan.Ops[i].Cmd : "?";
                Console.ForegroundColor = r.Ok ? ConsoleColor.Green : ConsoleColor.Red;
                Console.WriteLine($"  [{i:00}] {op,-25} Ok={r.Ok}  {r.Result}{(string.IsNullOrEmpty(r.Error) ? "" : "  ERR: " + r.Error)}");
                Console.ResetColor();
            }
        }
        return resp?.Ok == true ? 0 : 1;
    }

    static int FileDeletePaths(string[] paths)
    {
        if (paths.Length == 0)
        {
            Error("Usage: sfk file delete-paths <path1> <path2> ...");
            return 1;
        }

        Info($"Batch-deleting {paths.Length} path(s)...");
        var results = FileDestroyer.ForceDeletePaths(paths);

        int ok = 0;
        foreach (var (path, result, message) in results)
        {
            var summary = string.IsNullOrEmpty(message) ? result.ToString() : message;
            switch (result)
            {
                case DeleteResult.Success:
                    Success($"{path}  →  {summary}"); ok++; break;
                case DeleteResult.ScheduledForReboot:
                    Warn($"{path}  →  {summary}"); ok++; break;
                default:
                    Error($"{path}  →  {summary}"); break;
            }
        }

        Console.WriteLine();
        Info($"Batch: {ok}/{results.Count} succeeded");
        return ok == results.Count ? 0 : 1;
    }

    static void PrintFileResult(DeleteResult result, string message)
    {
        switch (result)
        {
            case DeleteResult.Success:
                Success(message);
                break;
            case DeleteResult.ScheduledForReboot:
                Warn(message);
                break;
            default:
                Error(message);
                break;
        }
    }

    // ── Registry Commands ──

    static int RegistryScan(bool suspiciousOnly)
    {
        Info("Scanning registry persistence locations...");
        var entries = suspiciousOnly
            ? RegistryCleaner.ScanSuspicious()
            : RegistryCleaner.ScanPersistenceLocations();

        if (entries.Count == 0)
        {
            Info(suspiciousOnly ? "No suspicious entries found." : "No entries found.");
            return 0;
        }

        Console.WriteLine();
        for (int i = 0; i < entries.Count; i++)
        {
            var e = entries[i];
            Console.ForegroundColor = e.Reason != null ? ConsoleColor.Yellow : ConsoleColor.Gray;
            Console.WriteLine($"[{i}] {e.HivePath}");
            Console.WriteLine($"    Name: {e.ValueName}");
            Console.WriteLine($"    Data: {e.ValueData}");
            if (e.Reason != null)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"    WARNING: {e.Reason}");
            }
            Console.ResetColor();
            Console.WriteLine();
        }

        Console.WriteLine($"Total: {entries.Count} entries" +
            (suspiciousOnly ? " (suspicious only)" : $" ({entries.Count(e => e.Reason != null)} suspicious)"));
        return 0;
    }

    static int RegistryClean(string target)
    {
        if (string.IsNullOrEmpty(target))
        {
            Error("Usage: sfk registry clean <index from scan>");
            return 1;
        }

        if (!int.TryParse(target, out int index))
        {
            Error("Provide the index number from 'registry scan' output.");
            return 1;
        }

        var entries = RegistryCleaner.ScanPersistenceLocations();
        if (index < 0 || index >= entries.Count)
        {
            Error($"Index {index} out of range (0-{entries.Count - 1}).");
            return 1;
        }

        var entry = entries[index];
        Console.WriteLine($"Removing: {entry.HivePath}\\{entry.ValueName}");
        Console.Write("Confirm? [y/N] ");
        if (Console.ReadLine()?.Trim().ToLowerInvariant() != "y")
        {
            Info("Cancelled.");
            return 0;
        }

        if (RegistryCleaner.RemoveEntry(entry))
        {
            Success("Removed.");
            return 0;
        }
        else
        {
            Error("Failed to remove entry.");
            return 1;
        }
    }

    static int RegistryCleanAll()
    {
        var suspicious = RegistryCleaner.ScanSuspicious();
        if (suspicious.Count == 0)
        {
            Info("No suspicious entries to clean.");
            return 0;
        }

        Console.WriteLine($"Found {suspicious.Count} suspicious entries:");
        foreach (var e in suspicious)
            Console.WriteLine($"  {e.HivePath}\\{e.ValueName} - {e.Reason}");

        Console.Write($"\nRemove all {suspicious.Count} entries? [y/N] ");
        if (Console.ReadLine()?.Trim().ToLowerInvariant() != "y")
        {
            Info("Cancelled.");
            return 0;
        }

        int removed = RegistryCleaner.RemoveEntries(suspicious);
        Success($"Removed {removed}/{suspicious.Count} entries.");
        return removed == suspicious.Count ? 0 : 1;
    }

    // ── Help ──

    static int Help()
    {
        PrintUsage();
        return 0;
    }

    static int Unknown(string cmd, string sub)
    {
        Error($"Unknown command: {cmd} {sub}");
        PrintUsage();
        return 1;
    }

    static void PrintUsage()
    {
        Console.WriteLine(@"
  ======================================
       System File Killer (SFK)
     Anti-Malware Defense Toolkit
  ======================================

  PROCESS COMMANDS:
    sfk process list                   List all running processes
    sfk process kill <pid|name>        Force-kill a process
    sfk process kill-tree <pid|name>   Kill process and all children

  FILE COMMANDS:
    sfk file delete <path>             Force-delete a file
    sfk file delete-dir <path>         Force-delete a directory tree
    sfk file delete-paths <p1> <p2>... Batch-delete N files/dirs in one pipe call
    sfk file unlock <path>             Unlock file handles (no delete)
    sfk file reboot-delete <path>      Schedule deletion on reboot

  REGISTRY COMMANDS:
    sfk registry scan                  Scan all persistence locations
    sfk registry scan-suspicious       Scan for suspicious entries only
    sfk registry clean <index>         Remove entry by scan index
    sfk registry clean-all             Remove all suspicious entries

  NUKE PLAYBOOK (one-call malware/app removal):
    sfk nuke <id>                      Show discovery + planned ops (no action)
    sfk nuke <id> dryrun               Dispatch with dry-run flag (server simulates)
    sfk nuke <id> execute              Confirm + run the full cleanup (destructive)

  Run as Administrator for full functionality.
");
    }

    // ── Output helpers ──

    static void Info(string msg)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"[*] {msg}");
        Console.ResetColor();
    }

    static void Success(string msg)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[+] {msg}");
        Console.ResetColor();
    }

    static void Warn(string msg)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"[!] {msg}");
        Console.ResetColor();
    }

    static void Error(string msg)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"[-] {msg}");
        Console.ResetColor();
    }
}
