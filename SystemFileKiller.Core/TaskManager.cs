using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace SystemFileKiller.Core;

public record ScheduledTaskInfo(
    string TaskName,
    string TaskPath,
    string Status,
    string Author,
    string TaskRun,
    string LastRunTime,
    string LastResult,
    string NextRunTime,
    bool IsSuspicious,
    string? SuspicionReason);

/// <summary>
/// Scheduled-task surface. Wraps <c>schtasks.exe</c> rather than the Task Scheduler COM API
/// — schtasks is always present, output is parseable, and the operations we need (list/disable/delete)
/// don't justify hauling in the COM type lib. Suspicion heuristics flag the common malware patterns:
/// AppData/Temp/ProgramData task targets, base64-encoded PowerShell, missing binaries.
/// </summary>
public static class TaskManager
{
    private static readonly string[] SuspiciousLocationFragments = new[]
    {
        @"\AppData\Local\Temp",
        @"\AppData\Roaming\",
        @"\AppData\Local\",
        @"\ProgramData\",
        @"\Users\Public\",
        @"\Windows\Temp\",
    };

    private static readonly Regex EncodedPowerShellRx = new(
        @"powershell.*?(-enc(odedcommand)?|-e\b)\s*[A-Za-z0-9+/=]{30,}",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static List<ScheduledTaskInfo> ListTasks(bool suspiciousOnly = false)
    {
        var list = new List<ScheduledTaskInfo>();
        var (rc, stdout, _) = RunSchtasks("/Query /FO CSV /V /NH");
        if (rc != 0 || string.IsNullOrWhiteSpace(stdout)) return list;

        foreach (var row in ParseCsv(stdout))
        {
            if (row.Length < 9) continue;
            // schtasks CSV column order (NH = no header):
            // 0: HostName, 1: TaskName(full path), 2: Next Run Time, 3: Status, 4: Logon Mode,
            // 5: Last Run Time, 6: Last Result, 7: Author, 8: Task To Run, 9..: Start In, etc.
            var taskNameFull = row[1].Trim('"');
            if (string.IsNullOrEmpty(taskNameFull) || taskNameFull.Equals("TaskName", StringComparison.OrdinalIgnoreCase))
                continue;
            var taskRun = row[8].Trim('"');
            var (sus, reason) = ScoreSuspicion(taskRun, row[7].Trim('"'), taskNameFull);
            if (suspiciousOnly && !sus) continue;

            var leaf = taskNameFull.Contains('\\')
                ? taskNameFull[(taskNameFull.LastIndexOf('\\') + 1)..]
                : taskNameFull;
            var parent = taskNameFull.Length > leaf.Length
                ? taskNameFull[..(taskNameFull.Length - leaf.Length - 1)]
                : "\\";

            list.Add(new ScheduledTaskInfo(
                TaskName: leaf,
                TaskPath: taskNameFull,
                Status: row[3].Trim('"'),
                Author: row[7].Trim('"'),
                TaskRun: taskRun,
                LastRunTime: row[5].Trim('"'),
                LastResult: row[6].Trim('"'),
                NextRunTime: row[2].Trim('"'),
                IsSuspicious: sus,
                SuspicionReason: reason));
        }
        return list;
    }

    public static ServiceOpResult DisableTask(string taskPath)
    {
        if (string.IsNullOrWhiteSpace(taskPath)) return ServiceOpResult.NotFound;
        var (rc, _, err) = RunSchtasks($"/Change /TN \"{taskPath}\" /Disable");
        return rc switch
        {
            0 => ServiceOpResult.Success,
            5 => ServiceOpResult.AccessDenied,
            _ when (err ?? "").Contains("not exist", StringComparison.OrdinalIgnoreCase) => ServiceOpResult.NotFound,
            _ => ServiceOpResult.Failed
        };
    }

    public static ServiceOpResult EnableTask(string taskPath)
    {
        if (string.IsNullOrWhiteSpace(taskPath)) return ServiceOpResult.NotFound;
        var (rc, _, err) = RunSchtasks($"/Change /TN \"{taskPath}\" /Enable");
        return rc switch
        {
            0 => ServiceOpResult.Success,
            5 => ServiceOpResult.AccessDenied,
            _ when (err ?? "").Contains("not exist", StringComparison.OrdinalIgnoreCase) => ServiceOpResult.NotFound,
            _ => ServiceOpResult.Failed
        };
    }

    public static ServiceOpResult DeleteTask(string taskPath)
    {
        if (string.IsNullOrWhiteSpace(taskPath)) return ServiceOpResult.NotFound;
        var (rc, _, err) = RunSchtasks($"/Delete /TN \"{taskPath}\" /F");
        return rc switch
        {
            0 => ServiceOpResult.Success,
            5 => ServiceOpResult.AccessDenied,
            _ when (err ?? "").Contains("not exist", StringComparison.OrdinalIgnoreCase) => ServiceOpResult.NotFound,
            _ => ServiceOpResult.Failed
        };
    }

    private static (bool, string?) ScoreSuspicion(string taskRun, string author, string taskPath)
    {
        if (string.IsNullOrEmpty(taskRun)) return (false, null);

        if (EncodedPowerShellRx.IsMatch(taskRun))
            return (true, "encoded PowerShell command");

        foreach (var frag in SuspiciousLocationFragments)
        {
            if (taskRun.Contains(frag, StringComparison.OrdinalIgnoreCase))
                return (true, $"target in user-writable location ({frag.TrimEnd('\\')})");
        }

        // Microsoft author claim on a non-Microsoft path is a classic impersonation tell.
        if (author.Equals("Microsoft Corporation", StringComparison.OrdinalIgnoreCase)
            && !taskPath.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase)
            && !string.IsNullOrEmpty(taskRun)
            && !taskRun.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase)
            && !taskRun.Contains(@"\Program Files\", StringComparison.OrdinalIgnoreCase))
        {
            return (true, "claims Microsoft author but runs outside system paths");
        }

        // Binary missing → either a typo or a deleted dropper that left the persistence behind.
        var firstToken = ExtractFirstPath(taskRun);
        if (firstToken != null && !File.Exists(firstToken)
            && (firstToken.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                || firstToken.EndsWith(".bat", StringComparison.OrdinalIgnoreCase)
                || firstToken.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase)))
        {
            return (true, $"target binary missing on disk ({firstToken})");
        }

        return (false, null);
    }

    private static string? ExtractFirstPath(string command)
    {
        if (string.IsNullOrEmpty(command)) return null;
        var s = command.TrimStart();
        if (s.StartsWith("\""))
        {
            int close = s.IndexOf('"', 1);
            return close > 1 ? s.Substring(1, close - 1) : null;
        }
        int space = s.IndexOf(' ');
        return space > 0 ? s[..space] : s;
    }

    private static (int Rc, string Stdout, string Stderr) RunSchtasks(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("schtasks.exe", args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };
            using var p = Process.Start(psi)!;
            var stdout = p.StandardOutput.ReadToEnd();
            var stderr = p.StandardError.ReadToEnd();
            p.WaitForExit(30000);
            return (p.ExitCode, stdout, stderr);
        }
        catch (Exception ex)
        {
            return (-1, "", ex.Message);
        }
    }

    // schtasks emits CSV with embedded commas inside quoted fields. Minimal parser handling that.
    private static IEnumerable<string[]> ParseCsv(string text)
    {
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (string.IsNullOrWhiteSpace(line)) continue;
            var fields = new List<string>();
            var sb = new StringBuilder();
            bool inQuotes = false;
            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];
                if (c == '"')
                {
                    if (inQuotes && i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; }
                    else inQuotes = !inQuotes;
                    sb.Append(c);
                }
                else if (c == ',' && !inQuotes)
                {
                    fields.Add(sb.ToString());
                    sb.Clear();
                }
                else sb.Append(c);
            }
            fields.Add(sb.ToString());
            yield return fields.ToArray();
        }
    }
}
