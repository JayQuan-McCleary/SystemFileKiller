using System.Text.RegularExpressions;

namespace SystemFileKiller.Core;

public record HostsEntry(int LineNumber, string Address, string Hostname, string? Comment, string RawLine);

/// <summary>
/// Inspect and edit <c>C:\Windows\System32\drivers\etc\hosts</c>. Real adware/PUP routinely
/// inserts entries here to redirect ad networks or competitor sites. Default Windows ships an
/// all-comment file — any data line is worth eyeballing.
/// </summary>
public static class HostsFileUtil
{
    private static readonly string HostsPath = Environment.ExpandEnvironmentVariables(@"%WinDir%\System32\drivers\etc\hosts");
    private static readonly Regex EntryRx = new(@"^\s*(?<addr>\S+)\s+(?<host>\S+)(\s+#(?<cmt>.*))?\s*$", RegexOptions.Compiled);

    public static List<HostsEntry> ReadEntries()
    {
        var list = new List<HostsEntry>();
        if (!File.Exists(HostsPath)) return list;
        var lines = File.ReadAllLines(HostsPath);
        for (int i = 0; i < lines.Length; i++)
        {
            var raw = lines[i];
            var trimmed = raw.TrimStart();
            if (string.IsNullOrWhiteSpace(trimmed)) continue;
            if (trimmed.StartsWith("#")) continue;
            var m = EntryRx.Match(raw);
            if (!m.Success) continue;
            list.Add(new HostsEntry(
                LineNumber: i + 1,
                Address: m.Groups["addr"].Value,
                Hostname: m.Groups["host"].Value,
                Comment: m.Groups["cmt"].Success ? m.Groups["cmt"].Value.Trim() : null,
                RawLine: raw));
        }
        return list;
    }

    public static (bool Ok, string Message, int Removed) RemoveMatching(string hostnamePattern)
    {
        if (string.IsNullOrWhiteSpace(hostnamePattern))
            return (false, "pattern required", 0);
        if (!File.Exists(HostsPath))
            return (false, "hosts file missing", 0);

        Regex rx;
        try { rx = new Regex(hostnamePattern, RegexOptions.IgnoreCase); }
        catch (Exception ex) { return (false, $"bad regex: {ex.Message}", 0); }

        try
        {
            var lines = File.ReadAllLines(HostsPath).ToList();
            int removed = 0;
            for (int i = lines.Count - 1; i >= 0; i--)
            {
                var trimmed = lines[i].TrimStart();
                if (trimmed.StartsWith("#") || string.IsNullOrWhiteSpace(trimmed)) continue;
                var m = EntryRx.Match(lines[i]);
                if (!m.Success) continue;
                if (rx.IsMatch(m.Groups["host"].Value))
                {
                    lines.RemoveAt(i);
                    removed++;
                }
            }
            if (removed == 0) return (true, "nothing matched", 0);

            // Atomic-ish write: write to .new then replace.
            var temp = HostsPath + ".sfk-new";
            File.WriteAllLines(temp, lines);
            File.Replace(temp, HostsPath, HostsPath + ".sfk-bak");
            return (true, $"removed {removed} entr{(removed == 1 ? "y" : "ies")}", removed);
        }
        catch (UnauthorizedAccessException) { return (false, "access denied (try elevated)", 0); }
        catch (Exception ex) { return (false, ex.Message, 0); }
    }
}
