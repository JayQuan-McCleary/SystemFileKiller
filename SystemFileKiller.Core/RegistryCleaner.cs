using Microsoft.Win32;

namespace SystemFileKiller.Core;

public record RegistryEntry(
    string HivePath,
    string ValueName,
    string? ValueData,
    string? Reason);

public static class RegistryCleaner
{
    private static readonly (RegistryKey Hive, string Path, string Description)[] PersistenceLocations =
    [
        (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
        (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
        (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
        (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
        (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices", "HKLM RunServices"),
        (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce", "HKLM RunServicesOnce"),
        (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Winlogon"),
        (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "Policy Run"),
        (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "User Policy Run"),
        (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", "User Shell Folders"),
        (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", "Shell Folders"),
    ];

    // Known safe entries that should not be flagged
    private static readonly HashSet<string> KnownSafePublishers = new(StringComparer.OrdinalIgnoreCase)
    {
        "microsoft", "windows", "realtek", "intel", "nvidia", "amd",
        "logitech", "corsair", "steam", "discord", "google", "mozilla",
    };

    /// <summary>
    /// Scans all known persistence locations and returns every entry found.
    /// Entries include a reason if they look suspicious.
    /// </summary>
    public static List<RegistryEntry> ScanPersistenceLocations()
    {
        var results = new List<RegistryEntry>();

        foreach (var (hive, path, desc) in PersistenceLocations)
        {
            try
            {
                using var key = hive.OpenSubKey(path, false);
                if (key == null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    var data = key.GetValue(valueName)?.ToString();
                    var reason = AnalyzeEntry(valueName, data);
                    var hiveName = hive == Registry.LocalMachine ? "HKLM" : "HKCU";
                    results.Add(new RegistryEntry(
                        $"{hiveName}\\{path}",
                        valueName,
                        data,
                        reason));
                }
            }
            catch { /* Some keys may be access-denied */ }
        }

        // Scan services for suspicious entries
        results.AddRange(ScanSuspiciousServices());

        return results;
    }

    /// <summary>
    /// Returns only entries flagged as suspicious.
    /// </summary>
    public static List<RegistryEntry> ScanSuspicious()
    {
        return ScanPersistenceLocations()
            .Where(e => e.Reason != null)
            .ToList();
    }

    /// <summary>
    /// Removes a specific registry value.
    /// </summary>
    public static bool RemoveEntry(RegistryEntry entry)
    {
        try
        {
            var (hive, subPath) = ParseHivePath(entry.HivePath);
            if (hive == null) return false;

            using var key = hive.OpenSubKey(subPath, true);
            if (key == null) return false;

            key.DeleteValue(entry.ValueName, false);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Removes a list of registry entries. Returns count of successful removals.
    /// </summary>
    public static int RemoveEntries(IEnumerable<RegistryEntry> entries)
    {
        return entries.Count(RemoveEntry);
    }

    private static List<RegistryEntry> ScanSuspiciousServices()
    {
        var results = new List<RegistryEntry>();
        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services", false);
            if (servicesKey == null) return results;

            foreach (var serviceName in servicesKey.GetSubKeyNames())
            {
                try
                {
                    using var svcKey = servicesKey.OpenSubKey(serviceName, false);
                    if (svcKey == null) continue;

                    var imagePath = svcKey.GetValue("ImagePath")?.ToString();
                    if (imagePath == null) continue;

                    var reason = AnalyzeServicePath(serviceName, imagePath);
                    if (reason != null)
                    {
                        results.Add(new RegistryEntry(
                            $@"HKLM\SYSTEM\CurrentControlSet\Services\{serviceName}",
                            "ImagePath",
                            imagePath,
                            reason));
                    }
                }
                catch { }
            }
        }
        catch { }

        return results;
    }

    private static string? AnalyzeEntry(string name, string? data)
    {
        if (string.IsNullOrEmpty(data)) return "Empty value data";

        var lower = data.ToLowerInvariant();

        // Check for suspicious paths
        if (lower.Contains("\\temp\\") || lower.Contains("\\tmp\\"))
            return "Runs from temp directory";
        if (lower.Contains("\\appdata\\local\\temp"))
            return "Runs from user temp folder";
        if (lower.Contains("powershell") && lower.Contains("-enc"))
            return "Encoded PowerShell command";
        if (lower.Contains("cmd.exe") && lower.Contains("/c"))
            return "Command shell execution";
        if (lower.Contains("regsvr32") && lower.Contains("/s"))
            return "Silent DLL registration (common malware technique)";
        if (lower.Contains("mshta") || lower.Contains("wscript") || lower.Contains("cscript"))
            return "Script host execution";
        if (lower.Contains("rundll32") && !IsKnownSafe(data))
            return "RunDLL32 execution";

        // Check for non-existent executables
        var exePath = ExtractExecutablePath(data);
        if (exePath != null && !File.Exists(exePath))
            return $"Executable not found: {exePath}";

        return null;
    }

    private static string? AnalyzeServicePath(string serviceName, string imagePath)
    {
        var lower = imagePath.ToLowerInvariant();

        if (lower.Contains("\\temp\\") || lower.Contains("\\tmp\\"))
            return "Service runs from temp directory";
        if (lower.Contains("\\appdata\\"))
            return "Service runs from user AppData";
        if (!lower.Contains("\\windows\\") && !lower.Contains("\\program files"))
        {
            var exePath = ExtractExecutablePath(imagePath);
            if (exePath != null && !File.Exists(exePath))
                return $"Service executable not found: {exePath}";
        }

        return null;
    }

    private static bool IsKnownSafe(string data)
    {
        var lower = data.ToLowerInvariant();
        return KnownSafePublishers.Any(p => lower.Contains(p));
    }

    private static string? ExtractExecutablePath(string data)
    {
        var trimmed = data.Trim();

        // Handle quoted paths
        if (trimmed.StartsWith('"'))
        {
            var end = trimmed.IndexOf('"', 1);
            if (end > 0)
                return trimmed[1..end];
        }

        // Handle unquoted paths (take until first space after .exe)
        var exeIdx = trimmed.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeIdx > 0)
            return trimmed[..(exeIdx + 4)];

        return null;
    }

    private static (RegistryKey? Hive, string SubPath) ParseHivePath(string hivePath)
    {
        if (hivePath.StartsWith("HKLM\\"))
            return (Registry.LocalMachine, hivePath[5..]);
        if (hivePath.StartsWith("HKCU\\"))
            return (Registry.CurrentUser, hivePath[5..]);
        if (hivePath.StartsWith("HKCR\\"))
            return (Registry.ClassesRoot, hivePath[5..]);
        if (hivePath.StartsWith("HKU\\"))
            return (Registry.Users, hivePath[4..]);
        if (hivePath.StartsWith("HKCC\\"))
            return (Registry.CurrentConfig, hivePath[5..]);
        return (null, hivePath);
    }

    /// <summary>
    /// Refuse to operate on system-critical registry roots. Mirrors the file-system protected
    /// path list — without this the helper service could brick the OS on bad input.
    /// </summary>
    public static bool IsProtectedKey(string hivePath, out string reason)
    {
        reason = "";
        if (string.IsNullOrWhiteSpace(hivePath)) { reason = "empty path"; return true; }

        var trimmed = hivePath.TrimEnd('\\');
        var upper = trimmed.ToUpperInvariant();

        // Roots themselves
        string[] roots = { "HKLM", "HKCU", "HKCR", "HKU", "HKCC",
                           "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", "HKEY_CLASSES_ROOT",
                           "HKEY_USERS", "HKEY_CURRENT_CONFIG" };
        if (roots.Contains(upper)) { reason = "registry hive root"; return true; }

        // System-critical subtrees
        string[] forbidden = {
            @"HKLM\SAM", @"HKLM\SECURITY", @"HKLM\HARDWARE",
            @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            @"HKLM\SYSTEM\Setup",
            @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
        };
        foreach (var f in forbidden)
        {
            if (upper.StartsWith(f.ToUpperInvariant() + "\\") || upper == f.ToUpperInvariant())
            {
                reason = $"under {f}";
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// Delete an entire registry key (and its subtree). Use for uninstall stubs, malware
    /// persistence containers, service entries. Refuses to touch <see cref="IsProtectedKey"/> roots.
    /// </summary>
    public static (bool Ok, string Message) RemoveKey(string hivePath)
    {
        if (IsProtectedKey(hivePath, out var reason)) return (false, $"Refused: {reason}");
        try
        {
            var (hive, subPath) = ParseHivePath(hivePath);
            if (hive is null) return (false, $"Unknown hive in: {hivePath}");
            using var probe = hive.OpenSubKey(subPath, writable: false);
            if (probe is null) return (true, "key already absent");
            hive.DeleteSubKeyTree(subPath, throwOnMissingSubKey: false);
            return (true, $"removed key: {hivePath}");
        }
        catch (System.Security.SecurityException) { return (false, "access denied (try elevated)"); }
        catch (UnauthorizedAccessException) { return (false, "access denied (try elevated)"); }
        catch (Exception ex) { return (false, ex.Message); }
    }

    /// <summary>
    /// Delete a single value under any registry key. Use for surgical removal of one Run entry,
    /// one ImagePath, etc. without nuking the whole key.
    /// </summary>
    public static (bool Ok, string Message) RemoveValue(string hivePath, string valueName)
    {
        if (IsProtectedKey(hivePath, out var reason)) return (false, $"Refused: {reason}");
        if (valueName is null) return (false, "value name required (use empty string for default)");
        try
        {
            var (hive, subPath) = ParseHivePath(hivePath);
            if (hive is null) return (false, $"Unknown hive in: {hivePath}");
            using var key = hive.OpenSubKey(subPath, writable: true);
            if (key is null) return (true, "key absent — value already gone");
            if (!key.GetValueNames().Contains(valueName)) return (true, "value already absent");
            key.DeleteValue(valueName, throwOnMissingValue: false);
            return (true, $"removed value: {hivePath}\\{valueName}");
        }
        catch (System.Security.SecurityException) { return (false, "access denied (try elevated)"); }
        catch (UnauthorizedAccessException) { return (false, "access denied (try elevated)"); }
        catch (Exception ex) { return (false, ex.Message); }
    }

    /// <summary>
    /// Write a registry value. Used to neutralize hijacks by overwriting (e.g. replacing a
    /// malicious Shell or Userinit value with the legitimate one) rather than deleting and
    /// breaking the host. Creates the key if missing. <paramref name="kind"/> defaults to String.
    /// </summary>
    public static (bool Ok, string Message) SetValue(string hivePath, string valueName, string value, RegistryValueKind kind = RegistryValueKind.String)
    {
        if (IsProtectedKey(hivePath, out var reason)) return (false, $"Refused: {reason}");
        try
        {
            var (hive, subPath) = ParseHivePath(hivePath);
            if (hive is null) return (false, $"Unknown hive in: {hivePath}");
            using var key = hive.CreateSubKey(subPath, writable: true);
            if (key is null) return (false, $"could not open or create: {hivePath}");

            object converted = kind switch
            {
                RegistryValueKind.DWord => int.TryParse(value, out var i) ? (object)i : 0,
                RegistryValueKind.QWord => long.TryParse(value, out var l) ? (object)l : 0L,
                RegistryValueKind.Binary => Convert.FromHexString(value.Replace(" ", "").Replace("-", "")),
                RegistryValueKind.MultiString => value.Split('\n').Select(s => s.TrimEnd('\r')).ToArray(),
                _ => value
            };
            key.SetValue(valueName, converted, kind);
            return (true, $"set: {hivePath}\\{valueName} = {value} ({kind})");
        }
        catch (System.Security.SecurityException) { return (false, "access denied (try elevated)"); }
        catch (UnauthorizedAccessException) { return (false, "access denied (try elevated)"); }
        catch (Exception ex) { return (false, ex.Message); }
    }
}
