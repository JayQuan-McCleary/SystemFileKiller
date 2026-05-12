using System.Diagnostics;
using System.Text;

namespace SystemFileKiller.Core;

public enum RestorePointResult
{
    Success,
    AccessDenied,
    ServiceDisabled,
    Failed
}

/// <summary>
/// System Restore checkpoint wrapper. Lets an AI cleanup pipeline snapshot known-good state
/// before a destructive batch — a one-click "undo everything" net if something legitimate gets
/// caught in the cleanup. Implementation defers to PowerShell <c>Checkpoint-Computer</c> which
/// internally calls SRSetRestorePoint with the correct flags.
/// </summary>
public static class RestorePointUtil
{
    public static (RestorePointResult Result, string Message) Create(string description)
    {
        if (string.IsNullOrWhiteSpace(description)) description = "SFK checkpoint";
        var safeDesc = description.Replace("'", "''");
        var psCommand = $"Checkpoint-Computer -Description '{safeDesc}' -RestorePointType MODIFY_SETTINGS";
        try
        {
            var psi = new ProcessStartInfo("powershell.exe",
                $"-NoProfile -ExecutionPolicy Bypass -Command \"{psCommand}\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };
            using var p = Process.Start(psi)!;
            var stderr = p.StandardError.ReadToEnd();
            p.WaitForExit(60_000);
            if (p.ExitCode == 0) return (RestorePointResult.Success, $"checkpoint created: {description}");
            if (stderr.Contains("disabled", StringComparison.OrdinalIgnoreCase)
                || stderr.Contains("not enabled", StringComparison.OrdinalIgnoreCase))
                return (RestorePointResult.ServiceDisabled, "System Protection is disabled — enable in System Properties");
            if (stderr.Contains("access", StringComparison.OrdinalIgnoreCase))
                return (RestorePointResult.AccessDenied, "access denied (must run elevated)");
            return (RestorePointResult.Failed, stderr.Trim());
        }
        catch (Exception ex) { return (RestorePointResult.Failed, ex.Message); }
    }
}
