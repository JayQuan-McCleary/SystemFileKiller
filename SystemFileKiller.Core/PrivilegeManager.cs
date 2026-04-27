using System.Diagnostics;
using System.Security.Principal;

namespace SystemFileKiller.Core;

/// <summary>
/// Token privilege helpers. Call <see cref="TryEnableDebugPrivilege"/> early in
/// process startup to gain SeDebugPrivilege when running elevated. With it,
/// OpenProcess succeeds against most non-PPL processes regardless of owner.
/// </summary>
public static class PrivilegeManager
{
    private static bool _debugAttempted;
    private static bool _debugEnabled;

    public static bool IsElevated
    {
        get
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    public static bool IsLocalSystem
    {
        get
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.IsSystem;
        }
    }

    /// <summary>
    /// Idempotent. Returns true if SeDebugPrivilege is now enabled in this process token.
    /// No-ops (returns false) when not running elevated — adjusting privileges requires it.
    /// </summary>
    public static bool TryEnableDebugPrivilege()
    {
        if (_debugAttempted) return _debugEnabled;
        _debugAttempted = true;

        if (!IsElevated && !IsLocalSystem)
        {
            _debugEnabled = false;
            return false;
        }

        // Process.EnterDebugMode wraps OpenProcessToken/LookupPrivilegeValue/AdjustTokenPrivileges.
        // Falls back to manual adjustment on the off-chance it fails.
        try
        {
            Process.EnterDebugMode();
            _debugEnabled = true;
            return true;
        }
        catch
        {
            _debugEnabled = TryAdjustPrivilegeManually(NativeMethods.SE_DEBUG_NAME);
            return _debugEnabled;
        }
    }

    private static bool TryAdjustPrivilegeManually(string privilege)
    {
        IntPtr token = IntPtr.Zero;
        try
        {
            if (!NativeMethods.OpenProcessToken(
                    NativeMethods.GetCurrentProcess(),
                    NativeMethods.TOKEN_ADJUST_PRIVILEGES | NativeMethods.TOKEN_QUERY,
                    out token))
                return false;

            if (!NativeMethods.LookupPrivilegeValue(null, privilege, out var luid))
                return false;

            var tp = new NativeMethods.TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privilege = new NativeMethods.LUID_AND_ATTRIBUTES
                {
                    Luid = luid,
                    Attributes = NativeMethods.SE_PRIVILEGE_ENABLED
                }
            };

            return NativeMethods.AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        }
        catch
        {
            return false;
        }
        finally
        {
            if (token != IntPtr.Zero) NativeMethods.CloseHandle(token);
        }
    }
}
