using System.Runtime.InteropServices;

namespace SystemFileKiller.Core;

internal static class NativeMethods
{
    // ── NT Status codes ──
    internal const uint STATUS_SUCCESS = 0x00000000;
    internal const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

    // ── Process access rights ──
    internal const uint PROCESS_TERMINATE = 0x0001;
    internal const uint PROCESS_DUP_HANDLE = 0x0040;
    internal const uint PROCESS_QUERY_INFORMATION = 0x0400;
    internal const uint PROCESS_SUSPEND_RESUME = 0x0800;
    internal const uint PROCESS_ALL_ACCESS = 0x001F0FFF;

    // ── Token access rights ──
    internal const uint TOKEN_QUERY = 0x0008;
    internal const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    internal const uint SE_PRIVILEGE_ENABLED = 0x0002;
    internal const string SE_DEBUG_NAME = "SeDebugPrivilege";

    // ── Duplicate object options ──
    internal const uint DUPLICATE_CLOSE_SOURCE = 0x00000001;
    internal const uint DUPLICATE_SAME_ACCESS = 0x00000002;

    // ── MoveFileEx flags ──
    internal const uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004;

    // ── System information classes ──
    internal const int SystemHandleInformation = 16;
    internal const int SystemExtendedHandleInformation = 64;

    // ── Object information classes ──
    internal const int ObjectNameInformation = 1;
    internal const int ObjectTypeInformation = 2;

    // ── Structures ──

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    {
        public IntPtr Object;
        public UIntPtr UniqueProcessId;
        public UIntPtr HandleValue;
        public uint GrantedAccess;
        public ushort CreatorBackTraceIndex;
        public ushort ObjectTypeIndex;
        public uint HandleAttributes;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct OBJECT_NAME_INFORMATION
    {
        public UNICODE_STRING Name;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct OBJECT_TYPE_INFORMATION
    {
        public UNICODE_STRING TypeName;
        // There are more fields but we only need TypeName
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privilege; // single-privilege variant; PrivilegeCount must be 1
    }

    // ── ntdll.dll ──

    [DllImport("ntdll.dll")]
    internal static extern uint NtQuerySystemInformation(
        int systemInformationClass,
        IntPtr systemInformation,
        int systemInformationLength,
        out int returnLength);

    [DllImport("ntdll.dll")]
    internal static extern uint NtQueryObject(
        IntPtr handle,
        int objectInformationClass,
        IntPtr objectInformation,
        int objectInformationLength,
        out int returnLength);

    [DllImport("ntdll.dll")]
    internal static extern uint NtDuplicateObject(
        IntPtr sourceProcessHandle,
        IntPtr sourceHandle,
        IntPtr targetProcessHandle,
        out IntPtr targetHandle,
        uint desiredAccess,
        uint handleAttributes,
        uint options);

    [DllImport("ntdll.dll")]
    internal static extern uint NtTerminateProcess(
        IntPtr processHandle,
        int exitStatus);

    [DllImport("ntdll.dll")]
    internal static extern uint NtSuspendProcess(IntPtr processHandle);

    [DllImport("ntdll.dll")]
    internal static extern uint NtResumeProcess(IntPtr processHandle);

    [DllImport("ntdll.dll")]
    internal static extern uint NtClose(IntPtr handle);

    // ── kernel32.dll ──

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr OpenProcess(
        uint processAccess,
        bool inheritHandle,
        int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool MoveFileEx(
        string lpExistingFileName,
        string? lpNewFileName,
        uint dwFlags);

    [DllImport("kernel32.dll")]
    internal static extern IntPtr GetCurrentProcess();

    // ── advapi32.dll (token privileges) ──

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool OpenProcessToken(
        IntPtr ProcessHandle,
        uint DesiredAccess,
        out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool LookupPrivilegeValue(
        string? lpSystemName,
        string lpName,
        out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle,
        [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        uint BufferLength,
        IntPtr PreviousState,
        IntPtr ReturnLength);
}
