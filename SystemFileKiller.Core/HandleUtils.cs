using System.Runtime.InteropServices;

namespace SystemFileKiller.Core;

public static class HandleUtils
{
    /// <summary>
    /// Finds all open handles to a specific file path across all processes.
    /// Returns list of (ProcessId, HandleValue) tuples.
    /// </summary>
    public static List<(int ProcessId, IntPtr Handle)> FindHandlesForFile(string filePath)
    {
        var results = new List<(int, IntPtr)>();
        var normalizedTarget = NormalizePathToNt(filePath);
        if (normalizedTarget == null) return results;

        var handles = EnumerateAllHandles();
        var currentPid = Environment.ProcessId;
        var currentProcess = NativeMethods.GetCurrentProcess();

        foreach (var entry in handles)
        {
            var pid = (int)entry.UniqueProcessId.ToUInt64();
            if (pid == currentPid || pid == 0 || pid == 4) continue;

            IntPtr processHandle = IntPtr.Zero;
            IntPtr dupHandle = IntPtr.Zero;

            try
            {
                processHandle = NativeMethods.OpenProcess(
                    NativeMethods.PROCESS_DUP_HANDLE, false, pid);
                if (processHandle == IntPtr.Zero) continue;

                var status = NativeMethods.NtDuplicateObject(
                    processHandle,
                    (IntPtr)entry.HandleValue,
                    currentProcess,
                    out dupHandle,
                    0,
                    0,
                    NativeMethods.DUPLICATE_SAME_ACCESS);

                if (status != NativeMethods.STATUS_SUCCESS || dupHandle == IntPtr.Zero) continue;

                // Check if it's a File type handle
                var typeName = GetObjectType(dupHandle);
                if (typeName != "File") continue;

                // Get the file name
                var name = GetObjectName(dupHandle);
                if (name != null && name.Equals(normalizedTarget, StringComparison.OrdinalIgnoreCase))
                {
                    results.Add((pid, (IntPtr)entry.HandleValue));
                }
            }
            catch
            {
                // Some handles can't be queried - skip them
            }
            finally
            {
                if (dupHandle != IntPtr.Zero)
                    NativeMethods.CloseHandle(dupHandle);
                if (processHandle != IntPtr.Zero)
                    NativeMethods.CloseHandle(processHandle);
            }
        }

        return results;
    }

    /// <summary>
    /// Forcefully closes a handle in a remote process.
    /// </summary>
    public static bool CloseRemoteHandle(int processId, IntPtr handle)
    {
        IntPtr processHandle = IntPtr.Zero;
        try
        {
            processHandle = NativeMethods.OpenProcess(
                NativeMethods.PROCESS_DUP_HANDLE, false, processId);
            if (processHandle == IntPtr.Zero) return false;

            // Duplicate with DUPLICATE_CLOSE_SOURCE closes the original handle
            var status = NativeMethods.NtDuplicateObject(
                processHandle,
                handle,
                IntPtr.Zero,
                out _,
                0,
                0,
                NativeMethods.DUPLICATE_CLOSE_SOURCE);

            return status == NativeMethods.STATUS_SUCCESS;
        }
        finally
        {
            if (processHandle != IntPtr.Zero)
                NativeMethods.CloseHandle(processHandle);
        }
    }

    internal static List<NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> EnumerateAllHandles()
    {
        var handles = new List<NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>();
        int size = 1024 * 1024; // Start at 1MB
        IntPtr buffer = IntPtr.Zero;

        try
        {
            while (true)
            {
                buffer = Marshal.AllocHGlobal(size);
                var status = NativeMethods.NtQuerySystemInformation(
                    NativeMethods.SystemExtendedHandleInformation,
                    buffer,
                    size,
                    out int needed);

                if (status == NativeMethods.STATUS_INFO_LENGTH_MISMATCH)
                {
                    Marshal.FreeHGlobal(buffer);
                    buffer = IntPtr.Zero;
                    size = needed + (1024 * 1024); // Add extra margin
                    continue;
                }

                if (status != NativeMethods.STATUS_SUCCESS) break;

                // Parse the buffer
                long count;
                int entryOffset;
                if (IntPtr.Size == 8)
                {
                    count = Marshal.ReadInt64(buffer, 0);
                    entryOffset = IntPtr.Size * 2; // Skip NumberOfHandles + Reserved
                }
                else
                {
                    count = Marshal.ReadInt32(buffer, 0);
                    entryOffset = IntPtr.Size * 2;
                }

                int entrySize = Marshal.SizeOf<NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>();

                for (long i = 0; i < count; i++)
                {
                    var entryPtr = buffer + entryOffset + (int)(i * entrySize);
                    var entry = Marshal.PtrToStructure<NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>(entryPtr);
                    handles.Add(entry);
                }
                break;
            }
        }
        finally
        {
            if (buffer != IntPtr.Zero)
                Marshal.FreeHGlobal(buffer);
        }

        return handles;
    }

    private static string? GetObjectName(IntPtr handle)
    {
        int size = 1024;
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            var status = NativeMethods.NtQueryObject(
                handle,
                NativeMethods.ObjectNameInformation,
                buffer,
                size,
                out int needed);

            if (status != NativeMethods.STATUS_SUCCESS)
            {
                Marshal.FreeHGlobal(buffer);
                buffer = Marshal.AllocHGlobal(needed);
                status = NativeMethods.NtQueryObject(
                    handle,
                    NativeMethods.ObjectNameInformation,
                    buffer,
                    needed,
                    out _);
            }

            if (status != NativeMethods.STATUS_SUCCESS) return null;

            var info = Marshal.PtrToStructure<NativeMethods.OBJECT_NAME_INFORMATION>(buffer);
            if (info.Name.Length == 0 || info.Name.Buffer == IntPtr.Zero) return null;
            return Marshal.PtrToStringUni(info.Name.Buffer, info.Name.Length / 2);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static string? GetObjectType(IntPtr handle)
    {
        int size = 1024;
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            var status = NativeMethods.NtQueryObject(
                handle,
                NativeMethods.ObjectTypeInformation,
                buffer,
                size,
                out _);

            if (status != NativeMethods.STATUS_SUCCESS) return null;

            var info = Marshal.PtrToStructure<NativeMethods.OBJECT_TYPE_INFORMATION>(buffer);
            if (info.TypeName.Length == 0 || info.TypeName.Buffer == IntPtr.Zero) return null;
            return Marshal.PtrToStringUni(info.TypeName.Buffer, info.TypeName.Length / 2);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>
    /// Converts a Win32 path to NT object path format.
    /// e.g., "C:\Windows\test.txt" -> "\Device\HarddiskVolume3\Windows\test.txt"
    /// </summary>
    private static string? NormalizePathToNt(string filePath)
    {
        try
        {
            var fullPath = Path.GetFullPath(filePath);
            // Get the drive letter
            var drive = Path.GetPathRoot(fullPath);
            if (drive == null) return null;

            // QueryDosDevice to get NT path for the drive
            var deviceBuffer = new char[1024];
            int length = QueryDosDevice(drive.TrimEnd('\\'), deviceBuffer, deviceBuffer.Length);
            if (length == 0) return null;

            var devicePath = new string(deviceBuffer, 0, Array.IndexOf(deviceBuffer, '\0'));
            return devicePath + fullPath[drive.TrimEnd('\\').Length..];
        }
        catch
        {
            return null;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int QueryDosDevice(string lpDeviceName, char[] lpTargetPath, int ucchMax);
}
