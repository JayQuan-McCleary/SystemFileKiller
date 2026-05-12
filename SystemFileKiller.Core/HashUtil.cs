using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SystemFileKiller.Core;

public record FileHashResult(string Path, long SizeBytes, string Sha256, string Md5);

public enum SignatureStatus
{
    Valid,
    Invalid,
    NotSigned,
    Expired,
    NotTrusted,
    Unknown
}

public record FileSignatureResult(
    string Path,
    SignatureStatus Status,
    string? Subject,
    string? Issuer,
    DateTime? SignedAt,
    DateTime? NotBefore,
    DateTime? NotAfter,
    string? Thumbprint,
    string? Detail);

/// <summary>
/// Cheap-to-compute identity for a file: SHA256/MD5 hashes plus Authenticode signature state.
/// Hash for VT/Talos lookups; signature for the "is this binary signed by who it claims to be"
/// triage question that catches a huge fraction of malware drops in user-writable locations.
/// </summary>
public static class HashUtil
{
    public static FileHashResult? ComputeHash(string path)
    {
        var full = Path.GetFullPath(path);
        if (!File.Exists(full)) return null;
        var fi = new FileInfo(full);
        using var stream = File.OpenRead(full);
        var sha256 = SHA256.HashData(stream);
        stream.Position = 0;
        var md5 = MD5.HashData(stream);
        return new FileHashResult(full, fi.Length, Convert.ToHexString(sha256), Convert.ToHexString(md5));
    }

    public static FileSignatureResult VerifySignature(string path)
    {
        var full = Path.GetFullPath(path);
        if (!File.Exists(full))
            return new FileSignatureResult(full, SignatureStatus.Unknown, null, null, null, null, null, null, "file not found");

        X509Certificate2? cert = null;
        try
        {
            // X509Certificate2.CreateFromSignedFile is the right tool but was removed in .NET 6+.
            // The X509CertificateLoader replacement reads cert FILES, not embedded PE signatures —
            // so we keep the legacy ctor (which DOES extract from PE) and suppress the deprecation.
#pragma warning disable SYSLIB0057
            using var legacy = new X509Certificate(full);
            cert = new X509Certificate2(legacy);
#pragma warning restore SYSLIB0057
        }
        catch (CryptographicException)
        {
            return new FileSignatureResult(full, SignatureStatus.NotSigned, null, null, null, null, null, null, "no embedded signature");
        }
        catch (Exception ex)
        {
            return new FileSignatureResult(full, SignatureStatus.Unknown, null, null, null, null, null, null, ex.Message);
        }

        var status = WinVerifyTrust(full);
        return new FileSignatureResult(
            Path: full,
            Status: status.Status,
            Subject: cert.Subject,
            Issuer: cert.Issuer,
            SignedAt: null,
            NotBefore: cert.NotBefore,
            NotAfter: cert.NotAfter,
            Thumbprint: cert.Thumbprint,
            Detail: status.Detail);
    }

    // ─── WinVerifyTrust ──────────────────────────────────────────────────────────
    private static (SignatureStatus Status, string? Detail) WinVerifyTrust(string filePath)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = filePath,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero,
        };
        var fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

        var trustData = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
            pPolicyCallbackData = IntPtr.Zero,
            pSIPClientData = IntPtr.Zero,
            dwUIChoice = 2, // WTD_UI_NONE
            fdwRevocationChecks = 0, // WTD_REVOKE_NONE
            dwUnionChoice = 1, // WTD_CHOICE_FILE
            pUnion = fileInfoPtr,
            dwStateAction = 0, // WTD_STATEACTION_IGNORE
            hWVTStateData = IntPtr.Zero,
            pwszURLReference = null,
            dwProvFlags = 0,
            dwUIContext = 0,
        };
        var policyGuid = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE"); // WINTRUST_ACTION_GENERIC_VERIFY_V2

        try
        {
            int rc = WinVerifyTrustNative(IntPtr.Zero, ref policyGuid, ref trustData);
            return rc switch
            {
                0 => (SignatureStatus.Valid, null),
                unchecked((int)0x800B0100) => (SignatureStatus.NotSigned, "TRUST_E_NOSIGNATURE"),
                unchecked((int)0x800B0101) => (SignatureStatus.Expired, "CERT_E_EXPIRED"),
                unchecked((int)0x800B010A) => (SignatureStatus.NotTrusted, "CERT_E_UNTRUSTEDROOT"),
                unchecked((int)0x800B010C) => (SignatureStatus.NotTrusted, "CERT_E_REVOKED"),
                unchecked((int)0x80092010) => (SignatureStatus.Invalid, "CRYPT_E_REVOKED"),
                unchecked((int)0x800B0109) => (SignatureStatus.NotTrusted, "CERT_E_UNTRUSTEDROOT"),
                _ => (SignatureStatus.Invalid, $"0x{rc:X8}")
            };
        }
        finally
        {
            Marshal.FreeHGlobal(fileInfoPtr);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pUnion;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        [MarshalAs(UnmanagedType.LPWStr)] public string? pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
    }

    [DllImport("wintrust.dll", EntryPoint = "WinVerifyTrust", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int WinVerifyTrustNative(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);
}
