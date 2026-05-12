using System.IO.Compression;
using System.Text.Json;

namespace SystemFileKiller.Core;

public record QuarantineItem(
    string Id,
    string OriginalPath,
    DateTime QuarantinedAt,
    long OriginalSizeBytes,
    string ArchivePath,
    bool WasDirectory);

public enum QuarantineResult
{
    Success,
    NotFound,
    AccessDenied,
    Failed
}

/// <summary>
/// Reversible delete. Zips the target into <c>%ProgramData%\SFK\Quarantine\&lt;timestamp&gt;_&lt;guid&gt;\</c>
/// with a sidecar metadata.json, then removes the original. Restore extracts back to the original
/// path; Purge deletes the archive permanently. Lets an AI cleanup workflow stage destructive
/// operations and roll back if something breaks.
/// </summary>
public static class QuarantineManager
{
    private static readonly string QuarantineRoot = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "SFK", "Quarantine");

    public static List<QuarantineItem> ListItems()
    {
        var items = new List<QuarantineItem>();
        if (!Directory.Exists(QuarantineRoot)) return items;

        foreach (var dir in Directory.EnumerateDirectories(QuarantineRoot))
        {
            var metaPath = Path.Combine(dir, "metadata.json");
            if (!File.Exists(metaPath)) continue;
            try
            {
                var item = JsonSerializer.Deserialize<QuarantineItem>(File.ReadAllText(metaPath));
                if (item is not null) items.Add(item);
            }
            catch { /* skip corrupt entries */ }
        }
        return items.OrderByDescending(i => i.QuarantinedAt).ToList();
    }

    public static (QuarantineResult Result, string Message, QuarantineItem? Item) Quarantine(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return (QuarantineResult.NotFound, "empty path", null);
        var full = Path.GetFullPath(path);
        bool isDir = Directory.Exists(full);
        bool isFile = !isDir && File.Exists(full);
        if (!isDir && !isFile) return (QuarantineResult.NotFound, $"not found: {full}", null);

        try
        {
            Directory.CreateDirectory(QuarantineRoot);
            var id = $"{DateTime.UtcNow:yyyyMMdd-HHmmss}_{Guid.NewGuid():N}";
            var bucket = Path.Combine(QuarantineRoot, id);
            Directory.CreateDirectory(bucket);
            var archive = Path.Combine(bucket, "content.zip");

            long size = 0;
            using (var zip = ZipFile.Open(archive, ZipArchiveMode.Create))
            {
                if (isDir)
                {
                    foreach (var f in Directory.EnumerateFiles(full, "*", new EnumerationOptions
                    {
                        IgnoreInaccessible = true,
                        RecurseSubdirectories = true,
                        AttributesToSkip = 0
                    }))
                    {
                        try
                        {
                            var rel = Path.GetRelativePath(full, f);
                            zip.CreateEntryFromFile(f, rel, CompressionLevel.Fastest);
                            size += new FileInfo(f).Length;
                        }
                        catch { /* skip per-file failures, continue archive */ }
                    }
                }
                else
                {
                    zip.CreateEntryFromFile(full, Path.GetFileName(full), CompressionLevel.Optimal);
                    size = new FileInfo(full).Length;
                }
            }

            var item = new QuarantineItem(
                Id: id,
                OriginalPath: full,
                QuarantinedAt: DateTime.UtcNow,
                OriginalSizeBytes: size,
                ArchivePath: archive,
                WasDirectory: isDir);
            File.WriteAllText(Path.Combine(bucket, "metadata.json"),
                JsonSerializer.Serialize(item, new JsonSerializerOptions { WriteIndented = true }));

            // Now remove the original. Use the full FileDestroyer escalation so locked files still go.
            if (isDir)
            {
                var (r, m) = FileDestroyer.ForceDeleteDirectory(full);
                if (r != DeleteResult.Success && r != DeleteResult.ScheduledForReboot)
                {
                    return (QuarantineResult.Failed, $"archived ok but delete failed: {m}", item);
                }
            }
            else
            {
                var (r, m) = FileDestroyer.ForceDelete(full);
                if (r != DeleteResult.Success && r != DeleteResult.ScheduledForReboot)
                {
                    return (QuarantineResult.Failed, $"archived ok but delete failed: {m}", item);
                }
            }
            return (QuarantineResult.Success, $"quarantined {(isDir ? "dir" : "file")}: {full} → {id}", item);
        }
        catch (UnauthorizedAccessException) { return (QuarantineResult.AccessDenied, "access denied", null); }
        catch (Exception ex) { return (QuarantineResult.Failed, ex.Message, null); }
    }

    public static (QuarantineResult Result, string Message) Restore(string id)
    {
        var bucket = Path.Combine(QuarantineRoot, id);
        if (!Directory.Exists(bucket)) return (QuarantineResult.NotFound, $"no such id: {id}");
        var metaPath = Path.Combine(bucket, "metadata.json");
        if (!File.Exists(metaPath)) return (QuarantineResult.Failed, "metadata missing");
        try
        {
            var item = JsonSerializer.Deserialize<QuarantineItem>(File.ReadAllText(metaPath))!;
            if (item.WasDirectory)
            {
                Directory.CreateDirectory(item.OriginalPath);
                ZipFile.ExtractToDirectory(item.ArchivePath, item.OriginalPath, overwriteFiles: true);
            }
            else
            {
                var parent = Path.GetDirectoryName(item.OriginalPath);
                if (parent is not null) Directory.CreateDirectory(parent);
                using var zip = ZipFile.OpenRead(item.ArchivePath);
                var entry = zip.Entries.FirstOrDefault();
                if (entry is null) return (QuarantineResult.Failed, "empty archive");
                entry.ExtractToFile(item.OriginalPath, overwrite: true);
            }
            return (QuarantineResult.Success, $"restored to {item.OriginalPath}");
        }
        catch (UnauthorizedAccessException) { return (QuarantineResult.AccessDenied, "access denied"); }
        catch (Exception ex) { return (QuarantineResult.Failed, ex.Message); }
    }

    public static (QuarantineResult Result, string Message, int Removed) Purge(int olderThanDays = 0)
    {
        if (!Directory.Exists(QuarantineRoot)) return (QuarantineResult.Success, "nothing to purge", 0);
        int removed = 0;
        var cutoff = DateTime.UtcNow.AddDays(-olderThanDays);
        foreach (var dir in Directory.EnumerateDirectories(QuarantineRoot))
        {
            try
            {
                var metaPath = Path.Combine(dir, "metadata.json");
                if (olderThanDays > 0 && File.Exists(metaPath))
                {
                    var item = JsonSerializer.Deserialize<QuarantineItem>(File.ReadAllText(metaPath));
                    if (item is not null && item.QuarantinedAt > cutoff) continue;
                }
                Directory.Delete(dir, recursive: true);
                removed++;
            }
            catch { /* skip stuck buckets */ }
        }
        return (QuarantineResult.Success, $"purged {removed} bucket(s)", removed);
    }
}
