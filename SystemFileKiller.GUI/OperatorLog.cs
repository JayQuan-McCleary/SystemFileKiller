using System;
using System.Collections.Generic;

namespace SystemFileKiller.GUI;

/// <summary>
/// Process-wide event log for operator actions. Every view's OnAction callback funnels into here
/// via MainWindow.SetStatus, and the Dashboard subscribes to render the "Recent operations" console.
/// In-memory only — capped at 200 entries.
/// </summary>
public static class OperatorLog
{
    public enum Kind { Info, Ok, Warn, Err }

    public sealed class Entry
    {
        public DateTime Timestamp { get; init; }
        public Kind Kind { get; init; }
        public string Text { get; init; } = "";
    }

    private const int MaxEntries = 200;
    private static readonly LinkedList<Entry> _entries = new();
    private static readonly object _lock = new();

    public static event Action<Entry>? Appended;

    public static IReadOnlyList<Entry> Snapshot()
    {
        lock (_lock)
        {
            return _entries.ToArray();
        }
    }

    public static void Append(Kind kind, string text)
    {
        var e = new Entry { Timestamp = DateTime.Now, Kind = kind, Text = text };
        lock (_lock)
        {
            _entries.AddLast(e);
            while (_entries.Count > MaxEntries) _entries.RemoveFirst();
        }
        Appended?.Invoke(e);
    }

    /// <summary>Heuristic kind classifier — looks at the action string to pick a level.</summary>
    public static Kind Classify(string text)
    {
        var t = text.ToLowerInvariant();
        if (t.Contains("error") || t.Contains("fail") || t.Contains("denied") || t.StartsWith("err ")) return Kind.Err;
        if (t.Contains("warn") || t.Contains("suspicious") || t.Contains("flagged")) return Kind.Warn;
        if (t.Contains("ok") || t.Contains("success") || t.Contains("→") || t.Contains("killed")
            || t.Contains("removed") || t.Contains("stopped")) return Kind.Ok;
        return Kind.Info;
    }
}
