namespace SystemFileKiller.Core;

/// <summary>
/// Wire format shared by <see cref="PipeClient"/> and the SystemFileKiller.Service pipe server.
/// Newline-delimited JSON, one request → one response per connection.
/// </summary>
public class PipeRequest
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Cmd { get; set; } = "";
    public int? Pid { get; set; }
    public string? Name { get; set; }
    public bool KillTree { get; set; }
}

public class PipeResponse
{
    public string Id { get; set; } = "";
    public bool Ok { get; set; }
    public string? Result { get; set; }
    public string? Error { get; set; }
}

public static class PipeProtocol
{
    public const string PipeName = "sfk";

    public static class Commands
    {
        public const string Ping = "ping";
        public const string KillProcess = "kill_process";
        public const string StopService = "stop_service";
    }
}
