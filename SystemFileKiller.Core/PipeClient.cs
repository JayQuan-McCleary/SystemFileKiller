using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace SystemFileKiller.Core;

/// <summary>
/// Client for the LocalSystem helper service. Connects to <c>\\.\pipe\sfk</c>, sends a
/// newline-delimited JSON <see cref="PipeRequest"/>, reads one <see cref="PipeResponse"/>, disconnects.
/// </summary>
public static class PipeClient
{
    /// <summary>
    /// True if the service is reachable and responds to a ping. Cheap probe — used as a gate
    /// before falling through to UAC elevation.
    /// </summary>
    public static bool IsServiceAvailable(int connectTimeoutMs = 500)
    {
        try
        {
            using var client = new NamedPipeClientStream(
                ".", PipeProtocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect(connectTimeoutMs);
            using var cts = new CancellationTokenSource(1000);
            var resp = SendOnStreamAsync(client, new PipeRequest { Cmd = PipeProtocol.Commands.Ping }, cts.Token)
                .GetAwaiter().GetResult();
            return resp.Ok;
        }
        catch
        {
            return false;
        }
    }

    public static PipeResponse Send(PipeRequest req, int timeoutMs = 5000)
    {
        try
        {
            using var client = new NamedPipeClientStream(
                ".", PipeProtocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect(Math.Min(timeoutMs, 2000));
            using var cts = new CancellationTokenSource(timeoutMs);
            return SendOnStreamAsync(client, req, cts.Token).GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
            return new PipeResponse { Id = req.Id, Ok = false, Error = "Pipe operation timed out" };
        }
        catch (Exception ex)
        {
            return new PipeResponse { Id = req.Id, Ok = false, Error = ex.Message };
        }
    }

    private static async Task<PipeResponse> SendOnStreamAsync(
        NamedPipeClientStream client, PipeRequest req, CancellationToken ct)
    {
        // ConfigureAwait(false) on every await — callers may use
        // `.GetAwaiter().GetResult()` from a UI thread; without this the continuation
        // deadlocks waiting for the UI thread that's blocked on GetResult.
        var json = JsonSerializer.Serialize(req);
        var bytes = Encoding.UTF8.GetBytes(json + "\n");
        await client.WriteAsync(bytes, ct).ConfigureAwait(false);
        await client.FlushAsync(ct).ConfigureAwait(false);

        using var ms = new MemoryStream();
        var buf = new byte[4096];
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            int n = await client.ReadAsync(buf, ct).ConfigureAwait(false);
            if (n == 0) break;
            ms.Write(buf, 0, n);
            var data = ms.GetBuffer();
            // Scan only the bytes actually written
            for (int i = 0; i < ms.Length; i++)
                if (data[i] == (byte)'\n') return Parse(ms.ToArray(), req.Id);
        }
        return Parse(ms.ToArray(), req.Id);
    }

    private static PipeResponse Parse(byte[] data, string fallbackId)
    {
        var s = Encoding.UTF8.GetString(data).TrimEnd('\n', '\r', '\0');
        if (string.IsNullOrEmpty(s))
            return new PipeResponse { Id = fallbackId, Ok = false, Error = "Empty response" };
        try
        {
            return JsonSerializer.Deserialize<PipeResponse>(s)
                   ?? new PipeResponse { Id = fallbackId, Ok = false, Error = "Null deserialization" };
        }
        catch (Exception ex)
        {
            return new PipeResponse { Id = fallbackId, Ok = false, Error = $"Bad response: {ex.Message}" };
        }
    }
}
