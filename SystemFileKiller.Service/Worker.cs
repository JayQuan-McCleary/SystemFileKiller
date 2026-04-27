using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SystemFileKiller.Core;

namespace SystemFileKiller.Service;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;

    public Worker(ILogger<Worker> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation(
            "SFK Service starting on \\\\.\\pipe\\{Pipe}",
            PipeProtocol.PipeName);

        var server = new PipeServer(_logger);
        try
        {
            await server.RunAsync(stoppingToken);
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown
        }
        finally
        {
            _logger.LogInformation("SFK Service stopped");
        }
    }
}
