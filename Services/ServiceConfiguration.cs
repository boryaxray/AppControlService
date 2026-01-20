using System.IO;

public class ServiceConfiguration
{
    // Раздельные пути
    public string LogsDirectory { get; set; }
    public string WhiteListDirectory { get; set; }
    public string ConfigPath { get; set; }
    public string DetailedLogPath { get; set; }
    public string ServiceLogPath { get; set; }
    public string TerminationsLogPath { get; set; }

    public ServiceConfiguration()
    {
        LogsDirectory = @"C:\ProgramData\AppControl\Logs";
        WhiteListDirectory = @"C:\ProgramData\AppControl\WhiteList";
        InitializePaths();
        CreateDirectories();
    }

    public ServiceConfiguration(string logsPath, string whiteListPath)
    {
        LogsDirectory = logsPath;
        WhiteListDirectory = whiteListPath;
        InitializePaths();
        CreateDirectories();
    }

    private void InitializePaths()
    {
        ConfigPath = Path.Combine(WhiteListDirectory, "config.json");
        DetailedLogPath = Path.Combine(LogsDirectory, "detailed.log");
        ServiceLogPath = Path.Combine(LogsDirectory, "service.log");
        TerminationsLogPath = Path.Combine(LogsDirectory, "terminations.log");
    }

    private void CreateDirectories()
    {
        try
        {
            if (!Directory.Exists(LogsDirectory))
                Directory.CreateDirectory(LogsDirectory);

            if (!Directory.Exists(WhiteListDirectory))
                Directory.CreateDirectory(WhiteListDirectory);
        }
        catch { }
    }
}