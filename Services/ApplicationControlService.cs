using System;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;

namespace ApplicationControlService
{
    public class ApplicationControlService : ServiceBase
    {
        private ProcessMonitor _monitor;
        private ServiceConfiguration _config;

        public ApplicationControlService()
        {
            this.ServiceName = "AppControlService";
            this.CanStop = true;
            this.CanPauseAndContinue = false;
            this.AutoLog = false;
        }

        protected override void OnStart(string[] args)
        {
            try
            {
                this.RequestAdditionalTime(60000);
                string logsPath = null;
                string whiteListPath = null;

                // Пытаемся прочитать параметры из аргументов
                if (args.Length >= 2)
                {
                    logsPath = args[0];
                    whiteListPath = args[1];
                }
                else
                {
                    // Если нет аргументов, пробуем прочитать из реестра
                    try
                    {
                        string registryPath = @"SYSTEM\CurrentControlSet\Services\AppControlService\Parameters";
                        using (var baseKey = Microsoft.Win32.Registry.LocalMachine)
                        using (var key = baseKey.OpenSubKey(registryPath))
                        {
                            if (key != null)
                            {
                                logsPath = key.GetValue("LogsPath") as string;
                                whiteListPath = key.GetValue("WhiteListPath") as string;
                            }
                        }
                    }
                    catch { }

                    // Если все еще нет - используем по умолчанию
                    if (string.IsNullOrEmpty(logsPath))
                        logsPath = @"C:\ProgramData\AppControl\Logs";

                    if (string.IsNullOrEmpty(whiteListPath))
                        whiteListPath = @"C:\ProgramData\AppControl\WhiteList";
                }

                LogService($"Путь для логов: {logsPath}");
                LogService($"Путь для белого списка: {whiteListPath}");

                // Создаем конфигурацию с путями
                _config = new ServiceConfiguration(logsPath, whiteListPath);
                _monitor = new ProcessMonitor(_config);
                _monitor.Start();

                LogService("Служба запущена");
            }
            catch (Exception ex)
            {
                LogService($"Ошибка запуска: {ex.Message}\n{ex.StackTrace}");
                throw;
            }
        }

        protected override void OnStop()
        {
            LogService("Остановка службы...");
            _monitor?.Stop();
            _monitor?.Dispose();
            LogService("Служба остановлена");
        }

        private void LogService(string message)
        {
            try
            {
                string logPath = _config?.ServiceLogPath ?? @"C:\ProgramData\AppControl\Logs\service.log";
                string logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}";
                File.AppendAllText(logPath, logEntry + Environment.NewLine);

                EventLog.WriteEntry(ServiceName, message, EventLogEntryType.Information);
            }
            catch { }
        }
    }
}