using System;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Threading;

namespace ApplicationControlService
{
    public class ApplicationControlService : ServiceBase
    {
        private ProcessMonitor _monitor;
        private ServiceConfiguration _config;
        private Timer _healthCheckTimer;
        private Timer _protectionTimer;
        private static bool _allowStop = false;

        public ApplicationControlService()
        {
            this.ServiceName = "AppControlService";
            this.CanStop = true;
            this.CanPauseAndContinue = false;
            this.AutoLog = false;
            this.CanHandlePowerEvent = true;
            this.CanHandleSessionChangeEvent = true;
            ExitCode = -1;
        }

        protected override void OnStart(string[] args)
        {
            try
            {
                this.RequestAdditionalTime(60000);

                string logsPath = null;
                string whiteListPath = null;

                // Сначала проверяем аргументы (если переданы)
                if (args != null && args.Length >= 2)
                {
                    logsPath = args[0];
                    whiteListPath = args[1];
                }

                // Если аргументов нет, читаем из реестра
                if (string.IsNullOrEmpty(logsPath) || string.IsNullOrEmpty(whiteListPath))
                {
                    try
                    {
                        string registryPath = @"SYSTEM\CurrentControlSet\Services\AppControlService\Parameters";
                        using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(registryPath))
                        {
                            if (key != null)
                            {
                                logsPath = key.GetValue("LogsPath") as string;
                                whiteListPath = key.GetValue("WhiteListPath") as string;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        LogService($"Ошибка чтения реестра: {ex.Message}");
                    }
                }

                // Значения по умолчанию
                if (string.IsNullOrEmpty(logsPath))
                    logsPath = @"C:\ProgramData\AppControl\Logs";
                if (string.IsNullOrEmpty(whiteListPath))
                    whiteListPath = @"C:\ProgramData\AppControl\WhiteList";

                // Очищаем пути от кавычек
                logsPath = logsPath?.Trim('"').Trim();
                whiteListPath = whiteListPath?.Trim('"').Trim();

                LogService($"Запуск службы. Логи: {logsPath}, Белый список: {whiteListPath}");

                // Создаем директории если не существуют
                try
                {
                    if (!Directory.Exists(logsPath))
                        Directory.CreateDirectory(logsPath);
                    if (!Directory.Exists(whiteListPath))
                        Directory.CreateDirectory(whiteListPath);
                }
                catch (Exception ex)
                {
                    LogService($"Ошибка создания директорий: {ex.Message}");
                }

                // Создаем конфигурацию
                _config = new ServiceConfiguration(logsPath, whiteListPath);

                // Запускаем монитор
                StartMonitor();

                // Таймер проверки здоровья
                _healthCheckTimer = new Timer(HealthCheckCallback, null,
                    TimeSpan.FromSeconds(30),
                    TimeSpan.FromSeconds(30));

                // Таймер защиты
                _protectionTimer = new Timer(ProtectionCallback, null,
                    TimeSpan.FromSeconds(60),
                    TimeSpan.FromSeconds(60));

                LogService("Служба успешно запущена");
                ExitCode = 0;
            }
            catch (Exception ex)
            {
                LogService($"КРИТИЧЕСКАЯ ОШИБКА ЗАПУСКА: {ex.Message}\n{ex.StackTrace}");
                ExitCode = -1;
                throw;
            }
        }


        private void StartMonitor()
        {
            try
            {
                if (_monitor != null)
                {
                    try { _monitor.Dispose(); } catch { }
                }

                _monitor = new ProcessMonitor(_config);
                _monitor.OnFatalError += ex =>
                {
                    LogService($"КРИТИЧЕСКАЯ ОШИБКА МОНИТОРА: {ex.Message}");

                    Thread.Sleep(5000);
                    try
                    {
                        LogService("Попытка перезапуска монитора...");
                        StartMonitor();
                        LogService("Монитор успешно перезапущен");
                    }
                    catch (Exception restartEx)
                    {
                        LogService($"Не удалось перезапустить монитор: {restartEx.Message}");
                    }
                };

                _monitor.Start();
                LogService("Монитор процессов запущен");
            }
            catch (Exception ex)
            {
                LogService($"Ошибка запуска монитора: {ex.Message}");
                throw;
            }
        }

        private void HealthCheckCallback(object state)
        {
            try
            {
                if (_monitor == null)
                {
                    LogService("Health Check: Монитор не инициализирован, запускаем...");
                    StartMonitor();
                    return;
                }

                var stats = _monitor.GetStatistics();
                if (stats == null || !stats.IsRunning)
                {
                    LogService("Health Check: Монитор остановлен, перезапускаем...");
                    StartMonitor();
                }
            }
            catch (Exception ex)
            {
                LogService($"Health Check ошибка: {ex.Message}");
                try { StartMonitor(); } catch { }
            }
        }

        private void ProtectionCallback(object state)
        {
            try
            {
                // Проверяем статус службы
                CheckServiceStatus();

                // Проверяем монитор
                if (_monitor == null)
                {
                    LogService("Protection: Монитор не работает, восстанавливаем...");
                    StartMonitor();
                }
            }
            catch (Exception ex)
            {
                LogService($"Protection ошибка: {ex.Message}");
            }
        }


        private void CheckRegistryIntegrity()
        {
            try
            {
                string servicePath = @"SYSTEM\CurrentControlSet\Services\AppControlService";

                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(servicePath, true))
                {
                    if (key != null)
                    {
                        // Проверяем тип запуска
                        int start = Convert.ToInt32(key.GetValue("Start", 2));
                        if (start != 2)
                        {
                            LogService($"Внимание: Тип запуска изменен на {start}, восстанавливаем AUTO...");
                            key.SetValue("Start", 2, Microsoft.Win32.RegistryValueKind.DWord);
                        }

                        // Проверяем ErrorControl
                        int errorControl = Convert.ToInt32(key.GetValue("ErrorControl", 1));
                        if (errorControl != 1)
                        {
                            key.SetValue("ErrorControl", 1, Microsoft.Win32.RegistryValueKind.DWord);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogService($"Ошибка проверки реестра: {ex.Message}");
            }
        }

        private void CheckServiceStatus()
        {
            try
            {
                using (var sc = new ServiceController("AppControlService"))
                {
                    if (sc.Status != ServiceControllerStatus.Running)
                    {
                        LogService($"Внимание: Статус службы - {sc.Status}. Запускаем...");
                        sc.Start();
                        sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(15));
                        LogService($"Служба запущена, статус: {sc.Status}");
                    }
                }
            }
            catch (Exception ex)
            {
                LogService($"Ошибка проверки статуса: {ex.Message}");
            }
        }

        protected override void OnStop()
        {
            LogService("Остановка службы...");

            _healthCheckTimer?.Dispose();
            _protectionTimer?.Dispose();
            _monitor?.Stop();
            _monitor?.Dispose();

            LogService("Служба остановлена");
        }

        protected override bool OnPowerEvent(PowerBroadcastStatus powerStatus)
        {
            LogService($"Power event: {powerStatus}");

            if (powerStatus == PowerBroadcastStatus.ResumeSuspend)
            {
                LogService("Выход из сна, проверяем монитор...");
                if (_monitor == null)
                {
                    StartMonitor();
                }
            }

            return base.OnPowerEvent(powerStatus);
        }

        protected override void OnSessionChange(SessionChangeDescription changeDescription)
        {
            LogService($"Session change: {changeDescription.Reason}");
            base.OnSessionChange(changeDescription);
        }

        public static void AllowStop()
        {
            _allowStop = true;
        }

        private void LogService(string message)
        {
            try
            {
                string logPath = _config?.ServiceLogPath ?? @"C:\ProgramData\AppControl\Logs\service.log";
                string logDir = Path.GetDirectoryName(logPath);

                if (!Directory.Exists(logDir))
                    Directory.CreateDirectory(logDir);

                string logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}";
                File.AppendAllText(logPath, logEntry + Environment.NewLine);

                try
                {
                    EventLog.WriteEntry(ServiceName, message, EventLogEntryType.Information);
                }
                catch { }
            }
            catch { }
        }
    }
}