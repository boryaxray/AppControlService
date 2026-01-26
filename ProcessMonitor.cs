using ApplicationControlService.Models;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;

namespace ApplicationControlService
{
    public class ProcessMonitor : IDisposable
    {
        private Timer _monitorTimer;
        private Timer _configReloadTimer;
        private HashSet<string> _allowedHashes;
        private Dictionary<int, VerifiedProcessEntry> _verifiedProcesses;
        private int _currentProcessId;
        private string _serviceHash;
        private ServiceConfiguration _config;
        private volatile bool _shutdown;
        private readonly string _configPath;
        private readonly string _logPath;
        private readonly string _detailedLogPath;
        private readonly string _serviceLogPath;
        private readonly string _terminationsLogPath;
        public event Action<Exception> OnFatalError;
        private bool _isRunning = false;
        private readonly object _lock = new object();
        class VerifiedProcessEntry
        {
            public int ProcessId;
            public string FilePath;
            public string Hash;
            public DateTime FileLastWriteUtc;
            public DateTime VerifiedAtUtc;
        }
        // FileSystemWatcher для отслеживания изменений конфигурационного файла
        private FileSystemWatcher _configWatcher;
        private DateTime _lastConfigModified = DateTime.MinValue;

        private static readonly HashSet<string> NEVER_TERMINATE = new HashSet<string>
{
                // Системные процессы
                "System", "Idle", "Registry", "Memory Compression", "Secure System",
                "smss", "csrss", "wininit", "lsass", "services", "winlogon",
                "svchost", "svchost.exe", "dllhost", "taskhostw", "taskhost",
                "fontdrvhost", "dwm", "logonui", "ctfmon", "sihost",
                "MsMpEng", "SecurityHealthService", "NisSrv", "Sense",
                "AvastSvc", "McSvHost", "bdagent", "vsserv",
                "ServiceHub.IdentityHost", "ServiceHub.IdentityHost.exe",
                "ServiceHub", "ServiceHub.*",
                "WindowsTerminal", "WindowsTerminal.exe", "wt.exe",
                "explorer.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
                "Code.exe", "devenv.exe", "VisualStudio.exe",
                "notepad.exe", "calc.exe", "regedit.exe", "control.exe", "taskmgr.exe",
                "mspaint.exe", "wordpad.exe", "write.exe",
                "WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE",
                "SearchUI.exe", "StartMenuExperienceHost.exe", "ShellExperienceHost.exe"
};
        public ProcessMonitor() : this(new ServiceConfiguration())
        {
        }

        public ProcessMonitor(ServiceConfiguration config = null)
        {
            _config = config ?? new ServiceConfiguration();

            _configPath = Path.Combine(_config.WhiteListDirectory, "config.json");

            _logPath = Path.Combine(_config.LogsDirectory, "service.log");
            _detailedLogPath = Path.Combine(_config.LogsDirectory, "detailed.log");
            _serviceLogPath = Path.Combine(_config.LogsDirectory, "service.log");
            _terminationsLogPath = Path.Combine(_config.LogsDirectory, "terminations.log");

            _currentProcessId = Process.GetCurrentProcess().Id;
            _verifiedProcesses = new Dictionary<int, VerifiedProcessEntry>(); // ИЗМЕНЕНИЕ: Вернули правильный тип
            _allowedHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // Логируем пути
            WriteServiceLog($"Конфиг: {_configPath}");
            WriteServiceLog($"Логи: {_config.LogsDirectory}");
            WriteServiceLog($"Белый список: {_config.WhiteListDirectory}");
        }
        private void Fatal(Exception ex, string source)
        {
            WriteServiceLog($"FATAL [{source}]: {ex}");
            OnFatalError?.Invoke(ex);
            Environment.FailFast(source, ex);
        }


        private void ConfigWatcher_Changed(object sender, FileSystemEventArgs e)
        {
            try
            {
                // Задержка для предотвращения многократных вызовов
                Thread.Sleep(1000);

                lock (_lock)
                {
                    if (File.Exists(_configPath))
                    {
                        var lastWriteTime = File.GetLastWriteTime(_configPath);

                        // Проверяем, действительно ли файл изменился
                        if (lastWriteTime > _lastConfigModified.AddSeconds(1))
                        {
                            WriteServiceLog($"Обнаружено изменение конфигурационного файла");
                            LoadConfiguration();
                            _lastConfigModified = lastWriteTime;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                WriteServiceLog($"Ошибка обработки изменения конфига: {ex.Message}");
            }
        }

        public void Start()
        {
            lock (_lock)
            {
                if (_isRunning)
                    return;

                try
                {
                    WriteServiceLog("Запуск монитора процессов");

                    InitializeDirectories();

                    // Получаем хэш текущей службы
                    string currentPath = Process.GetCurrentProcess().MainModule.FileName;
                    _serviceHash = CalculateSHA256(currentPath);
                    WriteServiceLog($"Хэш службы: {_serviceHash.Substring(0, 16)}...");

                    LoadConfiguration();

                    // Добавляем службу в белый список
                    if (!_allowedHashes.Contains(_serviceHash))
                    {
                        _allowedHashes.Add(_serviceHash);
                        WriteServiceLog("Служба добавлена в белый список");
                    }

                    // Запускаем таймер мониторинга процессов
                    _monitorTimer = new Timer(CheckProcessesCallback, null, 5000, 5000);

                    // Запускаем таймер проверки конфигурации (каждые 30 секунд)
                    _configReloadTimer = new Timer(CheckConfigReloadCallback, null, 30000, 30000);
                    _configWatcher = new FileSystemWatcher(
                                    Path.GetDirectoryName(_configPath),
                                    Path.GetFileName(_configPath)
                                );

                    _configWatcher.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size;
                    _configWatcher.Changed += ConfigWatcher_Changed;
                    _configWatcher.EnableRaisingEvents = true;
                    _isRunning = true;
                    WriteServiceLog("Монитор процессов запущен");
                }
                catch (Exception ex)
                {
                    WriteServiceLog($"Ошибка запуска: {ex.Message}");
                    Fatal(ex, "Start");
                    throw;
                }
            }
        }

        public void Stop()
        {
            lock (_lock)
            {
                if (!_isRunning)
                    return;

                WriteServiceLog("Остановка");

                _shutdown = true;

                _monitorTimer?.Dispose();
                _monitorTimer = null;

                _configReloadTimer?.Dispose();
                _configReloadTimer = null;

                _configWatcher?.Dispose();
                _configWatcher = null;

                _verifiedProcesses.Clear();
                _isRunning = false;
            }
        }

        private void InitializeDirectories()
        {
            try
            {
                // Создаем директории для логов
                string logsDir = Path.GetDirectoryName(_serviceLogPath);
                if (!Directory.Exists(logsDir))
                {
                    Directory.CreateDirectory(logsDir);
                    WriteServiceLog($"Создана директория для логов: {logsDir}");
                }

                // Создаем директорию для белого списка
                string whiteListDir = Path.GetDirectoryName(_configPath);
                if (!Directory.Exists(whiteListDir))
                {
                    Directory.CreateDirectory(whiteListDir);
                    WriteServiceLog($"Создана директория для белого списка: {whiteListDir}");
                }
            }
            catch (Exception ex)
            {
                WriteServiceLog($"Ошибка создания директорий: {ex.Message}");
            }
        }

        private void CheckConfigReloadCallback(object state)
        {
            try
            {
                if (_shutdown)
                    return;
                lock (_lock)
                {
                    if (File.Exists(_configPath))
                    {
                        var lastWriteTime = File.GetLastWriteTime(_configPath);
                        if (lastWriteTime > _lastConfigModified)
                        {
                            WriteServiceLog("Проверка обновления конфигурации...");
                            LoadConfiguration();
                            _lastConfigModified = lastWriteTime;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                WriteServiceLog($"Ошибка проверки конфигурации: {ex.Message}");
                Fatal(ex, "CheckConfigReloadCallback");
            }
        }

        private void LoadConfiguration()
        {
            try
            {
                WriteServiceLog($"Загрузка конфигурации из: {_configPath}");

                if (!File.Exists(_configPath))
                {
                    WriteServiceLog($"Конфиг не найден, создаём новый: {_configPath}");
                    CreateDefaultConfiguration();
                    return;
                }

                try
                {
                    string json = File.ReadAllText(_configPath, Encoding.UTF8);
                    json = json.Trim(new char[] { '\uFEFF', '\u200B' }).Trim();

                    if (string.IsNullOrEmpty(json) || json == "[]" || json == "{}")
                    {
                        WriteServiceLog("Конфиг пустой, создаём новый");
                        CreateDefaultConfiguration();
                        return;
                    }

                    using (MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(json)))
                    {
                        DataContractJsonSerializer serializer = new DataContractJsonSerializer(
                            typeof(List<WhiteListItem>),
                            new DataContractJsonSerializerSettings
                            {
                                UseSimpleDictionaryFormat = true,
                                EmitTypeInformation = System.Runtime.Serialization.EmitTypeInformation.Never
                            }
                        );

                        var items = (List<WhiteListItem>)serializer.ReadObject(ms) ?? new List<WhiteListItem>();

                        var validItems = items.Where(i => i.IsValid()).ToList();

                        _allowedHashes = new HashSet<string>(
                            validItems.Select(i => i.Hash),
                            StringComparer.OrdinalIgnoreCase);

                        WriteServiceLog($"Загружено {validItems.Count} приложений из белого списка");
                    }
                }
                catch (Exception ex)
                {
                    // ИЗМЕНЕНИЕ: Не создаем новый конфиг при ошибке парсинга
                    WriteServiceLog($"Ошибка парсинга конфига: {ex.Message}. Используется пустой список.");
                    _allowedHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                    // Только логируем ошибку, но не перезаписываем файл
                    WriteServiceLog($"Файл конфигурации поврежден. Пожалуйста, исправьте его вручную: {_configPath}");
                }
            }
            catch (Exception ex)
            {
                WriteServiceLog($"Ошибка загрузки конфигурации: {ex.Message}");
                _allowedHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                Fatal(ex, "LoadConfiguration");
            }
        }

        private void CreateDefaultConfiguration()
        {
            try
            {
                // ИЗМЕНЕНИЕ: Проверяем, существует ли уже файл
                if (File.Exists(_configPath))
                {
                    WriteServiceLog($"Конфиг уже существует: {_configPath}");
                    return;
                }

                WriteServiceLog($"Создание конфига по умолчанию: {_configPath}");

                var defaultApps = new List<WhiteListItem>();

                string[] safeSystemPaths = {
            @"C:\Windows\explorer.exe",
            @"C:\Windows\System32\cmd.exe",
            @"C:\Windows\System32\notepad.exe",
            @"C:\Windows\System32\calc.exe",
            @"C:\Windows\System32\regedit.exe"
        };

                foreach (var path in safeSystemPaths)
                {
                    try
                    {
                        if (File.Exists(path))
                        {
                            string hash = CalculateSHA256(path);
                            if (!string.IsNullOrEmpty(hash))
                            {
                                defaultApps.Add(new WhiteListItem(
                                    Path.GetFileNameWithoutExtension(path),
                                    hash
                                ));
                                WriteServiceLog($"Добавлено: {Path.GetFileNameWithoutExtension(path)}");
                            }
                        }
                    }
                    catch { }
                }

                // Создаём директорию если не существует
                string configDir = Path.GetDirectoryName(_configPath);
                if (!Directory.Exists(configDir))
                {
                    Directory.CreateDirectory(configDir);
                    WriteServiceLog($"Создана директория: {configDir}");
                }

                // Сохраняем конфиг ТОЛЬКО если его не было
                if (!File.Exists(_configPath))
                {
                    SaveConfigurationFile(defaultApps);
                }

                _allowedHashes = new HashSet<string>(
                    defaultApps.Select(i => i.Hash),
                    StringComparer.OrdinalIgnoreCase);

                WriteServiceLog($"Создан конфиг с {defaultApps.Count} приложениями");
            }
            catch (Exception ex)
            {
                WriteServiceLog($"Ошибка создания конфигурации: {ex.Message}");
            }
        }
        private void SaveConfigurationFile(List<WhiteListItem> items)
        {
            try
            {
                // ИЗМЕНЕНИЕ: Проверяем, существует ли файл
                if (File.Exists(_configPath))
                {
                    WriteServiceLog($"Файл конфигурации уже существует, не перезаписываем: {_configPath}");
                    return;
                }

                using (MemoryStream ms = new MemoryStream())
                {
                    DataContractJsonSerializer serializer = new DataContractJsonSerializer(
                        typeof(List<WhiteListItem>),
                        new DataContractJsonSerializerSettings
                        {
                            UseSimpleDictionaryFormat = true,
                            EmitTypeInformation = System.Runtime.Serialization.EmitTypeInformation.Never
                        }
                    );

                    serializer.WriteObject(ms, items);
                    ms.Position = 0;

                    string json = Encoding.UTF8.GetString(ms.ToArray());

                    // Простое форматирование
                    json = json.Replace("{\"", "{\n  \"")
                              .Replace(",\"", ",\n  \"")
                              .Replace("}]", "}\n]")
                              .Replace("},{", "},\n  {");

                    File.WriteAllText(_configPath, json, Encoding.UTF8);
                    WriteServiceLog($"Конфигурация сохранена: {_configPath}");
                }
            }
            catch (Exception ex)
            {
                WriteServiceLog($"Ошибка сохранения конфига: {ex.Message}");
            }
        }
        private void CheckProcessesCallback(object state)
        {
            try
            {
                if (_shutdown)
                    return;

                Process[] processes = Process.GetProcesses();
                int total = processes.Length;
                int checkedCount = 0;
                int terminatedCount = 0;
                int skippedCount = 0;
                int protectedCount = 0;

                foreach (var process in processes)
                {
                    checkedCount++;

                    try
                    {
                        lock (_lock)
                        {
                            // Проверяем кэш
                            if (_verifiedProcesses.TryGetValue(process.Id, out var cached))
                            {
                                // PID тот же, но файл мог измениться
                                DateTime lastWrite;
                                try
                                {
                                    lastWrite = File.GetLastWriteTimeUtc(cached.FilePath);
                                }
                                catch
                                {
                                    // Если файл удален или недоступен, сбрасываем кэш
                                    _verifiedProcesses.Remove(process.Id);
                                    continue;
                                }

                                if (cached.FileLastWriteUtc == lastWrite)
                                {
                                    // Файл не менялся → доверяем кешу
                                    continue;
                                }

                                // Файл изменился → сбрасываем кеш
                                _verifiedProcesses.Remove(process.Id);
                            }
                        }

                        // Пропускаем себя
                        if (process.Id == _currentProcessId)
                            continue;

                        // Получаем расширенную информацию через WinAPI
                        var processInfo = WinApiHelper.GetExtendedProcessInfo(process.Id);

                        // Проверяем, можно ли завершать этот процесс
                        if (!CanTerminateProcess(process, processInfo))
                        {
                            if (processInfo.Type == WinApiHelper.ProcessType.SystemCritical ||
                                processInfo.Type == WinApiHelper.ProcessType.SystemService)
                            {
                                protectedCount++;
                            }
                            else
                            {
                                skippedCount++;
                            }
                            continue;
                        }

                        // Получаем путь к файлу
                        string filePath = processInfo.FilePath;
                        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                        {
                            // Пытаемся получить путь стандартным способом
                            try
                            {
                                filePath = process.MainModule?.FileName;
                            }
                            catch
                            {
                                // Нет доступа к MainModule
                            }

                            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                            {
                                skippedCount++;
                                continue;
                            }
                        }

                        // Вычисляем хэш
                        string hash = CalculateSHA256(filePath);
                        if (string.IsNullOrEmpty(hash))
                        {
                            skippedCount++;
                            continue;
                        }

                        // Проверяем, разрешен ли процесс
                        bool isAllowed = _allowedHashes.Contains(hash);

                        // Логируем детали
                        WriteDetailedLog(processInfo, hash, isAllowed);

                        // Кэшируем проверенный процесс
                        lock (_lock)
                        {
                            _verifiedProcesses[process.Id] = new VerifiedProcessEntry
                            {
                                ProcessId = process.Id,
                                FilePath = filePath,
                                Hash = hash,
                                FileLastWriteUtc = File.GetLastWriteTimeUtc(filePath),
                                VerifiedAtUtc = DateTime.UtcNow
                            };
                        }

                        if (!isAllowed && processInfo.Type == WinApiHelper.ProcessType.UserApplication)
                        {
                            // Пытаемся завершить только пользовательские приложения
                            try
                            {
                                bool terminated = TryTerminateProcess(process, processInfo);

                                if (terminated)
                                {
                                    terminatedCount++;
                                    WriteTerminationLog(processInfo);
                                    WriteDetailedLogResult(processInfo, true);

                                    // Удаляем из кэша, так как процесс завершен
                                    lock (_lock)
                                    {
                                        _verifiedProcesses.Remove(process.Id);
                                    }
                                }
                                else
                                {
                                    WriteDetailedLogResult(processInfo, false);
                                }
                            }
                            catch (Exception killEx)
                            {
                                WriteServiceLog($"Не удалось завершить {processInfo.ProcessName}: {killEx.Message}");
                                WriteDetailedLogResult(processInfo, false);
                            }
                        }
                    }
                    catch (Win32Exception ex) when (ex.NativeErrorCode == 5) // Access denied
                    {
                        // Нет доступа к процессу - пропускаем
                        skippedCount++;
                        continue;
                    }
                    catch (Exception ex)
                    {
                        // Другие ошибки - логируем и пропускаем
                        WriteServiceLog($"Ошибка проверки процесса {process.ProcessName}: {ex.Message}");
                        skippedCount++;
                        continue;
                    }
                }

                // Очистка кэша от завершенных процессов
                CleanVerifiedCache();
            }
            catch (Exception ex)
            {
                WriteServiceLog($"Критическая ошибка в CheckProcessesCallback: {ex}");
                // Не вызываем Fatal, чтобы служба могла восстановиться
            }
        }

        private bool TryTerminateProcess(Process process, WinApiHelper.ExtendedProcessInfo processInfo)
        {
            try
            {
                // Сначала пытаемся закрыть корректно (если есть окно)
                if (process.CloseMainWindow())
                {
                    // Даем время на корректное завершение
                    if (process.WaitForExit(2000))
                    {
                        WriteServiceLog($"Корректно завершен: {processInfo.ProcessName} (PID: {processInfo.ProcessId})");
                        return true;
                    }
                }

                // Если корректное завершение не удалось, принудительно завершаем
                process.Kill();

                // Даем время на завершение
                if (process.WaitForExit(1000))
                {
                    WriteServiceLog($"Принудительно завершен: {processInfo.ProcessName} (PID: {processInfo.ProcessId})");
                    return true;
                }

                // Если процесс все еще жив, пробуем через taskkill
                return TerminateViaTaskKill(processInfo.ProcessId, processInfo.ProcessName);
            }
            catch (Exception ex)
            {
                WriteServiceLog($"Ошибка завершения {processInfo.ProcessName}: {ex.Message}");
                return false;
            }
        }

        private bool TerminateViaTaskKill(int processId, string processName)
        {
            try
            {
                Process taskkill = new Process();
                taskkill.StartInfo.FileName = "taskkill.exe";
                taskkill.StartInfo.Arguments = $"/F /PID {processId}";
                taskkill.StartInfo.UseShellExecute = false;
                taskkill.StartInfo.CreateNoWindow = true;
                taskkill.StartInfo.RedirectStandardOutput = true;
                taskkill.StartInfo.RedirectStandardError = true;

                taskkill.Start();
                taskkill.WaitForExit(3000);

                if (taskkill.ExitCode == 0)
                {
                    WriteServiceLog($"Завершен через taskkill: {processName} (PID: {processId})");
                    return true;
                }
            }
            catch { }

            return false;
        }

        private bool CanTerminateProcess(Process process, WinApiHelper.ExtendedProcessInfo info)
        {
            // Проверка 1: Session 0 = системные службы
            if (info.SessionId == 0)
            {
                return false;
            }

            // Проверка 2: Системные пользователи
            if (!string.IsNullOrEmpty(info.UserName))
            {
                string userNameLower = info.UserName.ToLowerInvariant();
                if (userNameLower.Contains("system") ||
                    userNameLower.Contains("local service") ||
                    userNameLower.Contains("network service"))
                {
                    return false;
                }
            }

            // Проверка 3: Известные системные процессы
            if (NEVER_TERMINATE.Contains(process.ProcessName))
            {
                return false;
            }

            // Проверка 4: По типу процесса из WinAPI
            if (info.Type == WinApiHelper.ProcessType.SystemCritical ||
                info.Type == WinApiHelper.ProcessType.SystemService ||
                info.Type == WinApiHelper.ProcessType.SecurityProcess)
            {
                return false;
            }

            // Проверка 5: Проверка по списку системных процессов
            if (IsKnownSystemProcess(process.ProcessName, info.FilePath))
            {
                return false;
            }

            if (process.Id == Process.GetCurrentProcess().Id)
            {
                return false;
            }

            return true;
        }

        private bool IsKnownSystemProcess(string processName, string filePath)
        {
            string[] knownSystemProcesses = {
        "svchost", "dllhost", "taskhostw", "taskhost", "runtimebroker",
        "smss", "csrss", "wininit", "winlogon", "services", "lsass",
        "spoolsv", "svchost.exe", "dllhost.exe", "taskhostw.exe", "msedgewebview2",
        "ServiceHub.IdentityHost", "ServiceHub.IdentityHost.exe",
        "ServiceHub.Host.CLR.*", "ServiceHub.VSDetouredHost",
        "WindowsTerminal", "WindowsTerminal.exe", "wt.exe",
        "explorer.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
        "notepad.exe", "notepad", "calc.exe", "regedit.exe", "control.exe", "taskmgr.exe",
        "mspaint.exe", "wordpad.exe", "write.exe",
        "msedge.exe", "chrome.exe", "firefox.exe",
        "SearchUI.exe", "StartMenuExperienceHost.exe", "ShellExperienceHost.exe",
        "ApplicationFrameHost.exe", "RuntimeBroker.exe","OpenConsole","OpenConsole.exe","VBCSCompiler.exe","VBCSCompiler"
    };

            foreach (var sysProc in knownSystemProcesses)
            {
                if (processName.Equals(sysProc, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        private void CleanVerifiedCache()
        {
            try
            {
                lock (_lock)
                {
                    var toRemove = new List<int>();

                    foreach (var kvp in _verifiedProcesses)
                    {
                        try
                        {
                            Process.GetProcessById(kvp.Key);
                        }
                        catch
                        {
                            toRemove.Add(kvp.Key);
                        }
                    }

                    foreach (var pid in toRemove)
                    {
                        _verifiedProcesses.Remove(pid);
                    }
                }
            }
            catch { }
        }

        private void WriteTerminationLog(WinApiHelper.ExtendedProcessInfo processInfo)
        {
            try
            {
                string logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {processInfo}";
                File.AppendAllText(_terminationsLogPath, logEntry + Environment.NewLine);

                WriteServiceLog($"Завершен: {processInfo.ProcessName} (PID: {processInfo.ProcessId}, User: {processInfo.UserName})");
            }
            catch { }
        }

        private void WriteDetailedLog(WinApiHelper.ExtendedProcessInfo processInfo, string hash, bool isAllowed)
        {
            try
            {

                // Создаем директорию если не существует
                string logDir = Path.GetDirectoryName(_detailedLogPath);
                if (!Directory.Exists(logDir))
                {
                    Directory.CreateDirectory(logDir);
                }

                // Создаем файл если не существует
                if (!File.Exists(_detailedLogPath))
                {
                    File.WriteAllText(_detailedLogPath,
                        $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] Файл детальных логов создан\n");
                }

                string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
                string status = isAllowed ? "ALLOWED" : "BLOCKED";
                string shortHash = hash.Length >= 12 ? hash.Substring(0, 12) + "..." : hash;
                string fileName = Path.GetFileName(processInfo.FilePath);
                string directory = Path.GetDirectoryName(processInfo.FilePath);

                if (string.IsNullOrEmpty(fileName))
                    fileName = "Unknown";

                if (string.IsNullOrEmpty(directory))
                    directory = "Unknown";

                // Формируем лог
                string logEntry = $"[{timestamp}] [{status}] {processInfo.ProcessName,-25} " +
                                 $"PID:{processInfo.ProcessId:00000} | " +
                                 $"User:{processInfo.UserName,-20} | " +
                                 $"Type:{processInfo.Type,-15} | " +
                                 $"File:{fileName,-30} | " +
                                 $"Hash:{shortHash}\n";

                File.AppendAllText(_detailedLogPath, logEntry, Encoding.UTF8);

                // Также пишем в компактный лог
                string compactLogPath = Path.Combine(_config.LogsDirectory, "compact.log");
                if (!File.Exists(compactLogPath))
                    File.WriteAllText(compactLogPath,
                        $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] Файл компактных логов создан\n");

                string compactEntry = $"[{timestamp}] {processInfo.ProcessName} - {status}\n";
                File.AppendAllText(compactLogPath, compactEntry, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                // Если не удалось записать в файл, пишем в службу
                WriteServiceLog($"Ошибка записи детального лога: {ex.Message}");
            }
        }
        private void WriteDetailedLogResult(WinApiHelper.ExtendedProcessInfo processInfo, bool terminated)
        {
            try
            {
                string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
                string result = terminated ? "ЗАВЕРШЕН" : "ОШИБКА";

                string logEntry = $"[{timestamp}] [{result}] {processInfo.ProcessName} (PID: {processInfo.ProcessId})";
                File.AppendAllText(_detailedLogPath, logEntry + Environment.NewLine);
            }
            catch { }
        }


        private void WriteServiceLog(string message)
        {
            try
            {
                string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
                string logEntry = $"[{timestamp}] {message}\n";

                // Записываем в файл service.log
                if (!File.Exists(_serviceLogPath))
                {
                    string logDir = Path.GetDirectoryName(_serviceLogPath);
                    if (!Directory.Exists(logDir))
                        Directory.CreateDirectory(logDir);

                    File.WriteAllText(_serviceLogPath,
                        $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] Файл логов службы создан\n");
                }

                File.AppendAllText(_serviceLogPath, logEntry, Encoding.UTF8);

                // Также пишем в EventLog
                EventLog.WriteEntry("AppControlService", message, EventLogEntryType.Information);
            }
            catch
            {
                // Если всё падает, пытаемся записать хотя бы в EventLog
                try
                {
                    EventLog.WriteEntry("AppControlService", message, EventLogEntryType.Information);
                }
                catch { }
            }
        }
        public string CalculateSHA256(string filePath)
        {
            try
            {
                using (SHA256 sha256 = SHA256.Create())
                using (FileStream stream = File.OpenRead(filePath))
                {
                    byte[] hash = sha256.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
            catch (Exception ex)
            {
                WriteServiceLog($"Ошибка вычисления хэша для {filePath}: {ex.Message}");
                return string.Empty;
            }
        }

        public string GetLogPath()
        {
            return _serviceLogPath;
        }

        public MonitoringStatistics GetStatistics()
        {
            lock (_lock)
            {
                return new MonitoringStatistics
                {
                    IsRunning = _isRunning,
                    AllowedApplicationsCount = _allowedHashes.Count,
                    VerifiedProcessesCount = _verifiedProcesses.Count,
                    ServiceHash = _serviceHash?.Substring(0, 16) + "...",
                    LogsDirectory = Path.GetDirectoryName(_serviceLogPath),
                    WhiteListDirectory = Path.GetDirectoryName(_configPath)
                };
            }
        }

        public void Dispose()
        {
            Stop();
            _monitorTimer?.Dispose();
            _configReloadTimer?.Dispose();
            _configWatcher?.Dispose();
        }
    }

    public class MonitoringStatistics
    {
        public bool IsRunning { get; set; }
        public int AllowedApplicationsCount { get; set; }
        public int VerifiedProcessesCount { get; set; }
        public string ServiceHash { get; set; } = string.Empty;
        public string LogsDirectory { get; set; } = string.Empty;
        public string WhiteListDirectory { get; set; } = string.Empty;

        public override string ToString()
        {
            return $"Статус: {(IsRunning ? "Активен" : "Остановлен")}, " +
                   $"Разрешено: {AllowedApplicationsCount}, " +
                   $"Проверено: {VerifiedProcessesCount}, " +
                   $"Логи: {LogsDirectory}, " +
                   $"Белый список: {WhiteListDirectory}";
        }
    }
}