using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.ServiceProcess;
using System.Text;
using System.Threading;

namespace ApplicationControlService
{
    static class Program
    {
        static int Main(string[] args)
        {
            // Если это запуск как служба (с параметрами из реестра)
            if (args.Length == 0 || (args.Length > 0 && !args[0].StartsWith("--")))
            {
                // Запуск как служба Windows
                ServiceBase.Run(new ApplicationControlService());
                return 0;
            }

            // Режим отладки
            if (args.Length > 0 && args[0] == "--debug")
            {
                return RunDebugMode(args);
            }

            // Обработка команд установки/удаления
            if (args.Length > 0)
            {
                return ProcessArguments(args);
            }

            return 0;
        }

        static int ProcessArguments(string[] args)
        {
            try
            {
                string command = args[0].ToLower();

                switch (command)
                {
                    case "--install":
                        string logsPath = args.Length > 1 ? args[1] : null;
                        string whiteListPath = args.Length > 2 ? args[2] : null;
                        return InstallService(logsPath, whiteListPath) ? 0 : 1;

                    case "--uninstall":
                        return UninstallService() ? 0 : 1;

                    case "--start":
                        return StartService() ? 0 : 1;

                    case "--stop":
                        return StopService() ? 0 : 1;

                    case "--status":
                        return CheckServiceStatus() ? 0 : 1;

                    default:
                        Console.WriteLine($"Неизвестная команда: {command}");
                        return 1;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка: {ex.Message}");
                return 1;
            }
        }

        static int RunDebugMode(string[] args)
        {
            Console.WriteLine("=== Application Control Service - Debug Mode ===");

            string logsPath = args.Length > 1 ? args[1] : null;
            string whiteListPath = args.Length > 2 ? args[2] : null;

            var config = new ServiceConfiguration(logsPath, whiteListPath);

            Console.WriteLine($"Путь для логов: {config.LogsDirectory}");
            Console.WriteLine($"Путь для белого списка: {config.WhiteListDirectory}");
            Console.WriteLine($"Файл конфигурации: {config.ConfigPath}");
            Console.WriteLine("Press Enter to stop...");

            using (var monitor = new ProcessMonitor(config))
            {
                monitor.Start();

                Console.ReadLine();

                monitor.Stop();
                var stats = monitor.GetStatistics();
                Console.WriteLine($"\nStatistics: {stats}");
            }

            return 0;
        }
        static bool InstallService(string logsPath = null, string whiteListPath = null)
        {
            try
            {
                Console.WriteLine("=== УСТАНОВКА СЛУЖБЫ AppControlService ===");

                if (!IsRunningAsAdministrator())
                {
                    Console.WriteLine("Требуются права администратора!");
                    return RestartAsAdministrator("--install", logsPath ?? "", whiteListPath ?? "");
                }

                string exePath = Assembly.GetExecutingAssembly().Location;
                exePath = exePath.Trim('"');

                // Пути по умолчанию
                if (string.IsNullOrEmpty(logsPath))
                    logsPath = @"C:\ProgramData\AppControl\Logs";
                if (string.IsNullOrEmpty(whiteListPath))
                    whiteListPath = @"C:\ProgramData\AppControl\WhiteList";

                logsPath = logsPath.Trim('"');
                whiteListPath = whiteListPath.Trim('"');

                Console.WriteLine($"\nПараметры установки:");
                Console.WriteLine($"  Файл службы: {exePath}");
                Console.WriteLine($"  Каталог логов: {logsPath}");
                Console.WriteLine($"  Каталог белого списка: {whiteListPath}");

                // Создаем каталоги
                Directory.CreateDirectory(logsPath);
                Directory.CreateDirectory(whiteListPath);
                Console.WriteLine("✓ Каталоги созданы");

                // Создаем пустой конфиг
                string configPath = Path.Combine(whiteListPath, "config.json");
                if (!File.Exists(configPath))
                {
                    File.WriteAllText(configPath, "[]", Encoding.UTF8);
                    Console.WriteLine($"✓ Конфиг создан: {configPath}");
                }

                // Удаляем старую службу
                Console.WriteLine("\n1. Удаление старой службы...");
                try
                {
                    RunSCCommand("stop AppControlService", "остановка");
                    Thread.Sleep(2000);
                }
                catch { }

                try
                {
                    RunSCCommand("delete AppControlService", "удаление");
                    Thread.Sleep(2000);
                }
                catch { }

                // Создаем службу с параметрами
                Console.WriteLine("\n2. Создание службы...");

                // Важно: БЕЗ кавычек для аргументов при создании службы
                string binPath = $"\"{exePath}\"";
                string createCmd = $"create AppControlService binPath= {binPath} start= auto type= own";

                // Добавляем параметры как отдельную команду
                if (!RunSCCommand(createCmd, "создание"))
                {
                    Console.WriteLine("✗ Не удалось создать службу");
                    return false;
                }

                // Сохраняем параметры в реестре ДО запуска службы
                Console.WriteLine("\n3. Сохранение параметров в реестре...");
                try
                {
                    string regPath = @"SYSTEM\CurrentControlSet\Services\AppControlService\Parameters";
                    using (var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(regPath))
                    {
                        key.SetValue("LogsPath", logsPath);
                        key.SetValue("WhiteListPath", whiteListPath);
                        key.SetValue("ImagePath", exePath);
                        Console.WriteLine("✓ Параметры сохранены в реестре");
                    }
                }
                catch (Exception regEx)
                {
                    Console.WriteLine($"⚠ Не удалось сохранить в реестр: {regEx.Message}");
                }

                // Настройка автозапуска
                Console.WriteLine("\n4. Настройка автозапуска...");
                ConfigureAutoStart();

                // Настройка восстановления
                Console.WriteLine("\n5. Настройка самовосстановления...");
                ConfigureRecoveryViaRegistry();

                // Скрываем службу
                Console.WriteLine("\n6. Скрытие службы...");
                HideServiceInRegistry();

                // Запускаем службу
                Console.WriteLine("\n7. Запуск службы...");
                Thread.Sleep(2000);

                if (RunSCCommand("start AppControlService", "запуск"))
                {
                    Console.WriteLine("✓ Служба запущена!");
                    Thread.Sleep(3000);
                    RunSCCommand("query AppControlService", "статус");
                    return true;
                }
                else
                {
                    Console.WriteLine("⚠ Служба создана, но не запущена");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"✗ Критическая ошибка: {ex.Message}");
                return false;
            }
        }

        private static void ConfigureAutoStart()
        {
            try
            {
                string servicePath = @"SYSTEM\CurrentControlSet\Services\AppControlService";

                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(servicePath, true))
                {
                    if (key != null)
                    {
                        // Start = 2 (Automatic)
                        key.SetValue("Start", 2, Microsoft.Win32.RegistryValueKind.DWord);

                        // DelayedAutoStart = 0 (не отложенный)
                        key.SetValue("DelayedAutoStart", 0, Microsoft.Win32.RegistryValueKind.DWord);

                        // ErrorControl = 1 (Normal)
                        key.SetValue("ErrorControl", 1, Microsoft.Win32.RegistryValueKind.DWord);

                        Console.WriteLine("  ✓ Тип запуска: Автоматический");
                    }
                }

                // Дополнительная проверка через sc.exe
                RunSCCommand("config AppControlService start= auto", "настройка автозапуска");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  ⚠ Ошибка настройки автозапуска: {ex.Message}");
            }
        }

        private static void HideServiceInRegistry()
        {
            try
            {
                string servicePath = @"SYSTEM\CurrentControlSet\Services\AppControlService";

                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(servicePath, true))
                {
                    if (key != null)
                    {
                        // Type = 0x10 (Win32OwnProcess) - это стандартный тип, не скрывает
                        // Но оставляем рабочим
                        key.SetValue("Type", 16, Microsoft.Win32.RegistryValueKind.DWord);
                        Console.WriteLine("  ✓ Конфигурация службы сохранена");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  ⚠ Ошибка: {ex.Message}");
            }
        }

        /*private static void ProtectRegistryKey()
        {
            try
            {
                // Устанавливаем права только для SYSTEM
                Process process = new Process();
                process.StartInfo.FileName = "cmd.exe";
                process.StartInfo.Arguments = $"/c icacls \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\AppControlService\" /inheritance:r /grant:r \"SYSTEM:(OI)(CI)F\" /grant:r \"Administrators:(OI)(CI)F\" /deny Everyone:(OI)(CI)WD";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.Verb = "runas";

                process.Start();
                process.WaitForExit(5000);

                Console.WriteLine("  ✓ Права реестра настроены");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  ⚠ Ошибка защиты реестра: {ex.Message}");
            }
        }*/

        // восстановление через реестр
        /* private static void ConfigureRecoveryViaRegistry()
         {
             try
             {
                 string servicePath = @"SYSTEM\CurrentControlSet\Services\AppControlService";

                 using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(servicePath, true))
                 {
                     if (key != null)
                     {
                         // 1. Устанавливаем автоматический запуск (Start = 2)
                         key.SetValue("Start", 2, Microsoft.Win32.RegistryValueKind.DWord);

                         // 2. Устанавливаем ErrorControl = 1 (Normal)
                         // 0 = Ignore, 1 = Normal, 2 = Severe, 3 = Critical
                         key.SetValue("ErrorControl", 1, Microsoft.Win32.RegistryValueKind.DWord);

                         // 3. Структура FailureActions для НЕМЕДЛЕННОГО перезапуска
                         // Формат бинарных данных:
                         // DWORD dwResetPeriod;    // Через сколько сбросить счетчик (сек)
                         // DWORD dwRebootMsg;      // Сообщение при перезагрузке
                         // DWORD dwCommand;        // Команда при сбое
                         // DWORD cActions;         // Количество действий
                         // SC_ACTION actions[];    // Массив действий
                         //   SC_ACTION:
                         //     DWORD Type;          // 0=None, 1=Restart, 2=Reboot, 3=RunCommand
                         //     DWORD Delay;         // Задержка в мс

                         byte[] failureActions = new byte[]
                         {
                     // Version (зарезервировано)
                     0x00, 0x00, 0x00, 0x00,

                     // ResetPeriod: 86400 секунд = 24 часа (сброс счетчика)
                     0x00, 0x00, 0x01, 0x00,

                     // RebootMessage (не используется)
                     0x00, 0x00, 0x00, 0x00,

                     // Command (не используется)
                     0x00, 0x00, 0x00, 0x00,

                     // Количество действий: 3
                     0x03, 0x00, 0x00, 0x00,

                     // Действие 1: SC_ACTION_RESTART (1) через 1000 мс
                     0x01, 0x00, 0x00, 0x00,  // Type: Restart
                     0xE8, 0x03, 0x00, 0x00,  // Delay: 1000 ms

                     // Действие 2: SC_ACTION_RESTART (1) через 1000 мс
                     0x01, 0x00, 0x00, 0x00,  // Type: Restart
                     0xE8, 0x03, 0x00, 0x00,  // Delay: 1000 ms

                     // Действие 3: SC_ACTION_RESTART (1) через 1000 мс
                     0x01, 0x00, 0x00, 0x00,  // Type: Restart
                     0xE8, 0x03, 0x00, 0x00   // Delay: 1000 ms
                         };

                         key.SetValue("FailureActions", failureActions, Microsoft.Win32.RegistryValueKind.Binary);
                         Console.WriteLine("   ✓ FailureActions записаны в реестр");

                         // 4. ВАЖНО: Включаем восстановление для ВСЕХ типов завершения
                         // 1 = Включить восстановление даже если служба завершилась без ошибки
                         key.SetValue("FailureActionsOnNonCrashFailures", 1, Microsoft.Win32.RegistryValueKind.DWord);
                         Console.WriteLine("   ✓ FailureActionsOnNonCrashFailures = 1 (восстановление при любом завершении)");

                         // 5. Защищаем от отключения восстановления
                         key.SetValue("DelayedAutoStart", 1, Microsoft.Win32.RegistryValueKind.DWord);

                         Console.WriteLine("   ✓ Все параметры восстановления записаны в реестр");
                     }
                     else
                     {
                         Console.WriteLine("   ✗ Не удалось открыть ключ реестра службы");
                     }
                 }
             }
             catch (Exception ex)
             {
                 Console.WriteLine($"   ✗ Ошибка записи в реестр: {ex.Message}");

                 // Пробуем через командную строку
                 try
                 {
                     string cmd = @"reg add ""HKLM\SYSTEM\CurrentControlSet\Services\AppControlService"" /v FailureActionsOnNonCrashFailures /t REG_DWORD /d 1 /f";
                     Process.Start("cmd.exe", $"/c {cmd}").WaitForExit(5000);
                     Console.WriteLine("   ✓ Параметры записаны через reg.exe");
                 }
                 catch { }
             }
         }*/
        private static void ConfigureRecoveryViaRegistry()
        {
            try
            {
                string servicePath = @"SYSTEM\CurrentControlSet\Services\AppControlService";

                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(servicePath, true))
                {
                    if (key != null)
                    {
                        // FailureActions - 3 попытки перезапуска с интервалом 1000 мс
                        byte[] failureActions = new byte[]
                        {
                            0x00, 0x00, 0x00, 0x00,  // Reset period (0 = never reset)
                            0x00, 0x00, 0x00, 0x00,  // Reboot message
                            0x00, 0x00, 0x00, 0x00,  // Command
                            0x03, 0x00, 0x00, 0x00,  // 3 actions
                            0x01, 0x00, 0x00, 0x00,  // Action 1: Restart
                            0xE8, 0x03, 0x00, 0x00,  // Delay: 1000 ms
                            0x01, 0x00, 0x00, 0x00,  // Action 2: Restart
                            0xE8, 0x03, 0x00, 0x00,  // Delay: 1000 ms
                            0x01, 0x00, 0x00, 0x00,  // Action 3: Restart
                            0xE8, 0x03, 0x00, 0x00   // Delay: 1000 ms
                        };

                        key.SetValue("FailureActions", failureActions, Microsoft.Win32.RegistryValueKind.Binary);
                        key.SetValue("FailureActionsOnNonCrashFailures", 1, Microsoft.Win32.RegistryValueKind.DWord);

                        Console.WriteLine("  ✓ Восстановление настроено: 3 попытки через 1 секунду");
                    }
                }

                // Дублируем через sc.exe для надежности
                RunSCCommand("failure AppControlService reset= 86400 actions= restart/1000/restart/1000/restart/1000", "настройка восстановления");
                RunSCCommand("failureflag AppControlService 1", "включение восстановления");
            }
            catch (Exception ex)
            {
                Console.WriteLine($" Ошибка настройки восстановления: {ex.Message}");
            }
        }


        private static void ConfigureRecoveryViaPowerShell()
        {
            try
            {
                // PowerShell команда для настройки восстановления службы
                string psCommand = @"
                    $service = Get-WmiObject Win32_Service -Filter ""Name='AppControlService'""
                    if ($service) {
                        # Устанавливаем автоматический запуск
                        $service.ChangeStartMode('Automatic')
    
                        # Настраиваем восстановление
                        sc.exe failure AppControlService reset= 86400 actions= restart/1000/restart/1000/restart/1000
                        sc.exe failureflag AppControlService 1
    
                        Write-Output 'Service recovery configured'
                    }";

                // Сохраняем в временный файл
                string tempFile = Path.GetTempFileName() + ".ps1";
                File.WriteAllText(tempFile, psCommand);

                Process process = new Process();
                process.StartInfo.FileName = "powershell.exe";
                process.StartInfo.Arguments = $"-ExecutionPolicy Bypass -File \"{tempFile}\"";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.RedirectStandardOutput = true;

                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit(10000);

                Console.WriteLine($"   ✓ PowerShell: {output.Trim()}");

                // Удаляем временный файл
                try { File.Delete(tempFile); } catch { }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   ⚠ Ошибка PowerShell: {ex.Message}");
            }
        }




        private static void ConfigureServiceRecovery()
        {
            try
            {
                Console.WriteLine("\n=== НАСТРОЙКА АВТОМАТИЧЕСКОГО ВОССТАНОВЛЕНИЯ СЛУЖБЫ ===");
                Console.WriteLine("Служба будет автоматически перезапущена при любом завершении!\n");

                // Способ 1: Настройка через sc.exe (самый надежный)
                Console.WriteLine("1. Настройка через SCM (Service Control Manager)...");

                // Команда: при падении службы перезапускать её 3 раза с интервалом 5 секунд
                string failureCommand = "failure AppControlService reset= 86400 actions= restart/5000/restart/5000/restart/5000";

                if (RunSCCommand(failureCommand, "настройка восстановления"))
                {
                    Console.WriteLine("   ✓ Восстановление настроено: 3 попытки перезапуска с интервалом 5 сек");
                }
                else
                {
                    Console.WriteLine("   ✗ Ошибка настройки через sc.exe");
                }

                // Включаем восстановление для всех типов завершения (включая kill процесса)
                string failureFlagCommand = "failureflag AppControlService 1";
                if (RunSCCommand(failureFlagCommand, "включение восстановления"))
                {
                    Console.WriteLine("   ✓ Восстановление включено для всех типов сбоев");
                }

                // Способ 2: Дублируем настройки через реестр (более детально)
                Console.WriteLine("\n2. Настройка через реестр Windows...");
                ConfigureRecoveryViaRegistry();

                // Способ 3: Настройка через PowerShell для гарантии
                Console.WriteLine("\n3. Дополнительная настройка через PowerShell...");
                ConfigureRecoveryViaPowerShell();

                // Проверяем что всё применилось
                Console.WriteLine("\n4. Проверка настроек восстановления...");
                RunSCCommand("qfailure AppControlService", "проверка настроек");

                Console.WriteLine("\n✓ АВТОВОССТАНОВЛЕНИЕ ПОЛНОСТЬЮ НАСТРОЕНО!");
                Console.WriteLine("  - Служба будет перезапущена при любом завершении");
                Console.WriteLine("  - 3 попытки восстановления с интервалом 5 секунд");
                Console.WriteLine("  - Счетчик сбоев сбрасывается через 24 часа");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка настройки восстановления: {ex.Message}");
            }
        }

        static bool UninstallService()
        {
            try
            {
                if (!IsRunningAsAdministrator())
                {
                    Console.WriteLine("Требуются права администратора для удаления службы.");
                    return RestartAsAdministrator("--uninstall");
                }

                Console.WriteLine("Удаление службы...");
                RunSCCommand("stop AppControlService", "остановка");
                Thread.Sleep(2000);
                RunSCCommand("delete AppControlService", "удаление");

                Console.WriteLine("Служба успешно удалена!");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка: {ex.Message}");
                return false;
            }
        }


        static bool StartService()
        {
            return RunSCCommand("start AppControlService", "запуск службы");
        }

        static bool StopService()
        {
            return RunSCCommand("stop AppControlService", "остановка службы");
        }

        static bool CheckServiceStatus()
        {
            return RunSCCommand("query AppControlService", "проверка статуса службы");
        }

        //static bool RunSCCommand(string arguments, string operationName)
        //{
        //    try
        //    {
        //        Console.WriteLine($"\n[{DateTime.Now:HH:mm:ss}] Выполнение: sc.exe {arguments}");

        //        Process process = new Process();
        //        process.StartInfo.FileName = "sc.exe";
        //        process.StartInfo.Arguments = arguments;
        //        process.StartInfo.UseShellExecute = false;
        //        process.StartInfo.CreateNoWindow = false;
        //        process.StartInfo.RedirectStandardOutput = true;
        //        process.StartInfo.RedirectStandardError = true;
        //        process.StartInfo.StandardOutputEncoding = Encoding.GetEncoding(866);
        //        process.StartInfo.StandardErrorEncoding = Encoding.GetEncoding(866);

        //        StringBuilder outputBuilder = new StringBuilder();
        //        process.OutputDataReceived += (sender, e) =>
        //        {
        //            if (!string.IsNullOrEmpty(e.Data))
        //            {
        //                outputBuilder.AppendLine(e.Data);
        //                Console.WriteLine($"  >> {e.Data}");
        //            }
        //        };

        //        StringBuilder errorBuilder = new StringBuilder();
        //        process.ErrorDataReceived += (sender, e) =>
        //        {
        //            if (!string.IsNullOrEmpty(e.Data))
        //            {
        //                errorBuilder.AppendLine(e.Data);
        //                Console.WriteLine($"  [ERROR] >> {e.Data}");
        //            }
        //        };

        //        process.Start();
        //        process.BeginOutputReadLine();
        //        process.BeginErrorReadLine();

        //        bool exited = process.WaitForExit(30000); // 30 секунд

        //        if (!exited)
        //        {
        //            process.Kill();
        //            Console.WriteLine("  [WARNING] Процесс не завершился вовремя");
        //            return false;
        //        }

        //        string fullOutput = outputBuilder.ToString();
        //        string fullError = errorBuilder.ToString();

        //        Console.WriteLine($"  Код завершения: {process.ExitCode}");

        //        // Для create команды код 0 - успех, код 1073 - уже существует
        //        if (process.ExitCode == 0 || process.ExitCode == 1073)
        //        {
        //            Console.WriteLine($"  {operationName} выполнено");
        //            return true;
        //        }

        //        // Проверяем вывод на наличие успешных сообщений
        //        if (fullOutput.Contains("SUCCESS") || fullOutput.Contains("успех"))
        //        {
        //            Console.WriteLine($"  {operationName} выполнено (по сообщению в выводе)");
        //            return true;
        //        }

        //        if (!string.IsNullOrEmpty(fullError))
        //        {
        //            Console.WriteLine($"  [ERROR] Детали: {fullError.Trim()}");
        //        }

        //        return false;
        //    }
        //    catch (Exception ex)
        //    {
        //        Console.WriteLine($"  [EXCEPTION] Ошибка при {operationName}: {ex.Message}");
        //        return false;
        //    }
        //}   
        static bool RunSCCommand(string arguments, string operationName)
        {
            try
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] sc.exe {arguments}");

                Process process = new Process();
                process.StartInfo.FileName = "sc.exe";
                process.StartInfo.Arguments = arguments;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;
                process.StartInfo.StandardOutputEncoding = Encoding.GetEncoding(866);
                process.StartInfo.StandardErrorEncoding = Encoding.GetEncoding(866);

                StringBuilder output = new StringBuilder();
                process.OutputDataReceived += (sender, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                    {
                        output.AppendLine(e.Data);
                        Console.WriteLine($"  {e.Data}");
                    }
                };

                process.ErrorDataReceived += (sender, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                    {
                        Console.WriteLine($"  [ОШИБКА] {e.Data}");
                    }
                };

                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                process.WaitForExit(15000);

                if (process.ExitCode == 0 || process.ExitCode == 1073 || output.ToString().Contains("SUCCESS"))
                {
                    Console.WriteLine($"  ✓ {operationName} - УСПЕШНО");
                    return true;
                }

                Console.WriteLine($"  ✗ {operationName} - НЕУДАЧА (код: {process.ExitCode})");
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  ✗ Ошибка при {operationName}: {ex.Message}");
                return false;
            }
        }
        static bool IsRunningAsAdministrator()
        {
            try
            {
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        static bool RestartAsAdministrator(params string[] arguments)
        {
            try
            {
                string exePath = Assembly.GetExecutingAssembly().Location;
                string argsString = string.Join(" ", arguments);

                ProcessStartInfo startInfo = new ProcessStartInfo
                {
                    FileName = exePath,
                    Arguments = argsString,
                    Verb = "runas",
                    UseShellExecute = true
                };

                Process.Start(startInfo);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка перезапуска: {ex.Message}");
                return false;
            }
        }



    }
}