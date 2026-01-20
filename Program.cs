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
            // Режим отладки
            if (args.Length > 0 && args[0] == "--debug")
            {
                return RunDebugMode(args);
            }

            // Обработка команд
            if (args.Length > 0)
            {
                return ProcessArguments(args);
            }

            // Запуск как служба
            ServiceBase.Run(new ApplicationControlService());
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
            Console.WriteLine(" Application Control Service - Debug Mode ");

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

        //        static bool InstallService(string logsPath = null, string whiteListPath = null)
        //        {
        //            try
        //            {
        //                if (!IsRunningAsAdministrator())
        //                {
        //                    Console.WriteLine("Требуются права администратора для установки службы.");
        //                    Console.WriteLine("Перезапускаем с правами администратора...");
        //                    return RestartAsAdministrator("--install", logsPath, whiteListPath);
        //                }

        //                string exePath = Assembly.GetExecutingAssembly().Location;
        //              /*  exePath = exePath.Trim('"');
        //*/
        //                // Используем переданные пути или по умолчанию
        //                if (string.IsNullOrEmpty(logsPath))
        //                    logsPath = @"C:\ProgramData\AppControl\Logs";

        //                if (string.IsNullOrEmpty(whiteListPath))
        //                    whiteListPath = @"C:\ProgramData\AppControl\WhiteList";

        //                logsPath = logsPath.Trim('"');
        //                whiteListPath = whiteListPath.Trim('"');

        //                Console.WriteLine($"Установка службы:");
        //                Console.WriteLine($"  EXE: {exePath}");
        //                Console.WriteLine($"  Логи: {logsPath}");
        //                Console.WriteLine($"  Белый список: {whiteListPath}");

        //                // Создаем директории
        //                if (!Directory.Exists(logsPath))
        //                {
        //                    Directory.CreateDirectory(logsPath);
        //                    Console.WriteLine($"Создана директория для логов: {logsPath}");
        //                }

        //                if (!Directory.Exists(whiteListPath))
        //                {
        //                    Directory.CreateDirectory(whiteListPath);
        //                    Console.WriteLine($"Создана директория для белого списка: {whiteListPath}");
        //                }

        //                // Создаем конфиг если нет
        //                string configPath = Path.Combine(whiteListPath, "config.json");
        //                if (!File.Exists(configPath))
        //                {
        //                    CreateSimpleConfig(configPath);
        //                    Console.WriteLine($"Создан конфиг по умолчанию: {configPath}");
        //                }

        //                string binPath = $"\"{exePath}\" {logsPath} {whiteListPath}";

        //                // Ключевое исправление: правильный формат команды
        //                string createCommand = $"create AppControlService binPath= \"{binPath}\" start= auto DisplayName= \"Application Control Service\"";

        //                Console.WriteLine($"\nСоздание службы: sc.exe {createCommand}");

        //                bool serviceCreated = false;
        //                if (RunSCCommand(createCommand, "создание службы"))
        //                {
        //                    serviceCreated = true;
        //                }
        //                else
        //                {
        //                    // Альтернативный вариант 
        //                    string createCommandAlt = $"create AppControlService binPath= \"{exePath} {logsPath} {whiteListPath}\" start= auto DisplayName= \"Application Control Service\"";
        //                    Console.WriteLine($"\nАльтернативный вариант: sc.exe {createCommandAlt}");

        //                    if (RunSCCommand(createCommandAlt, "создание службы (альтернатива)"))
        //                    {
        //                        serviceCreated = true;
        //                    }
        //                }

        //                if (!serviceCreated)
        //                {
        //                    Console.WriteLine("Не удалось создать службу");
        //                    return false;
        //                }

        //                Console.WriteLine("Служба успешно создана");

        //                // Задаем описание службы
        //                string descriptionCommand = $"description AppControlService \"Служба контроля запуска приложений\"";
        //                RunSCCommand(descriptionCommand, "назначение описания");

        //                // Устанавливаем тип восстановления
        //                string failureCommand = $"failure AppControlService reset= 86400 actions= restart/5000/restart/5000/restart/5000";
        //                RunSCCommand(failureCommand, "настройка восстановления");

        //                // Сохраняем параметры в реестр (на всякий случай)
        //                SetServiceParametersViaRegistry(logsPath, whiteListPath);

        //                Thread.Sleep(2000);

        //                // Запускаем службу
        //                Console.WriteLine("\nЗапуск службы...");
        //                if (StartService())
        //                {
        //                    Console.WriteLine(" Служба успешно запущена!");

        //                    // Ждем и проверяем статус
        //                    Thread.Sleep(3000);
        //                    RunSCCommand("query AppControlService", "проверка статуса службы");

        //                    return true;
        //                }
        //                else
        //                {
        //                    Console.WriteLine("Служба создана, но не запущена автоматически.");
        //                    Console.WriteLine("Попробуйте запустить вручную:");
        //                    Console.WriteLine("  sc start AppControlService");

        //                    // Все равно считаем успехом, т.к. служба создана
        //                    return true;
        //                }
        //            }
        //            catch (Exception ex)
        //            {
        //                Console.WriteLine($"Ошибка при установке: {ex.Message}");
        //                Console.WriteLine($"StackTrace: {ex.StackTrace}");
        //                return false;
        //            }
        //        }

        static bool InstallService(string logsPath = null, string whiteListPath = null)
        {
            try
            {
                Console.WriteLine("=== УСТАНОВКА СЛУЖБЫ AppControlService ===");

                // Проверка прав
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
                else
                {
                    Console.WriteLine($"✓ Конфиг уже существует: {configPath}");
                }

                // 1. УДАЛЯЕМ старую службу (если есть)
                Console.WriteLine("\n1. Удаление старой службы...");
                try
                {
                    RunSCCommand("stop AppControlService", "остановка");
                    Thread.Sleep(1000);
                }
                catch { }

                try
                {
                    RunSCCommand("delete AppControlService", "удаление");
                    Thread.Sleep(1000);
                }
                catch { }

                // 2. СОЗДАЕМ службу (ПРОСТАЯ команда)
                Console.WriteLine("\n2. Создание службы...");

                // Простейший вариант команды
                string binPath = $"\"{exePath}\" \"{logsPath}\" \"{whiteListPath}\"";
                string createCmd = $"create AppControlService binPath= {binPath} start= auto";

                Console.WriteLine($"Выполняем: sc.exe {createCmd}");

                if (!RunSCCommand(createCmd, "создание"))
                {
                    // Пробуем альтернативный вариант
                    Console.WriteLine("\nПробуем альтернативный вариант...");
                    string createCmdAlt = $"create AppControlService binPath= \"{exePath}\" start= auto";

                    if (!RunSCCommand(createCmdAlt, "создание (альтернатива)"))
                    {
                        Console.WriteLine("✗ Не удалось создать службу");
                        return false;
                    }
                }

                Console.WriteLine("✓ Служба создана");

                // 3. Добавляем описание
                Console.WriteLine("\n3. Настройка службы...");
                RunSCCommand($"description AppControlService \"Контроль запуска приложений\"", "описание");

                // Устанавливаем тип запуска АВТОМАТИЧЕСКИЙ
                RunSCCommand($"config AppControlService start= auto", "автозапуск");

                // Показываем информацию
                RunSCCommand($"qc AppControlService", "информация");

                // Сохраняем пути в реестр
                try
                {
                    string regPath = @"SYSTEM\CurrentControlSet\Services\AppControlService\Parameters";
                    using (var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(regPath))
                    {
                        key.SetValue("LogsPath", logsPath);
                        key.SetValue("WhiteListPath", whiteListPath);
                        Console.WriteLine("✓ Параметры сохранены в реестре");
                    }
                }
                catch (Exception regEx)
                {
                    Console.WriteLine($"⚠ Не удалось сохранить в реестр: {regEx.Message}");
                }

                Thread.Sleep(2000);

                // 4. ЗАПУСКАЕМ службу
                Console.WriteLine("\n4. Запуск службы...");
                if (RunSCCommand("start AppControlService", "запуск"))
                {
                    Console.WriteLine("✓ Служба запущена!");

                    // Проверяем статус
                    Thread.Sleep(3000);
                    Console.WriteLine("\n5. Проверка статуса...");
                    RunSCCommand("query AppControlService", "статус");

                    return true;
                }
                else
                {
                    Console.WriteLine("⚠ Служба создана, но не запущена");
                    Console.WriteLine("\nПопробуйте запустить вручную:");
                    Console.WriteLine("  sc start AppControlService");
                    Console.WriteLine("\nИли проверьте ошибки в Event Viewer");

                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"✗ Критическая ошибка: {ex.Message}");
                Console.WriteLine($"StackTrace: {ex.StackTrace}");
                return false;
            }
        }

        static void SetServiceParametersViaRegistry(string logsPath, string whiteListPath)
        {
            try
            {
                Console.WriteLine("Установка параметров через реестр...");

                // Параметры хранятся в реестре
                string registryPath = @"SYSTEM\CurrentControlSet\Services\AppControlService\Parameters";

                using (var baseKey = Microsoft.Win32.Registry.LocalMachine)
                using (var key = baseKey.CreateSubKey(registryPath))
                {
                    if (key != null)
                    {
                        key.SetValue("LogsPath", logsPath, Microsoft.Win32.RegistryValueKind.String);
                        key.SetValue("WhiteListPath", whiteListPath, Microsoft.Win32.RegistryValueKind.String);
                        Console.WriteLine($"Параметры сохранены в реестре: {logsPath}, {whiteListPath}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка сохранения в реестр: {ex.Message}");
            }
        }

        private static void CreateSimpleConfig(string configPath)
        {
            try
            {
                string simpleConfig = @"[
                  {
                    ""Name"": ""explorer"",
                    ""Hash"": """"
                  },
                  {
                    ""Name"": ""notepad"",
                    ""Hash"": """"
                  },
                  {
                    ""Name"": ""cmd"",
                    ""Hash"": """"
                  }
                ]";
                File.WriteAllText(configPath, simpleConfig, Encoding.UTF8);
            }
            catch { }
        }
        static bool UninstallService()
        {
            try
            {
                // Проверяем права администратора
                if (!IsRunningAsAdministrator())
                {
                    Console.WriteLine("Требуются права администратора для удаления службы.");
                    Console.WriteLine("Перезапускаем с правами администратора...");

                    return RestartAsAdministrator("--uninstall");
                }

                Console.WriteLine("Удаление службы...");

                // Останавливаем службу перед удалением
                Console.WriteLine("Остановка службы...");
                StopService();

                // Ждем остановки
                Thread.Sleep(3000);

                // Удаляем службу
                string deleteCommand = "delete AppControlService";
                if (RunSCCommand(deleteCommand, "удаление службы"))
                {
                    Console.WriteLine("Служба успешно удалена!");
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка: {ex.Message}");
                return false;
            }
        }

        static bool StartService()
        {
            try
            {
                return RunSCCommand("start AppControlService", "запуск службы");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка: {ex.Message}");
                return false;
            }
        }

        static bool StopService()
        {
            try
            {
                return RunSCCommand("stop AppControlService", "остановка службы");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка: {ex.Message}");
                return false;
            }
        }

        static bool CheckServiceStatus()
        {
            try
            {
                return RunSCCommand("query AppControlService", "проверка статуса службы");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка: {ex.Message}");
                return false;
            }
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

                process.WaitForExit(15000); // 15 секунд

                Console.WriteLine($"  Код выхода: {process.ExitCode}");

                // Коды успеха для sc.exe
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

                Process process = new Process();
                process.StartInfo = startInfo;
                process.Start();
                process.WaitForExit(30000);

                return process.ExitCode == 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка перезапуска: {ex.Message}");
                return false;
            }
        }
    }
}