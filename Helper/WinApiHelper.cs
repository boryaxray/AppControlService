using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace ApplicationControlService
{
    internal static class WinApiHelper
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(
            uint processAccess,
            bool bInheritHandle,
            int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            uint DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupAccountSid(
            string lpSystemName,
            IntPtr Sid,
            StringBuilder lpName,
            ref uint cchName,
            StringBuilder lpReferencedDomainName,
            ref uint cchReferencedDomainName,
            out SID_NAME_USE peUse);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            uint TokenInformationLength,
            out uint ReturnLength);

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern uint GetModuleFileNameEx(
            IntPtr hProcess,
            IntPtr hModule,
            StringBuilder lpFilename,
            uint nSize);

        [DllImport("ntdll.dll")]
        private static extern uint NtQuerySystemInformation(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            IntPtr SystemInformation,
            uint SystemInformationLength,
            out uint ReturnLength);

        [DllImport("kernel32.dll")]
        private static extern uint QueryFullProcessImageName(
            IntPtr hProcess,
            uint dwFlags,
            StringBuilder lpExeName,
            ref uint lpdwSize);

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

        [DllImport("user32.dll")]
        private static extern IntPtr GetShellWindow();

        // Константы для NtQuerySystemInformation
        private const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

        // SystemInformationClass для NtQuerySystemInformation
        private enum SYSTEM_INFORMATION_CLASS
        {
            SystemProcessInformation = 5,
            SystemExtendedProcessInformation = 57
        }

        // Структура SYSTEM_PROCESS_INFORMATION
        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_PROCESS_INFORMATION
        {
            public uint NextEntryOffset;
            public uint NumberOfThreads;
            public long SpareLi1;
            public long SpareLi2;
            public long SpareLi3;
            public long CreateTime;
            public long UserTime;
            public long KernelTime;
            public ushort ImageNameLength;
            public ushort ImageNameMaximumLength;
            public IntPtr ImageNameBuffer;
            public int BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
            public uint HandleCount;
            public uint SessionId;
            public uint PagefileUsage;
            public uint PeakPagefileUsage;
            public uint WorkingSetSize;
            public uint PeakWorkingSetSize;
            public uint Reserved3;
            public uint Reserved4;
            public IntPtr ReadOperationCount;
            public IntPtr WriteOperationCount;
            public IntPtr OtherOperationCount;
            public IntPtr ReadTransferCount;
            public IntPtr WriteTransferCount;
            public IntPtr OtherTransferCount;
        }

        // Структура UNICODE_STRING
        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        private enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            TokenIsAppContainer,
            TokenCapabilities,
            TokenAppContainerSid,
            TokenAppContainerNumber,
            TokenUserClaimAttributes,
            TokenDeviceClaimAttributes,
            TokenRestrictedUserClaimAttributes,
            TokenRestrictedDeviceClaimAttributes,
            TokenDeviceGroups,
            TokenRestrictedDeviceGroups,
            TokenSecurityAttributes,
            TokenIsRestricted,
            MaxTokenInfoClass
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        private enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer,
            SidTypeLabel
        }

        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint MAX_PATH = 260;

        // Определение типа процесса
        public enum ProcessType
        {
            Unknown,
            SystemCritical,     // Критические системные процессы (ядро)
            SystemService,      // Системные службы (Session 0)
            UserApplication,    // Пользовательские приложения
            BackgroundProcess,  // Фоновые процессы
            SecurityProcess,    // Процессы безопасности
            ShellProcess        // Процессы оболочки (explorer и т.д.)
        }

        // Расширенная информация о процессе
        public class ExtendedProcessInfo
        {
            public int ProcessId { get; set; }
            public int ParentProcessId { get; set; }
            public string ProcessName { get; set; } = string.Empty;
            public string FilePath { get; set; } = string.Empty;
            public string UserName { get; set; } = string.Empty;
            public ProcessType Type { get; set; }
            public bool IsShellProcess { get; set; }
            public bool IsCriticalSystemProcess { get; set; }
            public uint SessionId { get; set; }
            public uint HandleCount { get; set; }
            public long CreateTime { get; set; }
            public long UserTime { get; set; }
            public long KernelTime { get; set; }
            public uint WorkingSetSize { get; set; } // в байтах
            public uint PeakWorkingSetSize { get; set; }

            public override string ToString()
            {
                return $"[PID: {ProcessId}, Parent: {ParentProcessId}] {Type}: {ProcessName} ({UserName})";
            }

            public string ToDetailedString()
            {
                return $"[PID: {ProcessId}] {ProcessName}\n" +
                       $"  Родитель: {ParentProcessId}\n" +
                       $"  Пользователь: {UserName}\n" +
                       $"  Тип: {Type}\n" +
                       $"  Session: {SessionId}\n" +
                       $"  Дескрипторов: {HandleCount}\n" +
                       $"  Память: {WorkingSetSize / 1024 / 1024} MB\n" +
                       $"  Время CPU: {UserTime + KernelTime} тиков\n" +
                       $"  Путь: {FilePath}";
            }
        }

        // Получение расширенной информации о процессе
        public static ExtendedProcessInfo GetExtendedProcessInfo(int processId)
        {
            var info = new ExtendedProcessInfo { ProcessId = processId };

            IntPtr processHandle = IntPtr.Zero;
            IntPtr tokenHandle = IntPtr.Zero;

            try
            {
                // Открываем процесс
                processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, processId);
                if (processHandle == IntPtr.Zero)
                {
                    info.Type = ProcessType.Unknown;
                    return info;
                }

                // Получаем путь к исполняемому файлу
                info.FilePath = GetProcessFilePath(processHandle);
                info.ProcessName = System.IO.Path.GetFileNameWithoutExtension(info.FilePath);

                // Получаем имя пользователя
                info.UserName = GetProcessUserName(processHandle);

                // Получаем информацию из SYSTEM_PROCESS_INFORMATION
                var systemInfo = GetProcessInfoFromSystem(processId);
                if (systemInfo != null)
                {
                    info.ParentProcessId = systemInfo.Value.ParentProcessId;
                    info.SessionId = systemInfo.Value.SessionId;
                    info.HandleCount = systemInfo.Value.HandleCount;
                    info.CreateTime = systemInfo.Value.CreateTime;
                    info.UserTime = systemInfo.Value.UserTime;
                    info.KernelTime = systemInfo.Value.KernelTime;
                    info.WorkingSetSize = systemInfo.Value.WorkingSetSize;
                    info.PeakWorkingSetSize = systemInfo.Value.PeakWorkingSetSize;
                }
                else
                {
                    // Если не удалось получить из SYSTEM_PROCESS_INFORMATION, пробуем через Process
                    try
                    {
                        var process = Process.GetProcessById(processId);
                        info.SessionId = (uint)process.SessionId;

                        // Пытаемся получить родительский процесс через WMI
                        info.ParentProcessId = GetParentProcessIdViaWmi(processId);
                    }
                    catch { }
                }

                // Определяем тип процесса
                info.Type = DetermineProcessType(info);

                // Проверяем, является ли процесс частью оболочки Windows
                info.IsShellProcess = IsShellProcess(processId);

                // Проверяем, является ли процесс системно-критическим
                info.IsCriticalSystemProcess = IsCriticalSystemProcess(info);

                return info;
            }
            catch
            {
                return info;
            }
            finally
            {
                if (tokenHandle != IntPtr.Zero)
                    CloseHandle(tokenHandle);
                if (processHandle != IntPtr.Zero)
                    CloseHandle(processHandle);
            }
        }

        // Получение информации о процессе из SYSTEM_PROCESS_INFORMATION
        private static SystemProcessInfo? GetProcessInfoFromSystem(int processId)
        {
            try
            {
                uint bufferSize = 1024 * 1024; // 1 MB начальный размер
                IntPtr buffer = IntPtr.Zero;
                uint returnLength = 0;

                while (true)
                {
                    buffer = Marshal.AllocHGlobal((int)bufferSize);

                    uint status = NtQuerySystemInformation(
                        SYSTEM_INFORMATION_CLASS.SystemProcessInformation,
                        buffer,
                        bufferSize,
                        out returnLength);

                    if (status == 0)
                    {
                        break; // Успешно
                    }
                    else if (status == STATUS_INFO_LENGTH_MISMATCH)
                    {
                        Marshal.FreeHGlobal(buffer);
                        bufferSize = returnLength + 1024; // Добавляем запас
                    }
                    else
                    {
                        Marshal.FreeHGlobal(buffer);
                        return null; // Ошибка
                    }
                }

                try
                {
                    IntPtr currentEntry = buffer;

                    while (currentEntry != IntPtr.Zero)
                    {
                        var spi = Marshal.PtrToStructure<SYSTEM_PROCESS_INFORMATION>(currentEntry);

                        int currentProcessId = spi.UniqueProcessId.ToInt32();
                        if (currentProcessId == processId)
                        {
                            var result = new SystemProcessInfo
                            {
                                ParentProcessId = spi.InheritedFromUniqueProcessId.ToInt32(),
                                SessionId = spi.SessionId,
                                HandleCount = spi.HandleCount,
                                CreateTime = spi.CreateTime,
                                UserTime = spi.UserTime,
                                KernelTime = spi.KernelTime,
                                WorkingSetSize = spi.WorkingSetSize,
                                PeakWorkingSetSize = spi.PeakWorkingSetSize
                            };

                            // Получаем имя процесса из UNICODE_STRING
                            if (spi.ImageNameBuffer != IntPtr.Zero && spi.ImageNameLength > 0)
                            {
                                byte[] nameBytes = new byte[spi.ImageNameLength];
                                Marshal.Copy(spi.ImageNameBuffer, nameBytes, 0, nameBytes.Length);
                                result.ProcessName = Encoding.Unicode.GetString(nameBytes);
                            }

                            return result;
                        }

                        if (spi.NextEntryOffset == 0)
                            break;

                        currentEntry = IntPtr.Add(currentEntry, (int)spi.NextEntryOffset);
                    }

                    return null;
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            catch
            {
                return null;
            }
        }

        // Вспомогательная структура для информации из SYSTEM_PROCESS_INFORMATION
        private struct SystemProcessInfo
        {
            public int ParentProcessId;
            public string ProcessName;
            public uint SessionId;
            public uint HandleCount;
            public long CreateTime;
            public long UserTime;
            public long KernelTime;
            public uint WorkingSetSize;
            public uint PeakWorkingSetSize;
        }

        // Получение родительского процесса через WMI (запасной метод)
        private static int GetParentProcessIdViaWmi(int processId)
        {
            try
            {
                using (var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {processId}"))
                {
                    foreach (System.Management.ManagementObject obj in searcher.Get())
                    {
                        if (obj["ParentProcessId"] != null)
                        {
                            return Convert.ToInt32(obj["ParentProcessId"]);
                        }
                    }
                }
            }
            catch { }

            return -1;
        }

        // Получение пути к файлу процесса
        private static string GetProcessFilePath(IntPtr processHandle)
        {
            try
            {
                StringBuilder buffer = new StringBuilder((int)MAX_PATH);
                uint size = (uint)buffer.Capacity;

                if (QueryFullProcessImageName(processHandle, 0, buffer, ref size) != 0)
                {
                    return buffer.ToString();
                }

                // Альтернативный метод
                buffer = new StringBuilder((int)MAX_PATH);
                if (GetModuleFileNameEx(processHandle, IntPtr.Zero, buffer, (uint)buffer.Capacity) != 0)
                {
                    return buffer.ToString();
                }
            }
            catch { }

            return string.Empty;
        }

        // Получение имени пользователя процесса
        private static string GetProcessUserName(IntPtr processHandle)
        {
            IntPtr tokenHandle = IntPtr.Zero;

            try
            {
                if (!OpenProcessToken(processHandle, TOKEN_QUERY, out tokenHandle))
                    return string.Empty;

                // Получаем SID пользователя
                uint tokenInfoLength = 0;
                GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenUser,
                    IntPtr.Zero, 0, out tokenInfoLength);

                IntPtr tokenInfo = Marshal.AllocHGlobal((int)tokenInfoLength);

                try
                {
                    if (GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenUser,
                        tokenInfo, tokenInfoLength, out tokenInfoLength))
                    {
                        TOKEN_USER tokenUser = Marshal.PtrToStructure<TOKEN_USER>(tokenInfo);

                        StringBuilder name = new StringBuilder(256);
                        StringBuilder domain = new StringBuilder(256);
                        uint nameLength = (uint)name.Capacity;
                        uint domainLength = (uint)domain.Capacity;
                        SID_NAME_USE sidUse;

                        if (LookupAccountSid(null, tokenUser.User.Sid, name,
                            ref nameLength, domain, ref domainLength, out sidUse))
                        {
                            return domain.ToString() + "\\" + name.ToString();
                        }
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(tokenInfo);
                }
            }
            catch { }
            finally
            {
                if (tokenHandle != IntPtr.Zero)
                    CloseHandle(tokenHandle);
            }

            return string.Empty;
        }

        // Определение типа процесса
        private static ProcessType DetermineProcessType(ExtendedProcessInfo info)
        {
            // 1. Критические системные процессы (PID 0-4)
            if (info.ProcessId <= 4)
                return ProcessType.SystemCritical;

            if (string.IsNullOrEmpty(info.FilePath))
                return ProcessType.Unknown;

            string lowerPath = info.FilePath.ToLowerInvariant();
            string lowerUser = info.UserName?.ToLowerInvariant() ?? "";

            // 2. Процессы от имени SYSTEM, LOCAL SERVICE, NETWORK SERVICE
            if (lowerUser.Contains("system") ||
                lowerUser.Contains("local service") ||
                lowerUser.Contains("network service"))
            {
                return ProcessType.SystemService;
            }

            // 3. Системные файлы Windows из защищенных каталогов
            if (lowerPath.Contains(@"\windows\") ||
                lowerPath.Contains(@"\system32\") ||
                lowerPath.Contains(@"\syswow64\"))
            {
                return ProcessType.SystemService;  // Всегда системная служба
            }

            // 4. svchost.exe - ВСЕГДА системная служба
            if (info.ProcessName.Equals("svchost", StringComparison.OrdinalIgnoreCase))
            {
                return ProcessType.SystemService;
            }

            // 5. Сессия 0 - всегда системные службы
            if (info.SessionId <= 0)
            {
                return ProcessType.SystemService;
            }

            // 6. Проверка по Session ID (пользовательские сессии)
            if (info.SessionId > 0 && !string.IsNullOrEmpty(info.UserName))
            {
                // Это пользовательский процесс
                return ProcessType.UserApplication;
            }

            return ProcessType.Unknown;
        }

        // Проверка, является ли процесс частью оболочки Windows
        private static bool IsShellProcess(int processId)
        {
            try
            {
                // Получаем процесс оболочки (explorer)
                IntPtr shellWindow = GetShellWindow();
                if (shellWindow != IntPtr.Zero)
                {
                    GetWindowThreadProcessId(shellWindow, out uint shellProcessId);
                    return shellProcessId == processId;
                }
            }
            catch { }

            return false;
        }

        // Проверка, является ли процесс системно-критическим
        private static bool IsCriticalSystemProcess(ExtendedProcessInfo info)
        {
            // Известные критические системные процессы
            string[] criticalNames = {
                "csrss", "wininit", "winlogon", "lsass", "services",
                "smss", "dwm", "fontdrvhost", "logonui"
            };

            string processName = info.ProcessName.ToLowerInvariant();

            foreach (var name in criticalNames)
            {
                if (processName.Contains(name))
                    return true;
            }

            // Проверяем, работает ли процесс от имени SYSTEM
            if (!string.IsNullOrEmpty(info.UserName))
            {
                return info.UserName.ToLowerInvariant().Contains("system") &&
                       info.FilePath.ToLowerInvariant().Contains(@"\windows\");
            }

            return false;
        }

        // Получение родительского процесса
        public static int GetParentProcessId(int processId)
        {
            try
            {
                // Пробуем получить через SYSTEM_PROCESS_INFORMATION
                var info = GetProcessInfoFromSystem(processId);
                if (info != null && info.Value.ParentProcessId > 0)
                {
                    return info.Value.ParentProcessId;
                }

                // Запасной метод через WMI
                return GetParentProcessIdViaWmi(processId);
            }
            catch
            {
                return -1;
            }
        }

        // Получение списка всех процессов с расширенной информацией
        public static List<ExtendedProcessInfo> GetAllProcessesInfo()
        {
            var processes = new List<ExtendedProcessInfo>();

            try
            {
                var systemProcesses = GetSystemProcessesList();
                foreach (var proc in systemProcesses)
                {
                    var extendedInfo = GetExtendedProcessInfo(proc.ProcessId);
                    if (extendedInfo != null)
                    {
                        processes.Add(extendedInfo);
                    }
                }
            }
            catch { }

            return processes;
        }

        // Получение списка процессов из SYSTEM_PROCESS_INFORMATION
        private static List<SystemProcessEntry> GetSystemProcessesList()
        {
            var processes = new List<SystemProcessEntry>();

            try
            {
                uint bufferSize = 1024 * 1024; // 1 MB начальный размер
                IntPtr buffer = IntPtr.Zero;
                uint returnLength = 0;

                while (true)
                {
                    buffer = Marshal.AllocHGlobal((int)bufferSize);

                    uint status = NtQuerySystemInformation(
                        SYSTEM_INFORMATION_CLASS.SystemProcessInformation,
                        buffer,
                        bufferSize,
                        out returnLength);

                    if (status == 0)
                    {
                        break;
                    }
                    else if (status == STATUS_INFO_LENGTH_MISMATCH)
                    {
                        Marshal.FreeHGlobal(buffer);
                        bufferSize = returnLength + 1024;
                    }
                    else
                    {
                        Marshal.FreeHGlobal(buffer);
                        return processes;
                    }
                }

                try
                {
                    IntPtr currentEntry = buffer;

                    while (currentEntry != IntPtr.Zero)
                    {
                        var spi = Marshal.PtrToStructure<SYSTEM_PROCESS_INFORMATION>(currentEntry);

                        var entry = new SystemProcessEntry
                        {
                            ProcessId = spi.UniqueProcessId.ToInt32(),
                            ParentProcessId = spi.InheritedFromUniqueProcessId.ToInt32(),
                            SessionId = spi.SessionId,
                            HandleCount = spi.HandleCount
                        };

                        // Получаем имя процесса
                        if (spi.ImageNameBuffer != IntPtr.Zero && spi.ImageNameLength > 0)
                        {
                            byte[] nameBytes = new byte[spi.ImageNameLength];
                            Marshal.Copy(spi.ImageNameBuffer, nameBytes, 0, nameBytes.Length);
                            entry.ProcessName = Encoding.Unicode.GetString(nameBytes);
                        }

                        processes.Add(entry);

                        if (spi.NextEntryOffset == 0)
                            break;

                        currentEntry = IntPtr.Add(currentEntry, (int)spi.NextEntryOffset);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            catch { }

            return processes;
        }

        // Структура для хранения базовой информации о процессе
        private struct SystemProcessEntry
        {
            public int ProcessId;
            public int ParentProcessId;
            public string ProcessName;
            public uint SessionId;
            public uint HandleCount;
        }
    }
}