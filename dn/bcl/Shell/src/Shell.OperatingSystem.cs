using System.Runtime.InteropServices;

namespace FrostYeti;

public static partial class Shell
{
    public static partial class OS
    {
        private static readonly Lazy<bool> s_isWindows = new(() => System.OperatingSystem.IsWindows());
        private static readonly Lazy<bool> s_isLinux = new(() => System.OperatingSystem.IsLinux());
        private static readonly Lazy<bool> s_isDarwin = new(() => System.OperatingSystem.IsMacOS());
        private static readonly Lazy<bool> s_isWsl = new(() =>
        {
            if (s_isLinux.Value)
            {
                return File.Exists("/proc/version") &&
                       File.ReadAllText("/proc/version").Contains("Microsoft", StringComparison.OrdinalIgnoreCase);
            }

            return false;
        });

        public static bool Is64Bit
            => System.Environment.Is64BitOperatingSystem;

        public static Architecture Arch
            => System.Runtime.InteropServices.RuntimeInformation.OSArchitecture;

        public static bool IsWindows => s_isWindows.Value;

        public static bool IsLinux => s_isLinux.Value;

        public static bool IsDarwin => s_isDarwin.Value;

        public static bool IsWsl => s_isWsl.Value;
    }
}