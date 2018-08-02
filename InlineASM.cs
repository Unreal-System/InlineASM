/*
 资料使用
 https://blogs.msdn.microsoft.com/devinj/2005/07/13/dynamically-writing-and-executing-native-assembly-in-c/
 http://www.cnblogs.com/gc2013/p/4660430.html
 突发奇想熬夜想到了之前怎么想都想不出来的操作
 By: UnrealSystem
 Welcome Join To Group
 Please Decryption this code
 68747470733A2F2F742E6D652F556E7265616C53797374656D
 THIS FILE USE MIT LICENSE. FOR OUT C# LOVER.
 */

using System;
using System.Runtime.InteropServices;

namespace InlineASM
{
    internal class InlineASM
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr lpAddress, int dwSize, int flNewProtect, out int lpflOldProtect);

        private delegate Int32 ShellcodeMethod(Int32 x, Int32 y);

        internal InlineASM()
        {
            Byte[] shellcode = new Byte[]
            {
                0x8B, 0x44, 0x24, 0x08, // mov eax,dword ptr [esp+8]
                0x8B, 0x4C, 0x24, 0x04, // mov ecx,dword ptr [esp+4]
                0x03, 0xC1,             // add eax,ecx
                0xC2, 0x08, 0x00        // ret 8
            }; // 载体

            IntPtr shellcodePtr = IntPtr.Zero; // 载体句柄

            try
            {
                shellcodePtr = Marshal.AllocCoTaskMem(shellcode.Length); // 分配内存到句柄

                Marshal.Copy(shellcode, 0, shellcodePtr, shellcode.Length); // 加载 载体

                Win32API.VirtualProtect(shellcodePtr, shellcode.Length, 64, out int old); // 更改内存状态为可执行

                ShellcodeMethod scm = (ShellcodeMethod)Marshal.GetDelegateForFunctionPointer(shellcodePtr, typeof(ShellcodeMethod)); // 获取载体的函数指针

                Int32 Result = scm(4, 9); // 设置接收对象接收非托管方法运算值

                Console.WriteLine(Result.ToString();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

            Console.ReadLine();
        }


    }
}
