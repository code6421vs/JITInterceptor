using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace JITInterceptor
{
    internal class JITInterceptor
    {
        private static class JITNative
        {
            internal enum Protection
            {
                PAGE_NOACCESS = 0x01,
                PAGE_READONLY = 0x02,
                PAGE_READWRITE = 0x04,
                PAGE_WRITECOPY = 0x08,
                PAGE_EXECUTE = 0x10,
                PAGE_EXECUTE_READ = 0x20,
                PAGE_EXECUTE_READWRITE = 0x40,
                PAGE_EXECUTE_WRITECOPY = 0x80,
                PAGE_GUARD = 0x100,
                PAGE_NOCACHE = 0x200,
                PAGE_WRITECOMBINE = 0x400
            }

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize,
               Protection flNewProtect, out uint lpflOldProtect);

            [StructLayout(LayoutKind.Sequential)]
            public struct CorinfoSigInst
            {
                public uint classInstCount;
                public unsafe IntPtr* classInst;
                public uint methInstCount;
                public unsafe IntPtr* methInst;
            }

            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct CorMethodInfo
            {
                public IntPtr methodHandle;
                public IntPtr moduleHandle;
                public IntPtr ilCode;
                public UInt32 ilCodeSize;
                public UInt16 maxStack;
                public UInt16 EHCount;
                public UInt32 corInfoOptions;
                public CorinfoSigInst args;
                public CorinfoSigInst locals;
            }

            [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
            public unsafe delegate int CompileMethodDelegate(
                IntPtr thisPtr, [In] IntPtr corJitInfo, [In] CorMethodInfo* methodInfo, int flags,
                [Out] IntPtr nativeEntry, [Out] IntPtr nativeSizeOfCode);
        }


        [DllImport("Clrjit.dll", CallingConvention = CallingConvention.StdCall, PreserveSig = true)]
        private static extern IntPtr getJit();

        public static IntPtr VTableAddr
        {
            get
            {
                IntPtr pVTable = getJit();
                if (pVTable == IntPtr.Zero)
                    throw new Exception("Could not retrieve address for getJit");

                return pVTable;
            }
        }

        private static JITNative.CompileMethodDelegate OriginalCompileMethod;
        private static JITNative.CompileMethodDelegate NewCompileMethod;
        private static Dictionary<IntPtr, Module> _interceptorModules = new Dictionary<IntPtr, Module>();

        public static void RegisterModule(Module module)
        {
            var mPtr = module.ModuleHandle.GetType()
                .GetField("m_ptr",
                    BindingFlags.NonPublic | BindingFlags.Instance);
            var mPtrValue = mPtr.GetValue(module.ModuleHandle);
            var mpData =
                mPtrValue.GetType()
                    .GetField("m_pData",
                        BindingFlags.NonPublic | BindingFlags.Instance);
            var mpDataValue = (IntPtr) mpData.GetValue(mPtrValue);
            if (!_interceptorModules.ContainsKey(mpDataValue))
                _interceptorModules[mpDataValue] = module;
        }

        private static Module FindModule(IntPtr modulePtr)
        {
            if (_interceptorModules.ContainsKey(modulePtr))
                return _interceptorModules[modulePtr];
            return null;
        }
        
        private static unsafe int HookedCompileMethod(IntPtr thisPtr, [In] IntPtr corJitInfo,
            [In] JITNative.CorMethodInfo* methodInfo, int flags,
            [Out] IntPtr nativeEntry, [Out] IntPtr nativeSizeOfCode)
        {
            int token;
            var module = FindModule(methodInfo->moduleHandle);
            if (module != null)
            {
                token = (0x06000000 + *(ushort*)methodInfo->methodHandle);
                Console.WriteLine("\r\n");
                Console.WriteLine("Name: " + module.ResolveMethod(token).Name);
            }

            return OriginalCompileMethod(thisPtr, corJitInfo, methodInfo, flags, nativeEntry, nativeSizeOfCode);
        }

        public static unsafe bool Initialize()
        {
            NewCompileMethod = HookedCompileMethod;
            IntPtr pCompileMethod = Marshal.ReadIntPtr(VTableAddr);
            uint old;

            if (
                !JITNative.VirtualProtect(pCompileMethod, (uint)IntPtr.Size,
                    JITNative.Protection.PAGE_EXECUTE_READWRITE, out old))
                return false;

            OriginalCompileMethod =
                (JITNative.CompileMethodDelegate)
                    Marshal.GetDelegateForFunctionPointer(Marshal.ReadIntPtr(pCompileMethod), typeof(JITNative.CompileMethodDelegate));

            RuntimeHelpers.PrepareDelegate(NewCompileMethod);
            RuntimeHelpers.PrepareDelegate(OriginalCompileMethod);
            RuntimeHelpers.PrepareMethod(typeof(JITInterceptor).GetMethod("Initialize", BindingFlags.Static | BindingFlags.Public).MethodHandle);
            RuntimeHelpers.PrepareMethod(typeof(JITInterceptor).GetMethod("FindModule", BindingFlags.Static | BindingFlags.NonPublic).MethodHandle);

            Marshal.WriteIntPtr(pCompileMethod, Marshal.GetFunctionPointerForDelegate(NewCompileMethod));

            return JITNative.VirtualProtect(pCompileMethod, (uint)IntPtr.Size,
                (JITNative.Protection)old, out old);
        }

        public static bool UnInitialize()
        {
            IntPtr pCompileMethod = Marshal.ReadIntPtr(VTableAddr);
            uint old;

            if (
                !JITNative.VirtualProtect(pCompileMethod, (uint)IntPtr.Size,
                    JITNative.Protection.PAGE_EXECUTE_READWRITE, out old))
                return false;

            Marshal.WriteIntPtr(pCompileMethod, Marshal.GetFunctionPointerForDelegate(OriginalCompileMethod));

            return JITNative.VirtualProtect(pCompileMethod, (uint)IntPtr.Size,
                (JITNative.Protection)old, out old);
        }
    }
}
