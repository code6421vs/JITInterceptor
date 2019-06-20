using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace JITInterceptor
{
    class Program
    {
        class MyTest
        {
            public static void TestStatic()
            {
                Console.WriteLine("Static");
            }

            public void TestInstance()
            {
                Console.WriteLine("Instance");
            }
        }

        static void Main(string[] args)
        {
            JITInterceptor.RegisterModule(typeof(MyTest).Module);            
            JITInterceptor.Initialize();
            MyTest.TestStatic();
            var c = new MyTest();
            c.TestInstance();
            JITInterceptor.UnInitialize();
            Console.ReadLine();
        }
    }
}
