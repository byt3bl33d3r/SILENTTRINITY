using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace SILENTTRINITY.Utilities
{
    public static class Http
    {
        async public static Task<byte[]> GetAsync(Uri url)
        {
            return await new HttpClient().GetByteArrayAsync(url);
        }

        async public static Task<byte[]> PostAsync(Uri url, byte[] payload)
        {
            HttpClient client = new HttpClient();

            ByteArrayContent content = new ByteArrayContent(payload);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            content.Headers.ContentLength = payload.Length;

            HttpResponseMessage response = await client.PostAsync(url, content);

            if (response.StatusCode != HttpStatusCode.OK)
            {
                return default(byte[]);
            }

            return await response.Content.ReadAsByteArrayAsync();
        }
    }
}
