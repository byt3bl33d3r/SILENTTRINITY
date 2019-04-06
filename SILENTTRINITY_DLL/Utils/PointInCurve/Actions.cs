using System.IO;
using System.Runtime.Serialization.Json;
using System.Text;

namespace Kaliya.Utils.PointInCurve
{
    public static class Actions
    {
        // Create a User object and serialize it to a JSON stream.  
        public static string WriteJson(Coordinates keyCoords)
        {
            //Create a stream to serialize the object to.  
            var ms = new MemoryStream();

            // Serializer the User object to the stream.  
            var serializer = new DataContractJsonSerializer(typeof(Coordinates));
            serializer.WriteObject(ms, keyCoords);
            var json = ms.ToArray();
            ms.Close();
            return Encoding.UTF8.GetString(json, 0, json.Length);
        }

        // Deserialize a JSON stream to a User object.  
        public static Coordinates ParseJson(string json)
        {
            var deserializedKeyCoords = new Coordinates();
            var ms = new MemoryStream(Encoding.UTF8.GetBytes(json));
            var ser = new DataContractJsonSerializer(deserializedKeyCoords.GetType());
            deserializedKeyCoords = ser.ReadObject(ms) as Coordinates;
            ms.Close();
            return deserializedKeyCoords;
        }
    }
  
}