namespace Kaliya.Utils
{
    public static class Extras
    {
        public static string GetDllName(string name)
        {
            var dllName = name + ".dll";
            if (name.IndexOf(',') > 0)
            {
                dllName = name.Substring(0, name.IndexOf(',')) + ".dll";
            }

            return dllName;
        }
    }
}