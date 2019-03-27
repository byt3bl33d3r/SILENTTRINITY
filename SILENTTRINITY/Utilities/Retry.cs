using System;
using System.Collections.Generic;
using System.Threading;

namespace SILENTTRINITY.Utilities
{
    public static class Retry
    {
        public static T Do<T>(Func<T> action, TimeSpan retryInterval, int maxAttempts = 3)
        {
            var exceptions = new List<Exception>();

            for (int attempts = 0; attempts < maxAttempts; attempts++)
            {
                try
                {
                    if (attempts > 0)
                    {
                        Thread.Sleep(retryInterval);
                    }
#if DEBUG
                    Console.WriteLine(string.Format("[-] Attempt #{0}", attempts + 1));
#endif
                    return action();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("\t [!] {0}", ex.Message);
                    exceptions.Add(ex);
                }
            }

            throw new AggregateException(exceptions);
        }
    }
}
