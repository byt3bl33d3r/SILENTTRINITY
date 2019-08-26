import Microsoft.Win32


public static def Main():
    try:
        persistenceKey = Registry.BASE_KEY.CreateSubKey("KEY", true)
        persistenceKey.SetValue("NAME", "DATA")
        persistenceKey.Close()
    except e:
        print(e)
