import clr
clr.AddReference ("System")
clr.AddReference ("System.Management")
clr.AddReference("System.Core")

import System.Diagnostics
import System.Management
from System import Array

def GetProcessExtraInformation(ProcessId):
    Query = "Select * From Win32_Process Where ProcessID = " + str(ProcessId)
    Searcher = System.Management.ManagementObjectSearcher(Query)
    ProcessList = Searcher.Get()
    Description = "No Description"
    Username = "Unknown"
    for Object in ProcessList:
        ArgList = Array[str](['', ''])
        ReturnVal = System.Convert.ToInt32(Object.InvokeMethod("GetOwner", ArgList))
        if ReturnVal == 0:
            Username = "%s\\%s" % (ArgList[1], ArgList[0])
        if Object["ExecutablePath"] is not None:
            try:
                Info = System.Diagnostics.FileVersionInfo.GetVersionInfo(Object["ExecutablePath"].ToString())
                Description = Info.FileDescription
            except:
                pass
    return Username, Description

def ConvertToHumanReadableNumber(Num):
    for Unit in ['B','KiB','MiB','GiB','TiB','PiB']:
        if abs(Num) < 1024.0:
            return "%3.1f%s" % (Num, Unit)
        else:
            Num /= 1024.0

ProcessList = System.Diagnostics.Process.GetProcesses()

print("|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|")
print('| {:<40} | {:<6} | {:<10} | {:<12} | {:<30} | {:<50} |'.format("ProcessName", "PID", "Responsive", "Memory Usage", "ProcessOwner", "Description"))
print("|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|")

for Process in ProcessList:
        ExtraInfo = GetProcessExtraInformation(Process.Id)
        print('| {:<40} | {:<6} | {:<10} | {:<12} | {:<30} | {:<50} |'.format(Process.ProcessName, Process.Id, Process.Responding, ConvertToHumanReadableNumber(Process.PrivateMemorySize64), ExtraInfo[0], ExtraInfo[1]))