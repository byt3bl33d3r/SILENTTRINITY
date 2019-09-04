/*
    This module is inspired from SharpSploit (https://github.com/cobbr/SharpSploit)
*/
import System
import System.Diagnostics
import System.Management

public static def Main():
    print "[*] Listing running processes:\r\n"
    processes as (Process) = Process.GetProcesses()
    for process as Process in processes:
        search as ManagementObjectSearcher = ManagementObjectSearcher("root\\CIMV2", string.Format("SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {0}", process.Id))
        pidresult = search.Get().GetEnumerator()
        pidresult.MoveNext()
        parentId as uint = pidresult.Current["ParentProcessId"];
        print "\r\nProcess ID:         " + process.Id
        print "Parent process ID:  " + Convert.ToInt32(parentId)
        print "Process Name:       " + process.ProcessName
