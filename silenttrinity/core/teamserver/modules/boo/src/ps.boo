/** Name: ProcessManager
 * Author: TheWover
 * Description: Displays useful information about processes running on a local or remote machine.
 *
 * Last Modified: 04/13/2018
 *
 * Boolang port by @byt3bl33d3r
 */

import System
import System.Linq
import System.Diagnostics
import System.Runtime.InteropServices
import System.ComponentModel
import System.Security.Principal


public class ProcessManager:

    private struct Arguments:
        public processname as string
        public machinename as string
        public help as bool

    public static def Run(machinename as string, processname as string):
        Console.WriteLine('{0,-30} {1,-10} {2,-10} {3,-10} {4,-10} {5,-10} {6,-10} {7}', 'Process Name', 'PID', 'PPID', 'Arch', 'Managed', 'Session', 'Integrity', 'User')
        //If the user specifed that a different machine should be used, then parse for the machine name and run the command.
        if machinename.Length > 0:
            try:
                if processname.Length > 0:
                    //Enumerate the processes
                    DescribeProcesses(Process.GetProcessesByName(processname, machinename))
                else:
                    //Enumerate the processes
                    DescribeProcesses(Process.GetProcesses(machinename))
            except :
                Console.WriteLine('Error: Invalid machine name.')
                return
        elif processname.Length > 0:
            //Enumerate the processes
            DescribeProcesses(Process.GetProcessesByName(processname))
        else:
            //Enumerate the processes
            DescribeProcesses(Process.GetProcesses())

    private static def DescribeProcesses(processes as (Process)):
        //Sort in ascending order by PID
        processes = processes.OrderBy({ p | return p.Id }).ToArray()

        for process as Process in processes:
            //Get the PID
            details = ProcessDetails()
            details.name = process.ProcessName
            details.pid = process.Id

            try:
                //Get the PPID
                parent as Process = ParentProcessUtilities.GetParentProcess(process.Id)
                if parent is not null:
                    details.ppid = parent.Id
                else:
                    details.ppid = (-1)
            //Parent is no longer running
            except converterGeneratedName1 as InvalidOperationException:
                details.ppid = (-1)


            //Check the architecture
            try:
                if ProcessInspector.IsWow64Process(process):
                    details.arch = 'x86'
                else:
                    details.arch = 'x64'
            except :
                details.arch = '*'

            try:
                //Determine whether or not the process is managed (has the CLR loaded).
                details.managed = ProcessInspector.IsCLRLoaded(process)
            //Process is no longer running
            except converterGeneratedName2 as InvalidOperationException:
                details.managed = false


            try:
                //Gets the Session of the Process
                details.session = process.SessionId
            //Process is no longer running
            except converterGeneratedName3 as InvalidOperationException:
                details.session = (-1)


            try:
                //Gets the Integrity Level of the process
                details.integrity = TokenInspector.GetIntegrityLevel(process)
            //Process is no longer running
            except converterGeneratedName4 as InvalidOperationException:
                details.integrity = TokenInspector.IntegrityLevel.Unknown


            try:
                //Gets the User of the Process
                details.user = ProcessInspector.GetProcessUser(process)
            //Process is no longer running
            except converterGeneratedName5 as InvalidOperationException:
                details.user = ''

            Console.WriteLine('{0,-30} {1,-10} {2,-10} {3,-10} {4,-10} {5,-10} {6,-10} {7}', details.name, details.pid, details.ppid, details.arch, details.managed, details.session, details.integrity, details.user)


public struct ProcessDetails:
    public name as string
    public pid as int
    public ppid as int
    public arch as string
    public managed as bool
    public session as int
    public integrity as TokenInspector.IntegrityLevel
    public user as string


public static class ProcessInspector:


    [System.Runtime.InteropServices.DllImport('kernel32.dll')]
    public static def IsWow64Process(hProcess as System.IntPtr, ref lpSystemInfo as bool) as bool:
        pass


    [DllImport('ntdll.dll')]
    private static def NtQueryInformationProcess(processHandle as IntPtr, processInformationClass as int, ref processInformation as ParentProcessUtilities, processInformationLength as int, ref returnLength as int) as int:
        pass


    [DllImport('advapi32.dll', SetLastError: true)]
    private static def OpenProcessToken(ProcessHandle as IntPtr, DesiredAccess as uint, ref TokenHandle as IntPtr) as bool:
        pass

    [DllImport('kernel32.dll', SetLastError: true)]
    private static def CloseHandle(hObject as IntPtr) as bool:
        pass


    public static def GetParentProcess(process as Process) as Process:
        return ParentProcessUtilities.GetParentProcess(process.Id)


    public static def GetParentProcess() as Process:
        return GetParentProcess(Process.GetCurrentProcess())


    public static def IsWow64Process(process as Process) as bool:
        retVal = false
        IsWow64Process(process.Handle, retVal)
        return retVal


    public static def IsWow64Process() as bool:
        retVal = false
        IsWow64Process(Process.GetCurrentProcess().Handle, retVal)
        return retVal


    public static def IsCLRLoaded(process as Process) as bool:
        try:
            modules as List

            modules = [module for module in process.Modules.OfType[of ProcessModule]()]

            return modules.Any({ pm as duck| return pm.ModuleName.Contains('mscor')})
        //Access was denied
        except converterGeneratedName6 as Win32Exception:
            return false
        //Process has already exited
        except converterGeneratedName7 as InvalidOperationException:
            return false



    public static def GetProcessUser(process as Process) as string:
        processHandle as IntPtr = IntPtr.Zero
        try:
            OpenProcessToken(process.Handle, 8, processHandle)
            wi = WindowsIdentity(processHandle)
            return wi.Name
        except :
            return null
        ensure:
            if processHandle != IntPtr.Zero:
                CloseHandle(processHandle)


//end class
[StructLayout(LayoutKind.Sequential)]
public struct ParentProcessUtilities:
    // These members must match PROCESS_BASIC_INFORMATION
    internal Reserved1 as IntPtr
    internal PebBaseAddress as IntPtr
    internal Reserved2_0 as IntPtr
    internal Reserved2_1 as IntPtr
    internal UniqueProcessId as IntPtr
    internal InheritedFromUniqueProcessId as IntPtr


    [DllImport('ntdll.dll')]
    private static def NtQueryInformationProcess(processHandle as IntPtr, processInformationClass as int, ref processInformation as ParentProcessUtilities, processInformationLength as int, ref returnLength as int) as int:
        pass


    public static def GetParentProcess() as Process:
        return GetParentProcess(Process.GetCurrentProcess().Handle)


    public static def GetParentProcess(id as int) as Process:
        try:
            process as Process = Process.GetProcessById(id)

            GetParentProcess(process.Handle)

            return GetParentProcess(process.Handle)
        //Access was denied, or
        except :
            return null


    public static def GetParentProcess(handle as IntPtr) as Process:
        pbi = ParentProcessUtilities()
        returnLength as int
        status as int = NtQueryInformationProcess(handle, 0, pbi, Marshal.SizeOf(pbi), returnLength)
        if status != 0:
            raise Win32Exception(status)

        try:
            return Process.GetProcessById(pbi.InheritedFromUniqueProcessId.ToInt32())
        except converterGeneratedName8 as ArgumentException:
            // not found
            return null


public class TokenInspector:

    [DllImport('advapi32.dll', SetLastError: true)]
    private static def GetSidSubAuthority(sid as IntPtr, subAuthorityIndex as UInt32) as IntPtr:
        pass


    [DllImport('advapi32.dll', SetLastError: true)]
    private static def GetSidSubAuthorityCount(sid as IntPtr) as IntPtr:
        pass


    // winnt.h, Windows SDK v6.1
    private static final SECURITY_MANDATORY_UNTRUSTED_RID = 0

    private static final SECURITY_MANDATORY_LOW_RID = 4096

    private static final SECURITY_MANDATORY_MEDIUM_RID = 8192

    private static final SECURITY_MANDATORY_HIGH_RID = 12288

    private static final SECURITY_MANDATORY_SYSTEM_RID = 16384

    private static final SECURITY_MANDATORY_PROTECTED_PROCESS_RID = 20480


    [DllImport('advapi32.dll', SetLastError: true)]
    private static def OpenProcessToken(ProcessHandle as IntPtr, DesiredAccess as UInt32, ref TokenHandle as IntPtr) as bool:
        pass


    private static final TOKEN_QUERY as UInt32 = 8


    [DllImport('advapi32.dll', SetLastError: true)]
    private static def GetTokenInformation(TokenHandle as IntPtr, TokenInformationClass as TOKEN_INFORMATION_CLASS, TokenInformation as IntPtr, TokenInformationLength as uint, ref ReturnLength as uint) as bool:
        pass


    private enum TOKEN_INFORMATION_CLASS:
        TokenUser = 1
        TokenGroups
        TokenPrivileges
        TokenOwner
        TokenPrimaryGroup
        TokenDefaultDacl
        TokenSource
        TokenType
        TokenImpersonationLevel
        TokenStatistics
        TokenRestrictedSids
        TokenSessionId
        TokenGroupsAndPrivileges
        TokenSessionReference
        TokenSandBoxInert
        TokenAuditPolicy
        TokenOrigin
        TokenElevationType
        TokenLinkedToken
        TokenElevation
        TokenHasRestrictions
        TokenAccessInformation
        TokenVirtualizationAllowed
        TokenVirtualizationEnabled
        TokenIntegrityLevel
        TokenUIAccess
        TokenMandatoryPolicy
        TokenLogonSid
        MaxTokenInfoClass


    public enum IntegrityLevel:
        Low
        Medium
        High
        System
        None
        Unknown


    private static final ERROR_INVALID_PARAMETER = 87


    [DllImport('kernel32.dll', SetLastError: true)]
    private static def CloseHandle(hHandle as IntPtr) as bool:
        pass



    public static def GetIntegrityLevel(process as Process) as IntegrityLevel:
        try:
            pId as IntPtr = process.Handle
            hToken as IntPtr = IntPtr.Zero
            if OpenProcessToken(pId, TOKEN_QUERY, hToken):
                try:
                    pb as IntPtr = Marshal.AllocCoTaskMem(1000)
                    try:
                        cb as uint = 1000
                        if GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pb, cb, cb):
                            pSid as IntPtr = Marshal.ReadIntPtr(pb)

                            dwIntegrityLevel as int = Marshal.ReadInt32(GetSidSubAuthority(pSid, (Marshal.ReadByte(GetSidSubAuthorityCount(pSid)) - 1)))

                            if dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID:
                                return IntegrityLevel.Low
                            elif (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID) and (dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID):
                                // Medium Integrity
                                return IntegrityLevel.Medium
                            elif dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID:
                                // High Integrity
                                return IntegrityLevel.High
                            elif dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID:
                                // System Integrity
                                return IntegrityLevel.System
                            return IntegrityLevel.None
                        else:
                            return IntegrityLevel.Unknown
                    ensure:
                        Marshal.FreeCoTaskMem(pb)
                ensure:
                    CloseHandle(hToken)

        except ex as Win32Exception:
            return IntegrityLevel.Unknown

        //If we made it this far through all of the finally blocks and didn't return, then return unknown
        return IntegrityLevel.Unknown


public static def Main():
    machinename = "MACHINE_NAME"
    processname = "PROCESS_NAME"
    ProcessManager.Run(machinename, processname)
