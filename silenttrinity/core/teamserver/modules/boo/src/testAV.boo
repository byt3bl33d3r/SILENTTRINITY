/*
    This module is inspired from TestAntivirus (https://github.com/vletoux/TestAntivirus)
*/
import System
import System.Net
import System.Runtime.InteropServices
import System.Collections.Generic
import System.ComponentModel
import System.Diagnostics
import System.Runtime.InteropServices
import System.Security.Permissions
import System.Security.Principal
import System.Text

[DllImport('advapi32.dll', SetLastError: true)]
def LookupAccountName(
    lpSystemName as string,
    lpAccountName as string,
    [MarshalAs(UnmanagedType.LPArray)] Sid as (byte),
    ref cbSid as uint, ReferencedDomainName as StringBuilder,
    ref cchReferencedDomainName as uint,
    ref peUse as SID_NAME_USE
) as bool:
    pass

public enum SID_NAME_USE:
    SidTypeUser = 1
    SidTypeGroup
    SidTypeDomain
    SidTypeAlias
    SidTypeWellKnownGroup
    SidTypeDeletedAccount
    SidTypeInvalid
    SidTypeUnknown
    SidTypeComputer

def ConvertNameToSID(accountName as string, server as string) as SecurityIdentifier:
    NO_ERROR = 0
    ERROR_INSUFFICIENT_BUFFER = 122
    ERROR_INVALID_FLAGS = 1004

    Sid as (byte) = null
    cbSid as uint = 0
    referencedDomainName = StringBuilder()
    cchReferencedDomainName = (referencedDomainName.Capacity cast uint)
    sidUse as SID_NAME_USE

    err as int = NO_ERROR

    if LookupAccountName(server, accountName, Sid, cbSid, referencedDomainName, cchReferencedDomainName, sidUse):
        return SecurityIdentifier(Sid, 0)
    else:
        err = Marshal.GetLastWin32Error()
        if (err == ERROR_INSUFFICIENT_BUFFER) or (err == ERROR_INVALID_FLAGS):
            Sid = array(byte, cbSid)
            referencedDomainName.EnsureCapacity((cchReferencedDomainName cast int))
            err = NO_ERROR
            if LookupAccountName(null, accountName, Sid, cbSid, referencedDomainName, cchReferencedDomainName, sidUse):
                return SecurityIdentifier(Sid, 0)
    return null

public static def Main():

    computerName = "COMPUTER_NAME"

    dictionary = {"avast! Antivirus" : "Avast",
        "aswBcc" : "Avast",
        "Avast Business Console Client Antivirus Service" : "Avast",
        "epag" : "Bitdefender Endpoint Agent",
        "EPIntegrationService" : "Bitdefender Endpoint Integration Service",
        "EPProtectedService" : "Bitdefender Endpoint Protected Service",
        "epredline" : "Bitdefender Endpoint Redline Services",
        "EPSecurityService" : "Bitdefender Endpoint Security Service",
        "EPUpdateService" : "Bitdefender Endpoint Update Service",
        "CylanceSvc" : "Cylance",
        "epfw" : "ESET",
        "epfwlwf" : "ESET",
        "epfwwfp" : "ESET",
        "xagt" : "FireEye Endpoint Agent",
        "fgprocsvc" : "ForeScout Remote Inspection Service",
        "SecureConnector" : "ForeScout SecureConnector Service",
        "fsdevcon" : "F-Secure",
        "FSDFWD" : "F-Secure",
        "F-Secure Network Request Broker" : "F-Secure",
        "FSMA" : "F-Secure",
        "FSORSPClient" : "F-Secure",
        "klif" : "Kasperksky",
        "klim" : "Kasperksky",
        "kltdi" : "Kasperksky",
        "kavfsslp" : "Kasperksky",
        "KAVFSGT" : "Kasperksky",
        "KAVFS" : "Kasperksky",
        "enterceptagent" : "MacAfee",
        "macmnsvc" : "MacAfee Agent Common Services",
        "masvc" : "MacAfee Agent Service",
        "McAfeeFramework" : "MacAfee Agent Backwards Compatiblity Service",
        "McAfeeEngineService" : "MacAfee",
        "mfefire" : "MacAfee Firewall Core Service",
        "mfemms" : "MacAfee Service Controller",
        "mfevtp" : "MacAfee Validation Trust Protection Service",
        "mfewc" : "MacAfee Endpoint Security Web Control Service",
        "cyverak" : "PaloAlto Traps KernelDriver",
        "cyvrmtgn" : "PaloAlto Traps KernelDriver",
        "cyvrfsfd" : "PaloAlto Traps FileSystemDriver",
        "cyserver" : "PaloAlto Traps Reporting Service",
        "CyveraService" : "PaloAlto Traps",
        "tlaservice" : "PaloAlto Traps Local Analysis Service",
        "twdservice" : "PaloAlto Traps Watchdog Service",
        "SentinelAgent" : "SentinelOne",
        "SentinelHelperService" : "SentinelOne",
        "SentinelStaticEngine " : "SentinelIbe Static Service",
        "LogProcessorService " : "SentinelOne Agent Log Processing Service",
        "sophosssp" : "Sophos",
        "Sophos Agent" : "Sophos",
        "Sophos AutoUpdate Service" : "Sophos",
        "Sophos Clean Service" : "Sophos",
        "Sophos Device Control Service" : "Sophos",
        "Sophos File Scanner Service" : "Sophos",
        "Sophos Health Service" : "Sophos",
        "Sophos MCS Agent" : "Sophos",
        "Sophos MCS Client" : "Sophos",
        "Sophos Message Router" : "Sophos",
        "Sophos Safestore Service" : "Sophos",
        "Sophos System Protection Service" : "Sophos",
        "Sophos Web Control Service" : "Sophos",
        "sophossps" : "Sophos",
        "SepMasterService" : "Symantec Endpoint Protection",
        "SNAC" : "Symantec Network Access Control",
        "Symantec System Recovery" : "Symantec System Recovery",
        "Smcinst" : "Symantec Connect",
        "SmcService" : "Symantec Connect",
        "AMSP" : "Trend",
        "tmcomm" : "Trend",
        "tmactmon" : "Trend",
        "tmevtmgr" : "Trend",
        "ntrtscan" : "Trend Micro Worry Free Business",
        "WRSVC" : "Webroot",
        "WinDefend" : "Windows Defender Antivirus Service",
        "Sense " : "Windows Defender Advanced Threat Protection Service",
        "WdNisSvc " : "Windows Defender Antivirus Network Inspection Service"}

    if not computerName:
        print "\r\n[*] Retrieving antivirus of machine " + Dns.GetHostName() + " (localhost)\r\n"
    else:
        print "\r\n[*] Retrieving antivirus of machine " + computerName + "\r\n"

    for entry in dictionary:
        if (ConvertNameToSID("NT Service\\" + entry.Key, computerName) != null):
            print "found: " + entry.Value + " with " + entry.Key + "\r\n"
