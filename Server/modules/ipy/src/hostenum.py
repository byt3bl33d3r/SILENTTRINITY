import clr
clr.AddReference("System.Management")
clr.AddReference("System.Web.Extensions")

import System.BitConverter as BitConverter
import System.DateTime as DateTime
import System.DateTimeKind as DateTimeKind
import System.DateTimeOffset as DateTimeOffset
import System.Diagnostics as Diagnostics
import System.Diagnostics.Process as Process
import System.Diagnostics.EventLog as EventLog
import System.Environment as Env
import System.Net.IPAddress as IPAddress
import System.Net.NetworkInformation as NetworkInformation
from Microsoft.Win32 import Registry, RegistryKey
from System import Array, Byte, IntPtr, Console, UInt32, Boolean, Convert, String, Type, Activator
from System.Collections.Generic import Queue
from System.IO import Directory, DirectoryInfo, DriveInfo, SearchOption
from System.Management import ManagementScope, ManagementObjectSearcher, WqlObjectQuery
from System.Security.Principal import NTAccount, SecurityIdentifier, WindowsPrincipal, WindowsIdentity,  WindowsBuiltInRole
from System.Text.RegularExpressions import Regex
from System.Web.Script.Serialization import JavaScriptSerializer

def printHeader(header):
    return "{0}\n{1:^20}\n{0}\n".format("*" * 20, header, "*" * 20)

def printSubheader(header):
    return "\n{0}\n{1}\n".format(header, "-" * len(header))

def convertNumToIP(ipNum):
    ipBytes = IPAddress.Parse(ipNum.ToString()).GetAddressBytes()
    Array.Reverse(ipBytes)
    return IPAddress(ipBytes).ToString()

def recurseKeys(subkey, keySummary):
    if subkey.SubKeyCount:
        for sub in sorted(subkey.GetSubKeyNames()):
            try:
                curKey = subkey.OpenSubKey(sub)
                if curKey.ValueCount:
                    keySummary += printSubheader(curKey.ToString())
                    for value in sorted(curKey.GetValueNames()):
                            keySummary += "{0:<40} {1}\n".format(value, curKey.GetValue(value))
                    recurseKeys(curKey, keySummary)
            except (SystemError):
                pass
            finally:
                if curKey:
                    curKey.Close()
                    
    return keySummary

def recursiveFiles(root, filetype, summary):
    dirQ = Queue[DirectoryInfo]()
    dirQ.Enqueue(root)

    while dirQ.Count:
        curDir = dirQ.Dequeue()
        try:
            for file in curDir.GetFiles(filetype):
                summary += file.FullName.ToString() + "\n"
            dirList = curDir.GetDirectories()
            for d in dirList:
                if not "appdata" in d.FullName.ToString().ToLower():
                    dirQ.Enqueue(d)
        except (SystemError, IOError):
            pass

    return summary

def systemInfo():
    verInfo = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    psKey = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine"
    sysPolKey = r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System"

    sysSummary = printHeader("SYSTEM INFORMATION")
    sysSummary += "{0:<10}: {1}\n".format("Host", Env.MachineName)
    sysSummary += "{0:<10}: {1} {2}\n".format("OS", Registry.GetValue(verInfo, "ProductName", "Windows"), Diagnostics.FileVersionInfo.GetVersionInfo(Env.SystemDirectory + "\\kernel32.dll").ProductVersion)
    sysSummary += "{0:<10}: {1}\n".format("64-Bit", Env.Is64BitOperatingSystem)
    sysSummary += "{0:<10}: {1}\n".format("Date", DateTime.Now.ToString())
    sysSummary += "{0:<10}: {1}\n\n".format("Uptime", DateTimeOffset(DateTime.Now).AddMilliseconds(-Env.TickCount).LocalDateTime)
    
    sysSummary += "{0:<14}: {1}\{2}\n".format("Username", Env.UserDomainName, Env.UserName)
    sysSummary += "{0:<14}: {1}\n\n".format("Logon Server", Env.GetEnvironmentVariable("LOGONSERVER"))

    sysSummary += "{0:<22}: {1}\n".format("PowerShell Version", Registry.GetValue(psKey, "PowerShellVersion", "N/A - Likely 2.0"))
    sysSummary += "{0:<22}: {1}\n".format("PowerShell Compat", Registry.GetValue(psKey, "PSCompatibleVersion", "N/A - Likely 1.0, 2.0"))
    sysSummary += "{0:<22}: {1}\n".format("PS Script Block Log", Registry.GetValue("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging", "N/A"))
    sysSummary += "{0:<22}: {1}\n".format("PS Transcription", Registry.GetValue("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription", "EnableTranscripting", "N/A"))
    sysSummary += "{0:<22}: {1}\n".format("PS Transcription Dir", Registry.GetValue("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription", "OutputDirectory", "N/A"))
    sysSummary += "{0:<22}: {1}\n\n".format("PS Module Logging", Registry.GetValue("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging", "EnableModuleLogging", "N/A"))

    sysSummary += "{0:<27}: {1}\n".format("UAC Enabled", Convert.ToBoolean(Registry.GetValue(sysPolKey, "EnableLUA", "N/A")))
    sysSummary += "{0:<27}: {1}\n".format("High Integrity", WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
    sysSummary += "{0:<27}: {1}\n".format("UAC Token Filter Disabled", Registry.GetValue(sysPolKey, "LocalAccount", False))
    sysSummary += "{0:<27}: {1}\n".format("UAC Admin Filter Enabled", Registry.GetValue(sysPolKey, "FilterAdministratorToken", False))
    sysSummary += "{0:<27}: {1}\n".format("Local Admin Pass Solution", Registry.GetValue("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd", "AdmPwdEnabled", "N/A"))
    sysSummary += "{0:<27}: {1}\n".format("LSASS Protection", Registry.GetValue("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", "N/A"))
    sysSummary += "{0:<27}: {1}\n".format("Deny RDP Connections", Convert.ToBoolean(Registry.GetValue("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server", "FDenyTSConnections", "N/A")))

    return sysSummary

def avLookup():
    summary = printHeader("ANTIVIRUS CHECK")
    table = {
        'mcshield' :  "McAfee AV",
        'FrameworkService' :  "McAfee AV",
        'naPrdMgr' :  "McAfee AV",
        'windefend' :  "Windows Defender AV",
        'MSASCui' :  "Windows Defender AV",
        'msmpeng' :  "Windows Defender AV",
        'msmpsvc' :  "Windows Defender AV",
        'WRSA' :  "WebRoot AV",
        'savservice' :  "Sophos AV",
        'TMCCSF' :  "Trend Micro AV",
        'ntrtscan': "TrendMicro OfficeScan",
        "symantec antivirus" :  "Symantec AV",
        'ccSvcHst' :  "Symantec Endpoint Protection",
        'TaniumClient' :  "Tanium",
        'mbae' :  "MalwareBytes Anti-Exploit",
        'parity' :  "Bit9 application whitelisting",
        'cb' :  "Carbon Black behavioral analysis",
        "bds-vision" :  "BDS Vision behavioral analysis",
        'Triumfant' :  "Triumfant behavioral analysis",
        'CSFalcon' :  "CrowdStrike Falcon EDR",
        'ossec' :  "OSSEC intrusion detection",
        'TmPfw' :  "Trend Micro firewall",
        'dgagent' :  "Verdasys Digital Guardian DLP",
        'kvoop' :  "Forcepoint and others",
        'xagt' :  "FireEye Endpoint Agent",
        'bdservicehost': 'BitDefender AV',
        'bdagent': 'BitDefender AV',
        'fsav32': 'F-Secure AV',
        'ashServ': "Avast! AV",
        'AVENGINE': "Panda AV",
        'avgemc': "AVG AV",
        'tmntsrv': "TrendMicro AV",
        'nacapsvc': "Norton AV",
        'avp': "Kaspersky AV"
    }

    states = {
        "262144": "Up to date/Disabled",
        "262160": "Out of date/Disabled",
        "266240": "Up to date/Enabled",
        "266256": "Out of date/Enabled",
        "393216": "Up to date/Disabled",
        "393232": "Out of date/Disabled",
        "393488": "Out of date/Disabled",
        "397312": "Up to date/Enabled",
        "397328": "Out of date/Enabled",
        "397584": "Out of date/Enabled",
        "397568": "Up to date/Enabled",
        "393472": "Up to date/Disabled"
    }

    results = {}
    for av, name in table.items():
        proc = Process.GetProcessesByName(av)
        if proc:
            summary += "{0:<15}: {1}\n".format("AVProduct", name)
            summary += "{0:<15}: {1}\n".format("ProcessName", proc[0].ProcessName)
            summary += "{0:<15}: {1}\n\n".format("PID", proc[0].Id)


    scope = ManagementScope(r"\\%s\root\securitycenter2" % Env.MachineName)
    query = "Select * from antivirusproduct"
    search = ManagementObjectSearcher(scope, WqlObjectQuery(query), None)
    for result in search.Get():
        summary += "{0:<22}: {1}\n".format("Display Name", result.GetPropertyValue("displayName"))
        summary += "{0:<22}: {1}\n".format("Signed Product EXE:", result.GetPropertyValue("pathToSignedProductExe"))
        summary += "{0:<22}: {1}\n".format("Signed Reporting EXE:", result.GetPropertyValue("pathToSignedReportingExe"))
        summary += "{0:<22}: {1}\n".format("Product State", states.get(result.GetPropertyValue("productState").ToString()) or result.GetPropertyValue("productState") )
        summary += "{0:<22}: {1}\n\n".format("Update Time", result.GetPropertyValue("timestamp"))

    return summary

def environment():
    envSummary = printHeader("ENVIRONMENT")
    return envSummary + "".join(["{0:<25} --- {1}\n".format(var.Key, var.Value) for var in Env.GetEnvironmentVariables()])

def processList():
    summary = printHeader("PROCESS LIST")
    search = ManagementObjectSearcher("select * from Win32_process")
    summary += printSubheader("{0:<8} {1:<25} {2:<40} {3}".format("PID", "Name", "Owner", "Path"))
    for result in sorted(search.Get(), key=lambda x: int(x["Handle"])):
        args = Array[str](["", ""])
        owner = result.InvokeMethod("GetOwner", args)
        pOwn = "\\".join(args[::-1]) if args[0] != None else ""
        summary += "{0:<8} {1:<25} {2:<40} {3}\n".format(result["Handle"], result["Name"][:25], pOwn, result["ExecutablePath"] or "" )
    return summary

def userGroups():
    iden = WindowsIdentity.GetCurrent()
    userSummary = printHeader("USER GROUPS")
    for sid in iden.Groups:
        userSummary += "{0:<35}: {1}\n".format(SecurityIdentifier(sid.ToString()).Translate(NTAccount), sid) 

    return userSummary

def ipconfig():
    gp = NetworkInformation.IPGlobalProperties.GetIPGlobalProperties()
    details = (gp.HostName, gp.DomainName, gp.NodeType, gp.DhcpScopeName, gp.IsWinsProxy)
    ipconfigSummary = printHeader("IPCONFIG")
    ipconfigSummary += """Computer Name: {0}
    Domain Name: {1}
    Node Type: {2}
    DHCP Scope: {3}
    WINS Proxy: {4}\n""".format(*details)
    interfaces = NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
    for iface in interfaces:
        properties = iface.GetIPProperties()
        physAddr = iface.GetPhysicalAddress().ToString()
        physAddr = ":".join(x+y for x,y in zip(physAddr[::2], physAddr[1::2]))
        uniAddrs = ", ".join([uni.Address.ToString() for uni in properties.UnicastAddresses if uni.Address.AddressFamily.ToString() == "InterNetwork"])
        multiAddrs = ", ".join([multi.Address.ToString() for multi in properties.MulticastAddresses if multi.Address.AddressFamily.ToString() == "InterNetwork"])
        dhcpAddrs = ", ".join([convertNumToIP(dhcp.Address) for dhcp in properties.DhcpServerAddresses])
        
        try:
            dnsAddrs = ", ".join([convertNumToIP(dns.Address) for dns in properties.DnsAddresses])
        except Exception:
            dnsAddrs = ""

        gwAddrs = ", ".join([gw.Address.ToString() for gw in properties.GatewayAddresses])

        details = (iface.Name, iface.NetworkInterfaceType, iface.Description, physAddr, uniAddrs, multiAddrs, dhcpAddrs, dnsAddrs, properties.DnsSuffix, gwAddrs)
        ipconfigSummary += '''\nName: {0}
        Type: {1}
        Description: {2}
        Physical Address: {3}
        IP Addresses: {4}
        Multicast Addresses: {5}
        DHCP Addresses: {6}
        DNS Addresses: {7}
        DNS Suffix: {8}
        Gateway Addresses: {9}\n'''.format(*details)
    
    return ipconfigSummary

def netstat():
    gp = NetworkInformation.IPGlobalProperties.GetIPGlobalProperties()
    tcpConns = gp.GetActiveTcpConnections()
    tcpListeners = gp.GetActiveTcpListeners()
    udpListeners = gp.GetActiveUdpListeners()
    netstatSummary = printHeader("NETSTAT")
    for c in tcpConns:
        netstatSummary += "{0:5} {1:23} <-->\t{2:23}\t{3}\n".format("TCP:", c.LocalEndPoint.ToString(), c.RemoteEndPoint.ToString(), c.State.ToString())

    for t in tcpListeners:
        if t.AddressFamily.ToString() == "InterNetwork":
            state = "TCP:"
        else: 
            state = "TCP6:"

        netstatSummary += "{0:5} {1:23}\n".format(state, t.ToString())
    
    for u in udpListeners:
        if u.AddressFamily.ToString() == "InterNetwork":
            state = "UDP:"
        else: 
            state = "UDP6:"

        netstatSummary += "{0:5} {1:23}\n".format(state, t.ToString())
    
    return netstatSummary

def firewallStatus():
    fwKey = r"HKEY_LOCAL_MACHINE\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy"

    fwSummary = printHeader("FIREWALL STATUS")
    fwSummary += "Standard: {0}\n".format(Convert.ToBoolean(Registry.GetValue(fwKey + "\StandardProfile", "EnableFirewall", "N/A")))
    fwSummary += "Domain: {0}\n".format(Convert.ToBoolean(Registry.GetValue(fwKey + "\DomainProfile", "EnableFirewall", "N/A")))
    fwSummary += "Public: {0}\n".format(Convert.ToBoolean(Registry.GetValue(fwKey + "\PublicProfile", "EnableFirewall", "N/A")))
            
    return fwSummary

def interestingKeys():
    keySummary = printHeader("REGISTRY KEYS")
    regkeys =[
        r"HKEY_CURRENT_USER\software\microsoft\windows\currentversion\explorer\runmru",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\snmp\parameters\validcommunities",
        r"HKEY_CURRENT_USER\SYSTEM\CurrentControlSet\services\snmp\parameters\validcommunities",
        r"HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
        r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters",
        r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest",
        r"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer",
        r"HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer",
        r"HKEY_LOCAL_MACHINE\Software\Policies",
        r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies",
        r"HKEY_CURRENT_USER\Software\Policies",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies"
    ]

    for key in regkeys:
        if key.upper().startswith("HKEY_CURRENT_USER"):
            try:
                k = Registry.CurrentUser.OpenSubKey(key.split("\\", maxsplit=1)[1])
                if k.ValueCount:
                    keySummary += printSubheader(key)
                    for value in sorted(k.GetValueNames()):
                        keySummary += "{0:<40} {1}\n".format(value, k.GetValue(value))
                    
                keySummary = recurseKeys(k, keySummary)
            except AttributeError:
                pass
        
        if key.upper().startswith("HKEY_LOCAL_MACHINE"):
            try:
                k = Registry.LocalMachine.OpenSubKey(key.split("\\", maxsplit=1)[1])
                if k.ValueCount:
                    keySummary += printSubheader(key)
                    for value in sorted(k.GetValueNames()):
                        keySummary += "{0:<40} {1}\n".format(value, k.GetValue(value))
                    
                keySummary = recurseKeys(k, keySummary)
            except AttributeError:
                pass

        if key.upper().startswith("HKEY_USERS"):
            try:
                k = Registry.Users.OpenSubKey(key.split("\\", maxsplit=1)[1])
                if k.ValueCount:
                    keySummary += printSubheader(key)
                    for value in sorted(k.GetValueNames()):
                        keySummary += "{0:<40} {1}\n".format(value, k.GetValue(value))
                    
                keySummary = recurseKeys(k, keySummary)
            except AttributeError:
                pass
        
        if key.upper().startswith("HKEY_CURRENT_CONFIG"):
            try:
                k = Registry.LocalMachine.OpenSubKey(key.split("\\", maxsplit=1)[1])
                if k.ValueCount:
                    keySummary += printSubheader(key)
                    for value in sorted(k.GetValueNames()):
                        keySummary += "{0:<40} {1}\n".format(value, k.GetValue(value))
                    
                keySummary = recurseKeys(k, keySummary)
            except AttributeError:
                pass
        
        if key.upper().startswith("HKEY_CLASSES_ROOT"):
            try:
                k = Registry.LocalMachine.OpenSubKey(key.split("\\", maxsplit=1)[1])
                if k.ValueCount:
                    keySummary += printSubheader(key)
                    for value in sorted(k.GetValueNames()):
                        keySummary += "{0:<40} {1}\n".format(value, k.GetValue(value))
                    
                keySummary = recurseKeys(k, keySummary)
            except AttributeError:
                pass

        if k:
            k.Close()

    return keySummary

def indexedFiles():
    summary = printSubheader("INDEXED FILES")
    pattern  = [r"%secret%",r"%creds%",r"%credential%",r"%.vmdk",r"%confidential%",r"%proprietary%",r"%pass%",r"%credentials%",r"web.config",r"KeePass.config%",r"%.kdbx",r"%.key",r"tnsnames.ora",r"ntds.dit",r"%.dll.config",r"%.exe.config"]
    con = Activator.CreateInstance(Type.GetTypeFromProgID("ADODB.Connection"))
    rs = Activator.CreateInstance(Type.GetTypeFromProgID("ADODB.Recordset"))

    try:
        con.Open("Provider=Search.CollatorDSO;Extended Properties='Application=Windows';")
    except:
        summary += "Indexed file search provider not available\n"
    
    for p in pattern:
        try:
            rs.Open("SELECT System.ItemPathDisplay FROM SYSTEMINDEX WHERE System.FileName LIKE '" + p + "' " , con)
            while not rs.EOF:
                summary += rs.Fields.Item("System.ItemPathDisplay").Value
                rs.MoveNext()
        except EnvironmentError:
            pass

    return summary

def interestingFiles():
    filetypes = [ "*.ps1", "*pass*", "*diagram*", "*.pdf", "*.vsd", "*.doc", "*.docx", "*.xls", "*.xlsx", "*.kdbx", "*.key", "KeePass.config"]
    dirs = [
        Env.GetEnvironmentVariable("ProgramFiles"),
        Env.GetEnvironmentVariable("ProgramFiles(x86)"),
        Env.GetEnvironmentVariable("USERPROFILE") + "\Desktop",
        Env.GetEnvironmentVariable("USERPROFILE") + "\Documents",
    ]

    
    indexedFiles()
    filesSummary = printHeader("INTERESTING FILES")
    filesSummary += printSubheader ("Logical Drives")
    for drive in DriveInfo.GetDrives():
        try:
            filesSummary += "Drive {0}\n".format(drive.Name)
            filesSummary += "\tDrive Type: {0}\n".format(drive.DriveType)
            filesSummary += "\tVolume label: {0}\n".format(drive.VolumeLabel)
            filesSummary += "\tFile System: {0}\n".format(drive.DriveFormat)
            filesSummary += "\tAvailable Space for user: \t{0}\n".format(drive.AvailableFreeSpace)
            filesSummary += "\tTotal Available Space: \t\t{0}\n".format(drive.TotalFreeSpace)
            filesSummary += "\tTotal Drive Space: \t\t{0}\n".format(drive.TotalSize)
        except IOError:
            continue

    filesSummary += printSubheader ("DIRECTORY LISTINGS")
    for dir in dirs:
        dirInfo = DirectoryInfo(dir)
        filesSummary += dir + "\n"
        for d in dirInfo.GetDirectories():
            filesSummary += "  " + d.Name + "\n"
        filesSummary += "\n"

    filesSummary += printSubheader ("FILES BY EXTENSION")
    profile = DirectoryInfo(Env.GetEnvironmentVariable("USERPROFILE"))
    for t in filetypes:
        filesSummary = recursiveFiles(profile, t, filesSummary)

    filesSummary += printSubheader ("POWERSHELL HISTORY")
    psHistFile = Env.GetEnvironmentVariable("APPDATA") + "\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
    try:
        history = open(psHistFile, "r").readlines()[-50:]
        filesSummary += "".join(history)
    except IndexError:
        history = open(psHistFile, "r").readlines()
        filesSummary += "".join(history)
    except IOError:
        filesSummary += "No history!\n"

    filesSummary += printSubheader ("HOSTS FILE")
    filesSummary += open(Env.GetEnvironmentVariable("WINDIR") + "\System32\drivers\etc\hosts", "r").read()
    return filesSummary 

def recycleBin():
    summary = printHeader("RECYCLE BIN")
    if WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator):
        for drive in DriveInfo.GetDrives():
            try:
                recycleDir = DirectoryInfo(drive.Name + "$Recycle.Bin\\")
                for dir in DirectoryInfo.EnumerateDirectories(recycleDir):
                    fileList = DirectoryInfo.GetFiles(dir)
                    summary += printSubheader("Directory: {0}".format(dir.FullName))
                    for file in fileList:
                        name = file.FullName.split("\\")[-1]
                        if name.startswith("$I"):
                            info = open(file.FullName, "r").read()
                            summary += "{0}\t{1}\n".format(name.replace("$I", "$R"), info[26::2])
            except IOError:
                pass
    else:
        for drive in DriveInfo.GetDrives():
            try:
                recycleDir = drive.Name + "$Recycle.Bin\\"
                user = WindowsIdentity.GetCurrent()
                fileList = Directory.GetFiles(recycleDir + user.Owner.ToString())
                summary += printSubheader("Directory: {0}".format(recycleDir + user.Owner.ToString()))
                for file in fileList:
                    name = file.split("\\")[-1]
                    if name.startswith("$I"):
                        info = open(file, "r").read()
                        summary += "{0}\t{1}\n".format(name.replace("$I", "$R"), info[26::2])
            except IOError:
                pass

    return summary

def browserEnum():
    summary = printHeader("BROWSER ENUM")
    regex = Regex('(http|ftp|https|file)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?')

    #Active IE Urls
    summary += printSubheader("ACTIVE EXPLORER URLS")
    app = Activator.CreateInstance(Type.GetTypeFromProgID("Shell.Application"))
    summary += "\n".join([w.LocationUrl() for w in app.Windows()])

    #Chrome History
    summary += printSubheader("\n\nChrome History")
    try:
        cHistPath = "{0}\Users\{1}\AppData\Local\Google\Chrome\User Data\Default\History".format(Env.GetEnvironmentVariable("systemdrive"), Env.UserName)
        cHist = open(cHistPath, "r").read()
        summary += "\n".join(["[*] {0}\n".format(m.Value) for m in regex.Matches(cHist)][-10:])
    except:
        pass

    summary += printSubheader("\nChrome Bookmarks")
    #Chrome Bookmarks
    try:
        cBMPath = "{0}\Users\{1}\AppData\Local\Google\Chrome\User Data\Default\Bookmarks".format(Env.GetEnvironmentVariable("systemdrive"), Env.UserName)
        js = JavaScriptSerializer()
        cBM = js.DeserializeObject(open(cBMPath, "r").read())
        urls = cBM["roots"]["bookmark_bar"]["children"]
        for url in urls:
            u = url['url']
            d = url['name']
            summary += "[*] {0}\n{1}\n\n".format(d, u)
    except:
        pass

    summary += printSubheader("Firefox History")
    #Firefox History
    try:
        regex = Regex('(http|ftp|https|file)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?')
        fHistPath = "{0}\Users\{1}\AppData\Roaming\Mozilla\Firefox\Profiles".format(Env.GetEnvironmentVariable("systemdrive"), Env.UserName)
        for path in DirectoryInfo(fHistPath).EnumerateDirectories("*.default"):
            places = open(path.FullName + "\places.sqlite", "r").read()
            summary += "\n".join(["[*] {0}\n".format(m.Value) for m in regex.Matches(places)][:10])
    except:
        pass

    summary += printSubheader("IE History")
    typedUrlPath = "\Software\Microsoft\Internet Explorer\TypedURLs"
    for sid in Registry.Users.GetSubKeyNames():
        if sid != ".DEFAULT" and not sid.endswith("Classes"):
            try:
                typedUrlsKey = Registry.Users.OpenSubKey(sid + typedUrlPath)
                if typedUrlsKey != None:
                    summary += "[{0}][{1}]\n".format(sid, SecurityIdentifier(sid.ToString()).Translate(NTAccount))
                    for value in typedUrlsKey.GetValueNames():
                        summary += "\t{0}\n".format(typedUrlsKey.GetValue(value))
                summary += "\n"
            except SystemError:
                pass

    return summary    

def explicitLogonEvents():
    summary = printHeader("EXPLICIT LOGON EVENTS")
    if  WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator):
        sec = EventLog("Security")
        logons = [event for event in sec.Entries if event.InstanceId == 4648]
        for logon in logons[:10]:
            idx = logon.Message.IndexOf("This event is generated")
            message = logon.Message.Remove(idx)
            summary += printSubheader("Time Created: {0}".format(logon.TimeGenerated.ToString()))
            summary += message
        
        return summary
    else:
        return summary + "\nNot administrator!\n"

def logonEvents():
    summary = printHeader("LOGON EVENTS")
    if  WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator):
        sec = EventLog("Security")
        logons = [event for event in sec.Entries if event.InstanceId == 4624]
        for logon in logons[:10]:
            idx = logon.Message.IndexOf("This event is generated")
            message = logon.Message.Remove(idx)
            summary += printSubheader("Time Created: {0}".format(logon.TimeGenerated.ToString()))
            summary += message
        
        return summary
    else:
        return summary + "\nNot administrator!\n"

ENUM_LEVEL=
quick = [systemInfo, avLookup, userGroups, environment, ipconfig, netstat, processList]
full = quick + [firewallStatus, interestingKeys, interestingFiles, recycleBin, browserEnum, logonEvents, explicitLogonEvents]

if ENUM_LEVEL.lower() not in ["quick", "full"]:
    print "Not a valid option! Must choose 'quick' or 'full'"
elif ENUM_LEVEL.lower() == "quick":
    resp = [f() for f in quick]
    print "\n".join(resp)
elif ENUM_LEVEL.lower() == "full":
    resp = [f() for f in full]
    print "\n".join(resp)