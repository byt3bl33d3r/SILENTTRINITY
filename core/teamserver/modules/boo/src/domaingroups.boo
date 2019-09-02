/*
    This module is inspired from SharpSploit (https://github.com/cobbr/SharpSploit)
*/
import System
import System.DirectoryServices
import System.Text.RegularExpressions
import System.Security.Principal
import System.Security.AccessControl


public enum UACEnum:
    SCRIPT = 1
    ACCOUNTDISABLE = 2
    HOMEDIR_REQUIRED = 8
    LOCKOUT = 16
    PASSWD_NOTREQD = 32
    PASSWD_CANT_CHANGE = 64
    ENCRYPTED_TEXT_PWD_ALLOWED = 128
    TEMP_DUPLICATE_ACCOUNT = 256
    NORMAL_ACCOUNT = 512
    INTERDOMAIN_TRUST_ACCOUNT = 2048
    WORKSTATION_TRUST_ACCOUNT = 4096
    SERVER_TRUST_ACCOUNT = 8192
    DONT_EXPIRE_PASSWORD = 65536
    MNS_LOGON_ACCOUNT = 131072
    SMARTCARD_REQUIRED = 262144
    TRUSTED_FOR_DELEGATION = 524288
    NOT_DELEGATED = 1048576
    USE_DES_KEY_ONLY = 2097152
    DONT_REQ_PREAUTH = 4194304
    PASSWORD_EXPIRED = 8388608
    TRUSTED_TO_AUTH_FOR_DELEGATION = 16777216
    PARTIAL_SECRETS_ACCOUNT = 67108864


public enum GroupTypeEnum :
    CREATED_BY_SYSTEM = 1
    GLOBAL_SCOPE = 2
    DOMAIN_LOCAL_SCOPE = 4
    UNIVERSAL_SCOPE = 8
    APP_BASIC = 16
    APP_QUERY = 32
    SECURITY = -2147483648


public enum SamAccountTypeEnum:
    DOMAIN_OBJECT = 0
    GROUP_OBJECT = 268435456
    NON_SECURITY_GROUP_OBJECT = 268435457
    ALIAS_OBJECT = 536870912
    NON_SECURITY_ALIAS_OBJECT = 536870913
    USER_OBJECT = 805306368
    MACHINE_ACCOUNT = 805306369
    TRUST_ACCOUNT = 805306370
    APP_BASIC_GROUP = 1073741824
    APP_QUERY_GROUP = 1073741825
    ACCOUNT_TYPE_MAX = 2147483647


private static def ConvertLDAPProperty(Properties as ResultPropertyCollection, PropertyName as string ) as string:
    value as string = ""
    combobj as MarshalByRefObject
    high as int
    low as int
    if (PropertyName == "objectsid"):
        value = SecurityIdentifier(Properties["objectsid"][0], 0).Value
    elif (PropertyName == "sidhistory"):
        historyListTemp as List = []
        for bytes in Properties["sidhistory"]:
            historyListTemp.Add(SecurityIdentifier(bytes, 0).Value)
        value = historyListTemp.Join(", ")
    elif (PropertyName == "grouptype"):
        try:
            value = Properties["grouptype"][0] + " => "
            gtactivated as List = []
            for gt in System.Enum.GetValues(GroupTypeEnum):
                if Properties["grouptype"][0] % gt cast int:
                    gtactivated.Add(gt)
            value += gtactivated.Join(", ")
        except:
            value = Properties[PropertyName][0]
    elif (PropertyName == "samaccounttype"):
        try :
            value = Properties["samaccounttype"][0] + " => "
            for sat in System.Enum.GetValues(SamAccountTypeEnum):
                if Properties["samaccounttype"][0] == sat cast int:
                    value += sat
        except:
            value = Properties[PropertyName][0]
    elif (PropertyName == "objectguid"):
        value = Guid(Properties["objectguid"][0] cast (byte)).ToString()
    elif (PropertyName == "useraccountcontrol"):
        try:
            value = Properties["useraccountcontrol"][0] + " => "
            uacactivated as List = []
            for uac in System.Enum.GetValues(UACEnum):
                if Properties["useraccountcontrol"][0] % uac cast int:
                    uacactivated.Add(uac)
            value += uacactivated.Join(", ")
        except:
            value = Properties[PropertyName][0]
    elif (PropertyName == "ntsecuritydescriptor"):
        desc as RawSecurityDescriptor = RawSecurityDescriptor(Properties["ntsecuritydescriptor"][0], 0)
        value = "Owner: " + desc.Owner + "\r\nGroup: " + desc.Group + "\r\nDiscretionaryAcl: " + desc.DiscretionaryAcl + "\r\nSystemAcl: " + desc.SystemAcl
    elif (PropertyName == "accountexpires"):
        if (Properties[PropertyName][0] >= DateTime.MaxValue.Ticks):
            value = DateTime.MaxValue.ToString()
        try:
            value = DateTime.FromFileTime(Properties["accountexpires"][0] cast long).ToString()
        except ArgumentOutOfRangeException:
            value = DateTime.MaxValue.ToString()
    elif (PropertyName == "lastlogon" or PropertyName == "lastlogontimestamp" or PropertyName == "pwdlastset" or
             PropertyName == "lastlogoff" or PropertyName == "badPasswordTime"):
        dateTime as DateTime = DateTime.MinValue
        if (Properties[PropertyName][0].GetType().Name == "System.MarshalByRefObject"):
            comobj = Properties[PropertyName][0]
            high = comobj.GetType().InvokeMember("HighPart", System.Reflection.BindingFlags.GetProperty, null, comobj, null)
            low = comobj.GetType().InvokeMember("LowPart", System.Reflection.BindingFlags.GetProperty, null, comobj, null)
            dateTime = DateTime.FromFileTime(int.Parse("0x" + high + "" + low, System.Globalization.NumberStyles.HexNumber))
        else:
            dateTime = DateTime.FromFileTime(Properties[PropertyName][0] cast long)
        if (PropertyName in ["lastlogon", "lastlogontimestamp", "pwdlastset", "lastlogoff", "badPasswordTime"]):
            value = dateTime.ToString()
    else:
        property as string = "0"
        if (Properties[PropertyName][0].GetType().Name == "System.MarshalByRefObject"):
            comobj = Properties[PropertyName][0]
            high = comobj.GetType().InvokeMember("HighPart", System.Reflection.BindingFlags.GetProperty, null, comobj, null)
            low = comobj.GetType().InvokeMember("LowPart", System.Reflection.BindingFlags.GetProperty, null, comobj, null)
            property = int.Parse("0x" + high + "" + low, System.Globalization.NumberStyles.HexNumber).ToString()
        else:
            propertyList as List = []
            for prop as object in Properties[PropertyName]:
                propertyList.Add(prop.ToString())
            property = propertyList.Join(", ")
        value = property
    return value


public static def Main():
    identity = "IDENTITY"
    ldapFilter = "LDAP_FILTER"
    properties = "PROPERTIES"
    admincount = ADMINCOUNT
    groupScope = "GROUP_SCOPE"
    groupProperty = "GROUP_PROPERTY"
    findone = FIND_ONE

    Filter as string = ""
    if identity:
        if (Regex.IsMatch(identity, "^S-1-")):
            Filter += "(objectsid=" + identity + ")"
        elif (Regex.IsMatch(identity, "^CN=")):
            Filter += "(distinguishedname=" + identity + ")"
        elif (Regex.IsMatch(identity, "^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$")):
            bytes as (byte) = Guid(identity).ToByteArray()
            GuidByteString as string = ""
            for b as Byte in bytes:
                GuidByteString += "\\" + b.ToString("X2")
            Filter += "(objectguid=" + GuidByteString + ")"
        else:
            t = @/\\/.Split(identity)
            if (t.Length > 1):
                Filter += "(samAccountName=" + t[1] + ")"
            else:
                Filter += "(samAccountName=" + identity + ")"
    if admincount:
        Filter += "(admincount=1)"
    if groupScope == "DomainLocal":
        Filter += "(groupType:1.2.840.113556.1.4.803:=4)"
    elif groupScope == "NotDomainLocal":
        Filter += "(!(groupType:1.2.840.113556.1.4.803:=4))"
    elif groupScope == "Global":
        Filter += "(groupType:1.2.840.113556.1.4.803:=2)"
    elif groupScope == "NotGlobal":
        Filter += "(!(groupType:1.2.840.113556.1.4.803:=2))"
    elif groupScope == "Universal":
        Filter += "(groupType:1.2.840.113556.1.4.803:=8)"
    elif groupScope == "NotUniversal":
        Filter += "(!(groupType:1.2.840.113556.1.4.803:=8))"
    if groupProperty == "Security":
        Filter += "(groupType:1.2.840.113556.1.4.803:=2147483648)"
    elif groupProperty == "Distribution":
        Filter += "(!(groupType:1.2.840.113556.1.4.803:=2147483648))"
    elif groupProperty == "CreatedBySystem":
        Filter += "(groupType:1.2.840.113556.1.4.803:=1)"
    elif groupProperty == "NotCreatedBySystem":
        Filter += "(!(groupType:1.2.840.113556.1.4.803:=1))"
    Filter += ldapFilter
    Filter = "(&(objectCategory=group)" + Filter + ")"

    print "[*] Creating DirectorySearcher with filter: " + Filter
    directorysearcher as DirectorySearcher = DirectorySearcher(Filter)
    value as List
    directoryentry as DirectoryEntry
    try:
        if findone:
            result as SearchResult = directorysearcher.FindOne()
            if result:
                print "\r\n[*] Found 1 result:\r\n"
                directoryentry = result.GetDirectoryEntry()
                for k in result.Properties.PropertyNames:
                    if not properties or k in @/,/.Split(properties):
                        print "    " + k + ": " + ConvertLDAPProperty(result.Properties, k)
            else:
                print "\r\n[*] No result found\r\n"
        else:
            collection = directorysearcher.FindAll()
            if collection:
                print "\r\n[*] Found " + collection.Count + " results:\r\n"
                for result as SearchResult in collection:
                    directoryentry = result.GetDirectoryEntry()
                    for k in result.Properties.PropertyNames:
                        if not properties or k in @/,/.Split(properties):
                            print "    " + k + ": " + ConvertLDAPProperty(result.Properties, k)
                    print "\r\n"
              else:
                  print "\r\n[*] No result found\r\n"
    except e:
        print "Exception: Can't construct Domain Searcher: " + e.Message + e.StackTrace
