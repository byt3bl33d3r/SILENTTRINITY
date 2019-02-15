import System.DateTime as DateTime
import System.Environment as Env
import System.Diagnostics as Diagnostics

def getSystemInfo():
    summary = "\nHost: \t{0}\n".format(Env.MachineName)
    summary += "OS: \t{0} {1}\n".format(Env.OSVersion.Platform, Diagnostics.FileVersionInfo.GetVersionInfo(Env.SystemDirectory + "\\kernel32.dll").ProductVersion)
    summary += "64-Bit: {0}\n".format(Env.Is64BitOperatingSystem)
    summary += "Domain: {0}\n".format(Env.UserDomainName)
    summary += "User: \t{0}\n".format(Env.UserName)
    summary += "Date: \t{0}\n".format(DateTime.Now.ToString())
    return summary

print getSystemInfo()

