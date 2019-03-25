import System.DateTime as DateTime
import System.Environment as Env

def getSystemInfo():
    summary = "\nHost: \t{0}\n".format(Env.MachineName)
    summary += "OS: \t{0}\n".format(Env.OSVersion.Platform)
    summary += "64-Bit: {0}\n".format(Env.Is64BitOperatingSystem)
    summary += "Domain: {0}\n".format(Env.UserDomainName)
    summary += "User: \t{0}\n".format(Env.UserName)
    summary += "Date: \t{0}\n".format(DateTime.Now.ToString())
    return summary

print getSystemInfo()

