from System.Security import SecureString
from System.Diagnostics import Process


def ShellExecute(ShellCommand, Path="C:\\WINDOWS\\System32\\", Username=None, Domain=None, Password=None):

    ShellCommandName = ShellCommand.split()[0]
    ShellCommandArguments = ' '.join(ShellCommand.split()[1:])
    print "[*] Path: {} Command: {} Args: {}".format(Path, ShellCommandName, ShellCommandArguments)

    shellProcess = Process()
    if Username and Domain and Password:
        print "[*] Running command as {}\\{}:{}".format(Domain, Username, Password)
        shellProcess.StartInfo.UserName = Username
        shellProcess.StartInfo.Domain = Domain
        SecurePassword = SecureString()
        for c in Password:
            SecurePassword.AppendChar(c)
        shellProcess.StartInfo.Password = SecurePassword

    shellProcess.StartInfo.FileName = ShellCommandName
    shellProcess.StartInfo.Arguments = ShellCommandArguments
    shellProcess.StartInfo.WorkingDirectory = Path
    shellProcess.StartInfo.UseShellExecute = False
    shellProcess.StartInfo.CreateNoWindow = True
    shellProcess.StartInfo.RedirectStandardOutput = True
    shellProcess.Start()

    output = shellProcess.StandardOutput.ReadToEnd()
    shellProcess.WaitForExit()

    return output

print ShellExecute("COMMAND_TO_RUN", Username="USERNAME", Domain="DOMAIN", Password="PASSWORD")
