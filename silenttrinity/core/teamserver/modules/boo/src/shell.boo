import System
import System.Security
import System.Diagnostics

public static def ShellExecute(ShellCommand as string, Path as string, Username as string, Domain as string, Password as string) as string:

    ShellCommandName = ShellCommand.Split()[0]
    ShellCommandArguments = join(ShellCommand.Split()[1:], ' ')
    print "[*] Path: $(Path) Command: $(ShellCommandName) Args: $(ShellCommandArguments)"

    shellProcess = Process()
    if Username and Domain and Password:
        print "[*] Running command as $(Domain)\\$(Username):$(Password)"
        shellProcess.StartInfo.UserName = Username
        shellProcess.StartInfo.Domain = Domain
        SecurePassword = SecureString()
        for c in Password:
            SecurePassword.AppendChar(c)
        shellProcess.StartInfo.Password = SecurePassword

    shellProcess.StartInfo.FileName = ShellCommandName
    shellProcess.StartInfo.Arguments = ShellCommandArguments
    shellProcess.StartInfo.WorkingDirectory = Path
    shellProcess.StartInfo.UseShellExecute = false
    shellProcess.StartInfo.CreateNoWindow = true
    shellProcess.StartInfo.RedirectStandardOutput = true

    try:
        shellProcess.Start()

        output = shellProcess.StandardOutput.ReadToEnd()
        shellProcess.WaitForExit()
    except e:
        output = e.Message

    return output

public static def Main():
    print ShellExecute(ShellCommand="COMMAND_TO_RUN", Path=`PATH`, Username="USERNAME", Domain="DOMAIN", Password="PASSWORD")
