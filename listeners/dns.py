import asyncio
from core.listener import Listener
from core.utils import get_ipaddress
from core.thirdparty.dnschef import DNSServerProtocol


class STListener(Listener):
    def __init__(self):
        Listener.__init__(self)
        self.name = 'dns'
        self.author = '@byt3bl33d3r'
        self.description = 'DNS Listener'

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

    async def do_A(self, addr, record, qname, qtype):
        return "1.3.3.7"

    async def do_TXT(self, addr, record, qname, qtype):
        pass

    def run(self):
        pass
        """
        loop = asyncio.get_event_loop()
        loop.run_until_complete(start_cooking(
            interface=self['BindIP']
            nametodns=nametodns,
            nameservers="1.1.1.1#53",
            tcp=False,
            ipv6=False,
            port=self["Port"],
            dnsclass=self
        ))
        """