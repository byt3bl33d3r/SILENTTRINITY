from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/domaincomputers'
        self.language = 'boo'
        self.description = 'Retrieve domain computers information'
        self.author = '@Daudau'
        self.references = []
        self.options = {
            'Identity': {
                'Description': 'Optional computer name to search for.\r\nExpected: string',
                'Required': False,
                'Value': ""
            },
            'LDAPFilter': {
                'Description': 'Optional LDAP filter to apply to the search.\r\nExpected: string',
                'Required': False,
                'Value': ""
            },
            'Properties': {
                'Description': 'Optional list of properties (separated by comas without spaces) to retrieve from the DomainObject. If not specified, all properties are included.\r\nExpected: string',
                'Required': False,
                'Value': ""
            },
            'UACFilter': {
                'Description': 'Optional filter to parse the userAccountControl DomainObject property.\r\nExpected: int',
                'Required': False,
                'Value': ""
            },
            'Unconstrained': {
                'Description': 'Optionally filter for only a DomainObject that has unconstrained delegation.\r\nExpected: bool',
                'Required': False,
                'Value': False
            },
            'TrustedToAuth': {
                'Description': 'Optionally filter for only a DomainObject that is trusted to authenticate for other DomainObjects.\r\nExpected: bool',
                'Required': False,
                'Value': False
            },
            'Printers': {
                'Description': 'Optionally filter for only a DomainObject that is that is a printer.\r\nExpected: bool',
                'Required': False,
                'Value': False
            },
            'SPN': {
                'Description': 'Optionally filter for only a DomainObject with an SPN set.\r\nExpected: bool',
                'Required': False,
                'Value': False
            },
            'OperatingSystem': {
                'Description': 'Optionally filter for only a DomainObject with a specific Operating System, wildcards accepted.\r\nExpected: string',
                'Required': False,
                'Value': ""
            },
            'ServicePack': {
                'Description': 'Optionally filter for only a DomainObject with a specific service pack, wildcards accepted.\r\nExpected: string',
                'Required': False,
                'Value': ""
            },
            'SiteName': {
                'Description': 'Optionally filter for only a DomainObject in a specific Domain SiteName, wildcards accepted.\r\nExpected: string',
                'Required': False,
                'Value': ""
            },
            'FindOne': {
                'Description': 'Define if multiple results must be displayed. /!\\ Request may timeout if too many users are retrieved.\r\nExpected: bool',
                'Required': True,
                'Value': True
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/domaincomputers.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace("IDENTITY", self.options['Identity']['Value'])
            src = src.replace("LDAP_FILTER", self.options['LDAPFilter']['Value'])
            src = src.replace("PROPERTIES", self.options['Properties']['Value'].lower())
            src = src.replace("UAC_FILTER", self.options['UACFilter']['Value'])
            src = src.replace('UNCONSTRAINED', str(self.options['Unconstrained']['Value']).lower())
            src = src.replace('TRUSTED_TO_AUTH', str(self.options['TrustedToAuth']['Value']).lower())
            src = src.replace('PRINTERS', str(self.options['Printers']['Value']).lower())
            src = src.replace('SPN', str(self.options['SPN']['Value']).lower())
            src = src.replace('OPERATING_SYSTEM', self.options['OperatingSystem']['Value'])
            src = src.replace('SERVICE_PACK', self.options['ServicePack']['Value'])
            src = src.replace('SITE_NAME', self.options['SiteName']['Value'])
            src = src.replace('FIND_ONE', str(self.options['FindOne']['Value']).lower())
            return src
