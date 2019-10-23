from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/kerberoasting'
        self.language = 'boo'
        self.description = 'Perform kerberoasting'
        self.author = '@Daudau'
        self.references = []
        self.options = {
            'Identity': {
                'Description': 'Optional username to search for.\r\nExpected: string',
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
            'SPN': {
                'Description': 'Optionally filter for only a specific SPN\r\nExpected: string',
                'Required': False,
                'Value': ""
            },
            'DoAllowDelegation': {
                'Description': 'Optionally filter for only a DomainObject that allows for delegation.\r\nExpected: bool',
                'Required': False,
                'Value': False
            },
            'DisallowDelegation': {
                'Description': 'Optionally filter for only a DomainObject that does not allow for delegation.\r\nExpected: bool',
                'Required': False,
                'Value': False
            },
            'AdminCount': {
                'Description': 'Optionally filter for only a DomainObject with the AdminCount property set.\r\nExpected: bool',
                'Required': False,
                'Value': False
            },
            'TrustedToAuth': {
                'Description': 'Optionally filter for only a DomainObject that is trusted to authenticate for other DomainObjects.\r\nExpected: bool',
                'Required': False,
                'Value': False
            },
            'PreauthNotRequired': {
                'Description': 'Optionally filter for only a DomainObject does not require Kerberos preauthentication.\r\nExpected: bool',
                'Required': False,
                'Value': False
            },
            'FindOne': {
                'Description': 'Define if multiple results must be displayed. /!\\ Request may timeout if too many users are retrieved.\r\nExpected: bool',
                'Required': True,
                'Value': True
            }
        }

    def payload(self):
        with open(get_path_in_package('core/teamserver/modules/boo/src/kerberoasting.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace("IDENTITY", self.options['Identity']['Value'])
            src = src.replace("LDAP_FILTER", self.options['LDAPFilter']['Value'])
            src = src.replace("PROPERTIES", self.options['Properties']['Value'].lower())
            src = src.replace("UAC_FILTER", self.options['UACFilter']['Value'])
            src = src.replace('SPN', str(self.options['SPN']['Value']).lower())
            src = src.replace('DO_ALLOW_DELEGATION', str(self.options['DoAllowDelegation']['Value']).lower())
            src = src.replace('DISALLOW_DELEGATION', str(self.options['DisallowDelegation']['Value']).lower())
            src = src.replace('ADMINCOUNT', str(self.options['AdminCount']['Value']).lower())
            src = src.replace('TRUSTED_TO_AUTH', str(self.options['TrustedToAuth']['Value']).lower())
            src = src.replace('PREAUTH_NOT_REQUIRED', str(self.options['PreauthNotRequired']['Value']).lower())
            src = src.replace('FIND_ONE', str(self.options['FindOne']['Value']).lower())
            return src
