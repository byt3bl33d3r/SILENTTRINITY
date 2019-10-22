from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/domaingroups'
        self.language = 'boo'
        self.description = 'Retrieve domain groups information'
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
            'AdminCount': {
                'Description': 'Optionally filter for only a DomainObject with the AdminCount property set.\r\nExpected: bool',
                'Required': False,
                'Value': False
            },
            'GroupScope': {
                'Description': 'Optionally filter for a GroupScope (DomainLocal, Global, Universal, etc).\r\nExpected: string',
                'Required': False,
                'Value': ""
            },
            'GroupProperty': {
                'Description': 'Optionally filter for for a GroupProperty (Security, Distribution, CreatedBySystem, NotCreatedBySystem, etc).\r\nExpected: string',
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
        with open(get_path_in_package('core/teamserver/modules/boo/src/domaingroups.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace("IDENTITY", self.options['Identity']['Value'])
            src = src.replace("LDAP_FILTER", self.options['LDAPFilter']['Value'])
            src = src.replace("PROPERTIES", self.options['Properties']['Value'].lower())
            src = src.replace('ADMINCOUNT', str(self.options['AdminCount']['Value']).lower())
            src = src.replace('GROUP_SCOPE', self.options['GroupScope']['Value'])
            src = src.replace('GROUP_PROPERTY', self.options['GroupProperty']['Value'])
            src = src.replace('FIND_ONE', str(self.options['FindOne']['Value']).lower())
            return src
