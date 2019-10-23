from silenttrinity.core.utils import get_path_in_package
from silenttrinity.core.teamserver.module import Module


class STModule(Module):
    def __init__(self):
        self.name = 'boo/domainquery'
        self.language = 'boo'
        self.description = 'Perform LDAP query on domain'
        self.author = '@Daudau'
        self.references = []
        self.options = {
            'LDAPFilter': {
                'Description': 'Optional LDAP filter to apply to the search.\r\nExpected: string',
                'Required': True,
                'Value': ''
            },
            'Properties': {
                'Description': 'Optional list of properties (separated by comas without spaces) to retrieve from the DomainObject. If not specified, all properties are included.\r\nExpected: string',
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
        with open(get_path_in_package('core/teamserver/modules/boo/src/domainquery.boo'), 'r') as module_src:
            src = module_src.read()
            src = src.replace("LDAP_FILTER", self.options['LDAPFilter']['Value'])
            src = src.replace("PROPERTIES", self.options['Properties']['Value'].lower())
            src = src.replace('FIND_ONE', str(self.options['FindOne']['Value']).lower())
            return src
