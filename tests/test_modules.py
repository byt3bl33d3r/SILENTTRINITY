import pytest
import sys
import os

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(root_dir)

from silenttrinity.core.teamserver.module import Module
from silenttrinity.core.teamserver.contexts.listeners import Listeners
from silenttrinity.core.teamserver.contexts.stagers import Stagers
from silenttrinity.core.teamserver.loader import Loader

class MockTeamserver:
    pass

@pytest.fixture
def listener_context():
    return Listeners(MockTeamserver())

@pytest.fixture
def stager_context():
    return Stagers(MockTeamserver())

@pytest.fixture
def module_loader():
    ''' Load all of the modules'''
    return Loader(type="module", paths=["silenttrinity/core/teamserver/modules/boo"])

def test_module_payload_gen(module_loader, listener_context, stager_context):
    listener_context.use('http')
    listener_context.selected['BindIP'] = '192.168.0.1'
    listener_context.selected['Port'] = '8443'
    listener_context.listeners.append(listener_context.selected)

    for m in module_loader.loaded:
        print(f"Testing module '{m.name}'")
        assert isinstance(m, Module) == True

        if m.name == 'boo/inject':
            m['Listener'] = 'http'
            m['Processs'] = 'explorer.exe'
        elif m.name == 'boo/excel4dcom':
            m['Listener'] = 'http'
            m['Target'] = '192.168.1.1'
        elif m.name == 'boo/excelshellinject':
            m['Shellcode'] = './tests/shellcode.hex'
        elif m.name == 'boo/shellcode':
            m['Shellcode'] = './tests/shellcode.bin'
        elif m.name == 'boo/execute-assembly':
            m['Assembly'] = './silenttrinity/core/teamserver/data/naga.exe'
        elif m.name == 'boo/winrm':
            m['Listener'] = 'http'
            m['Host'] = '192.168.1.1'

        module_payload = m.payload()
        assert module_payload is not None and len(module_payload) > 0
