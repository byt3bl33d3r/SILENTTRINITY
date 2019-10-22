import pytest
import sys
import os
import uuid

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(root_dir)

from silenttrinity.core.teamserver.loader import Loader
from silenttrinity.core.teamserver.stager import Stager
from silenttrinity.core.teamserver.comms.utils import gen_stager_code
from silenttrinity.core.teamserver.contexts.listeners import Listeners
from silenttrinity.core.teamserver.contexts.stagers import Stagers

class MockTeamserver:
    pass

@pytest.fixture
def listener_context():
    return Listeners(MockTeamserver())

@pytest.fixture
def stager_loader():
    ''' Load all of the listeners'''
    return Loader(type="stager", paths=["silenttrinity/core/teamserver/stagers/"])

def test_stager_code_gen():
    stager_code = gen_stager_code(['http', 'https'], hook_assemblyresolve_event=True)
    assert len(stager_code) > 0 and stager_code is not None

def test_stager_gen(stager_loader, listener_context):
    listener_context.use('http')
    listener_context.selected['BindIP'] = '192.168.0.1'
    listener_context.selected['Port'] = '8443'
    listener_context.listeners.append(listener_context.selected)

    for s in stager_loader.loaded:
        print(f"Testing stager '{s.name}'")
        assert isinstance(s, Stager) == True

        guid, psk, stager_code = s.generate(listener_context.selected)

        assert isinstance(guid, uuid.UUID) == True
        assert psk is not None and len(psk) > 0
        assert stager_code is not None and len(stager_code) > 0
