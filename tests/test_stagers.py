import pytest
import sys
import os
import uuid

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(root_dir)

from core.teamserver.loader import Loader
from core.teamserver.contexts.listeners import Listeners
from core.teamserver.contexts.stagers import Stagers

class MockTeamserver:
    pass

@pytest.fixture
def listener_context():
    return Listeners(MockTeamserver())

@pytest.fixture
def stager_loader():
    ''' Load all of the listeners'''
    return Loader(type="stager", paths=["core/teamserver/stagers/"])

def test_stager_gen(stager_loader, listener_context):
    listener_context.use('http')
    listener_context.selected['BindIP'] = '192.168.0.1'
    listener_context.selected['Port'] = '8443'
    listener_context.listeners.append(listener_context.selected)

    for s in stager_loader.loaded:
        print(f"Testing stager '{s.name}'")
        guid, psk, stager_code = s.generate(listener_context.selected)

        assert isinstance(guid, uuid.UUID) == True
        assert psk is not None and len(psk) > 0
        assert stager_code is not None and len(stager_code) > 0
