import pytest
import requests
import sys
import os
import random
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(root_dir)

from core.teamserver.loader import Loader
from core.teamserver.listener import Listener

@pytest.fixture
def listener_loader():
    ''' Load all of the listeners'''
    return Loader(type="listener", paths=["core/teamserver/listeners/"])

def test_listeners(listener_loader):
    s = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=0.5
    )
    s.verify = False
    s.mount('http://', HTTPAdapter(max_retries=retries))
    s.mount('https://', HTTPAdapter(max_retries=retries))

    for l in listener_loader.loaded:
        print(f"Testing listener '{l.name}'")
        assert isinstance(l, Listener) == True

        if l.name in ['http', 'https']:
            l['BindIP'] = '127.0.0.1'
            l['Port'] = str(random.randint(3000, 6000))
            l.start()
            r = s.get(f"{l.name}://127.0.0.1:{l['Port']}/")
            assert r.status_code == 404
            l.stop()
            assert l.running == False
