import pytest
import sys
import os
import uuid

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(root_dir)

from silenttrinity.core.teamserver.crypto import gen_stager_psk
from silenttrinity.core.teamserver.db import STDatabase, AsyncSTDatabase

TEST_DB_PATH = './tests/st.db'
if os.path.exists(TEST_DB_PATH):
    os.remove(TEST_DB_PATH)

def test_database_creation():
    '''Create the database'''
    STDatabase.create_db_and_schema(db_path=TEST_DB_PATH)
    assert os.path.exists(TEST_DB_PATH) == True

def test_database_ops():
    guid = uuid.uuid4()
    psk = gen_stager_psk()
    with STDatabase(db_path=TEST_DB_PATH) as db:
        _psk = db.add_session(guid, psk)
        assert _psk == psk

        # Test to make sure nothing errors out if we try to add a second session with the same guid & psk
        _no_psk = db.add_session(guid, psk)
        assert _no_psk == None

        _psk = db.get_session_psk(guid)
        assert _psk == psk

        sessions = db.get_sessions()
        assert len(sessions) == 1
