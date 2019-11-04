import aiosqlite
import sqlite3
import logging
import asyncio
import uuid
from silenttrinity.core.utils import get_path_in_data_folder

# I'd preferably like to avoid having STD in any class names, should probably get that checked out.

class AsyncSTDatabase:

    def __init__(self, db_path=get_path_in_data_folder("st.db")):
        self.db_path = db_path

    @staticmethod
    async def create_db_and_schema(db_path=get_path_in_data_folder("st.db")):
        async with aiosqlite.connect(db_path) as db:
            await db.execute('''CREATE TABLE "sessions" (
                "id" integer PRIMARY KEY,
                "guid" text,
                "psk" text,
                UNIQUE(guid,psk)
            )''')

    async def add_session(self, guid, psk: str):
        await self.db.execute("INSERT INTO sessions (guid, psk) VALUES (?,?)", [str(guid), psk])
        return psk

    async def get_session_psk(self, guid):
        async with self.db.execute("SELECT psk FROM sessions WHERE guid=(?)", [str(guid)]) as cursor:
            result = await cursor.fetchone()
            return result[0]

    async def get_sessions(self):
        async with self.db.execute("SELECT * FROM sessions") as cursor:
            return cursor.fetchall()

    async def __aenter__(self):
        self.db = await aiosqlite.connect(self.db_path)
        return self

    async def __aexit__(self, exec_type, exc, tb):
        await self.db.commit()
        await self.db.close()

class STDatabase:

    def __init__(self, db_path=get_path_in_data_folder("st.db")):
        self.db_path = db_path

    @staticmethod
    def create_db_and_schema(db_path=get_path_in_data_folder("st.db")):
        with sqlite3.connect(db_path) as db:
            db.execute('''CREATE TABLE "sessions" (
                            "id" integer PRIMARY KEY,
                            "guid" text,
                            "psk" text,
                            UNIQUE(guid,psk)
                        )''')

    def add_session(self, guid, psk: str):
        with self.db:
            try:
                self.db.execute("INSERT INTO sessions (guid, psk) VALUES (?,?)", [str(guid), psk])
                return psk
            except sqlite3.IntegrityError:
                logging.debug(f"Session with guid {guid} already present in database")

    def remove_session(self, guid):
        with self.db:
            try:
                self.db.execute(f"DELETE FROM sessions WHERE guid = '{guid}'")
                return
            except sqlite3.IntegrityError:
                logging.debug(f"Could not remove {guid} from the database")

    def get_session_psk(self, guid):
        with self.db:
            query = self.db.execute("SELECT psk FROM sessions WHERE guid=(?)", [str(guid)])
            result = query.fetchone()
            return result[0] if result else None

    def get_sessions(self):
        with self.db:
            query = self.db.execute("SELECT * FROM sessions")
            return query.fetchall()

    def __enter__(self):
        self.db = sqlite3.connect(self.db_path)
        return self

    def __exit__(self, exec_type, exc, tb):
        self.db.close()
