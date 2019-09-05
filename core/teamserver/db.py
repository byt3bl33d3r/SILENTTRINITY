import aiosqlite
import sqlite3
import logging
import asyncio
import uuid

# I'd preferably like to avoid having STD in any class names, should probably get that checked out.

class AsyncSTDatabase:

    @staticmethod
    async def create_db_and_schema(db_path="./data/st.db"):
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

    async def __aenter__(self, db_path="./data/st.db"):
        self.db = await aiosqlite.connect(db_path)
        return self

    async def __aexit__(self, exec_type, exc, tb):
        await self.db.commit()
        await self.db.close()

class STDatabase:

    @staticmethod
    def create_db_and_schema(db_path="./data/st.db"):
        with sqlite3.connect(db_path) as db:
            db.execute('''CREATE TABLE "sessions" (
                            "id" integer PRIMARY KEY,
                            "guid" text,
                            "psk" text,
                            UNIQUE(guid,psk)
                        )''')

    def add_session(self, guid, psk: str):
        with self.db:
            self.db.execute("INSERT INTO sessions (guid, psk) VALUES (?,?)", [str(guid), psk])
            return psk

    def get_session_psk(self, guid):
        with self.db:
            query = self.db.execute("SELECT psk FROM sessions WHERE guid=(?)", [str(guid)])
            result = query.fetchone()
            return result[0]
    
    def get_sessions(self):
        with self.db:
            query = self.db.execute("SELECT * FROM sessions")
            return query.fetchall()

    def __enter__(self, db_path="./data/st.db"):
        self.db = sqlite3.connect(db_path)
        return self

    def __exit__(self, exec_type, exc, tb):
        self.db.close()
