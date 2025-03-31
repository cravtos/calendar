import hashlib
import pickle

import tornado
from sqlalchemy import insert, select

from io import BytesIO
from ..models import Event, User
from .base import BaseHandler

SECRET = "K6^igk56Hmr$zP*SiZdTFGe9U4sX$z!x"
MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 mb
HASH_BLOCK_SIZE = 32


class ImportEventsHandler(BaseHandler):
    @tornado.web.authenticated
    async def post(self):
        file_data = self.request.files.get("file")
        if not file_data:
            self.set_status(400)
            self.write({"error": "File is missing"})
            return

        data = file_data[0].body

        if len(data) > MAX_FILE_SIZE:
            self.set_status(400)
            self.write({"error": "File size exceeds the limit (1 MB)"})
            return

        if len(data) <= HASH_BLOCK_SIZE:
            self.set_status(400)
            self.write({"error": "File is too small!"})
            return

        parts = data.split(b"\n")
        if len(parts) != 2:
            self.set_status(400)
            self.write({"error": "Invalid data format"})
            return

        hash = parts[0].decode(errors="ignore")
        data = parts[1].decode(errors="ignore")

        try:
            data = bytes.fromhex(data)
        except ValueError:
            self.set_status(400)
            self.write({"error": "Invalid hexadecimal data format"})
            return

        expected_hash = hashlib.md5(SECRET.encode() + data).hexdigest()

        if expected_hash != hash:
            self.set_status(400)
            self.write({"error": "Invalid signature"})
            return

        username = self.current_user
        user_id = None
        async with self.application.db_sessionmaker() as session:
            stmt = select(User).where(User.username == username)
            result = await session.execute(stmt)
            user = result.scalar_one_or_none()
            if user is None:
                self.set_status(500)
                self.write({"error": "kak cookie iz palaty vibralas"})
                return

            user_id = user.id

        events = []
        for event in loadall(data):
            event["user_id"] = user_id
            events.append(event)

        self.application.log.error(f"Got events: {events}")

        async with self.application.db_sessionmaker() as session:
            res = await session.execute(insert(Event).returning(Event.id), events)
            await session.commit()

        imported = [str(id[0]) for id in res]
        self.application.log.info(f"User {username} imported events {imported}.")
        self.redirect(f"/?new={','.join(imported)}")  # 🩼


class ExportEventsHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self):
        event_ids = self.get_query_arguments("id")
        event_ids = [int(id) for id in event_ids]

        self.application.log.info(
            f"User {self.current_user} is trying to export events {event_ids}"
        )

        async with self.application.db_sessionmaker() as session:
            stmt = select(User.id).where(User.username == self.current_user)
            result = await session.execute(stmt)
            user_id = result.scalar_one_or_none()

            if user_id is None:
                self.set_status(500)
                self.write({"error": "user not found"})
                return

            stmt = (
                select(Event)
                .where(Event.id.in_(event_ids))
                .filter(Event.user_id == user_id)
                .order_by(Event.id)
            )
            result = await session.execute(stmt)
            events = result.all()

        if not events:
            self.set_status(404)
            self.write({"error": "Events not found"})
            return

        # ATTENTION!!!
        # External services are dependent on the format of the exported file.
        # Don't change data structure, only hash can be changed!
        serialized = bytes()
        for event in events:
            event = event[0]
            event_data = {
                "start": event.start,
                "end": event.end,
                "details": event.details,
                "private": event.private,
                "name": event.name,
            }
            serialized += pickle.dumps(event_data)

        response = (
            hashlib.md5(SECRET.encode() + serialized).hexdigest()
            + "\n"
            + serialized.hex()
        )

        self.set_header("Content-Type", "application/octet-stream")
        self.set_header(
            "Content-Disposition", f'attachment; filename="event_export.pkl"'
        )
        self.write(response)


def loadall(data: bytes):
    with BytesIO(data) as f:
        while True:
            try:
                yield pickle.load(
                    f, fix_imports=False, encoding="bytes", errors="ignore"
                )
            except EOFError:
                break
            except Exception:
                continue
