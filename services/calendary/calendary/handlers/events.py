from datetime import datetime

import tornado
from sqlalchemy import or_, select, union
from sqlalchemy.exc import IntegrityError

from ..helpers import convert_to_timestamp
from ..models import Event, EventShare, User
from .base import BaseHandler


class EventHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self, id):
        self.application.log.info(
            f"User {self.current_user} is trying to view event {id}"
        )

        id = int(id)

        async with self.application.db_sessionmaker() as session:
            owned_and_public_events_stmt = (
                select(
                    Event.id,
                    User.username,
                    Event.name,
                    Event.start,
                    Event.end,
                    Event.details,
                )
                .join(Event, User.id == Event.user_id)
                .where(or_(User.username == self.current_user, Event.private == False))
                .where(Event.id == id)
            )

            shared_events_stmt = (
                select(
                    Event.id,
                    User.username,
                    Event.name,
                    Event.start,
                    Event.end,
                    Event.details,
                )
                .join(EventShare, Event.id == EventShare.event_id)
                .join(User, Event.user_id == User.id)
                .where(EventShare.username == self.current_user)
                .where(Event.id == id)
            )

            now = datetime.now().timestamp()
            ended_events_stmt = (
                select(
                    Event.id,
                    User.username,
                    Event.name,
                    Event.start,
                    Event.end,
                    Event.details,
                )
                .join(Event, User.id == Event.user_id)
                .where(Event.end <= now)
                .where(Event.id == id)
            )

            stmt = union(
                owned_and_public_events_stmt, shared_events_stmt, ended_events_stmt
            )

            result = await session.execute(stmt)
            event = result.first()

        if event is None:
            self.set_status(404)
            self.write({"error": "Event not found"})
            return

        self.application.log.info(f"User {self.current_user} viewed event {event}")

        self.render("event.html", event=event)


class ShareEventHandler(BaseHandler):
    @tornado.web.authenticated
    async def post(self, id):
        username = self.get_argument("username")

        self.application.log.info(
            f"User {self.current_user} is trying to share event {id} with {username}"
        )

        share = EventShare(event_id=int(id), username=username)

        async with self.application.db_sessionmaker() as session:
            session.add(share)
            try:
                await session.commit()
            except IntegrityError:
                self.set_status(400)
                self.write({"error": "Share alredy exist or user not exist"})
                return

        self.set_status(200)
        self.redirect(f"/event/{id}/")


class CreateEventHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self):
        self.render("create.html")

    @tornado.web.authenticated
    async def post(self):
        start = self.get_argument("start")
        end = self.get_argument("end")
        details = self.get_argument("details")
        name = self.get_argument("name")
        username = self.current_user

        start = convert_to_timestamp(start)
        end = convert_to_timestamp(end)

        if start >= end:
            self.set_status(400)
            self.write({"error": "start time should be before end time."})
            return

        try:
            private = self.get_argument("private") == "on"
        except tornado.web.MissingArgumentError:
            private = False

        self.application.log.info(
            f"User {username} is trying to create an event {name} from {start} to {end} with details: {details}"
        )

        async with self.application.db_sessionmaker() as session:
            stmt = select(User).where(User.username == username)
            result = await session.execute(stmt)
            user = result.scalar_one_or_none()
            if user is None:
                self.set_status(500)
                self.write({"error": "cookie expired, please log in again"})
                return

            event = Event(
                user_id=user.id,
                name=name,
                start=start,
                end=end,
                details=details,
                private=private,
            )
            session.add(event)
            await session.commit()

        self.application.log.info(f"User {username} created an event {event.id}.")
        self.write({"message": "Event created successfully"})
        self.redirect(f"/event/{event.id}/")
