from datetime import datetime

from sqlalchemy import or_, select, union

from ..helpers import convert_to_timestamp
from ..models import Event, EventShare, User
from .base import BaseHandler


class IndexHandler(BaseHandler):
    async def get(self):
        current_user = self.current_user

        if current_user is None:
            self.render("index.html", current_user=None, events=None, status="Upcoming")
            return

        start = self.get_query_argument("start", 0)
        start = convert_to_timestamp(start)

        end = self.get_query_argument("end", 0)
        end = convert_to_timestamp(end)

        imported = self.get_query_argument("new", "").split(',')
        imported = list(filter(str.isdigit, imported))

        async with self.application.db_sessionmaker() as session:
            now = datetime.now().timestamp()
            owned_and_public_events_stmt = (
                select(Event.id, User.username, Event.name, Event.start, Event.end)
                .join(Event, User.id == Event.user_id)
                .where(or_(User.username == current_user, Event.private == False))
                .where(Event.end > now)
            )

            shared_events_stmt = (
                select(Event.id, User.username, Event.name, Event.start, Event.end)
                .join(EventShare, Event.id == EventShare.event_id)
                .join(User, Event.user_id == User.id)
                .where(EventShare.username == current_user)
                .where(Event.end > now)
            )

            if start != 0:
                owned_and_public_events_stmt = owned_and_public_events_stmt.where(
                    Event.start >= start
                )
                shared_events_stmt = shared_events_stmt.where(Event.start >= start)

            if end != 0:
                owned_and_public_events_stmt = owned_and_public_events_stmt.where(
                    Event.end <= end
                )
                shared_events_stmt = shared_events_stmt.where(Event.end <= end)

            stmt = union(owned_and_public_events_stmt, shared_events_stmt)
            result = await session.execute(stmt)
            events = result.all()

        self.render(
            "index.html", current_user=current_user, events=events, status="Upcoming", imported=imported
        )


class EndedHandler(BaseHandler):
    async def get(self):
        current_user = self.current_user

        if current_user is None:
            self.render("index.html", current_user=None, events=None, status="Ended")
            return

        start = self.get_query_argument("start", 0)
        start = convert_to_timestamp(start)

        end = self.get_query_argument("end", 0)
        end = convert_to_timestamp(end)

        async with self.application.db_sessionmaker() as session:
            # NOTE: Ended private events must be visible too
            now = datetime.now().timestamp()
            stmt = select(
                Event.id, User.username, Event.name, Event.start, Event.end
            ).join(Event, User.id == Event.user_id)

            if start != 0:
                stmt = stmt.where(Event.start >= start)

            result = await session.execute(stmt)
            events = result.all()

        # Filter only finished events
        # ----now---end---- -> then filter to now
        # ----end---now---- -> then filter to end
        if end == 0 or now < end:
            events = [event for event in events if not event.end >= now]
        else:
            events = [event for event in events if not event.end >= end]

        self.render(
            "index.html", current_user=current_user, events=events, status="Ended", imported=[]
        )