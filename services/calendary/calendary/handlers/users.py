import tornado
from sqlalchemy import select

from ..models import User
from .base import BaseHandler


class GetUsersHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self):
        async with self.application.db_sessionmaker() as session:
            stmt = select(User.username)
            result = await session.execute(stmt)
            users = result.all()

        self.render("users.html", users=users)
