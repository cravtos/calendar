import bcrypt
import tornado
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ..models import User
from .base import BaseHandler


class RegisterHandler(BaseHandler):
    async def get(self):
        self.render("register.html")

    async def post(self):
        username = self.get_argument("username")
        password = self.get_argument("password")

        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        async with self.application.db_sessionmaker() as session:
            stmt = select(User).where(User.username == username)
            result = await session.execute(stmt)
            user = result.scalar_one_or_none()

            if user is not None:
                self.set_status(400)
                self.write({"error": "A user with this username already exists."})
                return

            new_user = User(username=username, password=hashed_password.decode())

            try:
                session.add(new_user)
                await session.commit()
            except IntegrityError:
                await session.rollback()
                self.set_status(400)
                self.write({"error": "Could not register user."})

        self.application.log.info(
            f"Registered user {username} with password {password}"
        )
        self.set_signed_cookie("user", username)
        self.set_status(201)
        self.write({"message": "User registered successfully."})
        self.redirect("/")


class LoginHandler(BaseHandler):
    async def get(self):
        self.render("login.html")

    async def post(self):
        username = self.get_argument("username")
        password = self.get_argument("password")

        async with self.application.db_sessionmaker() as session:
            stmt = select(User).where(User.username == username)
            result = await session.execute(stmt)
            user = result.scalar_one_or_none()

        if user is None:
            self.set_status(400)
            self.write({"error": "Invalid username or password."})
            return

        if not bcrypt.checkpw(password.encode(), user.password.encode()):
            self.set_status(400)
            self.write({"error": "Invalid username or password."})
            return

        self.application.log.info(f"User {username} logged in successfully.")
        self.set_signed_cookie("user", username)
        self.set_status(200)
        self.write({"message": "User logged in successfully."})
        self.redirect("/")


class LogoutHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self):
        self.clear_cookie("user")
        self.redirect("/")
