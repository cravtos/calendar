import os

import tornado
from tornado.web import url

from .handlers import *


class Application(tornado.web.Application):
    def __init__(self, db_sessionmaker, log):
        self.db_sessionmaker = db_sessionmaker
        self.log = log
        handlers = [
            url(r"/", IndexHandler, name="index"),
            url(r"/ended", EndedHandler, name="index_ended"),
            url(r"/register", RegisterHandler, name="register"),
            url(r"/login", LoginHandler, name="login"),
            url(r"/logout", LogoutHandler, name="logout"),
            url(r"/users", GetUsersHandler, name="get_users"),
            url(r"/create", CreateEventHandler, name="create"),
            url(r"/event/(.*)/", EventHandler, name="event"),
            url(r"/event/(.*)/share", ShareEventHandler, name="share_event"),
            url(r"/export", ExportEventsHandler, name="export"),
            url(r"/import", ImportEventsHandler, name="import"),
        ]
        settings = {
            "static_path": os.path.join(os.path.dirname(__file__), "static"),
            "template_path": os.path.join(os.path.dirname(__file__), "templates"),
            "cookie_secret": "__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
            "debug": True,
            "login_url": "/login",
        }
        super().__init__(handlers, **settings)
