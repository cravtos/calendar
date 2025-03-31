import tornado


class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        username = self.get_signed_cookie("user")
        if username is None:
            return None

        return username.decode()