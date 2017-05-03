from google.appengine.ext import db
from utils import make_pw_hash, validate_pw


class User(db.Model):
    """ This is a class that holds information about users.
        Attributes:
            username (string): The name of the user.
            pw_hash (string): Hash of the user's password.
            email (string): User's email id.
    """
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        """Fetches a user by id and returns it."""
        return cls.get_by_id(uid)

    @classmethod
    def by_name(cls, username):
        """Fetches a user by username and returns it."""
        return cls.all().filter('username =', username).get()

    @classmethod
    def register(cls, username, password, email=None):
        """
        Registers a user by creating a new user in the Db.
        Stores the username, password hash and email-id.
        """
        pw_hash = make_pw_hash(password)
        return cls(username=username,
                   pw_hash=pw_hash,
                   email=email)

    @classmethod
    def login(cls, username, pw):
        """
        Logs a user in if the password validation is successful.
        Returns the username on success.
        """
        uname = cls.by_name(username)
        if uname and validate_pw(pw, uname.pw_hash):
            return uname
