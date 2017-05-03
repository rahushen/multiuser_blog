import re
import hmac
import hashlib
import random
from string import letters

# Random secret to add to hashes
SECRET = 'ldkasfhalasfgKEAHKRAK5758I0$%^&SLADHSLAKHDFL2814062148afo734'

# Regular expressions to validate Registration form
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def valid_username(username):
    """
    Validates that the username provided matches the regular expression.
    Returns True if valid.
    """
    return USER_RE.match(username)


def valid_password(password):
    """
    Validates that the password provided is between 3 and 20 characters.
    Returns True if valid.
    """
    return PASS_RE.match(password)


def valid_email(email):
    """
    Validates that the email provided has proper syntax.
    Returns True if valid.
    """
    return EMAIL_RE.match(email)


def make_secure_val(val):
    """
    Uses Hmac and a random secret to create a hash from val.
    Retruns string of the format "val|hash".
    """
    return "%s|%s" % (val, hmac.new(SECRET, val).hexdigest())


def check_secure_val(secure_val):
    """
    Take a string argument of format "val|hash" and returns val if
    hash(val) == hash
    """
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def make_salt(length=5):
    """
    Returns a random string of letters
    """
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(pw, salt=None):
    """
    Uses sha256 to hash a password.
    Salt is created if none is provided.
    Return string of the format "salt|password_hash"
    """
    if not salt:
        salt = make_salt()
    pw_hash = hashlib.sha256(pw + salt).hexdigest()
    return "%s|%s" % (salt, pw_hash)


def validate_pw(pw, h):
    """
    Validats password by verifying if hash values match.
    Returns hash of password is password is valid.
    """
    salt = h.split('|')[0]
    if h == make_pw_hash(pw, salt):
        return h


def login_required(func):
    """
    A decorator to confirm a user is logged in or redirect as needed.
    """
    def login(self, *args, **kwargs):
        # Redirect to login if user not logged in, else execute func.
        if not self.user_id:
            self.redirect("/blog/login")
        else:
            func(self, *args, **kwargs)
    return login
