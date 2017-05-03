# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
import webapp2
import jinja2
import re
import hmac
import hashlib
import random
from string import letters
from google.appengine.ext import db
import time


JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)

# Global Variables

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


class Blog(db.Model):
    """ This is a class that holds information about blogs.
        Attributes:
            title (string): The title of the blog.
            body (text): The content of the blog.
            user_id (int): User_id of the author.
            created (datetime) : time and date when blog was created.
            last_moodifed (datetime): time and date when blog was last
                                      modified.
            liked (list of int): list of user_ids who like the blog.
    """
    title = db.StringProperty(required=True)
    body = db.TextProperty(required=True)
    user_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    liked = db.ListProperty(int)

    @classmethod
    def by_id(cls, uid):
        """Fetches a blog by id."""
        return cls.get_by_id(uid)


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


class Comment(db.Model):
    """ This is a class that holds information about comments.
        Attributes:
            user_id (int): The id of the user that wrote the comment.
            blog_id (int): The id of the blog where the comment was written.
            created (datetime): Date and time when the comment was written.
            text (text): Text of the comment.
    """
    user_id = db.IntegerProperty(required=True)
    blog_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    text = db.TextProperty(required=True)

    @classmethod
    def by_id(cls, uid):
        """Fetches a comment by id and returns it."""
        return cls.get_by_id(uid)

    @classmethod
    def by_blog(cls, blog_id):
        """Fetches the latest 100 comments by blog id and returns it."""
        query = Comment.all().filter("blog_id =", int(blog_id))
        comments = query.order('-created').run(limit=100)
        return comments

    def get_username(self):
        """Returns the username of the user who wrote the comment."""
        user_id = self.user_id
        user = User.by_id(user_id)
        return user.username


class AppHandler(webapp2.RequestHandler):
    """ Wrapper class to the Google App Engine Request Handler."""
    def write(self, *args, **kwargs):
        """Wrapper for response.out.write()"""
        return self.response.out.write(*args, **kwargs)

    def render_str(self, template, **params):
        """ renders a template with the params"""
        t = JINJA_ENVIRONMENT.get_template(template)
        return t.render(params)

    def render(self, template, **kwargs):
        """displays the template on the browser"""
        self.write(self.render_str(template, **kwargs))

    def render_dict(self, template, d):
        """renders a template with the dictionary"""
        t = JINJA_ENVIRONMENT.get_template(template)
        return self.write(t.render(d))

    def set_cookie(self, name, val):
        """Sets a cookie 'user_id' with the userid and val"""
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_cookie(self, name):
        """Return the cookie val if it exists and passes validation"""
        cookie_val = self.request.cookies.get(name)
        if cookie_val:
            return check_secure_val(cookie_val)

    def login(self, user):
        """
        Creates a cookie called user_id and sets the val to the user_id|hash
        """
        self.set_cookie('user_id', str(user.key().id()))

    def logout(self):
        """
        Sets the value of the cookie user_id to none.
        """
        self.response.headers.add_header('Set-Cookie',
                                         'user_id=; Path=/')

    def initialize(self, *args, **kwargs):
        """
        Checks to see if user_id cookie is present or not.
        """
        webapp2.RequestHandler.initialize(self, *args, **kwargs)
        user_id = self.read_cookie('user_id')
        if user_id and User.by_id(int(user_id)):
            self.user_id = int(user_id)
        else:
            self.user_id = None


class NewBlogPage(AppHandler):
    """
    Handler to create a new blog page
    """
    def get(self):
        if self.user_id:
            self.render('newblog.html')
        else:
            # user not logged in redirect to signup page
            self.redirect('/blog/login')

    def post(self):
        if self.user_id:
            title = self.request.get('subject')
            text = self.request.get('content')
            if title and text:
                # both title and text are required
                blog = Blog(title=title, body=text, user_id=self.user_id)
                blog_id = blog.put().id()
                self.redirect("/blog/%d" % blog_id)
            else:
                error = 'Both fields are required.'
                self.render('newblog.html', error=error, title=title,
                            text=text)
        else:
            self.redirect('/blog/login')


class BlogEntryPage(AppHandler):
    """
    Handler to display a particular blog entry.
    """
    def get(self, post_id):
        # post_id is the blog id
        if self.user_id:
            blog = Blog.get_by_id(int(post_id))
            if blog:
                # Fetch all comments that are tied to the blog.
                comments = Comment.by_blog(post_id)
                self.render('blogpost.html', blog=blog, user_id=self.user_id,
                            comments=comments)
            else:
                self.redirect('/blog/permissionerror/')
        else:
            self.redirect('/blog/login')


class EditBlogPage(AppHandler):
    """
    Handler to display/process the form to edit a blog entry.
    """
    def get(self, post_id):
        if self.user_id:
            blog = Blog.by_id(int(post_id))
            if blog:
                # only the blog author can edit it
                if blog.user_id == self.user_id:
                    self.render('editblog.html', blog=blog)
                else:
                    error = 'Only the Blog owner can edit this blog post.'
                    comments = Comment.by_blog(post_id)
                    self.render('blogpost.html', blog=blog, error=error,
                                user_id=self.user_id, comments=comments)
            else:
                # Invalid blog - display error page
                self.render('permissionerror.html')
        else:
            self.redirect('/blog/login')

    def post(self, post_id):
        if self.user_id:
            title = self.request.get('subject')
            text = self.request.get('content')
            if title and text:
                blog = Blog.by_id(int(post_id))
                blog.title = title
                blog.body = text
                blog.put()
                self.redirect("/blog/%d" % int(post_id))
            else:
                error = 'Both fields are required.'
                self.render('editblog.html', error=error, title=title,
                            text=text)
        else:
            self.redirect('/blog/login')


class DeleteBlogPage(AppHandler):
    """
    Handler to delete a blog entry.
    """
    def post(self, post_id):
        if self.user_id:
            blog = Blog.by_id(int(post_id))
            if blog:
                # Only the blog author can delete the blog
                if blog.user_id == self.user_id:
                    db.delete(blog.key())
                    # Adding a sleep of 1 second here
                    # Observation - the database takes a while to reflect the
                    # change
                    time.sleep(1)
                    self.redirect('/blog')
                else:
                    error = 'Only the Blog owner can delete this blog post.'
                    comments = Comment.by_blog(post_id)
                    self.render('blogpost.html', blog=blog, error=error,
                                user_id=self.user_id, comments=comments)
            else:
                self.render('permissionerror.html')
        else:
            self.redirect('/blog/login')


class ToggleLike(AppHandler):
    """
    Handler to like/unlike a blog entry.
    """
    def post(self, post_id):
        if self.user_id:
            user_id = self.user_id
            blog = Blog.by_id(int(post_id))
            if blog:
                # Blog author can't like their own posts.
                if blog.user_id == user_id:
                    error = "You can't like your own posts."
                    comments = Comment.by_blog(post_id)
                    self.render('blogpost.html', blog=blog, error=error,
                                user_id=user_id, comments=comments)
                else:
                    if user_id in blog.liked:
                        blog.liked.remove(user_id)
                        blog.put()
                    else:
                        blog.liked.append(user_id)
                        blog.put()
                    self.redirect('/blog/%d' % int(post_id))
            else:
                self.render('permissionerror.html')
        else:
            self.redirect('/blog/login')


class AddComment(AppHandler):
    """
    Handler to add comments to a blog.
    """
    def post(self, post_id):
        if self.user_id:
            blog = Blog.by_id(int(post_id))
            text = self.request.get('text')
            if blog:
                if not text:
                    comment_error = "Can't post empty comment."
                    comments = Comment.by_blog(post_id)
                    self.render('blogpost.html', blog=blog,
                                add_comment_error=comment_error,
                                user_id=self.user_id, comments=comments)
                else:
                    comment = Comment(blog_id=int(post_id),
                                      user_id=self.user_id,
                                      text=text)
                    comment.put()
                    # Adding a sleep of 1 second here
                    # Observation - the database takes a while to reflect the
                    # change
                    time.sleep(1)
                    self.redirect('/blog/%d' % int(post_id))
            else:
                self.render('permissionerror.html')
        else:
            self.redirect('/blog/login')


class DeleteComment(AppHandler):
    """
    Handler to delete a comment.
    """
    def post(self, post_id):
        # post_id is the comment id.
        if self.user_id:
            comment = Comment.by_id(int(post_id))
            if comment:
                blog_id = comment.blog_id
                blog = Blog.by_id(blog_id)
                # Only the commentor can delete the comment.
                if comment.user_id == self.user_id:
                    db.delete(comment.key())
                    time.sleep(1)
                    self.redirect('/blog/%d' % blog_id)
                else:
                    comment_error = """Only the Commenter
                                    can delete this comment."""
                    comments = Comment.by_blog(blog_id)
                    self.render('blogpost.html', blog=blog,
                                user_id=self.user_id,
                                comments=comments,
                                comment_error_id=int(post_id),
                                comment_error=comment_error)
            else:
                self.render('permissionerror.html',
                            error="Comment doesn't exist")
        else:
            self.redirect('/blog/login')


class EditComment(AppHandler):
    """
    Blog Handler to delete a comment.
    """
    def get(self, post_id):
        if self.user_id:
            comment = Comment.by_id(int(post_id))
            if comment:
                # Only the commentor can edit the comment.
                if comment.user_id == self.user_id:
                    self.render('editcomment.html', comment=comment)
                else:
                    comment_error = """Only the Commenter
                                    can edit this comment."""
                    blog_id = comment.blog_id
                    blog = Blog.by_id(blog_id)
                    comments = Comment.by_blog(blog_id)
                    self.render('blogpost.html', blog=blog,
                                user_id=self.user_id,
                                comments=comments,
                                comment_error_id=int(post_id),
                                comment_error=comment_error)
            else:
                self.render('permissionerror.html',
                            error="Comment doesn't exist")
        else:
            self.redirect('/blog/login')

    def post(self, post_id):
        if self.user_id:
            text = self.request.get('content')
            if text:
                comment = Comment.by_id(int(post_id))
                if comment:
                    comment.text = text
                    comment.put()
                    time.sleep(1)
                    self.redirect("/blog/%d" % comment.blog_id)
                else:
                    self.render('permissionerror.html',
                                error="Comment doesn't exist")
            else:
                error = "Comment cannot be blank."
                self.render('editcomment.html', error=error)
        else:
            self.redirect('/blog/login')


class BlogPage(AppHandler):
    """
    Handler that displays the main blog page.
    Only the 10 latest blogs are displayed.
    """
    def get(self):
        # fetch the 10 latest blog entries.
        blogs = Blog.all().order('-created').run(limit=10)
        self.render('blog.html', blogs=blogs)


class Register(AppHandler):
    """
    Handler that displays/processes the Registration form.
    """
    def process_form(self, post_data):
        """
        Utility function to process the form and generate errors.
        """
        username = post_data[0]
        password = post_data[1]
        verify = post_data[2]
        email = post_data[3]
        errors = {}
        if not username or not valid_username(username):
            errors['username_error'] = "That's not a valid username."
        if not password or not valid_password(password):
            errors['password_error'] = "That wasn't a valid password."
        else:
            if not verify or verify != password:
                errors['verify_error'] = "Your passwords didn't match."
        if email and not valid_email(email):
            errors['email_error'] = "That's not a valid email."
        if errors:
            errors['email'] = email
            errors['username'] = username
        return errors

    def get(self):
        self.render('register.html')

    def post(self):
        data = [self.request.get('username'), self.request.get('password'),
                self.request.get('verify'), self.request.get('email')]
        errors = self.process_form(data)
        if errors:
            self.render_dict('register.html', errors)
        else:
            user_exists = User.by_name(data[0])
            if user_exists:
                errors['username_error'] = "Username exists."
                self.render_dict('register.html', errors)
            else:
                user = User.register(data[0], data[1], data[3])
                # add new user to the database.
                user.put()
                # create cookie for the user
                self.login(user)
                self.redirect('/blog/welcome')


class Login(AppHandler):
    """
    Handler that displays/processes the login form.
    """
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        user = User.login(username, password)
        if user:
            self.login(user)
            self.redirect('/blog/welcome')
        else:
            error = 'Invalid username and/or password.'
            self.render('login.html', error=error, username=username)


class Logout(AppHandler):
    """
    Handler to logout a user and delete the cookie.
    """
    def get(self):
        self.logout()
        self.redirect('/blog/login')


class Welcome(AppHandler):
    """
    Handler to display the welcome page after a user logs in.
    """
    def get(self):
        if self.user_id:
            user = User.by_id(self.user_id)
            self.render('welcome.html', username=user.username)
        else:
            self.redirect('/blog/login')


class PermissionErr(AppHandler):
    """
    Handler to show an error page.
    """
    def get(self):
        self.render('permissionerror.html')


# URL to handler mapping
app = webapp2.WSGIApplication([
    (r'/blog/?', BlogPage),
    (r'/blog/newpost/?', NewBlogPage),
    (r'/blog/(\d+)/?', BlogEntryPage),
    (r'/blog/(\d+)/edit/?', EditBlogPage),
    (r'/blog/(\d+)/delete/?', DeleteBlogPage),
    (r'/blog/(\d+)/togglelike/?', ToggleLike),
    (r'/blog/(\d+)/addcomment/?', AddComment),
    (r'/blog/comment/(\d+)/delete/?', DeleteComment),
    (r'/blog/comment/(\d+)/edit/?', EditComment),
    (r'/blog/signup/?', Register),
    (r'/blog/login/?', Login),
    (r'/blog/logout/?', Logout),
    (r'/blog/welcome/?', Welcome),
    (r'/blog/permissionerror/?', PermissionErr),
], debug=True)
