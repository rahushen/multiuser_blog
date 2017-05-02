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

SECRET = 'ldkasfhalasfgKEAHKRAK5758I0$%^&SLADHSLAKHDFL2814062148afo734'
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def valid_username(username):
    return USER_RE.match(username)


def valid_password(password):
    return PASS_RE.match(password)


def valid_email(email):
    return EMAIL_RE.match(email)


def make_secure_val(val):
    return "%s|%s" % (val, hmac.new(SECRET, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(pw, salt=None):
    if not salt:
        salt = make_salt()
    pw_hash = hashlib.sha256(pw + salt).hexdigest()
    return "%s|%s" % (salt, pw_hash)


def validate_pw(pw, h):
    salt = h.split('|')[0]
    if h == make_pw_hash(pw, salt):
        return h


class Blog(db.Model):
    title = db.StringProperty(required=True)
    body = db.TextProperty(required=True)
    user_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    liked = db.ListProperty(int)

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid)


class User(db.Model):
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid)

    @classmethod
    def by_name(cls, username):
        return cls.all().filter('username =', username).get()

    @classmethod
    def register(cls, username, password, email=None):
        pw_hash = make_pw_hash(password)
        return cls(username=username,
                   pw_hash=pw_hash,
                   email=email)

    @classmethod
    def login(cls, username, pw):
        uname = cls.by_name(username)
        if uname and validate_pw(pw, uname.pw_hash):
            return uname


class Comment(db.Model):
    user_id = db.IntegerProperty(required=True)
    blog_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    text = db.TextProperty(required=True)

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid)

    @classmethod
    def by_blog(cls, blog_id):
        query = db.GqlQuery('''SELECT * FROM Comment WHERE blog_id = %s
                            ORDER BY created DESC''' % blog_id)
        comments = query.fetch(100)
        return comments

    def get_username(self):
        user_id = self.user_id
        user = User.by_id(user_id)
        return user.username


class AppHandler(webapp2.RequestHandler):
    def write(self, *args, **kwargs):
        return self.response.out.write(*args, **kwargs)

    def render_str(self, template, **params):
        t = JINJA_ENVIRONMENT.get_template(template)
        return t.render(params)

    def render(self, template, **kwargs):
        self.write(self.render_str(template, **kwargs))

    def render_dict(self, template, d):
        t = JINJA_ENVIRONMENT.get_template(template)
        return self.write(t.render(d))

    def set_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        if cookie_val:
            return check_secure_val(cookie_val)

    def login(self, user):
        self.set_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie',
                                         'user_id=; Path=/')


class NewBlogPage(AppHandler):
    def get(self):
        self.render('newblog.html')

    def post(self):
        title = self.request.get('subject')
        text = self.request.get('content')
        if title and text:
            user_cookie = self.read_cookie('user_id')
            if user_cookie:
                user_id = int(user_cookie.split('|')[0])
                blog = Blog(title=title, body=text, user_id=user_id)
                key = blog.put()
                keyid = key.id()
                self.redirect("/blog/%d" % keyid)
            else:
                self.redirect('/blog/signup')
        else:
            error = 'Both fields are required.'
            self.render('newblog.html', error=error, title=title,
                        text=text)


class BlogEntryPage(AppHandler):
    def get(self, post_id):
        cookie = self.read_cookie('user_id')
        if cookie:
            user_id = int(cookie.split('|')[0])
            blog = Blog.get_by_id(int(post_id))
            comments = Comment.by_blog(post_id)
            if blog:
                self.render('blogpost.html', blog=blog, user_id=user_id,
                            comments=comments)
            else:
                self.redirect('/blog/permissionerror/')
        else:
            self.redirect('/blog/signup')


class EditBlogPage(AppHandler):
    def get(self, post_id):
        cookie = self.read_cookie('user_id')
        if cookie:
            user_id = int(cookie.split('|')[0])
            blog = Blog.by_id(int(post_id))
            comments = Comment.by_blog(post_id)
            if blog:
                if blog.user_id == user_id:
                    self.render('editblog.html', blog=blog)
                else:
                    error = 'Only the Blog owner can edit this blog post.'
                    self.render('blogpost.html', blog=blog, error=error,
                                user_id=user_id, comments=comments)
            else:
                self.render('permissionerror.html')
        else:
            self.redirect('/blog/signup')

    def post(self, post_id):
        title = self.request.get('subject')
        text = self.request.get('content')
        blog_id = post_id
        if title and text:
            user_cookie = self.read_cookie('user_id')
            if user_cookie:
                blog = Blog.by_id(int(blog_id))
                blog.title = title
                blog.body = text
                key = blog.put()
                keyid = key.id()
                self.redirect("/blog/%d" % keyid)
            else:
                self.redirect('/blog/signup')
        else:
            error = 'Both fields are required.'
            self.render('editblog.html', error=error, title=title,
                        text=text)


class DeleteBlogPage(AppHandler):
    def post(self, post_id):
        cookie = self.read_cookie('user_id')
        if cookie:
            user_id = int(cookie.split('|')[0])
            blog = Blog.by_id(int(post_id))
            comments = Comment.by_blog(post_id)
            if blog:
                if blog.user_id == user_id:
                    db.delete(blog.key())
                    time.sleep(1)
                    self.redirect('/blog')
                else:
                    error = 'Only the Blog owner can delete this blog post.'
                    self.render('blogpost.html', blog=blog, error=error,
                                user_id=user_id, comments=comments)
            else:
                self.render('permissionerror.html')
        else:
            self.redirect('/blog/signup')


class ToggleLike(AppHandler):
    def post(self, post_id):
        cookie = self.read_cookie('user_id')
        if cookie:
            user_id = int(cookie.split('|')[0])
            blog = Blog.by_id(int(post_id))
            comments = Comment.by_blog(post_id)
            if blog:
                if blog.user_id == user_id:
                    error = "You can't like your own posts."
                    self.render('blogpost.html', blog=blog, error=error,
                                user_id=user_id, comments=comments)
                else:
                    if user_id in blog.liked:
                        blog.liked.remove(user_id)
                        blog.put()
                    else:
                        blog.liked.append(user_id)
                        blog.put()
                    self.redirect('/blog/%d' % blog.key().id())
            else:
                self.render('permissionerror.html')
        else:
            self.redirect('/blog/signup')


class AddComment(AppHandler):
    def post(self, post_id):
        cookie = self.read_cookie('user_id')
        if cookie:
            user_id = int(cookie.split('|')[0])
            blog = Blog.by_id(int(post_id))
            comments = Comment.by_blog(post_id)
            text = self.request.get('text')
            if blog:
                if not text:
                    comment_error = "Can't post empty comment"
                    self.render('blogpost.html', blog=blog,
                                comment_error=comment_error,
                                user_id=user_id, comments=comments)
                else:
                    comment = Comment(blog_id=blog.key().id(),
                                      user_id=int(user_id),
                                      text=text)
                    comment.put()
                    time.sleep(1)
                    comments = Comment.by_blog(post_id)
                    self.render('blogpost.html', blog=blog,
                                user_id=user_id, comments=comments)
            else:
                self.render('permissionerror.html')
        else:
            self.redirect('/blog/signup')


class DeleteComment(AppHandler):
    def post(self, post_id):
        cookie = self.read_cookie('user_id')
        if cookie:
            user_id = int(cookie.split('|')[0])
            comment = Comment.by_id(int(post_id))
            if comment:
                blog_id = comment.blog_id
                blog = Blog.by_id(blog_id)
                if comment.user_id == user_id:
                    db.delete(comment.key())
                    time.sleep(1)
                    self.redirect('/blog/%d' % blog_id)
                else:
                    comment_error = """Only the Commenter
                                    can delete this comment."""
                    comments = Comment.by_blog(blog_id)
                    self.render('blogpost.html', blog=blog,
                                user_id=user_id,
                                comments=comments,
                                comment_error_id=post_id,
                                comment_error=comment_error)
            else:
                self.render('permissionerror.html',
                            error="Comment doesn't exist")
        else:
            self.redirect('/blog/signup')


class EditComment(AppHandler):
    def get(self, post_id):
        cookie = self.read_cookie('user_id')
        if cookie:
            user_id = int(cookie.split('|')[0])
            comment = Comment.by_id(int(post_id))
            if comment:
                if comment.user_id == user_id:
                    self.render('editcomment.html', comment=comment)
                else:
                    comment_error = """Only the Commenter
                                    can edit this comment."""
                    blog_id = comment.blog_id
                    blog = Blog.by_id(blog_id)
                    comments = Comment.by_blog(blog_id)
                    self.render('blogpost.html', blog=blog,
                                user_id=user_id,
                                comments=comments,
                                comment_error_id=post_id,
                                comment_error=comment_error)
            else:
                self.render('permissionerror.html',
                            error="Comment doesn't exist")
        else:
            self.redirect('/blog/signup')

    def post(self, post_id):
        text = self.request.get('content')
        if text:
            user_cookie = self.read_cookie('user_id')
            if user_cookie:
                comment = Comment.by_id(int(post_id))
                comment.text = text
                comment.put()
                time.sleep(1)
                self.redirect("/blog/%d" % comment.blog_id)
            else:
                self.redirect('/blog/signup')
        else:
            error = "Comment cannot be blank."
            self.render('editcomment.html', error=error,
                        text=text)


class BlogPage(AppHandler):
    def get(self):
        query = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC")
        blogs = query.fetch(10)
        self.render('blog.html', blogs=blogs)


class Register(AppHandler):
    def process_form(self, post_data):
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
                user.put()
                self.login(user)
                self.redirect('/blog/welcome')


class Login(AppHandler):
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
    def get(self):
        self.logout()
        self.redirect('/blog/signup')


class Welcome(AppHandler):
    def get(self):
        cookie = self.read_cookie('user_id')
        if cookie:
            user = User.by_id(int(cookie.split('|')[0]))
            self.render('welcome.html', username=user.username)
        else:
            self.redirect('/blog/signup')


class PermissionErr(AppHandler):
    def get(self):
        self.render('permissionerror.html')


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
