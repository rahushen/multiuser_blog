from google.appengine.ext import db
from user import User


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
