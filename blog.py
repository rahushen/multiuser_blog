from google.appengine.ext import db


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
