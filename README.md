# blog_project
Project 3 for the Udacity Full Stack Development NanoDegree.

In this project I built a blog where users can see my post blogs as well as like and comment on it.

## Table of contents

- [Install](#install)
- [Quick start](#quick-start)
- [Creator](#creator)

## Install

- [Download the project zip archive] (https://github.com/rahushen/multiuser_blog/archive/master.zip)
- Clone the repo: `git clone https://github.com/rahushen/multiuser_blog.git`

### What's included

The following files are included in the download :

```
multiuser_blog/
├── README.md
├── app.yaml
├── base.html
├── blog.html
├── blogpost.html
├── css
│   └── style.css
├── editblog.html
├── editcomment.html
├── index.yaml
├── login.html
├── multiuser_blog.py
├── multiuser_blog.pyc
├── newblog.html
├── permissionerror.html
├── register.html
└── welcome.html
```

## Quick start

The code has been tested to work with Python 2.7.X . Verify you have the right version of python running the `python -V` command.
Also have google app engine installed.

To run the code locally:

```
cd /path/to/the/install
dev_appserver.py .
```

Then open the browser and navigate to http://localhost:8080/blog/

To visit the blog on the internet:

Open the browser and navigate to https://hello-world-162506.appspot.com/blog/
```
Use the following URLs to achieve the following actions:

<server>/blog - get the homepage - the 10 latest blogs
<server>/blog/<blog_id> - to get a specific blog page
<server>/blog/signup - to register a new user
<server>/blog/login - to login in to the blog service if already registered
<server>/blog/logout - to logout a user
<server>/blog/welcome - to the welcome page for the user
<server>/blog/newpost - allows a user to create a new blog
```
where `server` is http://localhost:8080 for local dev app server and https://hello-world-162506.appspot.com on the internet.
```
Several Features are available for a user:
Like/Unlike - A user can like/unlike another user's blog using the Like/Unlike button on the blog page.
Edit/Delete a Blog - A user can edit/delete his own blog using the edit and delete button on the blog page respectively.
Comments - All users can comment on any blog using the 'Add comment' link on a blog.
Edit/Delete a Comment - A user can edit/delete his own comment using the edit and delete button on the comment respectively.
```
## Creator

**Rahul shenoy**
- <https://github.com/rahushen>
