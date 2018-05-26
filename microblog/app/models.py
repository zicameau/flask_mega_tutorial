from app import db, login

from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from hashlib import md5

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

class Post(db.Model):
    body = db.Column(db.String(140))
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Post {}>'.format(self.body)

class User(UserMixin, db.Model):
    about_me = db.Column(db.String(140))
    email = db.Column(db.String(120), index=True, unique=True)
    followers = db.Table('followers',
        db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
        db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
    )
    followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')
    id = db.Column(db.Integer, primary_key=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    username = db.Column(db.String(64), index=True, unique=True)


    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(
            digest, size)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)

    def followed_posts(self):
        followed = Post.query.join(
            followers, (followers.c.followed_id == Post.user_id)).filter(
                followers.c.follower_id == self.id)
        own = Post.query.filter_by(user_id=self.id)
        return followed.union(own).order_by(Post.timestamp.desc())

    def is_following(self, user):
        return self.followed.filter(
            followers.c.followed_id == user.id).count() > 0


    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)
