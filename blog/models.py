from blog import db, login_manager, app
from datetime import datetime
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_login import UserMixin


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(length=36), nullable=False, unique=True)
    email = db.Column(db.String(length=50), nullable=False, unique=True)
    password = db.Column(db.String(length=68), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow())
    img_file = db.Column(db.String(length=120), default='default.jpg')
    posts = db.relationship('Post', backref='author', lazy=True)
    role = db.Column(db.String(), default='user')

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return Users.query.get(user_id)

    def __repr__(self):
        return f'User({self.username}, {self.email})'


class Post(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    title = db.Column(db.String(length=100), nullable=False)
    content = db.Column(db.Text(), nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow(), nullable=False)
    post_img = db.Column(db.String())
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id'), nullable=False)


