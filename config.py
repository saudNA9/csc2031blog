from flask import Flask, url_for
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink
import secrets
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import MetaData
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pyotp  # For generating and verifying MFA keys
from flask_login import UserMixin

app = Flask(__name__)

# SECRET KEY FOR FLASK FORMS
app.config['SECRET_KEY'] = secrets.token_hex(16)

# Add reCAPTCHA keys to the configuration
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LdgyVUqAAAAAOlpHkzRlx7dr2F0SYp3QTp5Mo96'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LdgyVUqAAAAANmq8UrWlHqa4taLr7ZR8nJWh_Pd'

# DATABASE CONFIGURATION
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///csc2031blog.db'
app.config['SQLALCHEMY_ECHO'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# FLUID LAYOUT FOR ADMIN PAGES
app.config['FLASK_ADMIN_FLUID_LAYOUT'] = True  # This enables fluid layout for Flask-Admin pages

metadata = MetaData(
    naming_convention={
        "ix": 'ix_%(column_0_label)s',
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s"
    }
)

db = SQLAlchemy(app, metadata=metadata)
migrate = Migrate(app, db)

# DATABASE TABLES
class Post(db.Model):
   __tablename__ = 'posts'

   id = db.Column(db.Integer, primary_key=True)
   userid = db.Column(db.Integer, db.ForeignKey('users.id'))
   created = db.Column(db.DateTime, nullable=False)
   title = db.Column(db.Text, nullable=False)
   body = db.Column(db.Text, nullable=False)
   user = db.relationship("User", back_populates="posts")

   def __init__(self, title, body):
       self.created = datetime.now()
       self.title = title
       self.body = body

   def update(self, title, body):
       self.created = datetime.now()  # Update created time
       self.title = title  # Update title
       self.body = body  # Update body
       db.session.commit()  # Commit changes to the database

# User table modified to handle MFA key and MFA enabled status
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)

    # User authentication information.
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)

    # User information
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)

    # MFA fields
    mfa_key = db.Column(db.String(32), nullable=False, default='')  # Store MFA key
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)  # Track if MFA is enabled

    # User posts
    posts = db.relationship("Post", order_by=Post.id, back_populates="user")

    def get_id(self):
        return str(self.id)

    def __init__(self, email, firstname, lastname, phone, password, mfa_key='', mfa_enabled=False):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.password = password
        self.mfa_key = mfa_key
        self.mfa_enabled = mfa_enabled

    def verify_password(self, password):
        return self.password == password  # Simple password comparison (not hashed)

# DATABASE ADMINISTRATOR
class MainIndexLink(MenuLink):
    def get_url(self):
        return url_for('index')


class PostView(ModelView):
    column_display_pk = True
    column_hide_backrefs = False
    column_list = ('id', 'userid', 'created', 'title', 'body', 'user')

class UserView(ModelView):
    column_display_pk = True
    column_hide_backrefs = False
    column_list = ('id', 'email', 'password', 'firstname', 'lastname', 'phone', 'mfa_key', 'mfa_enabled', 'posts')

admin = Admin(app, name='DB Admin', template_mode='bootstrap4')
admin._menu = admin._menu[1:]
admin.add_link(MainIndexLink(name='Home Page'))
admin.add_view(PostView(Post, db.session))
admin.add_view(UserView(User, db.session))

# Application-wide rate limiter with a default limit of 500 function calls per day
limiter = Limiter(
    key_func=get_remote_address,  # Get the client's IP address
    app=app,
    default_limits=["500 per day"]  # Default rate limit
)

# Function to generate QR code URI for TOTP (for QR Code setup in Part 2)
def generate_mfa_qr_uri(email, mfa_key):
    totp = pyotp.TOTP(mfa_key)
    return totp.provisioning_uri(email, issuer_name="CSC2031 Blog")

# IMPORT BLUEPRINTS at the bottom
from accounts.views import accounts_bp
from posts.views import posts_bp
from security.views import security_bp

# REGISTER BLUEPRINTS
app.register_blueprint(accounts_bp)
app.register_blueprint(posts_bp)
app.register_blueprint(security_bp)
