from flask import Flask, url_for, redirect, flash, abort
from flask_admin import Admin, AdminIndexView, expose  # Added expose for custom views
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
from flask_login import UserMixin, current_user, login_required  # Ensures login_required is available

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
   created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
   title = db.Column(db.Text, nullable=False)
   body = db.Column(db.Text, nullable=False)
   user = db.relationship("User", back_populates="posts")

   def __init__(self, title, body, userid):
       self.created = datetime.now()
       self.title = title
       self.body = body
       self.userid = userid

   def update(self, title, body):
       self.created = datetime.now()  # Update created time
       self.title = title  # Update title
       self.body = body  # Update body
       db.session.commit()  # Commit changes to the database

# User table modified to handle MFA key and MFA enabled status
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)
    mfa_key = db.Column(db.String(32), nullable=False, default='')  # Store MFA key
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)  # Track if MFA is enabled
    role = db.Column(db.String(50), nullable=False, default='end_user')
    posts = db.relationship("Post", order_by=Post.id, back_populates="user")
    log = db.relationship("Log", uselist=False, back_populates="user")

    def get_id(self):
        return str(self.id)

    def __init__(self, email, firstname, lastname, phone, password, mfa_key='', mfa_enabled=False, role="end_user"):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.password = password
        self.mfa_key = mfa_key
        self.mfa_enabled = mfa_enabled
        self.role = role

    def verify_password(self, password):
        return self.password == password  # Simple password comparison (not hashed)

    def verify_mfa(self, mfa_pin):
        if not self.mfa_key:
            return False  # Return False if MFA is not set up
        totp = pyotp.TOTP(self.mfa_key)
        return totp.verify(mfa_pin)  # Verify the provided MFA PIN

    def create_log(self):
        if not self.log:
            user_log = Log(user_id=self.id)
            db.session.add(user_log)
            db.session.commit()


class Log(db.Model):
    __tablename__ = 'logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user_registered = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    latest_login = db.Column(db.DateTime)
    previous_login = db.Column(db.DateTime)
    latest_ip = db.Column(db.String(100))
    previous_ip = db.Column(db.String(100))
    user = db.relationship("User", back_populates="log")

    def __init__(self, user_id):
        self.user_id = user_id
        self.user_registered = datetime.now()


# DATABASE ADMINISTRATOR
class MyAdminIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        # Custom index view for DB Admin
        if not current_user.is_authenticated or current_user.role != 'db_admin':
            abort(403)
        return super().index()

    def is_accessible(self):
        return current_user.is_authenticated and current_user.role == 'db_admin'

    def inaccessible_callback(self, name, **kwargs):
        # If the user is authenticated but not authorized, show 403
        if current_user.is_authenticated:
            abort(403)
        # If the user is not authenticated, redirect to login page
        flash("Please log in to access this page.", "danger")
        return redirect(url_for('accounts.login'))

class PostView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.role == 'db_admin'

    def inaccessible_callback(self, name, **kwargs):
        abort(403)

class UserView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.role == 'db_admin'

    def inaccessible_callback(self, name, **kwargs):
        abort(403)

admin = Admin(app, name='DB Admin', template_mode='bootstrap4', index_view=MyAdminIndexView())
admin._menu = [item for item in admin._menu if item.name != "Home"]
admin.add_link(MenuLink(name="Home", url='/'))
admin.add_view(PostView(Post, db.session, name="Posts", endpoint="admin_post"))
admin.add_view(UserView(User, db.session, name="Users", endpoint="admin_user"))

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
