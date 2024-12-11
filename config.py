import logging, base64, os, secrets, pyotp
from cryptography.fernet import Fernet
from flask import Flask, url_for, redirect, flash, abort
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import MetaData
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import UserMixin, current_user, login_required
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv


load_dotenv()

app = Flask(__name__)
bcrypt = Bcrypt(app)


app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['RECAPTCHA_PUBLIC_KEY'] = os.getenv('RECAPTCHA_PUBLIC_KEY')
app.config['RECAPTCHA_PRIVATE_KEY'] = os.getenv('RECAPTCHA_PRIVATE_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_ECHO'] = os.getenv('SQLALCHEMY_ECHO') == 'True'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS') == 'False'
app.config['FLASK_ADMIN_FLUID_LAYOUT'] = os.getenv('FLASK_ADMIN_FLUID_LAYOUT') == 'True'

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


security_logger = logging.getLogger("security_logger")
security_logger.setLevel(logging.INFO)


file_handler = logging.FileHandler("security.log")
file_handler.setLevel(logging.INFO)


formatter = logging.Formatter('%(asctime)s - %(message)s')
file_handler.setFormatter(formatter)


security_logger.addHandler(file_handler)


class Post(db.Model):
   __tablename__ = 'posts'

   id = db.Column(db.Integer, primary_key=True)
   userid = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), nullable=False)
   created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
   title_encrypted = db.Column(db.LargeBinary, nullable=False)
   body_encrypted = db.Column(db.LargeBinary, nullable=False)
   user = db.relationship("User", back_populates="posts")

   def __init__(self, title, body, userid, encryption_key):
       self.created = datetime.now()
       self.title_encrypted = self.encrypt(title, encryption_key)
       self.body_encrypted = self.encrypt(body, encryption_key)
       self.userid = userid

   @staticmethod
   def derive_key(salt):
       return base64.urlsafe_b64encode(salt.encode('utf-8').ljust(32)[:32])

   @staticmethod
   def encrypt(data, key):
       fernet = Fernet(key)
       return fernet.encrypt(data.encode('utf-8'))

   @staticmethod
   def decrypt(data, key):
       fernet = Fernet(key)
       return fernet.decrypt(data).decode('utf-8')

   def update(self, title, body, encryption_key):
       self.created = datetime.now()
       self.title_encrypted = self.encrypt(title, encryption_key)
       self.body_encrypted = self.encrypt(body, encryption_key)
       db.session.commit()


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(128), nullable=False)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)
    mfa_key = db.Column(db.String(32), nullable=False, default='')
    salt = db.Column(db.String(44), nullable=False,default=lambda: base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8'))
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    role = db.Column(db.String(50), nullable=False, default='end_user')
    posts = db.relationship("Post", order_by=Post.id, back_populates="user")
    log = db.relationship("Log", uselist=False, back_populates="user", cascade="all, delete-orphan")

    def get_id(self):
        return str(self.id)

    def __init__(self, email, firstname, lastname, phone, password, mfa_key='', mfa_enabled=False, role="end_user"):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.password = self.hash_password(password)
        self.mfa_key = mfa_key
        self.mfa_enabled = mfa_enabled
        self.role = role

    @staticmethod
    def hash_password(password):
        return bcrypt.generate_password_hash(password).decode('utf-8')

    def verify_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def verify_mfa(self, mfa_pin):
        if not self.mfa_key:
            return False
        totp = pyotp.TOTP(self.mfa_key)
        return totp.verify(mfa_pin)

    def create_log(self):
        if not self.log:
            user_log = Log(user_id=self.id)
            db.session.add(user_log)
            db.session.commit()


class Log(db.Model):
    __tablename__ = 'logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), nullable=False)
    user_registered = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    latest_login = db.Column(db.DateTime)
    previous_login = db.Column(db.DateTime)
    latest_ip = db.Column(db.String(100))
    previous_ip = db.Column(db.String(100))
    user = db.relationship("User", back_populates="log")

    def __init__(self, user_id):
        self.user_id = user_id
        self.user_registered = datetime.now()



class MyAdminIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        if not current_user.is_authenticated or current_user.role != 'db_admin':
            abort(403)
        return super().index()

    def is_accessible(self):
        return current_user.is_authenticated and current_user.role == 'db_admin'

    def inaccessible_callback(self, name, **kwargs):

        if current_user.is_authenticated:
            abort(403)

        flash("You must be logged in to access this page.", "danger")
        return redirect(url_for('accounts.login'))

class PostView(ModelView):
    column_list = ('id', 'userid', 'created', 'title_encrypted', 'body_encrypted')
    column_formatters = {
        'title_encrypted': lambda view, context, model, name: model.title_encrypted.decode('utf-8'),
        'body_encrypted': lambda view, context, model, name: model.body_encrypted.decode('utf-8'),
    }

    can_edit = False
    can_create = False
    can_delete = False

    def is_accessible(self):
        return current_user.is_authenticated and current_user.role == 'db_admin'

    def inaccessible_callback(self, name, **kwargs):
        if not current_user.is_authenticated:

            flash("You must be logged in to access this page.", "danger")
            return redirect(url_for('accounts.login'))

        abort(403)

class UserView(ModelView):
    column_list = ['id', 'email', 'password', 'firstname', 'lastname', 'phone', 'mfa_key', 'salt', 'mfa_enabled', 'role', 'posts']
    form_excluded_columns = ['posts', 'log']
    column_formatters = {
        'posts': lambda view, context, model, name: ', '.join([f"Post {post.id}" for post in model.posts]) if model.posts else 'No Posts'
    }

    def on_model_delete(self, model):
        for post in model.posts:
            db.session.delete(post)
        db.session.commit()

    def is_accessible(self):
        return current_user.is_authenticated and current_user.role == 'db_admin'

    def inaccessible_callback(self, name, **kwargs):
        if not current_user.is_authenticated:

            flash("You must be logged in to access this page.", "danger")
            return redirect(url_for('accounts.login'))

        abort(403)

admin = Admin(app, name='DB Admin', template_mode='bootstrap4', index_view=MyAdminIndexView())
admin._menu = [item for item in admin._menu if item.name != "Home"]
admin.add_link(MenuLink(name="Home", url='/'))
admin.add_view(PostView(Post, db.session, name="Posts", endpoint="post"))
admin.add_view(UserView(User, db.session, name="Users", endpoint="user"))


limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["500 per day"]
)


def generate_mfa_qr_uri(email, mfa_key):
    totp = pyotp.TOTP(mfa_key)
    return totp.provisioning_uri(email, issuer_name="CSC2031 Blog")


from accounts.views import accounts_bp
from posts.views import posts_bp
from security.views import security_bp


app.register_blueprint(accounts_bp)
app.register_blueprint(posts_bp)
app.register_blueprint(security_bp)
