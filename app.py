from config import app, db, User  # Ensure User is imported from your models
from flask import render_template
from flask_login import LoginManager

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect unauthorized users to the login page

# Define the user loader callback
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('home/index.html')

# Error handling function for rate limit breaches
@app.errorhandler(429)
def ratelimit_error(e):
    return render_template('errors/rate_limit.html'), 429

@app.route('/registration')
def registration():
    return render_template('accounts/registration.html')

@app.route('/login')
def login():
    return render_template('accounts/login.html')

@app.route('/account')
def account():
    return render_template('accounts/account.html')

@app.route('/posts')
def posts():
    return render_template('posts/posts.html')

@app.route('/create')
def create():
    return render_template('posts/create.html')

@app.route('/update')
def update():
    return render_template('posts/update.html')

@app.route('/security')
def security():
    return render_template('security/security.html')

if __name__ == '__main__':
    app.run(debug=True)
