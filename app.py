from config import app, User  # Ensure User is imported from your models
from flask import render_template, request, redirect, url_for, flash
from flask_login import LoginManager, current_user

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'accounts.login'  # Redirect unauthorized users to the login page

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

@app.before_request
def restrict_access():
    # Restrict anonymous users
    if not current_user.is_authenticated:
        restricted_routes_anonymous = [
            'accounts.account', 'posts.posts', 'posts.create',
            'posts.update', 'posts.delete', 'accounts.logout', 'security.security'
        ]
        if request.endpoint in restricted_routes_anonymous:
            flash("You must be logged in to access this page.", "danger")
            return redirect(url_for('accounts.login'))
if __name__ == '__main__':
    app.run(debug=True)
