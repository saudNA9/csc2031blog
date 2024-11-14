from config import app, db, User, Post  # Ensure User is imported from your models
from flask import render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, current_user, login_required
from accounts.forms import LoginForm

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


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.verify_password(form.password.data) and user.verify_mfa(form.mfa_pin.data):
            login_user(user)
            flash('Login successful', 'success')

            # Get the 'next' parameter from the URL
            next_page = request.args.get('next')

            # Redirect to the next page if it exists, otherwise to the home page
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Invalid email, password, or MFA PIN', 'danger')

    return render_template('accounts/login.html', form=form)

@app.route('/posts')
def view_posts():
    posts = Post.query.all()
    return render_template('posts/posts.html', posts=posts)


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
