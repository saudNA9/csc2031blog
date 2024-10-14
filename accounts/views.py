from flask import Blueprint, render_template, flash, redirect, url_for
from accounts.forms import RegistrationForm, LoginForm
from config import User, db
from flask import session
from config import limiter

accounts_bp = Blueprint('accounts', __name__, template_folder='templates')


@accounts_bp.route('/registration', methods=['GET', 'POST'])
def registration():
    form = RegistrationForm()

    if form.validate_on_submit():

        if User.query.filter_by(email=form.email.data).first():
            flash('Email already exists', category="danger")
            return render_template('accounts/registration.html', form=form)

        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        )

        db.session.add(new_user)
        db.session.commit()

        flash('Account Created', category='success')
        return redirect(url_for('accounts.login'))

    return render_template('accounts/registration.html', form=form)

# Apply a rate limit of 3 per minute for testing (or adjust to 20 per minute later)

@accounts_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
def login():
    form = LoginForm()

    # Initialize failed attempts in session if not present
    if 'failed_attempts' not in session:
        session['failed_attempts'] = 0

    is_locked = session['failed_attempts'] >= 3  # Lock account after 3 failed attempts

    if form.validate_on_submit() and not is_locked:
        # Query for user by email
        user = User.query.filter_by(email=form.email.data).first()

        # Check if the user exists and the password is correct
        if not user or not user.verify_password(form.password.data):
            session['failed_attempts'] += 1  # Increment failed attempts
            remaining_attempts = 3 - session['failed_attempts']
            if session['failed_attempts'] >= 3:
                flash('Your account is locked due to too many invalid login attempts.', 'danger')
            else:
                flash(f'Invalid email or password. You have {remaining_attempts} attempt(s) remaining.', 'danger')
            return redirect(url_for('accounts.login'))

        # If login is successful, reset failed attempts and redirect
        session['failed_attempts'] = 0
        flash('Login successful', 'success')
        return redirect(url_for('posts.posts'))  # Assuming 'posts.posts' is the page to view posts

    return render_template('accounts/login.html', form=form, is_locked=is_locked)


@accounts_bp.route('/unlock', methods=['GET'])
def unlock_account():
    session['failed_attempts'] = 0  # Reset the failed attempts
    flash('Your account has been unlocked. You may try logging in again.', 'success')
    return redirect(url_for('accounts.login'))


@accounts_bp.route('/account')
def account():
    return render_template('accounts/account.html')
