from flask import Blueprint, render_template, flash, redirect, url_for, session, request, make_response
from accounts.forms import RegistrationForm, LoginForm
from config import User, db, Post, limiter
import pyotp
import logging
import qrcode
import io
from io import BytesIO
import base64
from flask_login import login_user, logout_user, login_required, current_user


# Initialize the logger
logging.basicConfig(level=logging.INFO)

accounts_bp = Blueprint('accounts', __name__, template_folder='templates')


# Function to verify MFA PIN using pyotp
def verify_mfa_pin(mfa_key, mfa_pin):
    totp = pyotp.TOTP(mfa_key)
    return totp.verify(mfa_pin)


# Function to generate QR code URI and base64 image
def generate_mfa_qr_uri(email, mfa_key):
    totp = pyotp.TOTP(mfa_key)
    uri = totp.provisioning_uri(name=email, issuer_name="CSC2031 BLOG")

    # Generate QR code as an image in base64 format
    qr = qrcode.make(uri)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return uri, f"data:image/png;base64,{qr_base64}"


@accounts_bp.route('/registration', methods=['GET', 'POST'])
def registration():
    form = RegistrationForm()

    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already exists', category="danger")
            return render_template('accounts/registration.html', form=form)

        # Generate an MFA key and QR code URI
        mfa_key = pyotp.random_base32()
        new_user = User(
            email=form.email.data,
            firstname=form.firstname.data,
            lastname=form.lastname.data,
            phone=form.phone.data,
            password=form.password.data,
            mfa_key=mfa_key,
            mfa_enabled=False  # Initially set MFA as disabled
        )

        db.session.add(new_user)
        db.session.commit()

        # Log the generated MFA key
        logging.info(f"MFA Key for {new_user.email} (During Registration): {new_user.mfa_key}")

        # Generate QR code URI for TOTP
        qr_code_uri, mfa_qr_uri = generate_mfa_qr_uri(new_user.email, mfa_key)
        flash('Account created successfully. Please set up MFA before logging in.', category='success')
        return redirect(url_for('accounts.mfa_setup', mfa_key=mfa_key, mfa_qr_uri=mfa_qr_uri))

    return render_template('accounts/registration.html', form=form)


@accounts_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("20 per minute")  # Apply a rate limit of 20 per minute
def login():
    form = LoginForm()

    if 'failed_attempts' not in session:
        session['failed_attempts'] = 0

    is_locked = session['failed_attempts'] >= 3

    if form.validate_on_submit() and not is_locked:
        user = User.query.filter_by(email=form.email.data).first()

        # Validate user credentials
        if not user or not user.verify_password(form.password.data):
            session['failed_attempts'] += 1
            attempts_left = 3 - session['failed_attempts']
            flash(f'Invalid email or password. You have {attempts_left} attempts remaining.', 'danger')
            return redirect(url_for('accounts.login'))

        totp = pyotp.TOTP(user.mfa_key)

        # If MFA is enabled, verify MFA PIN
        if user.mfa_enabled:
            if totp.verify(form.mfa_pin.data):
                login_user(user)
                session['failed_attempts'] = 0  # Reset failed attempts on successful login
                flash('Login successful', 'success')
                return redirect(url_for('posts.posts'))
            else:
                session['failed_attempts'] += 1
                attempts_left = 3 - session['failed_attempts']
                flash(f'Invalid MFA PIN. You have {attempts_left} attempts remaining.', 'danger')
        else:
            # If MFA is not enabled, verify MFA PIN and enable MFA
            if totp.verify(form.mfa_pin.data):
                user.mfa_enabled = True
                db.session.commit()
                session['failed_attempts'] = 0  # Reset failed attempts on successful login
                login_user(user)  # Log in the user immediately after MFA setup
                flash('MFA setup complete. You are now logged in.', 'success')
                return redirect(url_for('posts.posts'))
            else:
                session['failed_attempts'] += 1
                attempts_left = 3 - session['failed_attempts']
                qr_code_uri, mfa_qr_uri = generate_mfa_qr_uri(user.email, user.mfa_key)
                flash(f'MFA is not enabled for your account. Please set up MFA to proceed. You have {attempts_left} attempts remaining.', 'warning')
                return redirect(url_for('accounts.mfa_setup', mfa_key=user.mfa_key, mfa_qr_uri=mfa_qr_uri))

        # Check if the number of attempts has reached the limit
        attempts_left = 3 - session['failed_attempts']
        if session['failed_attempts'] >= 3:
            flash('Your account is locked due to too many failed login attempts.', 'danger')
            return redirect(url_for('accounts.unlock_account'))
        else:
            flash(f'Invalid email, password, or MFA PIN. Attempts remaining: {attempts_left}', 'danger')

    return render_template('accounts/login.html', form=form, is_locked=is_locked)


@accounts_bp.route('/mfa_setup/<mfa_key>')
def mfa_setup(mfa_key):
    mfa_qr_uri = request.args.get('mfa_qr_uri')
    if not mfa_qr_uri:
        flash("QR code URI missing. Please re-register.", "danger")
        return redirect(url_for("accounts.registration"))

    logging.info(f"MFA Key for {mfa_key} (MFA Setup Page): {mfa_key}")
    return render_template('accounts/mfa_setup.html', mfa_key=mfa_key, mfa_qr_uri=mfa_qr_uri)


@accounts_bp.route('/unlock', methods=['GET'])
def unlock_account():
    session['failed_attempts'] = 0
    flash('Your login attempts have been reset. You may try logging in again.', 'success')
    return redirect(url_for('accounts.login'))


@accounts_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('accounts.login'))


@accounts_bp.before_request
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

    # Restrict authenticated users
    if current_user.is_authenticated:
        restricted_routes_authenticated = ['accounts.registration', 'accounts.login']
        if request.endpoint in restricted_routes_authenticated:
            flash("You are already logged in.", "danger")
            return redirect(url_for('posts.posts'))



@accounts_bp.route('/account')
@login_required
def account():
    user = current_user  # Get the logged-in user
    user_posts = Post.query.filter_by(userid=user.id).all()  # Adjust column name to 'userid'
    return render_template('accounts/account.html', user=user, posts=user_posts)
