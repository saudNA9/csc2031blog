from flask import Blueprint, render_template, flash, redirect, url_for, session, request, make_response
from accounts.forms import RegistrationForm, LoginForm
from config import User, db, Post, limiter, security_logger
import pyotp
import logging
import qrcode
from io import BytesIO
import base64
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime


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

    if current_user.is_authenticated:
        flash("You are already logged in.", "danger")
        if current_user.role == 'db_admin':
            return redirect(url_for('admin.index'))
        elif current_user.role == 'sec_admin':
            return redirect(url_for('security.security'))
        else:  # Default for 'end_user'
            return redirect(url_for('posts.posts'))

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
            mfa_enabled=False,  # Initially set MFA as disabled
            role="end_user"
        )

        db.session.add(new_user)
        db.session.commit()
        new_user.create_log()

        logging.info(f"Registered new user: {new_user.email}, Role: {new_user.role}")
        logging.info(f"MFA Key for {new_user.email} (During Registration): {new_user.mfa_key}")

        # Generate QR code URI for TOTP
        qr_code_uri, mfa_qr_uri = generate_mfa_qr_uri(new_user.email, mfa_key)
        security_logger.info(
            f"User registration: Email={new_user.email}, Role={new_user.role}, IP={request.remote_addr}"
        )
        flash('Account created successfully. Please set up MFA before logging in.', category='success')
        return redirect(url_for('accounts.mfa_setup', mfa_key=mfa_key, mfa_qr_uri=mfa_qr_uri))

    return render_template('accounts/registration.html', form=form)


@accounts_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("20 per minute")  # Apply a rate limit of 20 per minute
def login():
    form = LoginForm()

    # Check if the user is already logged in
    if current_user.is_authenticated:
        flash("You are already logged in.", "danger")
        if current_user.role == 'db_admin':
            return redirect(url_for('admin.index'))
        elif current_user.role == 'sec_admin':
            return redirect(url_for('security.security'))
        else:  # Default for 'end_user'
            return redirect(url_for('posts.posts'))

    # Initialize failed attempts in session if not already present
    if 'failed_attempts' not in session:
        session['failed_attempts'] = 0

    # Check if the account is locked
    is_locked = session['failed_attempts'] >= 3

    if form.validate_on_submit() and not is_locked:
        user = User.query.filter_by(email=form.email.data).first()

        # Handle invalid credentials
        if not user or not user.verify_password(form.password.data):
            session['failed_attempts'] += 1
            attempts_left = 3 - session['failed_attempts']

            # Check if account is now locked
            if session['failed_attempts'] >= 3:
                # Log the lock event
                security_logger.error(
                    f"Max invalid login attempts: Email={form.email.data}, Attempts={session['failed_attempts']}, IP={request.remote_addr}"
                )
                flash('Your account is locked due to too many failed login attempts.', 'danger')
                return redirect(url_for('accounts.login'))  # Redirect back to login for locked account

            # Log invalid login attempt
            security_logger.warning(
                f"Invalid login attempt: Email={form.email.data}, Attempts={session['failed_attempts']}, IP={request.remote_addr}"
            )
            flash(f'Invalid email or password. You have {attempts_left} attempts remaining.', 'danger')
            return redirect(url_for('accounts.login'))

        totp = pyotp.TOTP(user.mfa_key)

        # Handle MFA if enabled
        if user.mfa_enabled:
            if totp.verify(form.mfa_pin.data):
                login_user(user)
                session['failed_attempts'] = 0  # Reset failed attempts on successful login
                security_logger.info(f"User login: Email={user.email}, Role={user.role}, IP={request.remote_addr}")
                flash('Login successful', 'success')
            else:
                session['failed_attempts'] += 1
                attempts_left = 3 - session['failed_attempts']
                flash(f'Invalid MFA PIN. You have {attempts_left} attempts remaining.', 'danger')
                return redirect(url_for('accounts.login'))
        else:
            # Enable MFA if not already enabled
            if totp.verify(form.mfa_pin.data):
                user.mfa_enabled = True
                db.session.commit()
                session['failed_attempts'] = 0  # Reset failed attempts
                login_user(user)
                flash('MFA setup complete. You are now logged in.', 'success')
            else:
                session['failed_attempts'] += 1
                attempts_left = 3 - session['failed_attempts']
                qr_code_uri, mfa_qr_uri = generate_mfa_qr_uri(user.email, user.mfa_key)
                flash(f'MFA is not enabled for your account. Please set up MFA to proceed. You have {attempts_left} attempts remaining.', 'warning')
                return redirect(url_for('accounts.mfa_setup', mfa_key=user.mfa_key, mfa_qr_uri=mfa_qr_uri))

        # Update user log with login details
        if user.log:
            user.log.previous_login = user.log.latest_login
            user.log.latest_login = datetime.now()
            user.log.previous_ip = user.log.latest_ip
            user.log.latest_ip = request.remote_addr
            db.session.commit()

        # Redirect based on user role
        if user.role == 'db_admin':
            return redirect(url_for('admin.index'))
        elif user.role == 'sec_admin':
            return redirect(url_for('security.security'))
        else:
            return redirect(url_for('posts.posts'))

    return render_template('accounts/login.html', form=form, is_locked=is_locked)  # Render the login page


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


@accounts_bp.app_errorhandler(403)
def forbidden_error(e):
    error_message = "You are not authorized to access this page."
    return render_template('errors/403.html', error=error_message), 403


@accounts_bp.route('/account')
@login_required
def account():
    user = current_user  # Get the logged-in user
    user_posts = Post.query.filter_by(userid=user.id).all()  # Adjust column name to 'userid'
    return render_template('accounts/account.html', user=user, posts=user_posts)
