from flask import Blueprint, render_template, flash, redirect, url_for, session, request
from accounts.forms import RegistrationForm, LoginForm
from config import User, db, limiter, generate_mfa_qr_uri
import pyotp
import secrets
import logging

# Initialize the logger
logging.basicConfig(level=logging.INFO)

accounts_bp = Blueprint('accounts', __name__, template_folder='templates')

# Function to verify MFA PIN using pyotp
def verify_mfa_pin(mfa_key, mfa_pin):
    totp = pyotp.TOTP(mfa_key)
    valid = totp.verify(mfa_pin)
    logging.info(f"Verifying MFA PIN: {mfa_pin}, Result: {valid}, Key: {mfa_key}")
    return valid

@accounts_bp.route('/registration', methods=['GET', 'POST'])
def registration():
    form = RegistrationForm()

    if form.validate_on_submit():
        # Check if email is already registered
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already exists', category="danger")
            return render_template('accounts/registration.html', form=form)

        # Generate a TOTP-compatible MFA key
        mfa_key = pyotp.random_base32()
        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        mfa_key=mfa_key,
                        mfa_enabled=False)  # Initially, MFA is not enabled

        db.session.add(new_user)
        db.session.commit()

        # Log the generated MFA key to verify consistency
        logging.info(f"MFA Key for {new_user.email} (During Registration): {new_user.mfa_key}")

        # Generate QR code URI for TOTP
        mfa_qr_uri = generate_mfa_qr_uri(new_user.email, mfa_key)
        flash('Account Created. You must set up MFA before logging in.', category='success')
        return redirect(url_for('accounts.mfa_setup', mfa_key=mfa_key, mfa_qr_uri=mfa_qr_uri))

    return render_template('accounts/registration.html', form=form)


@accounts_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("20 per minute")  # Apply a rate limit of 20 per minute
def login():
    form = LoginForm()

    # Initialize failed attempts in session if not present
    if 'failed_attempts' not in session:
        session['failed_attempts'] = 0

    is_locked = session['failed_attempts'] >= 3  # Lock account after 3 failed attempts

    if form.validate_on_submit() and not is_locked:
        # Query for user by email
        user = User.query.filter_by(email=form.email.data).first()

        logging.info(
            f"User found: {user.email if user else 'None'}, MFA Enabled: {user.mfa_enabled if user else 'N/A'}")

        # Check if the user exists and the password is correct
        if not user or not user.verify_password(form.password.data):
            session['failed_attempts'] += 1  # Increment failed attempts
            remaining_attempts = 3 - session['failed_attempts']
            if session['failed_attempts'] >= 3:
                flash('Your account is locked due to too many invalid login attempts.', 'danger')
            else:
                flash(f'Invalid email or password. You have {remaining_attempts} attempt(s) remaining.', 'danger')
            return redirect(url_for('accounts.login'))

        # Check if MFA is enabled
        if user.mfa_enabled:
            mfa_pin = form.mfa_pin.data
            if not verify_mfa_pin(user.mfa_key, mfa_pin):
                session['failed_attempts'] += 1
                flash('Login failed: Invalid MFA PIN.', 'danger')
                return redirect(url_for('accounts.login'))
        else:
            # Redirect to MFA setup if MFA is not enabled
            mfa_qr_uri = generate_mfa_qr_uri(user.email, user.mfa_key)
            flash('Please set up MFA before logging in.', 'danger')
            return redirect(url_for('accounts.mfa_setup', mfa_key=user.mfa_key, mfa_qr_uri=mfa_qr_uri))

        # Reset failed attempts if login is successful
        session['failed_attempts'] = 0

        # Enable MFA if not enabled (first-time MFA setup)
        if not user.mfa_enabled:
            user.mfa_enabled = True
            db.session.commit()
            logging.info(f"MFA enabled for user {user.email}")  # Log this action

        # If all checks pass, allow login and redirect to posts page
        flash('Login successful', 'success')
        return redirect(url_for('posts.posts'))  # Redirect to the main posts page

    return render_template('accounts/login.html', form=form, is_locked=is_locked)

@accounts_bp.route('/unlock', methods=['GET'])
def unlock_account():
    # Reset the failed attempts to unlock the account
    session['failed_attempts'] = 0
    flash('Your account has been unlocked. You may try logging in again.', 'success')
    return redirect(url_for('accounts.login'))

@accounts_bp.route('/mfa_setup/<mfa_key>')
def mfa_setup(mfa_key):
    # Get the QR code URI to display on the setup page
    mfa_qr_uri = request.args.get('mfa_qr_uri')
    # In mfa_setup route, check key when loading the page
    logging.info(f"MFA Key for {mfa_key} (MFA Setup Page): {mfa_key}")
    return render_template('accounts/mfa_setup.html', mfa_key=mfa_key, mfa_qr_uri=mfa_qr_uri)

@accounts_bp.route('/account')
def account():
    return render_template('accounts/account.html')
