from flask import Blueprint, render_template, flash, redirect, url_for
from accounts.forms import RegistrationForm, LoginForm
from config import User, db
from flask import session
from config import limiter
import pyotp  # Add pyotp to generate and verify MFA pins
import logging  # For debugging logs
import secrets  # Add back the secrets import to generate tokens

# Initialize the logger
logging.basicConfig(level=logging.INFO)

accounts_bp = Blueprint('accounts', __name__, template_folder='templates')


@accounts_bp.route('/registration', methods=['GET', 'POST'])
def registration():
    form = RegistrationForm()

    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already exists', category="danger")
            return render_template('accounts/registration.html', form=form)

        # Use pyotp to generate a proper TOTP-compatible MFA key
        mfa_key = pyotp.random_base32()  # Generate a random base32 key for TOTP

        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        mfa_key=mfa_key,
                        mfa_enabled=False)  # Initially MFA is not enabled

        db.session.add(new_user)
        db.session.commit()

        flash('Account Created. You must set up MFA before logging in.', category='success')
        return redirect(url_for('accounts.mfa_setup', mfa_key=mfa_key))  # Redirect to MFA setup page

    return render_template('accounts/registration.html', form=form)


# Function to verify MFA PIN using pyotp
def verify_mfa_pin(mfa_key, mfa_pin):
    totp = pyotp.TOTP(mfa_key)
    expected_pin = totp.now()  # Get the current MFA PIN
    logging.info(f"Expected MFA PIN for {mfa_key}: {expected_pin}")  # Log the expected MFA PIN
    valid = totp.verify(mfa_pin)
    logging.info(f"Verifying MFA PIN: {mfa_pin}, Result: {valid}")
    return valid

# Apply a rate limit of 20 per minute
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

        # Check if user exists, password matches, and MFA PIN matches
        if not user:
            flash('Login failed: Invalid email.', 'danger')
            session['failed_attempts'] += 1
            return redirect(url_for('accounts.login'))

        if not user.verify_password(form.password.data):
            flash('Login failed: Incorrect password.', 'danger')
            session['failed_attempts'] += 1
            return redirect(url_for('accounts.login'))

        # Check if MFA is enabled and verify MFA PIN if it is
        if user.mfa_enabled:
            mfa_pin = form.mfa_pin.data  # Assuming you added an mfa_pin field to your form
            if not verify_mfa_pin(user.mfa_key, mfa_pin):
                flash('Login failed: Invalid MFA PIN.', 'danger')
                session['failed_attempts'] += 1
                return redirect(url_for('accounts.login'))

        # If all checks pass, reset failed attempts and allow login
        session['failed_attempts'] = 0

        # If MFA was not previously enabled, set it now
        if not user.mfa_enabled:
            user.mfa_enabled = True
            db.session.commit()

        # Successful login message and redirect to the posts page
        flash('Login successful', 'success')
        return redirect(url_for('posts.posts'))

    # Render login form with lockout message if account is locked
    if is_locked:
        flash('Your account is locked due to too many invalid login attempts.', 'danger')
        return redirect(url_for('accounts.unlock_account'))

    return render_template('accounts/login.html', form=form, is_locked=is_locked)


@accounts_bp.route('/unlock', methods=['GET'])
def unlock_account():
    session['failed_attempts'] = 0  # Reset the failed attempts
    flash('Your account has been unlocked. You may try logging in again.', 'success')
    return redirect(url_for('accounts.login'))

@accounts_bp.route('/mfa_setup/<mfa_key>')
def mfa_setup(mfa_key):
    return render_template('accounts/mfa_setup.html', mfa_key=mfa_key)


@accounts_bp.route('/account')
def account():
    return render_template('accounts/account.html')
