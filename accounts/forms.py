from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, ValidationError, Regexp, Email
import re

# I have added this to custom password validator to enforce password strength rules.
def strong_password(form, field):
    password = field.data
    errors = []
    if len(password) < 8 or len(password) > 15:
        errors.append('Password must be between 8 and 15 characters.')
    if not re.search(r'[A-Z]', password):
        errors.append('Password must contain at least 1 uppercase letter.')
    if not re.search(r'[a-z]', password):
        errors.append('Password must contain at least 1 lowercase letter.')
    if not re.search(r'[0-9]', password):
        errors.append('Password must contain at least 1 digit.')
    if not re.search(r'[\W_]', password):
        errors.append('Password must contain at least 1 special character.')

    if errors:
        raise ValidationError(', '.join(errors))

class RegistrationForm(FlaskForm):
    firstname = StringField('First Name', validators=[
        DataRequired(),
        Regexp(r'^[a-zA-Z-]+$', message="First name can only contain letters or hyphens.")
    ])
    lastname = StringField('Last Name', validators=[
        DataRequired(),
        Regexp(r'^[a-zA-Z-]+$', message="Last name can only contain letters or hyphens.")
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email(message="Enter a valid email address.")
    ])
    phone = StringField('Phone Number', validators=[
        DataRequired(),
        Regexp(r'^(02\d-\d{8}|011\d-\d{7}|01\d{2}-\d{5,6})$',
               message="Enter a valid UK landline phone number (e.g., 011X-YYYYYYY).")
    ])

    # I have added a strong password validator to the password field
    password = PasswordField('Password', validators=[DataRequired(), strong_password])

    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(),
                                                 EqualTo('password', message='Both password fields must be equal!')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    mfa_pin = StringField('MFA PIN', validators=[DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField('Login')

class MFACodeForm(FlaskForm):
#I made this to ask the user to input their MFA PIN from their authenticator app.
    mfa_pin = StringField('Enter MFA PIN', validators=[DataRequired()])
    submit = SubmitField('Submit MFA PIN')
