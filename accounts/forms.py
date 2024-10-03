from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, ValidationError
import re


# Custom password validator to enforce password strength rules
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
    email = StringField('Email', validators=[DataRequired()])
    firstname = StringField('First Name', validators=[DataRequired()])
    lastname = StringField('Last Name', validators=[DataRequired()])
    phone = StringField('Phone', validators=[DataRequired()])

    # Adding strong password validator to the password field
    password = PasswordField('Password', validators=[DataRequired(), strong_password])

    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(),
                                                 EqualTo('password', message='Both password fields must be equal!')])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
