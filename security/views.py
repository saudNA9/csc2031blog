from flask import Blueprint, render_template, redirect, flash, url_for
from flask_login import login_required, current_user
security_bp = Blueprint('security', __name__, template_folder='templates')

@security_bp.route('/security')
@login_required
def security():
    if current_user.role in ['end_user', 'db_admin']:
        flash("You are not authorized to access the Security page.", "danger")
        return redirect(url_for('accounts.forbidden_error_page', error='Access Denied'))
    return render_template('security/security.html')

