from flask import Blueprint, render_template, redirect, flash, url_for, abort
from flask_login import login_required, current_user
security_bp = Blueprint('security', __name__, template_folder='templates')

@security_bp.route('/security')
@login_required
def security():
    if current_user.role in ['end_user', 'db_admin']:
        abort(403)
    return render_template('security/security.html')

