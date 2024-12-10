from flask import Blueprint, render_template, redirect, flash, url_for, abort, request
from flask_login import login_required, current_user
from config import Log, User, security_logger

security_bp = Blueprint('security', __name__, template_folder='templates')

@security_bp.route('/security')
@login_required
def security():
    if current_user.role != 'sec_admin':
        security_logger.error(
            f"Unauthorized role access: Email={current_user.email}, Role={current_user.role}, URL={request.url}, IP={request.remote_addr}"
        )
        abort(403)

    # Fetch logs only for active users
    logs = Log.query.join(User).all()

    # Fetch last 10 log entries from the file
    log_entries = []
    try:
        with open("security.log", "r") as log_file:
            lines = log_file.readlines()
            log_entries = lines[-10:][::-1]  # Get last 10 entries and reverse them
    except FileNotFoundError:
        flash("Security log file not found.", "warning")

    return render_template('security/security.html', logs=logs, log_entries=log_entries)
