from flask import Blueprint, render_template
from flask_login import login_required

security_bp = Blueprint('security', __name__, template_folder='templates')

@security_bp.route('/security')
@login_required
def security():
    return render_template('security/security.html')

