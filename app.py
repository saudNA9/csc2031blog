from config import app, User
from flask import render_template, request, redirect, url_for, flash
from flask_login import LoginManager, current_user
import re
from flask_talisman import Talisman

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'accounts.login'

csp = {
    "default-src": ["'self'"],

    "script-src": [
        "'self'",
        "'unsafe-inline'",
        "https://www.google.com/recaptcha/",
        "https://www.gstatic.com/recaptcha/",
        "https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/js/",
        "https://code.jquery.com/"
    ],

    "frame-src": [
        "https://www.google.com/recaptcha/"
    ],

    "style-src": [
        "'self'",
        "'unsafe-inline'",
        "https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/"
    ],

    "img-src": [
        "'self'",
        "data:",
        "https://www.gstatic.com/"
    ]
}

talisman = Talisman(app, content_security_policy=csp)


waf_rules = {
    "SQL Injection": re.compile(r"(\b(union|select|insert|drop|alter)\b|;|%3B|`|%60|'|%27|--)", re.IGNORECASE),
    "XSS": re.compile(r"(<script>|<iframe>|%3Cscript%3E|%3Ciframe%3E)", re.IGNORECASE),
    "Path Traversal": re.compile(r"(\.\./|\.\.|%2e%2e%2f|%2e%2e/|\.\.%2f)", re.IGNORECASE)
}



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('home/index.html')

@app.route('/firewall_error')
def firewall_error():
    attack_type = request.args.get('attack_type', 'Unknown')
    return render_template('errors/firewall.html', attack_type=attack_type)

# Error handling function for rate limit breaches
@app.errorhandler(429)
def ratelimit_error(e):
    return render_template('errors/rate_limit.html'), 429

@app.errorhandler(400)
def bad_request_error(e):
    return render_template('errors/400.html'), 400

@app.errorhandler(404)
def not_found_error(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('errors/500.html'), 500

@app.errorhandler(501)
def not_implemented_error(e):
    return render_template('errors/501.html'), 501

@app.before_request
def restrict_access_and_waf_function_name():
    excluded_routes = ['firewall_error', 'static', 'accounts.mfa_setup']
    if request.endpoint in excluded_routes:
        return

    if not current_user.is_authenticated:
        restricted_routes_anonymous = [
            'accounts.account', 'posts.posts', 'posts.create',
            'posts.update', 'posts.delete', 'accounts.logout', 'security.security'
        ]
        if request.endpoint in restricted_routes_anonymous:
            flash("You must be logged in to access this page.", "danger")
            return redirect(url_for('accounts.login'))


    path = request.path
    query = request.query_string.decode("utf-8")
    combined_request_data = f"{path} {query}"


    print(f"Combined Request Data: {combined_request_data}")


    for attack_type, pattern in waf_rules.items():
        if pattern.search(combined_request_data):
            matched_data = pattern.findall(combined_request_data)
            print(f"Detected Attack Type: {attack_type} | Matched Data: {matched_data}")
            flash(f"Attack detected: {attack_type}", "danger")
            return redirect(url_for('firewall_error', attack_type=attack_type))

if __name__ == '__main__':
  app.run(ssl_context=('certificate.crt', 'private.key'), debug=True)
