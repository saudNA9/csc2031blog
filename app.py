from config import app, User  # Ensure User is imported from your models
from flask import render_template, request, redirect, url_for, flash
from flask_login import LoginManager, current_user
import re
from flask_talisman import Talisman

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'accounts.login'  # Redirect unauthorized users to the login page

csp = {
    "default-src": ["'self'"],  # Restrict all resources by default to the same origin.

    "script-src": [
        "'self'",  # Allow inline and local scripts.
        "'unsafe-inline'",
        "https://www.google.com/recaptcha/",  # Allow Google reCAPTCHA resources.
        "https://www.gstatic.com/recaptcha/",  # Allow Google reCAPTCHA scripts.
        "https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/js/",  # Bootstrap JS.
        "https://code.jquery.com/"  # Allow jQuery (if used).
    ],

    "frame-src": [
        "https://www.google.com/recaptcha/"  # Allow embedding Google reCAPTCHA.
    ],

    "style-src": [
        "'self'",  # Allow local styles.
        "'unsafe-inline'",  # Allow inline styles (necessary for Bootstrap).
        "https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/"  # Allow Bootstrap CSS.
    ],

    "img-src": [
        "'self'",  # Allow images hosted on the same domain.
        "data:",  # Allow base64-encoded inline images for QR codes.
        "https://www.gstatic.com/"  # Allow Google reCAPTCHA images.
    ]
}
# Integrate Talisman with the Flask application using the custom CSP
talisman = Talisman(app, content_security_policy=csp)

# Define WAF rules using regex patterns
waf_rules = {
    "SQL Injection": re.compile(r"(\b(union|select|insert|drop|alter)\b|;|%3B|`|%60|'|%27|--)", re.IGNORECASE),
    "XSS": re.compile(r"(<script>|<iframe>|%3Cscript%3E|%3Ciframe%3E)", re.IGNORECASE),
    "Path Traversal": re.compile(r"(\.\./|\.\.|%2e%2e%2f|%2e%2e/|\.\.%2f)", re.IGNORECASE)
}


# Define the user loader callback
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
    # Exclude specific routes from WAF and access restrictions
    excluded_routes = ['firewall_error', 'static']
    if request.endpoint in excluded_routes:
        return  # Skip the check for these routes

    if not current_user.is_authenticated:
        restricted_routes_anonymous = [
            'accounts.account', 'posts.posts', 'posts.create',
            'posts.update', 'posts.delete', 'accounts.logout', 'security.security'
        ]
        if request.endpoint in restricted_routes_anonymous:
            flash("You must be logged in to access this page.", "danger")
            return redirect(url_for('accounts.login'))

    # Inspect only path and query string
    path = request.path
    query = request.query_string.decode("utf-8")
    combined_request_data = f"{path} {query}"

    # Log the data being checked for debugging
    print(f"Combined Request Data: {combined_request_data}")

    # Check WAF rules
    for attack_type, pattern in waf_rules.items():
        if pattern.search(combined_request_data):
            print(f"Detected Attack Type: {attack_type} | Data: {combined_request_data}")
            flash(f"Attack detected: {attack_type}", "danger")
            return redirect(url_for('firewall_error', attack_type=attack_type))

if __name__ == '__main__':
  app.run(ssl_context=('certificate.crt', 'private.key'), debug=True)
