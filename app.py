import os
import secrets
from datetime import timedelta

from flask import Flask, render_template, request, redirect, session, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf

app = Flask(__name__)

# ============ Security Configuration ============

# Secret key — read from env var, fallback to random (session will reset on restart)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Session security settings
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,         # Set to True if using HTTPS in production
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    SESSION_PERMANENT=True,
    SESSION_REFRESH_EACH_REQUEST=True,
    SESSION_COOKIE_NAME="session",
)

# CSRF Protection
csrf = CSRFProtect(app)

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)


# ============ Security Headers ============

@app.after_request
def add_security_headers(response):
    """Add security headers to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "0"  # Deprecated, but safe to set
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), interest-cohort=()"
    )
    return response


# WSGI middleware to prevent server version disclosure
class SecurityWSGIMiddleware:
    def __init__(self, app):
        self.app = app
    def __call__(self, environ, start_response):
        def replace_server_header(status, headers, exc_info=None):
            new_headers = [(k, v) for k, v in headers if k.lower() != "server"]
            new_headers.append(("Server", "Server"))
            return start_response(status, new_headers, exc_info)
        return self.app(environ, replace_server_header)


app.wsgi_app = SecurityWSGIMiddleware(app.wsgi_app)


# ============ User Data ============

USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}


# ============ Routes ============

@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = USERS[username]
    return render_template("index.html", user=user_info)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")  # Rate limit: max 10 login attempts per minute per IP
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Input validation
        if not username or not password:
            error = "用户名和密码不能为空"
        elif len(username) > 64 or len(password) > 256:
            error = "输入内容过长"
        elif username in USERS and check_password_hash(USERS[username]["password"], password):
            session["username"] = username
            session.permanent = True
            user_info = USERS[username]
            return render_template("index.html", user=user_info)
        else:
            error = "用户名或密码错误"

    csrf_token = generate_csrf()
    return render_template("login.html", error=error, csrf_token=csrf_token)


@app.route("/logout")
def logout():
    # Expire session properly
    session.clear()
    resp = redirect("/")
    resp.set_cookie(
        app.config.get("SESSION_COOKIE_NAME", "session"),
        "",
        expires=0,
        httponly=True,
        samesite="Lax",
    )
    return resp


# ============ Health Check ============

@app.route("/health")
def health():
    return {"status": "ok"}, 200


# ============ Main Entry ============

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
