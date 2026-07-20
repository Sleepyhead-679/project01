import os
import secrets
import sqlite3
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


# ============ Database Initialization ============

def init_db():
    """Initialize SQLite database with users table."""
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
    """)
    # Insert default users with INSERT OR IGNORE to prevent duplicates
    default_users = [
        ("admin", generate_password_hash("admin123"), "admin@example.com", "13800138000"),
        ("alice", generate_password_hash("alice2025"), "alice@example.com", "13900139001"),
    ]
    c.executemany(
        "INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
        default_users,
    )
    conn.commit()
    conn.close()
    print("[DB] Database initialized: data/users.db")


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

def get_user_from_db(username):
    """Look up user by username from SQLite database."""
    try:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        c.execute("SELECT username, password, email, phone FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        if row:
            return {
                "username": row[0],
                "password": row[1],
                "email": row[2],
                "phone": row[3],
                "role": "user",
                "balance": 0
            }
    except Exception:
        pass
    return None


@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username:
        if username in USERS:
            user_info = USERS[username]
        else:
            user_info = get_user_from_db(username)
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
        else:
            # Try hardcoded USERS dict first
            if username in USERS and check_password_hash(USERS[username]["password"], password):
                session["username"] = username
                session.permanent = True
                user_info = USERS[username]
                return render_template("index.html", user=user_info)
            # Then try SQLite database (for newly registered users)
            db_user = get_user_from_db(username)
            if db_user and check_password_hash(db_user["password"], password):
                session["username"] = username
                session.permanent = True
                return render_template("index.html", user=db_user)
            else:
                error = "用户名或密码错误"

    csrf_token = generate_csrf()
    msg = request.args.get("msg", "")
    return render_template("login.html", error=error, msg=msg, csrf_token=csrf_token)


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


# ============ Register ============

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    success = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # Input validation
        if not username or not password:
            error = "用户名和密码不能为空"
        elif len(username) > 64 or len(password) > 256:
            error = "输入内容过长"
        elif not email:
            error = "邮箱不能为空"
        else:
            # Hash password with bcrypt
            hashed_pw = generate_password_hash(password)

            # ✅ FIXED: Use parameterized query to prevent SQL injection
            conn = sqlite3.connect("data/users.db")
            c = conn.cursor()
            sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
            print(f"[SQL] {sql} | params: username={username!r}")
            try:
                c.execute(sql, (username, hashed_pw, email, phone))
                conn.commit()
                success = "注册成功，请登录"
            except sqlite3.IntegrityError:
                error = "注册失败：用户名已存在"
            except Exception:
                error = "注册失败，请稍后重试"
            finally:
                conn.close()

        if success:
            return redirect(f"/login?msg={success}")

    csrf_token = generate_csrf()
    return render_template("register.html", error=error, csrf_token=csrf_token)


# ============ Search ============

@app.route("/search")
def search():
    keyword = request.args.get("keyword", "").strip()
    results = []

    if keyword:
        if len(keyword) > 128:
            keyword = keyword[:128]
        # ✅ FIXED: Use parameterized query to prevent SQL injection
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        like_pattern = f"%{keyword}%"
        print(f"[SQL] {sql} | params: keyword={keyword!r}")
        try:
            c.execute(sql, (like_pattern, like_pattern))
            rows = c.fetchall()
            for row in rows:
                results.append({"id": row[0], "username": row[1], "email": row[2], "phone": row[3]})
        except Exception as e:
            print(f"[SQL] Error: {e}")
        finally:
            conn.close()

    username = session.get("username")
    user_info = None
    if username:
        if username in USERS:
            user_info = USERS[username]
        else:
            user_info = get_user_from_db(username)
    return render_template("index.html", user=user_info, search_results=results, keyword=keyword)


# ============ Main Entry ============

if __name__ == "__main__":
    init_db()
    app.run(debug=False, host="0.0.0.0", port=5000)
