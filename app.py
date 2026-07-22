import os
import secrets
import sqlite3
from datetime import timedelta

from flask import Flask, render_template, request, redirect, session, abort, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf

app = Flask(__name__)

# ============ Security Configuration ============

# Secret key — read from env var, fallback to random (session will reset on restart)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Max upload size: 16MB
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

# Upload folder
UPLOAD_FOLDER = os.path.join(app.static_folder, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

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
            phone TEXT,
            avatar TEXT DEFAULT NULL,
            balance REAL DEFAULT 0
        )
    """)
    # Add columns if missing (for existing databases)
    for col in ["avatar", "balance"]:
        try:
            c.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT DEFAULT NULL" if col == "avatar" else f"ALTER TABLE users ADD COLUMN {col} REAL DEFAULT 0")
        except sqlite3.OperationalError:
            pass
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
        "balance": 99999,
        "avatar": None
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
        "avatar": None
    }
}


# ============ Routes ============

def get_user_from_db(username):
    """Look up user by username from SQLite database."""
    try:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        c.execute("SELECT username, password, email, phone, avatar, balance FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        if row:
            return {
                "username": row[0],
                "password": row[1],
                "email": row[2],
                "phone": row[3],
                "avatar": row[4],
                "balance": row[5] or 0,
                "role": "user",
            }
    except Exception:
        pass
    return None


def get_db_id(username):
    """Get user id from database by username."""
    try:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        return row[0] if row else None
    except Exception:
        return None


def get_balance_from_db(username):
    """Get user balance from database."""
    try:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        c.execute("SELECT balance FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        return row[0] if row else None
    except Exception:
        return None


def get_avatar_url(username):
    """Get avatar URL for a user — check DB first, fallback to USERS dict."""
    # Check DB first (persistent)
    db_user = get_user_from_db(username)
    if db_user and db_user.get("avatar"):
        return f"/static/uploads/{db_user['avatar']}"
    # Fallback to USERS dict
    if username in USERS and USERS[username].get("avatar"):
        return f"/static/uploads/{USERS[username]['avatar']}"
    return None


@app.context_processor
def inject_globals():
    """Make session_avatar and current_user_id available in all templates."""
    username = session.get("username")
    avatar_url = get_avatar_url(username) if username else None
    user_id = session.get("user_id", 1)
    return dict(session_avatar=avatar_url, current_user_id=user_id)


@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username:
        if username in USERS:
            user_info = USERS[username]
            # Override balance from DB for consistency
            db_balance = get_balance_from_db(username)
            if db_balance is not None:
                user_info["balance"] = db_balance
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
                session["user_id"] = get_db_id(username) or 1
                session.permanent = True
                user_info = USERS[username]
                return render_template("index.html", user=user_info)
            # Then try SQLite database (for newly registered users)
            db_user = get_user_from_db(username)
            if db_user and check_password_hash(db_user["password"], password):
                session["username"] = username
                session["user_id"] = get_db_id(username) or 1
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


# ============ Profile ============

def get_user_by_id(user_id):
    """Look up user by ID from database."""
    try:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = "SELECT id, username, email, phone, balance FROM users WHERE id = ?"
        c.execute(sql, (user_id,))
        row = c.fetchone()
        conn.close()
        if row:
            return {
                "id": row[0],
                "username": row[1],
                "email": row[2],
                "phone": row[3],
                "balance": row[4]
            }
    except Exception as e:
        print(f"[SQL] Profile query error: {e}")
    return None


@app.route("/profile")
def profile():
    """Display current user's profile — requires login, uses session user_id."""
    username = session.get("username")
    if not username:
        return redirect("/login")

    user_id = session.get("user_id")
    user_info = get_user_by_id(user_id) if user_id else None

    csrf_token = generate_csrf()
    return render_template("profile.html", user=user_info, csrf_token=csrf_token)


# ============ Recharge ============

@app.route("/recharge", methods=["POST"])
def recharge():
    """Add positive amount to current user's balance — requires login."""
    username = session.get("username")
    if not username:
        return redirect("/login")

    user_id = session.get("user_id")
    amount_str = request.form.get("amount", "0")

    error = None
    if not user_id:
        error = "用户信息错误"
    else:
        try:
            amount = float(amount_str)
            if amount <= 0:
                error = "充值金额必须为正数"
            elif amount > 100000:
                error = "单次充值金额不能超过 100,000 元"
            else:
                conn = sqlite3.connect("data/users.db")
                c = conn.cursor()
                sql = "UPDATE users SET balance = balance + ? WHERE id = ?"
                print(f"[SQL] {sql} | params: amount={amount}, user_id={user_id}")
                c.execute(sql, (amount, user_id))
                conn.commit()
                conn.close()

                # Sync USERS dict balance if applicable
                if username in USERS:
                    USERS[username]["balance"] = USERS[username].get("balance", 0) + amount

        except (ValueError, TypeError):
            error = "充值金额格式错误"

    if error:
        csrf_token = generate_csrf()
        user_info = get_user_by_id(user_id) if user_id else None
        return render_template("profile.html", user=user_info, error=error, csrf_token=csrf_token)

    return redirect(f"/profile")


# ============ Upload Avatar ============

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "bmp"}
ALLOWED_MIMETYPES = {"image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp"}

# Magic bytes signatures for image validation
IMAGE_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": "image/png",
    b"\xff\xd8\xff": "image/jpeg",
    b"GIF87a": "image/gif",
    b"GIF89a": "image/gif",
    b"RIFF": "image/webp",   # WEBP: RIFF....WEBP
    b"BM": "image/bmp",
}

DANGEROUS_EXTENSIONS = {"php", "phtml", "php3", "php4", "php5", "php7", "pht", "phps", "asp", "aspx", "jsp", "jspx", "exe", "sh", "py", "pl", "cgi", "htaccess", "htpasswd"}


def allowed_file(filename):
    """Check if file has an allowed image extension (whitelist approach)."""
    if "." not in filename:
        return False
    # Ensure the last extension is a valid image extension
    ext = filename.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False
    # Block hidden files and files starting with dot
    if filename.startswith("."):
        return False
    # Block known dangerous extensions anywhere in the filename
    parts = filename.lower().split(".")
    for part in parts:
        if part in DANGEROUS_EXTENSIONS:
            return False
    return True


def validate_image_content(file_storage):
    """Validate file content by checking magic bytes (signature-based)."""
    header = file_storage.read(16)
    file_storage.seek(0)  # Reset file pointer for later save

    for signature, img_type in IMAGE_SIGNATURES.items():
        if header.startswith(signature):
            # For WEBP, need deeper check
            if signature == b"RIFF":
                if header[8:12] != b"WEBP":
                    return False
            return True

    return False


def secure_filename_original(name):
    """Strip path traversal characters from filename while keeping original name."""
    # Remove any directory separators to prevent path traversal
    name = name.replace("\\", "/")
    # Keep only the last component (filename)
    name = name.rsplit("/", 1)[-1] if "/" in name else name
    # Remove any null bytes
    name = name.replace("\x00", "")
    return name


@app.route("/upload", methods=["GET", "POST"])
def upload():
    """Handle avatar upload with image validation."""
    username = session.get("username")
    if not username:
        return redirect("/login")

    error = None
    success = None
    file_url = None

    if request.method == "POST":
        if "file" not in request.files:
            error = "没有选择文件"
        else:
            f = request.files["file"]
            if f.filename == "":
                error = "没有选择文件"
            else:
                filename = secure_filename_original(f.filename)

                # V-U01, V-U06, V-U09, V-U10: Validate extension
                if not allowed_file(filename):
                    error = "不支持的文件类型，仅允许上传图片文件（PNG/JPG/GIF/WEBP/BMP）"
                else:
                    # V-U08: Validate Content-Type MIME
                    content_type = f.content_type or ""
                    # Only reject if content type is explicitly set to a non-image type
                    if content_type and content_type not in ALLOWED_MIMETYPES:
                        error = "文件类型不匹配，请上传有效的图片文件"
                    else:
                        # V-U01, V-U08: Validate file content via magic bytes
                        if not validate_image_content(f):
                            error = "文件内容校验失败，请上传有效的图片文件"
                        else:
                            save_path = os.path.join(UPLOAD_FOLDER, filename)

                            # V-U07: Protect against file overwriting
                            if os.path.exists(save_path):
                                error = "文件已存在，请修改文件名后重试"
                            else:
                                # Check file is within uploads directory (path traversal protection)
                                real_path = os.path.realpath(save_path)
                                if not real_path.startswith(os.path.realpath(UPLOAD_FOLDER)):
                                    error = "非法的文件路径"
                                else:
                                    f.save(save_path)
                                    file_url = f"/static/uploads/{filename}"

                                    # Store avatar reference in USERS dict and DB
                                    if username in USERS:
                                        USERS[username]["avatar"] = filename
                                    # Always persist to DB
                                    conn = sqlite3.connect("data/users.db")
                                    c = conn.cursor()
                                    c.execute("UPDATE users SET avatar = ? WHERE username = ?", (filename, username))
                                    conn.commit()
                                    conn.close()

                                    success = "头像上传成功"

    current_avatar = get_avatar_url(username)

    csrf_token = generate_csrf()
    return render_template(
        "upload.html",
        error=error,
        success=success,
        file_url=file_url,
        current_avatar=current_avatar,
        csrf_token=csrf_token,
    )


@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large error."""
    csrf_token = generate_csrf()
    return render_template(
        "upload.html",
        error="文件过大，最大允许 16MB",
        csrf_token=csrf_token,
    ), 413


# ============ Main Entry ============

if __name__ == "__main__":
    init_db()
    app.run(debug=False, host="0.0.0.0", port=5000)
