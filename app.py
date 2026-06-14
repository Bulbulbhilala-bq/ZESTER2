from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import sqlite3
import re
import os
import bleach
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, static_folder=".", static_url_path="")
CORS(app, origins=os.getenv("ALLOWED_ORIGINS", "http://localhost:5000").split(","))

# ── RATE LIMITER ─────────────────────────────────────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

DB = "zest.db"

# ── ADMIN AUTH ───────────────────────────────────────────────
ADMIN_KEY = os.getenv("ADMIN_API_KEY", "change-this-secret-key-in-production")

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-Admin-Key") or request.args.get("admin_key")
        if not key or key != ADMIN_KEY:
            return jsonify({"success": False, "message": "Unauthorized. Admin key required."}), 401
        return f(*args, **kwargs)
    return decorated

# ── FRONTEND SERVE ───────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(".", "index.html")

# ── DATABASE SETUP ──────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS newsletter (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            email     TEXT UNIQUE NOT NULL,
            joined_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS comments (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id    TEXT NOT NULL,
            name       TEXT NOT NULL,
            email      TEXT NOT NULL,
            message    TEXT NOT NULL,
            created_at TEXT NOT NULL,
            is_approved INTEGER DEFAULT 0
        );
    """)
    conn.commit()
    conn.close()
    print("✅ Database ready!")

# ── HELPERS ─────────────────────────────────────────────────
def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def now():
    return datetime.now().strftime("%d %b %Y, %I:%M %p")

def sanitize(text, max_length=1000):
    """Strip all HTML tags and limit length."""
    cleaned = bleach.clean(text, tags=[], strip=True)
    return cleaned[:max_length].strip()

# ── NEWSLETTER ROUTES ────────────────────────────────────────
@app.route("/api/newsletter/subscribe", methods=["POST"])
@limiter.limit("5 per hour")   # max 5 subscribe attempts per IP per hour
def subscribe():
    data = request.get_json(silent=True) or {}
    email = sanitize(data.get("email") or "", 254).lower()
    if not email or not is_valid_email(email):
        return jsonify({"success": False, "message": "Please enter a valid email address!"}), 400
    try:
        conn = get_db()
        conn.execute("INSERT INTO newsletter (email, joined_at) VALUES (?, ?)", (email, now()))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": f"🎉 Welcome aboard! {email} subscribed."}), 201
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "This email is already subscribed!"}), 409

# 🔒 ADMIN ONLY — requires X-Admin-Key header
@app.route("/api/newsletter/list", methods=["GET"])
@require_admin
def list_subscribers():
    conn = get_db()
    rows = conn.execute("SELECT id, email, joined_at FROM newsletter ORDER BY id DESC").fetchall()
    conn.close()
    return jsonify({"total": len(rows), "subscribers": [dict(r) for r in rows]})

@app.route("/api/newsletter/unsubscribe", methods=["DELETE"])
@limiter.limit("10 per hour")
def unsubscribe():
    data = request.get_json(silent=True) or {}
    email = sanitize(data.get("email") or "", 254).lower()
    conn = get_db()
    cur = conn.execute("DELETE FROM newsletter WHERE email = ?", (email,))
    conn.commit()
    conn.close()
    if cur.rowcount:
        return jsonify({"success": True, "message": f"{email} unsubscribed."})
    return jsonify({"success": False, "message": "Email not found."}), 404

# ── COMMENTS ROUTES ──────────────────────────────────────────
@app.route("/api/comments", methods=["POST"])
@limiter.limit("10 per hour")   # max 10 comments per IP per hour
def add_comment():
    data = request.get_json(silent=True) or {}
    post_id = sanitize(data.get("post_id") or "", 100)
    name    = sanitize(data.get("name") or "", 100)
    email   = sanitize(data.get("email") or "", 254).lower()
    message = sanitize(data.get("message") or "", 2000)

    if not all([post_id, name, email, message]):
        return jsonify({"success": False, "message": "Please fill in all fields!"}), 400
    if not is_valid_email(email):
        return jsonify({"success": False, "message": "Please enter a valid email address!"}), 400
    if len(message) < 5:
        return jsonify({"success": False, "message": "Comment is too short!"}), 400

    conn = get_db()
    conn.execute(
        "INSERT INTO comments (post_id, name, email, message, created_at, is_approved) VALUES (?, ?, ?, ?, ?, ?)",
        (post_id, name, email, message, now(), 1)  # set 0 for manual moderation
    )
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Comment posted successfully! 🎉"}), 201

@app.route("/api/comments/<post_id>", methods=["GET"])
@limiter.limit("60 per minute")
def get_comments(post_id):
    post_id = sanitize(post_id, 100)
    conn = get_db()
    rows = conn.execute(
        "SELECT id, name, message, created_at FROM comments WHERE post_id = ? AND is_approved = 1 ORDER BY id DESC",
        (post_id,)
    ).fetchall()
    conn.close()
    return jsonify({"post_id": post_id, "total": len(rows), "comments": [dict(r) for r in rows]})

# 🔒 ADMIN ONLY
@app.route("/api/comments/<int:comment_id>", methods=["DELETE"])
@require_admin
def delete_comment(comment_id):
    conn = get_db()
    cur = conn.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    conn.commit()
    conn.close()
    if cur.rowcount:
        return jsonify({"success": True, "message": "Comment deleted successfully."})
    return jsonify({"success": False, "message": "Comment not found."}), 404

# 🔒 ADMIN — list all comments including unapproved
@app.route("/api/comments/admin/all", methods=["GET"])
@require_admin
def admin_all_comments():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, post_id, name, email, message, created_at, is_approved FROM comments ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return jsonify({"total": len(rows), "comments": [dict(r) for r in rows]})

# 🔒 ADMIN — approve a comment
@app.route("/api/comments/<int:comment_id>/approve", methods=["PATCH"])
@require_admin
def approve_comment(comment_id):
    conn = get_db()
    cur = conn.execute("UPDATE comments SET is_approved = 1 WHERE id = ?", (comment_id,))
    conn.commit()
    conn.close()
    if cur.rowcount:
        return jsonify({"success": True, "message": "Comment approved."})
    return jsonify({"success": False, "message": "Comment not found."}), 404

# ── HEALTH CHECK ─────────────────────────────────────────────
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "🟢 Server is running!", "time": now()})

# ── ERROR HANDLERS ───────────────────────────────────────────
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"success": False, "message": "Too many requests. Please slow down!"}), 429

@app.errorhandler(404)
def not_found(e):
    return jsonify({"success": False, "message": "Route not found."}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"success": False, "message": "Internal server error."}), 500

# ── MAIN ─────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    port = int(os.getenv("PORT", 5000))
    print("🚀 ZEST Backend started → http://localhost:" + str(port))
    print(f"🔒 Debug mode: {debug_mode}")
    app.run(debug=debug_mode, port=port)
