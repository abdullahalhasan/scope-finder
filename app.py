# app.py
import json
import os
import sqlite3
import secrets
from datetime import datetime
from functools import wraps
from io import BytesIO, StringIO
import csv
import threading
import secrets
import time
import calendar
from datetime import datetime, timezone, timedelta, date

from flask import (
    Flask,
    abort,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
    flash,
    make_response,
)

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from werkzeug.security import check_password_hash, generate_password_hash

from scanner import scan_range, parse_exclusions, FileBlobCollector, expand_targets

# -----------------------
# Basic config
# -----------------------

#DB_PATH = os.path.join(os.path.dirname(__file__), "scopefinder.db")

DB_PATH = os.getenv("DB_PATH", "scope_finder.db")
SECRET_KEY = os.getenv("SECRET_KEY", "DEVELOPER-NAME-HASAN")

VALID_LICENSE_KEY = "SF-TRIAL-2026"  # demo license key for now

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Implementing Session Lifetime
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=5)
# Optional: refresh the cookie expiry on every request while active
app.config["SESSION_REFRESH_EACH_REQUEST"] = True

# Global cancel flag for stop button
scan_cancelled = False

# Real-time scan progress (per user)
scan_progress_lock = threading.Lock()
scan_progress = {}  # key: user_id -> dict

# Session Idle Timeout
SESSION_IDLE_TIMEOUT_SECONDS = 5 * 60  # 5 minutes

# Define License Settings
LICENSE_SETTING_KEYS = {
    "license_key",
    "license_org",
    "license_contact",
    "license_expiry",
    "license_activated_at",
}

# -----------------------
# DB helpers
# -----------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _column_exists(db: sqlite3.Connection, table: str, column: str) -> bool:
    cur = db.execute(f"PRAGMA table_info({table})")
    cols = [r[1] for r in cur.fetchall()]  # (cid, name, type, notnull, dflt_value, pk)
    return column in cols


def _ensure_scan_columns(db: sqlite3.Connection):
    """
    Lightweight migration for existing DBs:
    - Add scans.exclude_ips column if missing
    """
    if not _column_exists(db, "scans", "exclude_ips"):
        db.execute("ALTER TABLE scans ADD COLUMN exclude_ips TEXT NOT NULL DEFAULT ''")
        db.commit()


def init_db():
    db = get_db()

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )
        """
    )

    # UPDATED: scans table includes exclude_ips
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            target TEXT NOT NULL,
            exclude_ips TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            result_json TEXT NOT NULL,
            cancelled INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            actor_username TEXT,
            actor_user_id INTEGER,
            actor_role TEXT,
            source TEXT,
            action TEXT NOT NULL,
            details TEXT
        )
        """
    )

    # Admin-managed named IP lists (target ranges + exclude lists)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS ip_lists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            list_type TEXT NOT NULL,
            value_text TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            created_by INTEGER
        )
        """
    )

    db.commit()

    # Run migration(s) for existing DBs
    _ensure_scan_columns(db)

    # Ensure there is at least one admin user
    cur = db.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    row = cur.fetchone()
    if not row:
        password_hash = generate_password_hash("admin123")
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", password_hash, "admin"),
        )
        db.commit()
        print("Created default admin user: admin / admin123")

    # Ensure we have a 'siem' service user for token auth
    cur = db.execute("SELECT id FROM users WHERE username = ?", ("siem",))
    row = cur.fetchone()
    if not row:
        password_hash = generate_password_hash(secrets.token_hex(16))
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("siem", password_hash, "admin"),
        )
        db.commit()
        print("Created SIEM service user: siem")

def purge_everything_except_license():
    """
    Deletes ALL app data except license settings.
    Keeps schema intact.
    Keeps users table by default (so you don't lock yourself out).
    """
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        # Avoid FK constraint issues while deleting
        cur.execute("PRAGMA foreign_keys=OFF;")

        # 1) Delete from every table except settings/users
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
        tables = [r[0] for r in cur.fetchall()]

        for t in tables:
            if t in ("settings", "users"):
                continue
            cur.execute(f"DELETE FROM {t};")

        # 2) In settings: keep only license keys
        placeholders = ",".join(["?"] * len(LICENSE_SETTING_KEYS))
        cur.execute(
            f"DELETE FROM settings WHERE key NOT IN ({placeholders});",
            tuple(LICENSE_SETTING_KEYS),
        )

        # OPTIONAL: if you ALSO want to remove all non-admin users, uncomment this:
        # cur.execute("DELETE FROM users WHERE role <> 'admin';")

        conn.commit()
    finally:
        conn.close()

def set_progress(user_id: int, **kwargs):
    now = time.time()
    with scan_progress_lock:
        cur = scan_progress.get(user_id) or {}
        if "started_at" not in cur:
            cur["started_at"] = now
        cur["updated_at"] = now
        cur.update(kwargs)

        # Convenience: compute elapsed seconds
        cur["elapsed_sec"] = round(now - cur["started_at"], 3)

        scan_progress[user_id] = cur


def clear_progress(user_id: int):
    with scan_progress_lock:
        scan_progress.pop(user_id, None)


def get_setting(key: str) -> str | None:
    db = get_db()
    cur = db.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = cur.fetchone()
    return row["value"] if row else None

def get_setting_default(key: str, default: str = "") -> str:
    try:
        v = get_setting(key)
        return v if v is not None else default
    except Exception:
        return default

def set_setting(key: str, value: str):
    db = get_db()
    db.execute(
        """
        INSERT INTO settings (key, value)
        VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (key, value),
    )
    db.commit()

def _utc_ts_z():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def generate_api_token() -> str:
    # 32 bytes → ~43 chars urlsafe; strong enough
    return secrets.token_urlsafe(32)

def store_api_token(token_plain: str) -> None:
    # Store only hash + a short prefix for UI display
    token_hash = generate_password_hash(token_plain)  # pbkdf2:sha256 by default
    token_prefix = token_plain[:6]  # show only first 6 chars in UI
    ts = _utc_ts_z()

    set_setting("api_token_hash", token_hash)
    set_setting("api_token_prefix", token_prefix)
    set_setting("api_token_created_at", ts)

#def verify_api_token(token_plain: str) -> bool:
#    token_hash = get_setting("api_token_hash", "")
#    if not token_hash or not token_plain:
#        return False
#    return check_password_hash(token_hash, token_plain)

def verify_api_token(token_plain: str) -> bool:
    token_hash = get_setting_default("api_token_hash", "")
    if not token_hash or not token_plain:
        return False
    return check_password_hash(token_hash, token_plain)



def session_or_api_token_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Allow logged-in browser session
        if session.get("user_id"):
            return fn(*args, **kwargs)

        # Allow API token for SIEM / automation calls
        token = request.headers.get("X-API-Token")
        if not token:
            auth = request.headers.get("Authorization", "")
            if auth.lower().startswith("bearer "):
                token = auth.split(" ", 1)[1].strip()

        if token and verify_api_token(token):
            return fn(*args, **kwargs)

        return jsonify({"error": "Unauthorized"}), 401
    return wrapper


def fetch_ip_lists():
    db = get_db()
    cur = db.execute(
        """
        SELECT id, name, list_type, value_text, created_at, updated_at
        FROM ip_lists
        ORDER BY name COLLATE NOCASE
        """
    )
    rows = cur.fetchall()
    return [dict(r) for r in rows]

@app.before_request
def enforce_session_timeout():
    # Skip checks for static files and login page (adjust endpoint names if yours differ)
    if request.endpoint in {"static", "login"}:
        return

    if session.get("user_id"):
        now = int(time.time())
        last = session.get("last_activity", now)

        if (now - last) > SESSION_IDLE_TIMEOUT_SECONDS:
            session.clear()
            flash("Session expired due to inactivity. Please log in again.", "warning")
            return redirect(url_for("login"))

        # User is active: bump activity timestamp (idle timeout)
        session["last_activity"] = now

# -----------------------
# Licensing
# -----------------------
def is_license_valid() -> bool:
    stored_key = get_setting("license_key")
    if stored_key != VALID_LICENSE_KEY:
        return False

    expiry = get_setting("license_expiry")
    if not expiry:
        # Backward compatible: if expiry not set, treat as valid
        return True

    try:
        exp_date = datetime.strptime(expiry, "%Y-%m-%d").date()
    except ValueError:
        # If someone stored a bad format, don't brick the app
        return True

    today_utc = datetime.now(timezone.utc).date()
    return today_utc <= exp_date


def _add_one_month(d: date) -> date:
    """Add 1 calendar month to a date (handles month-end correctly)."""
    year = d.year + (d.month // 12)
    month = (d.month % 12) + 1
    last_day = calendar.monthrange(year, month)[1]
    return date(year, month, min(d.day, last_day))

def _ensure_one_month_expiry_on_first_activation():
    """
    Set activated_at + expiry ONLY the first time a valid key is activated.
    Do NOT overwrite if already set.
    """
    if not get_setting("license_activated_at"):
        set_setting("license_activated_at", _utc_ts_z())

    if not get_setting("license_expiry"):
        today_utc = datetime.now(timezone.utc).date()
        set_setting("license_expiry", _add_one_month(today_utc).isoformat())  # YYYY-MM-DD


@app.before_request
def check_license():
    # Allow static files
    if request.path.startswith("/static"):
        return

    # Endpoints allowed without active license
    open_endpoints = {"login", "license"}
    if request.endpoint in open_endpoints:
        return

    # Ensure DB and tables exist
    #init_db()

    # License gate for all other endpoints
    if not is_license_valid() and request.endpoint != "license":
        return redirect(url_for("license"))


# -----------------------
# Audit log helpers
# -----------------------
def _actor_context():
    username = None
    user_id = None
    role = None
    source = "system"

    if "user_id" in session:
        username = session.get("username")
        user_id = session.get("user_id")
        role = session.get("role")
        source = "ui"
    elif hasattr(g, "api_user_id"):
        username = getattr(g, "api_username", None)
        user_id = getattr(g, "api_user_id", None)
        role = getattr(g, "api_role", None)
        source = "api"

    return username, user_id, role, source


def log_audit(action: str, details: str | None = None):
    db = get_db()
    username, user_id, role, source = _actor_context()
    #ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    db.execute(
        """
        INSERT INTO audit_log (timestamp, actor_username, actor_user_id,
                               actor_role, source, action, details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (ts, username, user_id, role, source, action, details),
    )
    db.commit()


# -----------------------
# Auth / RBAC / API token
# -----------------------
def login_required(role: str | None = None):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                abort(403)
            return fn(*args, **kwargs)

        return wrapped

    return decorator


def api_or_login_required(fn):
    """
    For API endpoints: allow either
    - browser session (normal login), or
    - SIEM token via X-API-Token or Authorization: Bearer <token>.
    """
    @wraps(fn)
    def wrapped(*args, **kwargs):
        # Case 1: browser session
        if "user_id" in session:
            g.api_user_id = session["user_id"]
            g.api_username = session.get("username")
            g.api_role = session.get("role")
            return fn(*args, **kwargs)

        # Case 2: API token
        token = request.headers.get("X-API-Token")
        if not token:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.lower().startswith("bearer "):
                token = auth_header[7:].strip()

        if not token:
            return jsonify({"success": False, "error": "Missing API token."}), 401

        siem_token = get_setting("siem_api_token")
        if not siem_token or token != siem_token:
            log_audit("api_auth_failed", "Invalid API token provided.")
            return jsonify({"success": False, "error": "Invalid API token."}), 401

        # Token ok -> act as 'siem' user
        db = get_db()
        cur = db.execute("SELECT id, username, role FROM users WHERE username = ?", ("siem",))
        user = cur.fetchone()
        if not user:
            password_hash = generate_password_hash(secrets.token_hex(16))
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("siem", password_hash, "admin"),
            )
            db.commit()
            cur = db.execute("SELECT id, username, role FROM users WHERE username = ?", ("siem",))
            user = cur.fetchone()

        g.api_user_id = user["id"]
        g.api_username = user["username"]
        g.api_role = user["role"]

        return fn(*args, **kwargs)

    return wrapped


def current_user_id() -> int:
    if "user_id" in session:
        return session["user_id"]
    if hasattr(g, "api_user_id"):
        return g.api_user_id
    raise RuntimeError("No authenticated user context.")


@app.route("/login", methods=["GET", "POST"])
def login():
    db = get_db()
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        cur = db.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (username,),
        )
        user = cur.fetchone()

        if not user or not check_password_hash(user["password_hash"], password):
            error = "Invalid username or password."
            log_audit("login_failed", f"Login failed for username='{username}'.")
        else:
            # on successful login
            
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["last_activity"] = int(time.time())
            # enables PERMANENT_SESSION_LIFETIME
            session.permanent = True                  
            log_audit("login_success", f"User '{username}' logged in.")
            return redirect(url_for("index"))

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    log_audit("logout", "User logged out.")
    session.clear()
    return redirect(url_for("login"))


# -----------------------
# License pages
# -----------------------
@app.route("/license", methods=["GET", "POST"])
def license():
    error = None
    success = None

    current_key = get_setting("license_key")
    activated_at = get_setting("license_activated_at")
    expiry = get_setting("license_expiry")
    license_valid = is_license_valid()

    if request.method == "POST":
        key = (request.form.get("license_key") or "").strip()

        if key != VALID_LICENSE_KEY:
            error = "Invalid license key."
            log_audit("license_activation_failed", f"Attempted activation with key prefix='{key[:4] if key else ''}'")
        else:
            was_valid = (current_key == VALID_LICENSE_KEY)

            set_setting("license_key", key)

            # Only set expiry/activated_at on first transition to valid
            if not was_valid:
                _ensure_one_month_expiry_on_first_activation()

            # IMPORTANT: purge everything except license data
            purge_everything_except_license()

            success = "License activated successfully."
            log_audit("license_activated", f"License key set (prefix='{key[:4]}...')")

            # refresh values for display
            current_key = get_setting("license_key")
            activated_at = get_setting("license_activated_at")
            expiry = get_setting("license_expiry")
            license_valid = is_license_valid()

    return render_template(
        "license.html",
        error=error,
        success=success,
        current_key=current_key,
        activated_at=activated_at,
        expiry=expiry,
        license_valid=license_valid,
    )



@app.route("/licenses", methods=["GET", "POST"])
@login_required("admin")
def manage_licenses():
    error = None
    success = None

    current_key = get_setting("license_key")
    org = get_setting("license_org")
    contact = get_setting("license_contact")
    expiry = get_setting("license_expiry")
    license_valid = is_license_valid()

    if request.method == "POST":
        new_key = (request.form.get("license_key") or "").strip()

        if new_key and new_key != current_key:
            if new_key != VALID_LICENSE_KEY:
                error = "Invalid license key."
            else:
                was_valid = (current_key == VALID_LICENSE_KEY)
                set_setting("license_key", new_key)

                if not was_valid:
                    _ensure_one_month_expiry_on_first_activation()

                log_audit("license_key_updated", f"License key updated (prefix='{new_key[:4]}...')")
                success = "License key updated."

        # re-load display values
        current_key = get_setting("license_key")
        org = get_setting("license_org")
        contact = get_setting("license_contact")
        expiry = get_setting("license_expiry")
        license_valid = is_license_valid()

    return render_template(
        "licenses.html",
        current_key=current_key,
        org=org,
        contact=contact,
        expiry=expiry,
        license_valid=license_valid,
        error=error,
        success=success,
    )


# IP List Page for Admin
@app.route("/ip-lists", methods=["GET", "POST"])
@login_required("admin")
def manage_ip_lists():
    db = get_db()
    error = None
    success = None

    if request.method == "POST":
        action = request.form.get("action")

        if action == "create":
            name = (request.form.get("name") or "").strip()
            list_type = (request.form.get("list_type") or "").strip()
            value_text = (request.form.get("value_text") or "").strip()

            if not name or not value_text:
                error = "Name and value are required."
            elif list_type not in ("target", "exclude"):
                error = "Invalid list type."
            else:
                try:
                    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
                    db.execute(
                        """
                        INSERT INTO ip_lists (name, list_type, value_text, created_at, updated_at, created_by)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (name, list_type, value_text, ts, ts, current_user_id()),
                    )
                    db.commit()
                    log_audit("ip_list_created", f"name='{name}', type='{list_type}', value='{value_text}'")
                    success = "List created."
                except sqlite3.IntegrityError:
                    error = "A list with this name already exists."

        elif action == "update":
            list_id = (request.form.get("list_id") or "").strip()
            name = (request.form.get("name") or "").strip()
            list_type = (request.form.get("list_type") or "").strip()
            value_text = (request.form.get("value_text") or "").strip()

            if not list_id:
                error = "Missing list id."
            elif not name or not value_text:
                error = "Name and value are required."
            elif list_type not in ("target", "exclude"):
                error = "Invalid list type."
            else:
                try:
                    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
                    db.execute(
                        """
                        UPDATE ip_lists
                        SET name = ?, list_type = ?, value_text = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (name, list_type, value_text, ts, list_id),
                    )
                    db.commit()
                    log_audit("ip_list_updated", f"id={list_id}, name='{name}', type='{list_type}'")
                    success = "List updated."
                except sqlite3.IntegrityError:
                    error = "A list with this name already exists."

        elif action == "delete":
            list_id = (request.form.get("list_id") or "").strip()
            if not list_id:
                error = "Missing list id."
            else:
                cur = db.execute("SELECT name FROM ip_lists WHERE id = ?", (list_id,))
                row = cur.fetchone()
                db.execute("DELETE FROM ip_lists WHERE id = ?", (list_id,))
                db.commit()
                log_audit("ip_list_deleted", f"id={list_id}, name='{row['name'] if row else ''}'")
                success = "List deleted."

    ip_lists = fetch_ip_lists()
    return render_template("ip_lists.html", ip_lists=ip_lists, error=error, success=success)



# -----------------------
# API Token management (admin only)
# -----------------------
@app.route("/api-token", methods=["GET", "POST"])
@login_required("admin")
def api_token():
    # token is shown only once after creation/rotation
    new_token = session.pop("new_api_token", None)

    if request.method == "POST":
        action = (request.form.get("action") or "").strip()

        if action in ("generate", "rotate"):
            token_plain = generate_api_token()
            store_api_token(token_plain)

            # show once using session
            session["new_api_token"] = token_plain

            log_audit("api_token_rotated", "API token rotated (hash stored; plaintext shown once).")
            return redirect(url_for("api_token"))
        
    
    token_prefix = get_setting_default("api_token_prefix", "")
    token_created_at = get_setting_default("api_token_created_at", "")
    token_hash = get_setting_default("api_token_hash", "")


    return render_template(
        "api_token.html",
        new_token=new_token,
        token_prefix=token_prefix,
        token_created_at=token_created_at,
    )

# -----------------------
# Helper: cancel flag
# -----------------------
def is_cancelled() -> bool:
    global scan_cancelled
    return scan_cancelled


# -----------------------
# Main pages
# -----------------------
@app.route("/", methods=["GET", "POST"])
@login_required()
def index():
    """
    UI scan page:
    - supports exclude_ips
    - runs scan_range
    - stores scan in DB (same as API)
    """
    results = None
    error = None

    if request.method == "POST":
        global scan_cancelled
        scan_cancelled = False

        target = (request.form.get("target") or "").strip()
        exclusions_text = (request.form.get("exclude_ips") or "").strip()
        min_port = int(request.form.get("min_port") or 1)
        max_port = int(request.form.get("max_port") or 1024)

        if not target:
            error = "Target is required."
        else:
            try:
                # Optional SMB/NetBIOS/AD parsing from evidence files (safe)
                collector = FileBlobCollector(base_dir="evidence")

                scan_results = scan_range(
                    target=target,
                    cancel_check=is_cancelled,
                    min_port=min_port,
                    max_port=max_port,
                    exclusions_text=exclusions_text,
                    smb_collector=collector,
                )

                cancelled = scan_cancelled
                scan_cancelled = False

                # Build JSON for DB/API (including exclude_ips + findings)
                json_results = {}
                for ip, host in scan_results.items():
                    json_results[ip] = {
                        "ip": host.ip,
                        "hostname": host.hostname,
                        "ports": [
                            {
                                "port": p.port,
                                "protocol": p.protocol,
                                "service": p.service,
                                "state": p.state,
                                "banner": p.banner,
                            }
                            for p in host.ports
                        ],
                        "findings": host.findings or {},
                    }

                # Save scan to DB (store exclude_ips explicitly)
                db = get_db()
                created_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"
                user_id = current_user_id()
                db.execute(
                    """
                    INSERT INTO scans (user_id, target, exclude_ips, created_at, result_json, cancelled)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        user_id,
                        target,
                        exclusions_text,
                        created_at,
                        json.dumps(json_results),
                        1 if cancelled else 0,
                    ),
                )
                db.commit()
                scan_id = db.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

                log_audit("scan_completed_ui", f"Scan id={scan_id} target='{target}' exclude_ips='{exclusions_text}' cancelled={cancelled}")

                # What you pass to template
                results = {
                    "scan_id": scan_id,
                    "target": target,
                    "exclude_ips": exclusions_text,
                    "excluded_count": len(parse_exclusions(exclusions_text)),
                    "cancelled": cancelled,
                    "hosts": json_results,
                }

            except Exception as e:
                log_audit("scan_failed_ui", f"Scan failed for target='{target}': {e}")
                error = f"Scan failed: {type(e).__name__}: {e}"

    #return render_template("index.html", results=results, error=error)
    return render_template("index.html", results=results, error=error, ip_lists=fetch_ip_lists())




@app.route("/history")
@login_required()
def history():
    db = get_db()
    if session.get("role") == "admin":
        cur = db.execute(
            """
            SELECT scans.id, scans.target, scans.exclude_ips, scans.created_at, scans.cancelled,
                   users.username
            FROM scans
            JOIN users ON scans.user_id = users.id
            ORDER BY scans.created_at DESC
            """
        )
    else:
        cur = db.execute(
            """
            SELECT scans.id, scans.target, scans.exclude_ips, scans.created_at, scans.cancelled,
                   users.username
            FROM scans
            JOIN users ON scans.user_id = users.id
            WHERE scans.user_id = ?
            ORDER BY scans.created_at DESC
            """,
            (session["user_id"],),
        )

    scans = cur.fetchall()
    return render_template("history.html", scans=scans)


@app.route("/api-docs")
@login_required()
def api_docs():
    return render_template("api_docs.html")


# -----------------------
# User management (admin)
# -----------------------
@app.route("/users", methods=["GET", "POST"])
@login_required("admin")
def manage_users():
    db = get_db()
    error = None
    success = None

    if request.method == "POST":
        action = request.form.get("action")

        if action == "create":
            username = (request.form.get("username") or "").strip()
            password = (request.form.get("password") or "").strip()
            role = (request.form.get("role") or "viewer").strip()

            if not username or not password:
                error = "Username and password are required."
            elif role not in ("admin", "viewer"):
                error = "Role must be 'admin' or 'viewer'."
            else:
                try:
                    pw_hash = generate_password_hash(password)
                    db.execute(
                        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                        (username, pw_hash, role),
                    )
                    db.commit()
                    success = f"User '{username}' created successfully."
                    log_audit("user_created", f"Created user '{username}' with role='{role}'.")
                except sqlite3.IntegrityError:
                    error = "Username already exists."

        elif action == "reset_password":
            user_id = request.form.get("user_id")
            new_password = (request.form.get("new_password") or "").strip()
            if not new_password:
                error = "New password is required."
            else:
                cur = db.execute("SELECT username FROM users WHERE id = ?", (user_id,))
                u = cur.fetchone()
                if not u:
                    error = "User not found."
                elif u["username"] == "siem":
                    error = "Cannot reset password of SIEM service user from UI."
                else:
                    pw_hash = generate_password_hash(new_password)
                    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (pw_hash, user_id))
                    db.commit()
                    success = f"Password updated for '{u['username']}'."
                    log_audit("user_password_reset", f"Password reset for user '{u['username']}'.")

        elif action == "delete":
            user_id = request.form.get("user_id")
            cur = db.execute("SELECT username FROM users WHERE id = ?", (user_id,))
            u = cur.fetchone()
            if not u:
                error = "User not found."
            elif u["username"] in ("admin", "siem"):
                error = "Cannot delete built-in users 'admin' or 'siem'."
            elif str(session.get("user_id")) == str(user_id):
                error = "You cannot delete your own account while logged in."
            else:
                db.execute("DELETE FROM users WHERE id = ?", (user_id,))
                db.commit()
                success = f"User '{u['username']}' deleted."
                log_audit("user_deleted", f"Deleted user '{u['username']}'.")

    cur = db.execute("SELECT id, username, role FROM users ORDER BY username ASC")
    users = cur.fetchall()

    return render_template("users.html", users=users, error=error, success=success)


# -----------------------
# Audit log page (admin)
# -----------------------
def build_audit_query(filters, limit: int | None = 500):
    sql = """
        SELECT id, timestamp, actor_username, actor_user_id,
               actor_role, source, action, details
        FROM audit_log
        WHERE 1=1
    """
    params: list[str] = []

    if filters.get("start_date"):
        sql += " AND timestamp >= ?"
        params.append(filters["start_date"] + "T00:00:00Z")

    if filters.get("end_date"):
        sql += " AND timestamp <= ?"
        params.append(filters["end_date"] + "T23:59:59Z")

    if filters.get("actor"):
        sql += " AND actor_username LIKE ?"
        params.append(f"%{filters['actor']}%")

    if filters.get("action"):
        sql += " AND action LIKE ?"
        params.append(f"%{filters['action']}%")

    if filters.get("source"):
        sql += " AND source = ?"
        params.append(filters["source"])

    sql += " ORDER BY timestamp DESC"

    if limit is not None:
        sql += " LIMIT ?"
        params.append(limit)

    return sql, params


@app.route("/audit")
@login_required("admin")
def audit_page():
    db = get_db()

    filters = {
        "start_date": (request.args.get("start_date") or "").strip(),
        "end_date": (request.args.get("end_date") or "").strip(),
        "actor": (request.args.get("actor") or "").strip(),
        "action": (request.args.get("action") or "").strip(),
        "source": (request.args.get("source") or "").strip(),
    }

    sql, params = build_audit_query(filters, limit=500)
    cur = db.execute(sql, params)
    logs = cur.fetchall()

    return render_template("audit.html", logs=logs, filters=filters)


@app.route("/audit/export")
@login_required("admin")
def audit_export():
    db = get_db()

    filters = {
        "start_date": (request.args.get("start_date") or "").strip(),
        "end_date": (request.args.get("end_date") or "").strip(),
        "actor": (request.args.get("actor") or "").strip(),
        "action": (request.args.get("action") or "").strip(),
        "source": (request.args.get("source") or "").strip(),
    }

    sql, params = build_audit_query(filters, limit=None)
    cur = db.execute(sql, params)
    rows = cur.fetchall()

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "timestamp", "actor_username", "actor_user_id", "actor_role", "source", "action", "details"])

    for r in rows:
        writer.writerow(
            [
                r["id"],
                r["timestamp"],
                r["actor_username"] or "",
                r["actor_user_id"] or "",
                r["actor_role"] or "",
                r["source"] or "",
                r["action"] or "",
                (r["details"] or "").replace("\n", " ").replace("\r", " "),
            ]
        )

    csv_data = output.getvalue()
    response = make_response(csv_data)
    response.headers["Content-Type"] = "text/csv"
    response.headers["Content-Disposition"] = "attachment; filename=scope_finder_audit_log.csv"
    return response


# -----------------------
# API endpoints (session OR token)
# -----------------------


@app.route("/api/scan", methods=["POST"])
@session_or_api_token_required
def api_scan():

    global scan_cancelled
    scan_cancelled = False

    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    exclude_ips = (data.get("exclude_ips") or "").strip()
    min_port = int(data.get("min_port", 1))
    max_port = int(data.get("max_port", 1024))

    user_id = current_user_id()

    # Precompute excluded list + total hosts for progress
    try:
        exclude_set = parse_exclusions(exclude_ips)
        all_ips = expand_targets(target, exclusions=set())
        ips = [ip for ip in all_ips if ip not in exclude_set]
        excluded_list = sorted(set(all_ips) & exclude_set)
    except Exception:
        ips = []
        excluded_list = []

    set_progress(
        user_id,
        phase="starting",
        target=target,
        exclude_ips=exclude_ips,
        excluded_count=len(excluded_list),
        excluded_sample=excluded_list[:25],  # limit for UI
        host_total=len(ips),
        host_index=0,
        current_ip=None,
        port_total=(max_port - min_port + 1),
        ports_done=0,
        last_port=None,
        open_found=0,
        message="Starting scan…"
    )

    def progress_cb(evt: dict):
        # evt can include: phase, current_ip, host_index, host_total, ports_done, port_total, last_port, open_found, message
        payload = dict(evt or {})
        # Compute percent when we have enough info
        ht = payload.get("host_total")
        hi = payload.get("host_index")
        pt = payload.get("port_total")
        pd = payload.get("ports_done")
        if ht and hi and pt and pd is not None:
            overall_done = (max(hi - 1, 0) * pt) + pd
            overall_total = ht * pt
            payload["percent"] = round((overall_done / overall_total) * 100, 2) if overall_total else 0.0
        set_progress(user_id, **payload)


    if not target:
        return jsonify({"success": False, "error": "Target is required."}), 400

    try:
        collector = FileBlobCollector(base_dir="evidence")

        results = scan_range(
            target=target,
            cancel_check=is_cancelled,
            min_port=min_port,
            max_port=max_port,
            exclusions_text=exclude_ips,
            smb_collector=collector,
            progress_cb=progress_cb,
            progress_every_n_ports=25,
        )
    except Exception as e:
        log_audit("scan_failed", f"Scan failed for target='{target}': {e}")
        return jsonify({"success": False, "error": f"Scan failed: {type(e).__name__}: {e}"}), 500

    cancelled = scan_cancelled
    scan_cancelled = False

    json_results = {}
    for ip, host in results.items():
        json_results[ip] = {
            "ip": host.ip,
            "hostname": host.hostname,
            "ports": [
                {"port": p.port, "protocol": p.protocol, "service": p.service, "state": p.state, "banner": p.banner}
                for p in host.ports
            ],
            "findings": host.findings or {},
        }

    db = get_db()
    created_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    user_id = current_user_id()
    db.execute(
        """
        INSERT INTO scans (user_id, target, exclude_ips, created_at, result_json, cancelled)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user_id, target, exclude_ips, created_at, json.dumps(json_results), 1 if cancelled else 0),
    )
    db.commit()
    scan_id = db.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

    log_audit("scan_completed", f"Scan id={scan_id} target='{target}' exclude_ips='{exclude_ips}' cancelled={cancelled}")

    clear_progress(user_id)

    return jsonify(
        {
            "success": True,
            "scan_id": scan_id,
            "target": target,
            "exclude_ips": exclude_ips,
            "excluded_count": len(parse_exclusions(exclude_ips)),
            "results": json_results,
            "cancelled": cancelled,
        }
    )


@app.route("/api/stop", methods=["POST"])
@session_or_api_token_required
def api_stop():
    global scan_cancelled
    scan_cancelled = True
    uid = current_user_id()
    set_progress(uid, phase="stopping", message="Stop requested…")
    log_audit("scan_stop_requested", "Stop requested for running scan.")
    # DO NOT clear_progress(uid) here
    return jsonify({"success": True})



@app.route("/api/scans", methods=["GET"])
@session_or_api_token_required
def api_scans_list():

    db = get_db()

    if "user_id" in session and session.get("role") == "admin":
        cur = db.execute(
            """
            SELECT scans.id, scans.target, scans.exclude_ips, scans.created_at, scans.cancelled,
                   users.username
            FROM scans
            JOIN users ON scans.user_id = users.id
            ORDER BY scans.created_at DESC
            """
        )
    else:
        uid = current_user_id()
        cur = db.execute(
            """
            SELECT scans.id, scans.target, scans.exclude_ips, scans.created_at, scans.cancelled,
                   users.username
            FROM scans
            JOIN users ON scans.user_id = users.id
            WHERE scans.user_id = ?
            ORDER BY scans.created_at DESC
            """,
            (uid,),
        )

    rows = cur.fetchall()
    data = [
        {
            "id": r["id"],
            "target": r["target"],
            "exclude_ips": r["exclude_ips"],
            "created_at": r["created_at"],
            "cancelled": bool(r["cancelled"]),
            "username": r["username"],
        }
        for r in rows
    ]
    return jsonify({"success": True, "scans": data})


@app.route("/api/scans/<int:scan_id>", methods=["GET"])
@session_or_api_token_required
def api_scan_detail(scan_id: int):

    db = get_db()
    cur = db.execute(
        """
        SELECT scans.id, scans.target, scans.exclude_ips, scans.created_at, scans.cancelled,
               scans.result_json, scans.user_id, users.username
        FROM scans
        JOIN users ON scans.user_id = users.id
        WHERE scans.id = ?
        """,
        (scan_id,),
    )
    row = cur.fetchone()
    if not row:
        return jsonify({"success": False, "error": "Scan not found."}), 404

    uid = current_user_id()
    role = session.get("role") if "user_id" in session else getattr(g, "api_role", None)
    if role != "admin" and row["user_id"] != uid:
        abort(403)

    results = json.loads(row["result_json"])
    return jsonify(
        {
            "success": True,
            "scan": {
                "id": row["id"],
                "target": row["target"],
                "exclude_ips": row["exclude_ips"],
                "created_at": row["created_at"],
                "cancelled": bool(row["cancelled"]),
                "username": row["username"],
                "results": results,
            },
        }
    )

@app.route("/api/progress", methods=["GET"])
@session_or_api_token_required
def api_progress():

    user_id = current_user_id()
    with scan_progress_lock:
        p = scan_progress.get(user_id)

    if not p:
        return jsonify({"active": False})

    return jsonify({"active": True, **p})


# -----------------------
# PDF download (UI only)
# -----------------------
@app.route("/scans/<int:scan_id>/pdf")
@login_required()
def download_scan_pdf(scan_id: int):
    db = get_db()
    cur = db.execute(
        """
        SELECT scans.id, scans.target, scans.exclude_ips, scans.created_at, scans.cancelled,
               scans.result_json, scans.user_id, users.username
        FROM scans
        JOIN users ON scans.user_id = users.id
        WHERE scans.id = ?
        """,
        (scan_id,),
    )
    row = cur.fetchone()
    if not row:
        abort(404)

    if session.get("role") != "admin" and row["user_id"] != session["user_id"]:
        abort(403)

    results = json.loads(row["result_json"])

    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    y = height - 50
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "Scope Finder - Scan Report")
    y -= 30

    c.setFont("Helvetica", 10)
    c.drawString(50, y, f"Scan ID: {row['id']}")
    y -= 15
    c.drawString(50, y, f"Target: {row['target']}")
    y -= 15
    c.drawString(50, y, f"Exclude IPs: {row['exclude_ips'] or 'None'}")
    y -= 15
    c.drawString(50, y, f"Created At (UTC): {row['created_at']}")
    y -= 15
    c.drawString(50, y, f"User: {row['username']}")
    y -= 15
    c.drawString(50, y, f"Cancelled: {'Yes' if row['cancelled'] else 'No'}")
    y -= 25

    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Hosts:")
    y -= 20
    c.setFont("Helvetica", 9)

    for ip, host in results.items():
        if y < 90:
            c.showPage()
            y = height - 50
            c.setFont("Helvetica", 9)

        hostname = host.get("hostname") or "N/A"
        c.drawString(50, y, f"{ip} (Hostname: {hostname})")
        y -= 14

        # ports
        ports = host.get("ports", [])
        if not ports:
            c.drawString(70, y, "No open ports detected.")
            y -= 14
        else:
            for p in ports:
                if y < 60:
                    c.showPage()
                    y = height - 50
                    c.setFont("Helvetica", 9)

                port = p.get("port")
                service = p.get("service")
                state = p.get("state")
                banner = (p.get("banner") or "")[:80]
                c.drawString(70, y, f"Port {port}/tcp - {service} ({state}) - {banner}")
                y -= 12

        # SMB parsed findings (if any)
        findings = host.get("findings") or {}
        w = findings.get("windows_smb") if isinstance(findings, dict) else None
        if w and isinstance(w, dict):
            if y < 90:
                c.showPage()
                y = height - 50
                c.setFont("Helvetica", 9)

            c.setFont("Helvetica-Bold", 9)
            c.drawString(70, y, "Windows/SMB Findings (parsed):")
            y -= 12
            c.setFont("Helvetica", 9)

            ad = w.get("ad") or {}
            if ad:
                c.drawString(85, y, f"AD: {str(ad)[:95]}")
                y -= 12

            shares = w.get("shares") or []
            if shares:
                c.drawString(85, y, f"Shares: {len(shares)}")
                y -= 12
                for s in shares[:8]:
                    if y < 60:
                        c.showPage()
                        y = height - 50
                        c.setFont("Helvetica", 9)
                    c.drawString(100, y, f"- {s.get('share','?')} ({s.get('access','?')})")
                    y -= 11

        y -= 10

    c.showPage()
    c.save()
    buffer.seek(0)

    filename = f"scope_finder_scan_{scan_id}.pdf"
    return send_file(buffer, as_attachment=True, download_name=filename, mimetype="application/pdf")


# -----------------------
# Main
# -----------------------
if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
