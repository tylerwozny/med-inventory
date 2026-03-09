import json
import logging
import os
import re
from datetime import date, datetime, timezone
from functools import wraps
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from cryptography.fernet import Fernet
from flask import (Flask, abort, flash, redirect, render_template,
                   request, session, url_for)
from flask_login import (LoginManager, UserMixin, current_user,
                         login_required, login_user, logout_user)
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# App configuration
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("DEV_MODE") != "true"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 1800  # 30 minutes
app.config["DEBUG"] = False

ENCRYPTION_KEY = os.environ["ENCRYPTION_KEY"].encode()
fernet = Fernet(ENCRYPTION_KEY)

BASE_DIR = Path(__file__).parent
DATA_FILE = BASE_DIR / "data.json"
USERS_FILE = BASE_DIR / "users.json"
AUDIT_LOG = BASE_DIR / "audit.log"

CONCENTRATIONS = [10, 20, 30, 40]
SESSION_TIMEOUT = 1800  # seconds

# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

_audit_logger = logging.getLogger("hipaa_audit")
_audit_logger.setLevel(logging.INFO)
_audit_handler = logging.FileHandler(AUDIT_LOG, mode="a", encoding="utf-8")
_audit_handler.setFormatter(logging.Formatter("%(message)s"))
_audit_logger.addHandler(_audit_handler)


def audit_log(action, detail=""):
    user = current_user.username if current_user.is_authenticated else "anonymous"
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    timestamp = datetime.now(timezone.utc).isoformat()
    _audit_logger.info(f"{timestamp} | {user} | {action} | {detail} | {ip}")


# ---------------------------------------------------------------------------
# Encrypted data helpers
# ---------------------------------------------------------------------------

def load_data():
    if not DATA_FILE.exists():
        return {"inventory": [], "records": []}
    return json.loads(fernet.decrypt(DATA_FILE.read_bytes()))


def save_data(data):
    DATA_FILE.write_bytes(fernet.encrypt(json.dumps(data, indent=2).encode()))


def load_users():
    if not USERS_FILE.exists():
        return []
    return json.loads(fernet.decrypt(USERS_FILE.read_bytes()))


def save_users(users):
    USERS_FILE.write_bytes(fernet.encrypt(json.dumps(users, indent=2).encode()))


# ---------------------------------------------------------------------------
# Flask-Login
# ---------------------------------------------------------------------------

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this application."
login_manager.session_protection = "strong"


class User(UserMixin):
    def __init__(self, username, role, active=True):
        self.id = username
        self.username = username
        self.role = role
        self._active = active

    def get_id(self):
        return self.username

    @property
    def is_active(self):
        return self._active


@login_manager.user_loader
def load_user(username):
    for u in load_users():
        if u["username"] == username:
            return User(u["username"], u["role"], u.get("active", True))
    return None


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def check_session_timeout(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if current_user.is_authenticated:
            last_active = session.get("last_active")
            now = datetime.now(timezone.utc).timestamp()
            if last_active and (now - last_active) > SESSION_TIMEOUT:
                audit_log("SESSION_TIMEOUT", f"user={current_user.username}")
                logout_user()
                session.clear()
                flash("Your session expired. Please log in again.", "warning")
                return redirect(url_for("login"))
            session["last_active"] = now
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            audit_log("UNAUTHORIZED_ACCESS", f"route={request.path}")
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Password validation
# ---------------------------------------------------------------------------

def validate_password(password):
    errors = []
    if len(password) < 12:
        errors.append("Minimum 12 characters required.")
    if not re.search(r"[A-Z]", password):
        errors.append("Must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        errors.append("Must contain at least one lowercase letter.")
    if not re.search(r"\d", password):
        errors.append("Must contain at least one digit.")
    if not re.search(r'[!@#$%^&*()\-_,.?\":{}|<>]', password):
        errors.append("Must contain at least one special character.")
    return errors


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user_data = next((u for u in load_users() if u["username"] == username), None)
        if user_data and user_data.get("active", True) and \
                check_password_hash(user_data["password_hash"], password):
            user = User(user_data["username"], user_data["role"], user_data.get("active", True))
            login_user(user)
            session["last_active"] = datetime.now(timezone.utc).timestamp()
            session.permanent = True
            audit_log("LOGIN_SUCCESS", f"user={username}")
            return redirect(url_for("index"))
        audit_log("LOGIN_FAILURE", f"attempted_user={username}")
        flash("Invalid username or password.", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    audit_log("LOGOUT", f"user={current_user.username}")
    logout_user()
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Main app routes
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
@check_session_timeout
def index():
    data = load_data()
    audit_log("INVENTORY_VIEW")
    return render_template(
        "index.html",
        inventory=data["inventory"],
        records=data["records"],
        concentrations=CONCENTRATIONS,
    )


@app.route("/inventory/add", methods=["POST"])
@login_required
@check_session_timeout
def add_inventory():
    data = load_data()
    lot = request.form["lot_number"].strip()
    concentration = int(request.form["concentration"])
    quantity = int(request.form["quantity"])

    if not lot:
        return redirect(url_for("index"))

    for entry in data["inventory"]:
        if entry["lot_number"] == lot and entry["concentration"] == concentration:
            entry["quantity"] += quantity
            save_data(data)
            audit_log("INVENTORY_ADD", f"lot={lot} concentration={concentration}mg qty={quantity} (added to existing)")
            return redirect(url_for("index"))

    data["inventory"].append({
        "lot_number": lot,
        "concentration": concentration,
        "quantity": quantity,
        "date_received": str(date.today()),
    })
    save_data(data)
    audit_log("INVENTORY_ADD", f"lot={lot} concentration={concentration}mg qty={quantity}")
    return redirect(url_for("index"))


@app.route("/inventory/delete", methods=["POST"])
@login_required
@check_session_timeout
def delete_inventory():
    data = load_data()
    lot = request.form["lot_number"]
    concentration = int(request.form["concentration"])
    data["inventory"] = [
        e for e in data["inventory"]
        if not (e["lot_number"] == lot and e["concentration"] == concentration)
    ]
    save_data(data)
    audit_log("INVENTORY_DELETE", f"lot={lot} concentration={concentration}mg")
    return redirect(url_for("index"))


@app.route("/dispense", methods=["POST"])
@login_required
@check_session_timeout
def dispense():
    data = load_data()
    patient = request.form["patient_name"].strip()
    lot = request.form["lot_number"].strip()
    concentration = int(request.form["concentration"])
    quantity = int(request.form["quantity"])

    if not patient or not lot:
        return redirect(url_for("index"))

    for entry in data["inventory"]:
        if entry["lot_number"] == lot and entry["concentration"] == concentration:
            entry["quantity"] = max(0, entry["quantity"] - quantity)
            break

    data["records"].append({
        "patient_name": patient,
        "lot_number": lot,
        "concentration": concentration,
        "quantity": quantity,
        "date": str(date.today()),
    })
    save_data(data)
    audit_log("DISPENSE", f"patient={patient} lot={lot} concentration={concentration}mg qty={quantity}")
    return redirect(url_for("index"))


@app.route("/patient/<path:name>")
@login_required
@check_session_timeout
def patient_lookup(name):
    data = load_data()
    audit_log("PATIENT_LOOKUP", f"patient={name}")
    records = [r for r in data["records"] if r["patient_name"].lower() == name.lower()]
    from flask import jsonify
    return jsonify(records)


@app.route("/record/delete", methods=["POST"])
@login_required
@check_session_timeout
def delete_record():
    data = load_data()
    idx = int(request.form["index"])
    detail = ""
    if 0 <= idx < len(data["records"]):
        r = data["records"][idx]
        detail = f"patient={r['patient_name']} lot={r['lot_number']} date={r['date']}"
        data["records"].pop(idx)
    save_data(data)
    audit_log("RECORD_DELETE", detail)
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------

@app.route("/admin/users")
@login_required
@check_session_timeout
@admin_required
def admin_users():
    users = load_users()
    safe_users = [{"username": u["username"], "role": u["role"],
                   "active": u.get("active", True)} for u in users]
    return render_template("admin.html", users=safe_users, tab="users")


@app.route("/admin/users/create", methods=["POST"])
@login_required
@check_session_timeout
@admin_required
def create_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "staff")

    errors = validate_password(password)
    if errors:
        flash(" ".join(errors), "danger")
        return redirect(url_for("admin_users"))

    users = load_users()
    if any(u["username"] == username for u in users):
        flash("Username already exists.", "danger")
        return redirect(url_for("admin_users"))

    users.append({
        "username": username,
        "password_hash": generate_password_hash(password, method="pbkdf2:sha256"),
        "role": role,
        "active": True,
    })
    save_users(users)
    audit_log("USER_CREATE", f"new_user={username} role={role}")
    flash(f"User '{username}' created.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/delete", methods=["POST"])
@login_required
@check_session_timeout
@admin_required
def delete_user():
    username = request.form.get("username", "")
    if username == current_user.username:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("admin_users"))
    users = load_users()
    remaining_admins = [u for u in users if u["role"] == "admin" and u["username"] != username]
    if not remaining_admins:
        flash("Cannot delete the last admin account.", "danger")
        return redirect(url_for("admin_users"))
    users = [u for u in users if u["username"] != username]
    save_users(users)
    audit_log("USER_DELETE", f"deleted_user={username}")
    flash(f"User '{username}' deleted.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/audit")
@login_required
@check_session_timeout
@admin_required
def admin_audit():
    audit_log("AUDIT_LOG_VIEW", "admin viewed audit log")
    lines = []
    if AUDIT_LOG.exists():
        with open(AUDIT_LOG, "r", encoding="utf-8") as f:
            lines = f.readlines()
    lines = list(reversed(lines[-500:]))
    parsed = []
    for line in lines:
        parts = [p.strip() for p in line.strip().split(" | ")]
        if len(parts) == 5:
            parsed.append({
                "timestamp": parts[0],
                "user": parts[1],
                "action": parts[2],
                "detail": parts[3],
                "ip": parts[4],
            })
    return render_template("admin.html", audit_lines=parsed, tab="audit")


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(403)
def forbidden(e):
    return render_template("login.html", error="You do not have permission to access that page."), 403


if __name__ == "__main__":
    app.run(debug=False, port=5050)
