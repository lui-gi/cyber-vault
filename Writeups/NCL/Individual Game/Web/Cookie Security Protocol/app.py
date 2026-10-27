import os
import secrets
from functools import wraps
from flask import (
    Flask,
    Response,
    abort,
    g,
    render_template,
    request,
    session,
    url_for,
)

ADMIN_USERNAME = "admin"
ADMIN_PW = os.environ.get("ADMINPW")
FLAG = os.environ.get("APPFLAG")

app = Flask(__name__, template_folder="views")
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="None",
    SESSION_COOKIE_SECURE=True,
)

users = {}
comments = {}

def create_user(username, password, role="user"):
    users[username] = {"password": password, "role": role}


def check_password(username, password):
    record = users.get(username)
    return bool(record) and secrets.compare_digest(record["password"], password)


def is_admin(username):
    record = users.get(username)
    return bool(record) and record["role"] == "admin"

@app.before_request
def init_security():
    g.csp_nonce = secrets.token_urlsafe(16)
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)


@app.before_request
def csrf_protect():
    if request.method == "POST":
        expected = session.get("csrf_token")
        provided = request.form.get("csrf_token", "")
        if not expected or not secrets.compare_digest(expected, provided):
            abort(400, "CSRF validation failed")


@app.context_processor
def inject_security():
    user = session.get("user")
    return {
        "csrf_token": session.get("csrf_token", ""),
        "csp_nonce": g.get("csp_nonce", ""),
        "user": user,
        "is_admin": is_admin(user) if user else False,
    }


@app.after_request
def set_security_headers(resp):
    nonce = g.get("csp_nonce", "")
    resp.headers["Content-Security-Policy"] = (
        "base-uri 'none'; "
        "child-src 'none'; "
        "connect-src 'none'; "
        "default-src 'none'; "
        "fenced-frame-src 'none'; "
        "font-src 'none'; "
        "form-action 'self'; "
        "frame-src 'none'; "
        "img-src 'none'; "
        "manifest-src 'none'; "
        "media-src 'none'; "
        "navigate-to 'none'; "
        "object-src 'none'; "
        "prefetch-src 'none'; "
        f"script-src 'nonce-{nonce}'; "
        f"script-src-attr 'none'; "
        f"script-src-elem 'nonce-{nonce}'; "
        f"style-src 'nonce-{nonce}'; "
        f"style-src-attr 'none'; "
        f"style-src-elem 'nonce-{nonce}'; "
        "trusted-types 'none'; "
        "worker-src 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


def redirect(location):
    resp = Response(status=302)
    resp.headers["Location"] = location
    return resp


def is_safe_next(target):
    return bool(target) and target.startswith("/")


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = session.get("user")
        if not user:
            # Not logged in: send to login, returning here afterwards.
            return redirect(url_for("login", next=request.path))
        if not is_admin(user):
            abort(403)
        return view(*args, **kwargs)

    return wrapped


@app.route("/")
def index():
    return render_template("index.html", user=session.get("user"))


@app.route("/register", methods=["GET", "POST"])
def register():
    next_url = request.args.get("next", "")
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username in users:
            error = "User already exists."
        else:
            create_user(username, password)
            session["user"] = username
            if is_safe_next(next_url):
                return redirect(next_url)
            return redirect(url_for("index"))
    return render_template("register.html", error=error, next=next_url)


@app.route("/login", methods=["GET", "POST"])
def login():
    next_url = request.args.get("next", "")
    error = None
    if request.method == "GET" and session.get("user") and is_safe_next(next_url):
        return redirect(next_url)
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if check_password(username, password):
            session["user"] = username
            if is_safe_next(next_url):
                return redirect(next_url)
            return redirect(url_for("index"))
        error = "Invalid credentials."
    return render_template("login.html", error=error, next=next_url)


@app.route("/board", methods=["GET", "POST"])
def board():
    user = session.get("user")
    if request.method == "POST":
        if not user:
            return redirect(url_for("login", next=url_for("board")))
        comments[user] = request.form["comment"]
        return redirect(url_for("board"))
    return render_template(
        "board.html",
        user=user,
        comments=comments,
        my_comment=comments.get(user, ""),
    )


@app.route("/admin")
@admin_required
def admin():
    return render_template("admin.html", users=users, flag=FLAG)


@app.route("/admin/promote", methods=["POST"])
@admin_required
def promote():
    username = request.form.get("username", "")
    if username not in users:
        abort(404)
    users[username]["role"] = "admin"
    return redirect(url_for("admin"))


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))

create_user(
    ADMIN_USERNAME,
    ADMIN_PW,
    role="admin",
)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False, ssl_context="adhoc")
