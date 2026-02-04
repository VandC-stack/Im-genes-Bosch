from flask import Flask, request, render_template, jsonify, send_from_directory, redirect, url_for, abort, session
import os
import json
from datetime import datetime
import re
import hmac
from functools import wraps
from werkzeug.security import check_password_hash
from typing import Optional

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY", "change-me")

CONFIG_FILE = "config.json"
HISTORY_FILE = "upload_history.json"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}


# =========================
# CONFIGURACIÓN
# =========================
def load_config():
    if not os.path.exists(CONFIG_FILE):
        return {"destination_folder": "uploads", "clients": {}}
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        return {"destination_folder": "uploads", "clients": {}}

    data.setdefault("destination_folder", "uploads")
    data.setdefault("clients", {})
    return data


def save_config(path):
    data = load_config()
    data["destination_folder"] = path
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def sanitize_path(path: str) -> str:
    if not path:
        return ""

    path = path.strip()

    if (path.startswith('"') and path.endswith('"')) or \
       (path.startswith("'") and path.endswith("'")):
        path = path[1:-1]

    return path.strip()


def is_allowed_extension(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def sanitize_filename(name: str) -> str:
    name = name.strip()
    name = re.sub(r"[^\w\-]+", "_", name)
    return name or None


def get_client(username: str):
    if not username:
        return None
    return load_config().get("clients", {}).get(username)


def verify_password(stored: str, provided: str) -> bool:
    if not stored:
        return False
    if stored.startswith("pbkdf2:") or stored.startswith("scrypt:") or stored.startswith("argon2:"):
        return check_password_hash(stored, provided)
    return hmac.compare_digest(stored, provided)


def get_upload_folder(username: Optional[str] = None):
    config = load_config()
    folder = None
    if username:
        client = get_client(username)
        if client:
            folder = client.get("folder")

    if not folder:
        folder = config.get("destination_folder", "uploads")

    os.makedirs(folder, exist_ok=True)
    return folder


def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []

    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def append_history(entries):
    if not entries:
        return

    history = load_history()
    history.extend(entries)

    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2, ensure_ascii=False)


def list_images(username=None, name_filter=None, date_from=None, date_to=None):
    folder = get_upload_folder(username)
    entries = []

    for filename in os.listdir(folder):
        if not is_allowed_extension(filename):
            continue

        full_path = os.path.join(folder, filename)

        try:
            stats = os.stat(full_path)
            mtime = datetime.fromtimestamp(stats.st_mtime)
        except OSError:
            continue

        entries.append({
            "name": filename,
            "url": url_for("serve_file", filename=filename),
            "modified": mtime,
            "modified_iso": mtime.strftime("%Y-%m-%d %H:%M"),
            "size": stats.st_size
        })

    if name_filter:
        lowered = name_filter.lower()
        entries = [e for e in entries if lowered in e["name"].lower()]

    def parse_date(value):
        if not value:
            return None
        try:
            return datetime.strptime(value, "%Y-%m-%d")
        except ValueError:
            return None

    start = parse_date(date_from)
    end = parse_date(date_to)

    if start:
        entries = [e for e in entries if e["modified"].date() >= start.date()]
    if end:
        entries = [e for e in entries if e["modified"].date() <= end.date()]

    return sorted(entries, key=lambda x: x["modified"], reverse=True)


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get("username"):
            if request.path == "/upload":
                return jsonify({"error": "No autorizado"}), 401
            next_url = request.path
            return redirect(url_for("login", next=next_url))
        return view_func(*args, **kwargs)

    return wrapper


def is_safe_next(value: Optional[str]) -> bool:
    return bool(value) and value.startswith("/")


# =========================
# RUTAS
# =========================
@app.route("/")
@login_required
def index():
    return render_template("index.html", username=session.get("username"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        next_url = request.form.get("next") or request.args.get("next")

        client = get_client(username)
        if not client or not verify_password(client.get("password", ""), password):
            return render_template(
                "login.html",
                error="Usuario o contraseña inválidos",
                next=next_url
            )

        session["username"] = username
        if not is_safe_next(next_url):
            next_url = url_for("index")
        return redirect(next_url)

    return render_template("login.html", error=None, next=request.args.get("next", ""))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No se enviaron archivos"}), 400

    files = request.files.getlist("file")
    custom_names = request.form.getlist("custom_name")

    username = session.get("username")
    upload_folder = get_upload_folder(username)
    saved = []
    history_entries = []

    for i, file in enumerate(files):
        if not file.filename or not is_allowed_extension(file.filename):
            continue

        ext = file.filename.rsplit(".", 1)[1].lower()

        base_name = None
        if i < len(custom_names):
            base_name = sanitize_filename(custom_names[i])

        if not base_name:
            base_name = datetime.now().strftime("IMG_%Y%m%d_%H%M%S_%f")

        filename = f"{base_name}.{ext}"
        file.save(os.path.join(upload_folder, filename))
        saved.append(filename)

        history_entries.append({
            "filename": filename,
            "original_name": file.filename,
            "folder": upload_folder,
            "uploaded_at": datetime.utcnow().isoformat(),
            "url": url_for("serve_file", filename=filename),
            "username": username
        })

    append_history(history_entries)

    return jsonify({
        "status": "ok",
        "archivos": saved,
        "ruta": upload_folder
    })


@app.route("/admin/ruta", methods=["GET", "POST"])
@login_required
def admin_ruta():
    if request.method == "POST":
        raw_path = request.form.get("nueva_ruta", "")
        new_path = sanitize_path(raw_path)

        if not new_path:
            return "Ruta inválida", 400

        try:
            os.makedirs(new_path, exist_ok=True)
        except OSError as e:
            return f"Error al crear la ruta: {e}", 400

        save_config(new_path)

        # 🔁 REDIRECCIÓN (evita pantalla en blanco)
        return redirect(url_for("admin_ruta"))

    current_folder = load_config().get("destination_folder", "uploads")
    return render_template("admin_ruta.html", current_folder=current_folder)


@app.route("/files/<path:filename>")
@login_required
def serve_file(filename):
    if not is_allowed_extension(filename):
        abort(404)

    folder = get_upload_folder(session.get("username"))
    return send_from_directory(folder, filename)


@app.route("/gallery")
@login_required
def gallery():
    query = request.args.get("q", "").strip()
    date_from = request.args.get("from")
    date_to = request.args.get("to")

    username = session.get("username")
    images = list_images(username, query or None, date_from, date_to)

    history = [
        entry for entry in load_history()
        if entry.get("username") == username
    ]
    history = sorted(history, key=lambda x: x.get("uploaded_at", ""), reverse=True)[:100]

    return render_template(
        "gallery.html",
        images=images,
        query=query,
        date_from=date_from,
        date_to=date_to,
        history=history,
        current_folder=get_upload_folder(username)
    )


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, "static"),
        "favicon.ico",
        mimetype="image/vnd.microsoft.icon"
    )


# =========================
# MAIN
# =========================
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=8000,
        debug=False,
        threaded=True
    )
