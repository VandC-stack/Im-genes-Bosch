from flask import Flask, request, render_template, jsonify, send_from_directory, redirect, url_for, abort
import os
import json
from datetime import datetime
import re

app = Flask(__name__)

CONFIG_FILE = "config.json"
HISTORY_FILE = "upload_history.json"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}


# =========================
# CONFIGURACIÓN
# =========================
def load_config():
    if not os.path.exists(CONFIG_FILE):
        return {"destination_folder": "uploads"}
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_config(path):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump({"destination_folder": path}, f, indent=4)


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


def get_upload_folder():
    folder = load_config().get("destination_folder", "uploads")
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


def list_images(name_filter=None, date_from=None, date_to=None):
    folder = get_upload_folder()
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


# =========================
# RUTAS
# =========================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No se enviaron archivos"}), 400

    files = request.files.getlist("file")
    custom_names = request.form.getlist("custom_name")

    upload_folder = get_upload_folder()
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
            "url": url_for("serve_file", filename=filename)
        })

    append_history(history_entries)

    return jsonify({
        "status": "ok",
        "archivos": saved,
        "ruta": upload_folder
    })


@app.route("/admin/ruta", methods=["GET", "POST"])
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
def serve_file(filename):
    if not is_allowed_extension(filename):
        abort(404)

    folder = get_upload_folder()
    return send_from_directory(folder, filename)


@app.route("/gallery")
def gallery():
    query = request.args.get("q", "").strip()
    date_from = request.args.get("from")
    date_to = request.args.get("to")

    images = list_images(query or None, date_from, date_to)

    history = sorted(
        load_history(),
        key=lambda x: x.get("uploaded_at", ""),
        reverse=True
    )[:100]

    return render_template(
        "gallery.html",
        images=images,
        query=query,
        date_from=date_from,
        date_to=date_to,
        history=history,
        current_folder=get_upload_folder()
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
        port=5000,
        debug=False,
        threaded=True
    )
