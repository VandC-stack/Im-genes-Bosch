from flask import Flask, request, render_template, jsonify, send_from_directory, redirect, url_for
import os
import json
from datetime import datetime
import re

app = Flask(__name__)

CONFIG_FILE = "config.json"
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


def sanitize_filename(name: str) -> str:
    name = name.strip()
    name = re.sub(r"[^\w\-]+", "_", name)
    return name or None


def get_upload_folder():
    folder = load_config().get("destination_folder", "uploads")
    os.makedirs(folder, exist_ok=True)
    return folder


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

    for i, file in enumerate(files):
        if not file.filename or "." not in file.filename:
            continue

        ext = file.filename.rsplit(".", 1)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            continue

        base_name = None
        if i < len(custom_names):
            base_name = sanitize_filename(custom_names[i])

        if not base_name:
            base_name = datetime.now().strftime("IMG_%Y%m%d_%H%M%S_%f")

        filename = f"{base_name}.{ext}"
        file.save(os.path.join(upload_folder, filename))
        saved.append(filename)

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
