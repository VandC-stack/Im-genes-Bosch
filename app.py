from flask import Flask, request, render_template, jsonify, send_from_directory
import os
import json
from datetime import datetime

app = Flask(__name__)

CONFIG_FILE = "config.json"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}


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
    upload_folder = get_upload_folder()
    saved = []

    for file in files:
        if not file.filename:
            continue

        ext = file.filename.rsplit(".", 1)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            continue

        ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filename = f"IMG_{ts}.{ext}"
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
        new_path = request.form.get("nueva_ruta")

        if not new_path:
            return "Ruta inválida", 400

        os.makedirs(new_path, exist_ok=True)
        save_config(new_path)
        return "Ruta guardada correctamente"

    current_folder = load_config().get("destination_folder", "uploads")
    return render_template("admin_ruta.html", current_folder=current_folder)


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, "static"),
        "favicon.ico",
        mimetype="image/vnd.microsoft.icon"
    )