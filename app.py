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
ASSIGNMENTS_FILE = "assignments.json"
IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
ALLOWED_EXTENSIONS = IMAGE_EXTENSIONS | {
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "txt",
    "csv"
}
ROLE_CLIENTE = "cliente"
ROLE_SUPERVISOR = "supervisor"
ROLE_INSPECTOR = "inspector"
ALLOWED_ROLES = {ROLE_CLIENTE, ROLE_SUPERVISOR, ROLE_INSPECTOR}


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


def is_image_extension(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in IMAGE_EXTENSIONS


def sanitize_filename(name: str) -> str:
    name = name.strip()
    name = re.sub(r"[^\w\-]+", "_", name)
    return name or None


def get_client(username: str):
    if not username:
        return None
    return load_config().get("clients", {}).get(username)


def normalize_role(role: Optional[str]) -> str:
    if not role:
        return ROLE_CLIENTE
    normalized = role.strip().lower()
    return normalized if normalized in ALLOWED_ROLES else ROLE_CLIENTE


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


def load_assignments():
    if not os.path.exists(ASSIGNMENTS_FILE):
        return []

    try:
        with open(ASSIGNMENTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def save_assignments(data):
    with open(ASSIGNMENTS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def get_assignment(filename: str):
    assignments = load_assignments()
    return next((a for a in assignments if a.get("filename") == filename), None)


def append_history(entries):
    if not entries:
        return

    history = load_history()
    history.extend(entries)

    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2, ensure_ascii=False)


def list_images(username=None, name_filter=None, date_from=None, date_to=None, all_clients=False):
    entries = []
    
    if all_clients and username:
        # Supervisor: listar imágenes de TODOS los clientes
        config = load_config()
        for client_name, client_data in config.get("clients", {}).items():
            folder = client_data.get("folder")
            if not folder or not os.path.exists(folder):
                continue
            
            for filename in os.listdir(folder):
                if not is_allowed_extension(filename):
                    continue

                full_path = os.path.join(folder, filename)

                try:
                    stats = os.stat(full_path)
                    mtime = datetime.fromtimestamp(stats.st_mtime)
                    entries.append({
                        "name": filename,
                        "url": url_for("serve_file", filename=filename),
                        "modified": mtime,
                        "modified_iso": mtime.strftime("%Y-%m-%d %H:%M"),
                        "size": stats.st_size,
                        "ext": filename.rsplit(".", 1)[1].lower() if "." in filename else "",
                        "is_image": is_image_extension(filename),
                        "client": client_name
                    })
                except OSError:
                    continue
    else:
        # Cliente: listar solo sus propias imágenes
        folder = get_upload_folder(username)
        for filename in os.listdir(folder):
            if not is_allowed_extension(filename):
                continue

            full_path = os.path.join(folder, filename)

            try:
                stats = os.stat(full_path)
                mtime = datetime.fromtimestamp(stats.st_mtime)
                entries.append({
                    "name": filename,
                    "url": url_for("serve_file", filename=filename),
                    "modified": mtime,
                    "modified_iso": mtime.strftime("%Y-%m-%d %H:%M"),
                    "size": stats.st_size,
                    "ext": filename.rsplit(".", 1)[1].lower() if "." in filename else "",
                    "is_image": is_image_extension(filename)
                })
            except OSError:
                continue

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


def role_required(*allowed_roles):
    allowed = {normalize_role(role) for role in allowed_roles}

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            current_role = normalize_role(session.get("role"))
            if current_role not in allowed:
                abort(403)
            return view_func(*args, **kwargs)

        return wrapper

    return decorator


def is_safe_next(value: Optional[str]) -> bool:
    return bool(value) and value.startswith("/")


# =========================
# RUTAS
# =========================
@app.route("/")
def root():
    return redirect(url_for("login"))


@app.route("/index")
@login_required
def index():
    role = normalize_role(session.get("role"))
    
    # Redirigir según el rol
    if role == ROLE_SUPERVISOR:
        return redirect(url_for("solicitudes"))
    elif role == ROLE_INSPECTOR:
        return redirect(url_for("inspector_panel"))
    
    # ROLE_CLIENTE: mostrar index normal
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
        session["role"] = normalize_role(client.get("role"))
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


@app.route("/api/user-role")
@login_required
def get_user_role():
    role = normalize_role(session.get("role"))
    return jsonify({"role": role})


@app.route("/admin/ruta", methods=["GET", "POST"])
@login_required
@role_required(ROLE_SUPERVISOR)
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

    username = session.get("username")
    role = normalize_role(session.get("role"))
    
    # Supervisor: puede servir archivos de cualquier cliente
    if role == ROLE_SUPERVISOR:
        config = load_config()
        for client_name, client_data in config.get("clients", {}).items():
            folder = client_data.get("folder")
            if not folder:
                continue
            file_path = os.path.join(folder, filename)
            if os.path.exists(file_path):
                return send_from_directory(folder, filename)
    
    # Cliente/Técnico: solo puede servir sus propios archivos
    folder = get_upload_folder(username)
    return send_from_directory(folder, filename)


@app.route("/files-by-path")
@login_required
def serve_file_by_path():
    file_path = request.args.get("file_path")
    
    if not file_path or not os.path.exists(file_path):
        abort(404)
    
    if not is_allowed_extension(file_path):
        abort(404)
    
    username = session.get("username")
    role = normalize_role(session.get("role"))
    
    # Supervisor e Inspector: pueden acceder a archivos asignados
    if role == ROLE_SUPERVISOR:
        directory = os.path.dirname(file_path)
        filename = os.path.basename(file_path)
        return send_from_directory(directory, filename)
    
    if role == ROLE_INSPECTOR:
        # Verificar que el archivo esté asignado a este inspector
        assignments = load_assignments()
        assigned = any(
            a.get("file_path") == file_path and a.get("assigned_to") == username
            for a in assignments
        )
        if assigned:
            directory = os.path.dirname(file_path)
            filename = os.path.basename(file_path)
            return send_from_directory(directory, filename)
    
    abort(403)


@app.route("/gallery")
@login_required
def gallery():
    query = request.args.get("q", "").strip()
    date_from = request.args.get("from")
    date_to = request.args.get("to")

    username = session.get("username")
    role = normalize_role(session.get("role"))
    
    # Supervisor: ve todas las imágenes de todos los clientes
    all_clients = (role == ROLE_SUPERVISOR)
    images = list_images(username, query or None, date_from, date_to, all_clients=all_clients)

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


@app.route("/solicitudes")
@login_required
@role_required(ROLE_SUPERVISOR)
def solicitudes():
    page = request.args.get("page", 1, type=int)
    per_page = 12
    
    # Obtener todas las imágenes de todos los clientes para el supervisor
    config = load_config()
    all_images = []
    seen_paths = set()  # Para evitar duplicados
    
    for username, client_data in config.get("clients", {}).items():
        # Saltar supervisores, solo mostrar imágenes de clientes e inspectores
        if normalize_role(client_data.get("role")) == ROLE_SUPERVISOR:
            continue
            
        client_folder = client_data.get("folder")
        if not client_folder or not os.path.exists(client_folder):
            continue
        
        for filename in os.listdir(client_folder):
            if not is_image_extension(filename):
                continue
            
            full_path = os.path.join(client_folder, filename)
            
            # Evitar duplicados si dos usuarios comparten carpeta
            if full_path in seen_paths:
                continue
            seen_paths.add(full_path)
            
            try:
                stats = os.stat(full_path)
                mtime = datetime.fromtimestamp(stats.st_mtime)
                assignment = get_assignment(filename)
                
                all_images.append({
                    "filename": filename,
                    "client": username,
                    "folder": client_folder,
                    "url": url_for("serve_file", filename=filename),
                    "modified": mtime,
                    "modified_iso": mtime.strftime("%Y-%m-%d %H:%M"),
                    "size": stats.st_size,
                    "assigned_to": assignment.get("assigned_to") if assignment else None,
                    "status": assignment.get("status", "pending") if assignment else "pending"
                })
            except OSError:
                continue
    
    # Ordenar por fecha descendente
    all_images = sorted(all_images, key=lambda x: x["modified"], reverse=True)
    
    # Paginación
    total = len(all_images)
    start = (page - 1) * per_page
    end = start + per_page
    images_page = all_images[start:end]
    total_pages = (total + per_page - 1) // per_page
    
    # Obtener lista de inspectores
    inspectors = [u for u, data in config.get("clients", {}).items() 
                   if normalize_role(data.get("role")) == ROLE_INSPECTOR]
    
    return render_template(
        "solicitudes.html",
        images=images_page,
        page=page,
        total_pages=total_pages,
        total=total,
        per_page=per_page,
        inspectors=inspectors
    )


@app.route("/api/assign-image", methods=["POST"])
@login_required
@role_required(ROLE_SUPERVISOR)
def assign_image():
    data = request.get_json()
    filename = data.get("filename")
    inspector = data.get("inspector")
    client = data.get("client")
    folder = data.get("folder")
    
    if not filename or not inspector or not client or not folder:
        return jsonify({"error": "Datos inválidos"}), 400
    
    file_path = os.path.join(folder, filename)
    
    assignments = load_assignments()
    existing = next((a for a in assignments if a.get("file_path") == file_path), None)
    
    if existing:
        existing["assigned_to"] = inspector
        existing["assigned_at"] = datetime.utcnow().isoformat()
        existing["assigned_by"] = session.get("username")
    else:
        assignments.append({
            "filename": filename,
            "file_path": file_path,
            "client": client,
            "folder": folder,
            "assigned_to": inspector,
            "assigned_by": session.get("username"),
            "assigned_at": datetime.utcnow().isoformat(),
            "status": "pending"
        })
    
    save_assignments(assignments)
    return jsonify({"status": "ok"})


@app.route("/inspector")
@login_required
@role_required(ROLE_INSPECTOR)
def inspector_panel():
    username = session.get("username")
    assignments = load_assignments()
    
    # Filtrar solo las asignaciones de este inspector
    my_assignments = [a for a in assignments if a.get("assigned_to") == username]
    
    assigned_images = []
    
    for assignment in my_assignments:
        file_path = assignment.get("file_path")
        filename = assignment.get("filename")
        client = assignment.get("client")
        folder = assignment.get("folder")
        
        if not file_path or not os.path.exists(file_path):
            continue
        
        try:
            stats = os.stat(file_path)
            mtime = datetime.fromtimestamp(stats.st_mtime)
            
            assigned_images.append({
                "filename": filename,
                "client": client,
                "folder": folder,
                "file_path": file_path,
                "url": url_for("serve_file_by_path", file_path=file_path),
                "modified": mtime,
                "modified_iso": mtime.strftime("%Y-%m-%d %H:%M"),
                "size": stats.st_size,
                "assigned_at": assignment.get("assigned_at"),
                "assigned_by": assignment.get("assigned_by"),
                "status": assignment.get("status", "pending"),
                "is_image": is_image_extension(filename),
                "ext": filename.rsplit(".", 1)[1].lower() if "." in filename else ""
            })
        except OSError:
            continue
    
    # Ordenar por fecha de asignación descendente
    assigned_images = sorted(assigned_images, key=lambda x: x.get("assigned_at", ""), reverse=True)
    
    return render_template(
        "inspector.html",
        images=assigned_images,
        total=len(assigned_images),
        username=username
    )


@app.route("/admin")
@login_required
@role_required(ROLE_SUPERVISOR)
def admin_users():
    config = load_config()
    clients = config.get("clients", {})
    
    users_list = []
    for username, data in clients.items():
        users_list.append({
            "username": username,
            "role": data.get("role", "Cliente"),
            "folder": data.get("folder", "")
        })
    
    return render_template("admin.html", users=users_list)


@app.route("/api/create-user", methods=["POST"])
@login_required
@role_required(ROLE_SUPERVISOR)
def create_user():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role = data.get("role", "Cliente")
    folder = data.get("folder", "").strip()
    
    if not username or not password or not folder:
        return jsonify({"error": "Todos los campos son requeridos"}), 400
    
    config = load_config()
    
    if username in config.get("clients", {}):
        return jsonify({"error": "El usuario ya existe"}), 400
    
    config["clients"][username] = {
        "password": password,
        "folder": folder,
        "role": role
    }
    
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4)
    
    return jsonify({"status": "ok"})


@app.route("/api/delete-user", methods=["POST"])
@login_required
@role_required(ROLE_SUPERVISOR)
def delete_user():
    data = request.get_json()
    username = data.get("username", "").strip()
    
    if not username:
        return jsonify({"error": "Usuario requerido"}), 400
    
    # No permitir eliminar al propio supervisor
    if username == session.get("username"):
        return jsonify({"error": "No puedes eliminarte a ti mismo"}), 400
    
    config = load_config()
    
    if username not in config.get("clients", {}):
        return jsonify({"error": "Usuario no encontrado"}), 404
    
    del config["clients"][username]
    
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4)
    
    return jsonify({"status": "ok"})


# =========================
# MAIN
# =========================
if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        threaded=True
    )
