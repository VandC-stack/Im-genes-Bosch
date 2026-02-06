from flask import Flask, request, render_template, jsonify, send_from_directory, redirect, url_for, abort, session, send_file
import os
import json
from datetime import datetime, timezone
import re
import secrets
import hmac
import base64
import binascii
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

STATUS_UPLOADED = "subido"
STATUS_ASSIGNED = "asignado"
STATUS_IN_REVIEW = "en_revision"
STATUS_ACCEPTED = "aceptado"
STATUS_REJECTED = "rechazado"
VALID_STATUSES = {
    STATUS_UPLOADED,
    STATUS_ASSIGNED,
    STATUS_IN_REVIEW,
    STATUS_ACCEPTED,
    STATUS_REJECTED
}


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
            data = json.load(f)
            if not isinstance(data, list):
                return []

            changed = ensure_assignment_fields(data)
            if changed:
                save_assignments(data)
            return data
    except (json.JSONDecodeError, OSError):
        return []


def save_assignments(data):
    with open(ASSIGNMENTS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# =========================
# JINJA2 FILTERS
# =========================
def datetime_format(value, format_str="%d/%m/%Y %H:%M"):
    """Formatea un string ISO datetime a un formato específico"""
    if not value:
        return ""
    try:
        # Si es un string ISO 8601, convertir a datetime
        if isinstance(value, str):
            # Manejar formato ISO con 'T' o espacio
            if 'T' in value:
                dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
            else:
                dt = datetime.fromisoformat(value)
        else:
            dt = value
        return dt.strftime(format_str)
    except (ValueError, AttributeError):
        return str(value)


app.jinja_env.filters['datetime_format'] = datetime_format


def normalize_status(value: Optional[str], assigned_to: Optional[str] = None) -> str:
    if not value:
        return STATUS_ASSIGNED if assigned_to else STATUS_UPLOADED

    normalized = value.strip().lower()

    if normalized == "pending":
        return STATUS_ASSIGNED if assigned_to else STATUS_UPLOADED
    if normalized == "accepted":
        return STATUS_ACCEPTED
    if normalized == "rejected":
        return STATUS_REJECTED

    if normalized in VALID_STATUSES:
        return normalized

    return STATUS_ASSIGNED if assigned_to else STATUS_UPLOADED


def generate_folio(existing_folios: set) -> str:
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    while True:
        suffix = f"{secrets.randbelow(10000):04d}"
        folio = f"FOL-{date_str}-{suffix}"
        if folio not in existing_folios:
            return folio


def ensure_assignment_fields(assignments: list) -> bool:
    changed = False
    existing_folios = {a.get("folio") for a in assignments if a.get("folio")}

    for assignment in assignments:
        normalized_status = normalize_status(
            assignment.get("status"),
            assignment.get("assigned_to")
        )
        if assignment.get("status") != normalized_status:
            assignment["status"] = normalized_status
            changed = True

        if not assignment.get("folio"):
            folio = generate_folio(existing_folios)
            assignment["folio"] = folio
            existing_folios.add(folio)
            changed = True

    return changed


def get_assignment_by_path(file_path: str):
    if not file_path:
        return None
    assignments = load_assignments()
    return next((a for a in assignments if a.get("file_path") == file_path), None)


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
    assignments = load_assignments()
    assignments_by_path = {
        a.get("file_path"): a for a in assignments if a.get("file_path")
    }
    existing_folios = {a.get("folio") for a in assignments if a.get("folio")}
    assignments_changed = False
    
    if all_clients and username:
        # Supervisor: listar imágenes de TODOS los clientes
        config = load_config()
        for client_name, client_data in config.get("clients", {}).items():
            folder = client_data.get("folder")
            if not folder or not os.path.exists(folder):
                continue
            
            try:
                folder_contents = os.listdir(folder)
            except OSError:
                continue
            
            for filename in folder_contents:
                if not is_allowed_extension(filename):
                    continue

                full_path = os.path.join(folder, filename)

                try:
                    stats = os.stat(full_path)
                    mtime = datetime.fromtimestamp(stats.st_mtime)
                    assignment = assignments_by_path.get(full_path)
                    if not assignment:
                        folio = generate_folio(existing_folios)
                        existing_folios.add(folio)
                        assignment = {
                            "filename": filename,
                            "file_path": full_path,
                            "client": client_name,
                            "folder": folder,
                            "assigned_to": None,
                            "assigned_by": None,
                            "assigned_at": None,
                            "status": STATUS_UPLOADED,
                            "folio": folio,
                            "uploaded_at": datetime.now(timezone.utc).isoformat(),
                            "comments": []
                        }
                        assignments.append(assignment)
                        assignments_by_path[full_path] = assignment
                        assignments_changed = True

                    status = normalize_status(
                        assignment.get("status") if assignment else None,
                        assignment.get("assigned_to") if assignment else None
                    )
                    entries.append({
                        "name": filename,
                        "url": url_for("serve_file_by_path", file_path=full_path),
                        "modified": mtime,
                        "modified_iso": mtime.strftime("%Y-%m-%d %H:%M"),
                        "size": stats.st_size,
                        "ext": filename.rsplit(".", 1)[1].lower() if "." in filename else "",
                        "is_image": is_image_extension(filename),
                        "client": client_name,
                        "file_path": full_path,
                        "status": status,
                        "folio": assignment.get("folio") if assignment else None
                    })
                except OSError:
                    continue
    else:
        # Cliente: listar solo sus propias imágenes
        folder = get_upload_folder(username)
        seen_paths = set()

        client_assignments = [
            a for a in assignments
            if a.get("client") == username and a.get("file_path")
        ]

        for assignment in client_assignments:
            full_path = assignment.get("file_path")
            if not full_path or not os.path.exists(full_path):
                continue
            if not is_allowed_extension(full_path):
                continue

            try:
                stats = os.stat(full_path)
                mtime = datetime.fromtimestamp(stats.st_mtime)
                filename = assignment.get("filename") or os.path.basename(full_path)
                status = normalize_status(
                    assignment.get("status") if assignment else None,
                    assignment.get("assigned_to") if assignment else None
                )
                entries.append({
                    "name": filename,
                    "url": url_for("serve_file_by_path", file_path=full_path),
                    "modified": mtime,
                    "modified_iso": mtime.strftime("%Y-%m-%d %H:%M"),
                    "size": stats.st_size,
                    "ext": filename.rsplit(".", 1)[1].lower() if "." in filename else "",
                    "is_image": is_image_extension(filename),
                    "file_path": full_path,
                    "status": status,
                    "folio": assignment.get("folio") if assignment else None
                })
                seen_paths.add(full_path)
            except OSError:
                continue

        try:
            folder_contents = os.listdir(folder)
        except OSError:
            folder_contents = []

        for filename in folder_contents:
            if not is_allowed_extension(filename):
                continue

            full_path = os.path.join(folder, filename)
            if full_path in seen_paths:
                continue

            try:
                stats = os.stat(full_path)
                mtime = datetime.fromtimestamp(stats.st_mtime)
                assignment = assignments_by_path.get(full_path)
                if not assignment:
                    folio = generate_folio(existing_folios)
                    existing_folios.add(folio)
                    assignment = {
                        "filename": filename,
                        "file_path": full_path,
                        "client": username,
                        "folder": folder,
                        "assigned_to": None,
                        "assigned_by": None,
                        "assigned_at": None,
                        "status": STATUS_UPLOADED,
                        "folio": folio,
                        "uploaded_at": datetime.now(timezone.utc).isoformat(),
                        "comments": []
                    }
                    assignments.append(assignment)
                    assignments_by_path[full_path] = assignment
                    assignments_changed = True

                status = normalize_status(
                    assignment.get("status") if assignment else None,
                    assignment.get("assigned_to") if assignment else None
                )
                entries.append({
                    "name": filename,
                    "url": url_for("serve_file_by_path", file_path=full_path),
                    "modified": mtime,
                    "modified_iso": mtime.strftime("%Y-%m-%d %H:%M"),
                    "size": stats.st_size,
                    "ext": filename.rsplit(".", 1)[1].lower() if "." in filename else "",
                    "is_image": is_image_extension(filename),
                    "file_path": full_path,
                    "status": status,
                    "folio": assignment.get("folio") if assignment else None
                })
            except OSError:
                continue

    if assignments_changed:
        save_assignments(assignments)

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


# Prevenir caché de páginas protegidas
@app.after_request
def add_no_cache_headers(response):
    """Añade headers para prevenir caché en navegadores"""
    if 'Cache-Control' not in response.headers:
        # No cachear páginas HTML para prevenir acceso después de logout
        if response.content_type and 'text/html' in response.content_type:
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, private'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
    return response


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
    assignments = load_assignments()
    existing_folios = {a.get("folio") for a in assignments if a.get("folio")}
    assignments_changed = False

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
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)
        saved.append(filename)

        history_entries.append({
            "filename": filename,
            "original_name": file.filename,
            "folder": upload_folder,
            "uploaded_at": datetime.now(timezone.utc).isoformat(),
            "url": url_for("serve_file", filename=filename),
            "username": username
        })

        assignment = next(
            (a for a in assignments if a.get("file_path") == file_path),
            None
        )
        if assignment:
            assignment["filename"] = filename
            assignment["client"] = username
            assignment["folder"] = upload_folder
            assignment["status"] = STATUS_UPLOADED
            assignment["uploaded_at"] = datetime.now(timezone.utc).isoformat()
        else:
            folio = generate_folio(existing_folios)
            existing_folios.add(folio)
            assignments.append({
                "filename": filename,
                "file_path": file_path,
                "client": username,
                "folder": upload_folder,
                "assigned_to": None,
                "assigned_by": None,
                "assigned_at": None,
                "status": STATUS_UPLOADED,
                "folio": folio,
                "uploaded_at": datetime.now(timezone.utc).isoformat(),
                "comments": []
            })
        assignments_changed = True

    append_history(history_entries)

    if assignments_changed:
        save_assignments(assignments)

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
        return send_from_directory(directory, filename, max_age=0)
    
    if role == ROLE_INSPECTOR:
        # Verificar que el archivo esté asignado a este inspector
        assignments = load_assignments()
        assignment = next(
            (a for a in assignments if a.get("file_path") == file_path and a.get("assigned_to") == username),
            None
        )
        if assignment:
            current_status = normalize_status(assignment.get("status"), assignment.get("assigned_to"))
            if current_status in {STATUS_ASSIGNED, STATUS_UPLOADED}:
                assignment["status"] = STATUS_IN_REVIEW
                assignment["status_updated_at"] = datetime.now(timezone.utc).isoformat()
                assignment["status_updated_by"] = username
                save_assignments(assignments)
            directory = os.path.dirname(file_path)
            filename = os.path.basename(file_path)
            return send_from_directory(directory, filename, max_age=0)
    
    # Cliente: puede acceder a archivos asignados a él
    if role == ROLE_CLIENTE:
        assignments = load_assignments()
        assigned = any(
            a.get("file_path") == file_path and a.get("client") == username
            for a in assignments
        )
        if assigned:
            directory = os.path.dirname(file_path)
            filename = os.path.basename(file_path)
            return send_from_directory(directory, filename, max_age=0)
    
    abort(403)


def can_access_file_path(file_path: str, role: str, username: str) -> bool:
    if not file_path:
        return False

    if role == ROLE_SUPERVISOR:
        return True

    assignments = load_assignments()

    if role == ROLE_INSPECTOR:
        return any(
            a.get("file_path") == file_path and a.get("assigned_to") == username
            for a in assignments
        )

    if role == ROLE_CLIENTE:
        return any(
            a.get("file_path") == file_path and a.get("client") == username
            for a in assignments
        )

    return False


@app.route("/api/get-image")
@login_required
def get_image_by_path():
    file_path = request.args.get("file_path")
    if not file_path or not os.path.exists(file_path):
        return jsonify({"error": "Archivo no encontrado"}), 404

    if not is_allowed_extension(file_path):
        return jsonify({"error": "Extensión no permitida"}), 400

    username = session.get("username")
    role = normalize_role(session.get("role"))

    if not can_access_file_path(file_path, role, username):
        return jsonify({"error": "No autorizado"}), 403

    directory = os.path.dirname(file_path)
    filename = os.path.basename(file_path)
    return send_from_directory(directory, filename, max_age=0)


@app.route("/api/save-edited-image", methods=["POST"])
@login_required
@role_required(ROLE_INSPECTOR, ROLE_SUPERVISOR)
def save_edited_image():
    data = request.get_json() or {}
    filename = data.get("filename")
    file_path = data.get("file_path")
    image_data = data.get("image_data")

    if not filename or not file_path or not image_data:
        return jsonify({"error": "Datos inválidos"}), 400

    username = session.get("username")
    role = normalize_role(session.get("role"))

    if not can_access_file_path(file_path, role, username):
        return jsonify({"error": "No autorizado"}), 403

    if not is_image_extension(filename):
        return jsonify({"error": "Solo se permiten imágenes"}), 400

    try:
        match = re.match(r"^data:image/\w+;base64,", image_data)
        if match:
            image_data = image_data[match.end():]

        image_bytes = base64.b64decode(image_data)

        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "wb") as f:
            f.write(image_bytes)

        assignments = load_assignments()
        assignment = next((a for a in assignments if a.get("file_path") == file_path), None)
        if assignment:
            assignment["last_edited_at"] = datetime.now(timezone.utc).isoformat()
            assignment["last_edited_by"] = username
            current_status = normalize_status(assignment.get("status"), assignment.get("assigned_to"))
            if current_status in {STATUS_ASSIGNED, STATUS_UPLOADED}:
                assignment["status"] = STATUS_IN_REVIEW
                assignment["status_updated_at"] = datetime.now(timezone.utc).isoformat()
                assignment["status_updated_by"] = username
            save_assignments(assignments)

        return jsonify({"status": "ok"})
    except (OSError, binascii.Error) as e:
        return jsonify({"error": f"Error al guardar imagen: {str(e)}"}), 500


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
    client_filter = request.args.get("client", "").strip()
    file_type = request.args.get("file_type", "all").strip()
    
    # Obtener todas las imágenes y documentos de todos los clientes para el supervisor
    config = load_config()
    all_files = []
    seen_paths = set()  # Para evitar duplicados
    clients_list = []  # Lista de clientes para el filtro
    
    for username, client_data in config.get("clients", {}).items():
        # Saltar supervisores, solo mostrar archivos de clientes e inspectores
        if normalize_role(client_data.get("role")) == ROLE_SUPERVISOR:
            continue
            
        clients_list.append(username)
        
        # Aplicar filtro de cliente si existe
        if client_filter and username != client_filter:
            continue
            
        client_folder = client_data.get("folder")
        if not client_folder or not os.path.exists(client_folder):
            continue
        
        for filename in os.listdir(client_folder):
            # Ahora incluimos TODOS los archivos permitidos, no solo imágenes
            if not is_allowed_extension(filename):
                continue
            
            full_path = os.path.join(client_folder, filename)
            
            # Evitar duplicados si dos usuarios comparten carpeta
            if full_path in seen_paths:
                continue
            seen_paths.add(full_path)
            
            # Determinar tipo y extensión
            is_image = is_image_extension(filename)
            ext = filename.rsplit(".", 1)[1].lower() if "." in filename else ""
            
            # Aplicar filtro de tipo de archivo
            if file_type == "images" and not is_image:
                continue
            elif file_type == "documents" and is_image:
                continue
            
            try:
                stats = os.stat(full_path)
                mtime = datetime.fromtimestamp(stats.st_mtime)
                assignment = get_assignment_by_path(full_path)
                status = normalize_status(
                    assignment.get("status") if assignment else None,
                    assignment.get("assigned_to") if assignment else None
                )
                
                all_files.append({
                    "filename": filename,
                    "client": username,
                    "folder": client_folder,
                    "url": url_for("serve_file", filename=filename),
                    "modified": mtime,
                    "modified_iso": mtime.strftime("%Y-%m-%d %H:%M"),
                    "size": stats.st_size,
                    "assigned_to": assignment.get("assigned_to") if assignment else None,
                    "status": status,
                    "folio": assignment.get("folio") if assignment else None,
                    "is_image": is_image,
                    "ext": ext
                })
            except OSError:
                continue
    
    # Ordenar por fecha descendente
    all_files = sorted(all_files, key=lambda x: x["modified"], reverse=True)
    
    # Paginación
    total = len(all_files)
    start = (page - 1) * per_page
    end = start + per_page
    files_page = all_files[start:end]
    total_pages = (total + per_page - 1) // per_page
    
    # Obtener lista de inspectores
    inspectors = [u for u, data in config.get("clients", {}).items() 
                   if normalize_role(data.get("role")) == ROLE_INSPECTOR]
    
    return render_template(
        "solicitudes.html",
        images=files_page,
        page=page,
        total_pages=total_pages,
        total=total,
        per_page=per_page,
        inspectors=inspectors,
        clients=sorted(clients_list),
        client_filter=client_filter,
        file_type=file_type
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
        existing["assigned_at"] = datetime.now(timezone.utc).isoformat()
        existing["assigned_by"] = session.get("username")
        existing["status"] = STATUS_ASSIGNED
        existing["status_updated_at"] = datetime.now(timezone.utc).isoformat()
        existing["status_updated_by"] = session.get("username")
    else:
        assignments_folios = {a.get("folio") for a in assignments if a.get("folio")}
        folio = generate_folio(assignments_folios)
        assignments.append({
            "filename": filename,
            "file_path": file_path,
            "client": client,
            "folder": folder,
            "assigned_to": inspector,
            "assigned_by": session.get("username"),
            "assigned_at": datetime.now(timezone.utc).isoformat(),
            "status": STATUS_ASSIGNED,
            "folio": folio,
            "status_updated_at": datetime.now(timezone.utc).isoformat(),
            "status_updated_by": session.get("username")
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
                "status": normalize_status(assignment.get("status"), assignment.get("assigned_to")),
                "folio": assignment.get("folio"),
                "is_image": is_image_extension(filename),
                "ext": filename.rsplit(".", 1)[1].lower() if "." in filename else ""
            })
        except OSError:
            continue
    
    # Ordenar por fecha de asignación descendente
    assigned_images = sorted(assigned_images, key=lambda x: x.get("assigned_at", ""), reverse=True)
    
    # Calcular contadores
    total_assignments = len(assigned_images)
    pending_count = len([img for img in assigned_images if img.get("status") in [STATUS_ASSIGNED, STATUS_IN_REVIEW]])
    completed_count = len([img for img in assigned_images if img.get("status") in [STATUS_ACCEPTED, STATUS_REJECTED]])
    
    return render_template(
        "inspector.html",
        images=assigned_images,
        total_assignments=total_assignments,
        pending_count=pending_count,
        completed_count=completed_count,
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
# EDITOR DE IMÁGENES
# =========================
@app.route("/editor")
@login_required
@role_required(ROLE_INSPECTOR)
def image_editor():
    """Página del editor de imágenes para inspectores"""
    filename = request.args.get("filename")
    file_path = request.args.get("file_path")
    client = request.args.get("client")
    
    if not filename or not file_path or not client:
        return "Parámetros inválidos", 400
    
    # Verificar que el archivo está asignado al inspector actual
    username = session.get("username")
    assignments = load_assignments()
    assignment = next((a for a in assignments if a.get("file_path") == file_path and a.get("assigned_to") == username), None)
    
    if not assignment:
        return "Archivo no asignado a este inspector", 403

    current_status = normalize_status(assignment.get("status"), assignment.get("assigned_to"))
    if current_status in {STATUS_ASSIGNED, STATUS_UPLOADED}:
        assignment["status"] = STATUS_IN_REVIEW
        assignment["status_updated_at"] = datetime.now(timezone.utc).isoformat()
        assignment["status_updated_by"] = username
        save_assignments(assignments)
    
    return render_template("image_editor.html", 
                         filename=filename, 
                         file_path=file_path, 
                         client=client,
                         user_role=normalize_role(session.get("role")))


@app.route("/api/image-status", methods=["GET", "POST"])
@login_required
def image_status():
    """Obtener o actualizar el estado de una imagen"""
    filename = request.args.get("filename") if request.method == "GET" else request.get_json().get("filename")
    file_path = request.args.get("file_path") if request.method == "GET" else request.get_json().get("file_path")
    
    if not filename and not file_path:
        return jsonify({"error": "Filename o file_path requerido"}), 400
    
    assignments = load_assignments()
    assignment = None
    if file_path:
        assignment = next((a for a in assignments if a.get("file_path") == file_path), None)
    if not assignment and filename:
        assignment = next((a for a in assignments if a.get("filename") == filename), None)
    
    if request.method == "GET":
        status = normalize_status(
            assignment.get("status") if assignment else None,
            assignment.get("assigned_to") if assignment else None
        )
        return jsonify({"status": status})
    
    # POST: actualizar estado
    role = normalize_role(session.get("role"))
    if role != ROLE_SUPERVISOR and role != ROLE_INSPECTOR:
        return jsonify({"error": "No autorizado"}), 403
    
    data = request.get_json()
    status = data.get("status")
    file_path = data.get("file_path")
    
    if not status or status not in [STATUS_ACCEPTED, STATUS_REJECTED]:
        return jsonify({"error": "Estado inválido"}), 400
    
    if assignment:
        assignment["status"] = status
        assignment["status_updated_at"] = datetime.now(timezone.utc).isoformat()
        assignment["status_updated_by"] = session.get("username")
        save_assignments(assignments)
        return jsonify({"status": "ok"})
    
    return jsonify({"error": "Archivo no encontrado"}), 404


@app.route("/api/image-file-path", methods=["GET"])
@login_required
def get_image_file_path():
    """Obtener el file_path completo de un archivo"""
    filename = request.args.get("filename")
    
    if not filename:
        return jsonify({"error": "Filename requerido"}), 400
    
    username = session.get("username")
    role = normalize_role(session.get("role"))
    
    # Buscar en asignaciones primero
    assignments = load_assignments()
    assignment = next((a for a in assignments if a.get("filename") == filename), None)
    
    if assignment:
        return jsonify({"file_path": assignment.get("file_path")})
    
    # Si no está en asignaciones, buscar en la carpeta del usuario
    folder = get_upload_folder(username)
    full_path = os.path.join(folder, filename)
    
    if os.path.exists(full_path):
        return jsonify({"file_path": full_path})
    
    return jsonify({"error": "Archivo no encontrado"}), 404


@app.route("/api/image-comments", methods=["GET"])
@login_required
def get_image_comments():
    """Obtener comentarios de una imagen"""
    filename = request.args.get("filename")
    
    if not filename:
        return jsonify({"error": "Filename requerido"}), 400
    
    assignments = load_assignments()
    assignment = next((a for a in assignments if a.get("filename") == filename), None)
    
    if not assignment:
        return jsonify({"comments": []})
    
    comments = assignment.get("comments", [])
    return jsonify({"comments": comments})


@app.route("/api/add-image-comment", methods=["POST"])
@login_required
def add_image_comment():
    """Agregar comentario a una imagen"""
    data = request.get_json()
    filename = data.get("filename")
    text = data.get("text", "").strip()
    
    if not filename or not text:
        return jsonify({"error": "Datos inválidos"}), 400
    
    username = session.get("username")
    role = normalize_role(session.get("role"))
    
    assignments = load_assignments()
    assignment = next((a for a in assignments if a.get("filename") == filename), None)
    
    if not assignment:
        return jsonify({"error": "Archivo no encontrado"}), 404
    
    # Verificar permisos: inspector o supervisor
    if role not in [ROLE_INSPECTOR, ROLE_SUPERVISOR]:
        return jsonify({"error": "No autorizado"}), 403
    
    # Si es inspector, debe ser el asignado
    if role == ROLE_INSPECTOR and assignment.get("assigned_to") != username:
        return jsonify({"error": "No autorizado"}), 403
    
    if "comments" not in assignment:
        assignment["comments"] = []
    
    assignment["comments"].append({
        "author": username,
        "text": text,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "role": role
    })
    
    save_assignments(assignments)
    return jsonify({"status": "ok"})


@app.route("/api/update-assignment-status", methods=["POST"])
@login_required
@role_required(ROLE_INSPECTOR)
def update_assignment_status():
    """Actualizar el estado de una asignación (aceptado/rechazado)"""
    data = request.get_json()
    file_path = data.get("file_path")
    new_status = data.get("status", "").strip().lower()
    
    if not file_path or new_status not in [STATUS_ACCEPTED, STATUS_REJECTED]:
        return jsonify({"error": "Datos inválidos"}), 400
    
    username = session.get("username")
    assignments = load_assignments()
    assignment = next((a for a in assignments if a.get("file_path") == file_path and a.get("assigned_to") == username), None)
    
    if not assignment:
        return jsonify({"error": "Asignación no encontrada"}), 404
    
    # Actualizar estado
    assignment["status"] = new_status
    assignment["status_updated_at"] = datetime.now(timezone.utc).isoformat()
    assignment["status_updated_by"] = username
    
    save_assignments(assignments)
    return jsonify({"status": "ok", "new_status": new_status})


@app.route("/api/reupload-file", methods=["POST"])
@login_required
@role_required(ROLE_INSPECTOR)
def reupload_file():
    """Reemplazar un archivo asignado (imagen o documento)"""
    if "file" not in request.files:
        return jsonify({"error": "No se envió archivo"}), 400
    
    file = request.files["file"]
    filename = request.form.get("filename")
    file_path = request.form.get("file_path")
    
    if not filename or not file_path or not file.filename:
        return jsonify({"error": "Datos inválidos"}), 400
    
    if not is_allowed_extension(file.filename):
        return jsonify({"error": "Tipo de archivo no permitido"}), 400
    
    # Verificar que el archivo está asignado al inspector
    username = session.get("username")
    assignments = load_assignments()
    assignment = next((a for a in assignments if a.get("file_path") == file_path and a.get("assigned_to") == username), None)
    
    if not assignment:
        return jsonify({"error": "Archivo no asignado"}), 403
    
    try:
        # Reemplazar archivo
        if os.path.exists(file_path):
            os.remove(file_path)
        
        file.save(file_path)
        
        # Actualizar estado a en_revision
        assignment["status"] = STATUS_IN_REVIEW
        assignment["status_updated_at"] = datetime.now(timezone.utc).isoformat()
        assignment["status_updated_by"] = username
        save_assignments(assignments)
        
        return jsonify({"status": "ok"})
    except OSError as e:
        return jsonify({"error": f"Error al reemplazar archivo: {str(e)}"}), 500


@app.route("/view-image")
@login_required
def view_image():
    """Ver imagen con comentarios y estado (cliente/supervisor)"""
    filename = request.args.get("filename")
    file_path = request.args.get("file_path")
    
    if not filename and not file_path:
        return "Parámetros inválidos", 400
    
    username = session.get("username")
    role = normalize_role(session.get("role"))
    
    # Obtener información de la asignación
    assignments = load_assignments()
    assignment = None
    if file_path:
        assignment = next((a for a in assignments if a.get("file_path") == file_path), None)
    if not assignment and filename:
        assignment = next((a for a in assignments if a.get("filename") == filename), None)
    
    if not assignment:
        return "Archivo no encontrado", 404
    
    # Permisos: supervisor ve todo, cliente solo ve sus propias asignaciones
    if role == ROLE_CLIENTE:
        if assignment.get("client") != username:
            return "No autorizado", 403
    elif role != ROLE_SUPERVISOR:
        return "No autorizado", 403
    
    return render_template("view_image.html",
                         filename=filename,
                         file_path=assignment.get("file_path"),
                         client=assignment.get("client"),
                         status=normalize_status(assignment.get("status"), assignment.get("assigned_to")),
                         folio=assignment.get("folio"),
                         comments=assignment.get("comments", []),
                         assigned_to=assignment.get("assigned_to"),
                         assigned_at=assignment.get("assigned_at"),
                         assigned_by=assignment.get("assigned_by"))


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
