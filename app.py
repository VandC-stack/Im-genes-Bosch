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
USERS_FILE = "Users.json"
HISTORY_FILE = "upload_history.json"
ASSIGNMENTS_FILE = "assignments.json"
COMMITS_FILE = "commits.json"
SERVICE_REQUESTS_FILE = "service_requests.json"
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
ROLE_EJECUTIVO = "ejecutivo"
ROLE_BOSCH = "bosch"
ALLOWED_ROLES = {ROLE_CLIENTE, ROLE_SUPERVISOR, ROLE_EJECUTIVO, ROLE_BOSCH}

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


def load_users():
    """Load users from Users.json (ejecutivos and supervisors)"""
    if not os.path.exists(USERS_FILE):
        return []
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, list) else []


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
    """Get user from Users.json (ejecutivos/supervisors) or config.json (clients)"""
    if not username:
        return None
    
    # First, check Users.json for ejecutivos and supervisors
    users = load_users()
    for user in users:
        firma = user.get("FIRMA")
        if firma and firma.strip().lower() == username.strip().lower():
            # Return in the same format as config clients
            return {
                "password": user.get("CONTRASEÑA", ""),
                "role": user.get("PUESTO", "Ejecutivo"),
                "folder": None,  # Ejecutivos and supervisors don't have their own folder
                "nombre": user.get("NOMBRE"),
                "correo": user.get("CORREO"),
                "normas": user.get("NORMAS")
            }
    
    # If not found in Users.json, check config.json for clients
    return load_config().get("clients", {}).get(username)


def normalize_role(role: Optional[str]) -> str:
    if not role:
        return ROLE_CLIENTE
    normalized = role.strip().lower()
    if normalized == "inspector":
        return ROLE_EJECUTIVO
    if normalized == "supervisor":
        return ROLE_SUPERVISOR
    return normalized if normalized in ALLOWED_ROLES else ROLE_CLIENTE


def verify_password(stored: str, provided: str) -> bool:
    if not stored:
        return False
    if stored.startswith("pbkdf2:") or stored.startswith("scrypt:") or stored.startswith("argon2:"):
        return check_password_hash(stored, provided)
    return hmac.compare_digest(stored, provided)


def parse_normas(normas_string: Optional[str]) -> set:
    """Parse normas string (separated by ; or ,) into a set of normalized normas"""
    if not normas_string:
        return set()
    normas = re.split(r'[;,]', str(normas_string))
    return {n.strip().upper() for n in normas if n.strip()}


def get_compatible_ejecutivos(folio_normas: Optional[str]) -> list:
    """Get ejecutivos from Users.json whose normas are compatible with folio normas"""
    users = load_users()
    compatible = []
    
    # If no normas specified in folio, all ejecutivos are compatible
    folio_normas_set = parse_normas(folio_normas)
    if not folio_normas_set:
        for user in users:
            if user.get("PUESTO", "").lower() in ["ejecutivo", "supervisor"]:
                compatible.append({
                    "firma": user.get("FIRMA"),
                    "nombre": user.get("NOMBRE"),
                    "puesto": user.get("PUESTO"),
                    "all_normas": parse_normas(user.get("NORMAS"))
                })
        return compatible
    
    # Filter to only ejecutivos that have all required normas
    for user in users:
        if user.get("PUESTO", "").lower() not in ["ejecutivo", "supervisor"]:
            continue
        
        user_normas_set = parse_normas(user.get("NORMAS"))
        
        # Check if user has all the required normas from folio
        if folio_normas_set.issubset(user_normas_set):
            compatible.append({
                "firma": user.get("FIRMA"),
                "nombre": user.get("NOMBRE"),
                "puesto": user.get("PUESTO"),
                "all_normas": user_normas_set
            })
    
    # Sort by nombre
    compatible.sort(key=lambda x: x.get("nombre", ""))
    return compatible


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


def find_commit_entry(commits: list, filename: Optional[str] = None, file_path: Optional[str] = None):
    if file_path:
        for entry in commits:
            if entry.get("file_path") == file_path:
                return entry
    if filename:
        for entry in commits:
            if entry.get("filename") == filename:
                return entry
    return None


def migrate_assignment_comments(commits: list) -> bool:
    assignments = load_assignments()
    assignments_changed = False
    commits_changed = False

    for assignment in assignments:
        comments = assignment.pop("comments", None)
        if comments is not None:
            assignments_changed = True
        if not isinstance(comments, list) or not comments:
            continue

        entry = find_commit_entry(
            commits,
            filename=assignment.get("filename"),
            file_path=assignment.get("file_path")
        )
        if not entry:
            entry = {
                "filename": assignment.get("filename"),
                "file_path": assignment.get("file_path"),
                "comments": []
            }
            commits.append(entry)

        entry_comments = entry.setdefault("comments", [])
        if isinstance(entry_comments, list):
            entry_comments.extend([c for c in comments if isinstance(c, dict)])
            commits_changed = True

    if assignments_changed:
        save_assignments(assignments)

    return commits_changed


def load_commits():
    if not os.path.exists(COMMITS_FILE):
        commits = []
        if migrate_assignment_comments(commits):
            save_commits(commits)
        return commits

    try:
        with open(COMMITS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def save_commits(data):
    with open(COMMITS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_service_requests():
    if not os.path.exists(SERVICE_REQUESTS_FILE):
        return []

    try:
        with open(SERVICE_REQUESTS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def save_service_requests(data):
    with open(SERVICE_REQUESTS_FILE, "w", encoding="utf-8") as f:
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
                            "uploaded_at": datetime.now(timezone.utc).isoformat()
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
                        "uploaded_at": datetime.now(timezone.utc).isoformat()
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
    elif role == ROLE_EJECUTIVO:
        return redirect(url_for("ejecutivo_panel"))
    elif role == ROLE_BOSCH:
        # ROLE_BOSCH: mostrar index normal
        pass
    
    # ROLE_CLIENTE: mostrar index normal
    return render_template("index.html", username=session.get("username"))


@app.route("/welcome")
@login_required
def welcome():
    role = normalize_role(session.get("role"))

    if role == ROLE_SUPERVISOR:
        return redirect(url_for("solicitudes"))
    if role == ROLE_EJECUTIVO:
        return redirect(url_for("ejecutivo_panel"))
    if role == ROLE_BOSCH:
        return redirect(url_for("index"))

    return render_template("welcome.html", username=session.get("username"))


@app.route("/dashboard")
@login_required
@role_required(ROLE_CLIENTE)
def dashboard():
    """Vista principal del cliente con resumen de solicitudes"""
    return render_template("dashboard.html", username=session.get("username"))


@app.route("/captura")
@login_required
@role_required(ROLE_CLIENTE)
def captura():
    """Formulario para crear una nueva solicitud"""
    return render_template("captura.html", username=session.get("username"))

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
                error="Cliente o contraseña inválidos",
                next=next_url
            )

        session["username"] = username
        session["role"] = normalize_role(client.get("role"))
        if not is_safe_next(next_url):
            next_url = url_for("welcome") if session["role"] == ROLE_CLIENTE else url_for("index")
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
            # Asegurar que la asignación tenga folio (válido para documentos e imágenes)
            if not assignment.get("folio"):
                folio = generate_folio(existing_folios)
                existing_folios.add(folio)
                assignment["folio"] = folio
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
                "uploaded_at": datetime.now(timezone.utc).isoformat()
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


@app.route("/api/solicitudes", methods=["GET", "POST"])
@login_required
@role_required(ROLE_CLIENTE)
def api_solicitudes():
    username = session.get("username")

    if request.method == "POST":
        tipo_servicio = request.form.get("tipo_servicio", "").strip()
        nombre_proyecto = request.form.get("nombre_proyecto", "").strip()
        norma = request.form.get("norma", "").strip()
        num_skus = request.form.get("num_skus", "").strip()
        medidas = request.form.get("medidas", "").strip()
        prioridad = request.form.get("prioridad", "").strip()
        importador = request.form.get("importador", "").strip()
        marca = request.form.get("marca", "").strip()
        pais_origen = request.form.get("pais_origen", "").strip()
        contenido = request.form.get("contenido", "").strip()

        if not tipo_servicio or not nombre_proyecto or not prioridad:
            return jsonify({"error": "Datos incompletos"}), 400

        assignments = load_assignments()
        existing_folios = {a.get("folio") for a in assignments if a.get("folio")}
        requests_data = load_service_requests()
        existing_folios.update({r.get("folio") for r in requests_data if r.get("folio")})
        folio = generate_folio(existing_folios)

        upload_folder = get_upload_folder(username)
        files = request.files.getlist("file")
        saved_files = []
        history_entries = []
        assignments_changed = False

        for file in files:
            if not file.filename or not is_allowed_extension(file.filename):
                continue

            ext = file.filename.rsplit(".", 1)[1].lower()
            base_raw = os.path.splitext(file.filename)[0]
            base_name = sanitize_filename(base_raw)
            if not base_name:
                base_name = datetime.now().strftime("IMG_%Y%m%d_%H%M%S_%f")

            filename = f"{base_name}.{ext}"
            file_path = os.path.join(upload_folder, filename)
            counter = 1
            while os.path.exists(file_path):
                filename = f"{base_name}_{counter}.{ext}"
                file_path = os.path.join(upload_folder, filename)
                counter += 1

            file.save(file_path)

            saved_files.append({
                "filename": filename,
                "original_name": file.filename,
                "file_path": file_path
            })

            history_entries.append({
                "filename": filename,
                "original_name": file.filename,
                "folder": upload_folder,
                "uploaded_at": datetime.now(timezone.utc).isoformat(),
                "url": url_for("serve_file", filename=filename),
                "username": username
            })

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
                "uploaded_at": datetime.now(timezone.utc).isoformat()
            })
            assignments_changed = True

        if history_entries:
            append_history(history_entries)

        if assignments_changed:
            save_assignments(assignments)

        requests_data.append({
            "folio": folio,
            "client": username,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "tipo_servicio": tipo_servicio,
            "nombre_proyecto": nombre_proyecto,
            "norma": norma,
            "num_skus": num_skus,
            "medidas": medidas,
            "prioridad": prioridad,
            "importador": importador,
            "marca": marca,
            "pais_origen": pais_origen,
            "contenido": contenido,
            "files": saved_files
        })

        save_service_requests(requests_data)

        return jsonify({"status": "ok", "folio": folio})

    def parse_iso(value):
        if not value:
            return None
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return None
        return value

    def request_status(statuses):
        if not statuses:
            return "PENDIENTE"
        if all(s in {STATUS_ACCEPTED, STATUS_REJECTED} for s in statuses):
            return "FINALIZADO"
        if any(s == STATUS_IN_REVIEW for s in statuses):
            return "EN REVISIÓN"
        if any(s == STATUS_ASSIGNED for s in statuses):
            return "EN PROCESO"
        return "PENDIENTE"

    tipo_map = {
        "consultoria": "Consultoria",
        "constancia": "Constancia",
        "diseno": "Diseño"
    }
    modalidad_map = {"urgente": "URGENTE", "regular": "REGULAR"}

    requests_data = load_service_requests()
    client_requests = [r for r in requests_data if r.get("client") == username]

    assignments = load_assignments()
    client_assignments = [a for a in assignments if a.get("client") == username]
    assignments_by_folio = {}
    for assignment in client_assignments:
        folio = assignment.get("folio")
        if not folio:
            continue
        assignments_by_folio.setdefault(folio, []).append(assignment)

    solicitudes = []
    used_folios = set()

    for req in client_requests:
        folio = req.get("folio")
        used_folios.add(folio)
        linked = assignments_by_folio.get(folio, [])
        statuses = [normalize_status(a.get("status"), a.get("assigned_to")) for a in linked]
        status_label = request_status(statuses)

        created_at = parse_iso(req.get("created_at"))
        completion_dates = [parse_iso(a.get("status_updated_at")) for a in linked]
        completion_dates = [d for d in completion_dates if d]
        completed_at = max(completion_dates) if completion_dates else None

        # Obtener el ciclo máximo de los assignments vinculados
        ciclos = [a.get("ciclo_actual", 1) for a in linked if a.get("ciclo_actual")]
        ciclo_actual = max(ciclos) if ciclos else 1

        solicitudes.append({
            "fecha": req.get("created_at"),
            "folio": folio,
            "tipo": tipo_map.get(req.get("tipo_servicio"), req.get("tipo_servicio") or "—"),
            "modalidad": modalidad_map.get(req.get("prioridad"), (req.get("prioridad") or "").upper() or "—"),
            "proyecto": req.get("nombre_proyecto") or "—",
            "estatus": status_label,
            "fechaEnvio": completed_at.isoformat() if completed_at else None,
            "ciclo": ciclo_actual,
            "norma": req.get("norma"),
            "num_skus": req.get("num_skus"),
            "medidas": req.get("medidas"),
            "prioridad": req.get("prioridad"),
            "importador": req.get("importador"),
            "marca": req.get("marca"),
            "pais_origen": req.get("pais_origen"),
            "contenido": req.get("contenido")
        })

    for folio, linked in assignments_by_folio.items():
        if folio in used_folios:
            continue

        statuses = [normalize_status(a.get("status"), a.get("assigned_to")) for a in linked]
        status_label = request_status(statuses)

        created_at = None
        for a in linked:
            created_at = parse_iso(a.get("uploaded_at")) or created_at
            if created_at:
                break

        completion_dates = [parse_iso(a.get("status_updated_at")) for a in linked]
        completion_dates = [d for d in completion_dates if d]
        completed_at = max(completion_dates) if completion_dates else None

        # Obtener el ciclo máximo de los assignments vinculados
        ciclos = [a.get("ciclo_actual", 1) for a in linked if a.get("ciclo_actual")]
        ciclo_actual = max(ciclos) if ciclos else 1

        project_hint = linked[0].get("filename") if linked else "—"
        solicitudes.append({
            "fecha": created_at.isoformat() if created_at else None,
            "folio": folio,
            "tipo": "Archivo",
            "modalidad": "REGULAR",
            "proyecto": f"Archivo: {project_hint}",
            "estatus": status_label,
            "fechaEnvio": completed_at.isoformat() if completed_at else None,
            "ciclo": ciclo_actual,
            "norma": "",
            "num_skus": "",
            "medidas": "",
            "prioridad": "regular",
            "importador": "",
            "marca": "",
            "pais_origen": "",
            "contenido": ""
        })

    solicitudes = sorted(solicitudes, key=lambda x: x.get("fecha") or "", reverse=True)
    return jsonify({"solicitudes": solicitudes})


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
    
    # Supervisor y Ejecutivo: pueden acceder a archivos asignados
    if role == ROLE_SUPERVISOR:
        directory = os.path.dirname(file_path)
        filename = os.path.basename(file_path)
        return send_from_directory(directory, filename, max_age=0)
    
    if role == ROLE_EJECUTIVO:
        # Verificar que el archivo esté asignado a este ejecutivo
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

    if role == ROLE_EJECUTIVO:
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
@role_required(ROLE_EJECUTIVO, ROLE_SUPERVISOR)
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

    # Verificar que el archivo no esté en estatus aceptado (bloqueado)
    assignments = load_assignments()
    assignment = next((a for a in assignments if a.get("file_path") == file_path), None)
    if assignment:
        current_status = normalize_status(assignment.get("status"), assignment.get("assigned_to"))
        if current_status == STATUS_ACCEPTED:
            return jsonify({"error": "No se puede editar: archivo ya aceptado"}), 403

    try:
        match = re.match(r"^data:image/\w+;base64,", image_data)
        if match:
            image_data = image_data[match.end():]

        image_bytes = base64.b64decode(image_data)

        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "wb") as f:
            f.write(image_bytes)

        # Actualizar assignment con nuevo ciclo
        if assignment:
            # Incrementar ciclo en cada edición
            ciclo_actual = assignment.get("ciclo_actual", 1)
            assignment["ciclo_actual"] = ciclo_actual + 1
            
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
    folio_filter = request.args.get("folio", "").strip()

    username = session.get("username")
    role = normalize_role(session.get("role"))
    
    # Supervisor: ve todas las imágenes de todos los clientes
    all_clients = (role == ROLE_SUPERVISOR)
    images = list_images(username, query or None, date_from, date_to, all_clients=all_clients)

    # Si se proporciona un folio específico, filtrar solo esos archivos
    if folio_filter:
        images = [img for img in images if img.get("folio") == folio_filter]

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
        folio=folio_filter,
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

    requests_data = load_service_requests()
    requests_by_folio = {
        r.get("folio"): r for r in requests_data if r.get("folio")
    }
    
    for username, client_data in config.get("clients", {}).items():
        # Saltar supervisores, solo mostrar archivos de clientes y ejecutivos
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

    # Agrupar por folio para vista tipo collage
    grouped = {}
    for entry in all_files:
        folio = entry.get("folio") or "SIN-FOLIO"
        group = grouped.get(folio)
        if not group:
            request_data = requests_by_folio.get(folio)
            group = {
                "folio": folio,
                "client": entry.get("client"),
                "files": [],
                "latest_modified": entry.get("modified"),
                "image_count": 0,
                "document_count": 0,
                "assigned_count": 0,
                "norma": request_data.get("norma") if request_data else "",
                "assigned_to": entry.get("assigned_to") if entry.get("assigned_to") else None
            }
            grouped[folio] = group
        else:
            if group.get("client") and entry.get("client") != group.get("client"):
                group["client"] = "Varios"
            if entry.get("assigned_to"):
                if group.get("assigned_to") is None:
                    group["assigned_to"] = entry.get("assigned_to")
                elif group.get("assigned_to") != entry.get("assigned_to"):
                    group["assigned_to"] = "Varios"

        group["files"].append(entry)
        if entry.get("is_image"):
            group["image_count"] += 1
        else:
            group["document_count"] += 1
        if entry.get("assigned_to"):
            group["assigned_count"] += 1

        if entry.get("modified") and entry["modified"] > group["latest_modified"]:
            group["latest_modified"] = entry["modified"]

    groups = list(grouped.values())
    for group in groups:
        group["files"] = sorted(group["files"], key=lambda x: x["modified"], reverse=True)
        group["total_files"] = len(group["files"])
        # Add compatible ejecutivos for this folio
        group["compatible_ejecutivos"] = get_compatible_ejecutivos(group.get("norma"))

    groups = sorted(groups, key=lambda x: x["latest_modified"], reverse=True)

    # Paginación por folios
    total_files = len(all_files)
    total_folios = len(groups)
    start = (page - 1) * per_page
    end = start + per_page
    groups_page = groups[start:end]
    total_pages = (total_folios + per_page - 1) // per_page
    start_index = start + 1 if total_folios else 0
    end_index = min(end, total_folios)
    
    # Obtener lista de ejecutivos de Users.json
    all_ejecutivos = get_compatible_ejecutivos(None)  # Get all ejecutivos when no norma filter
    ejecutivos = [e.get("firma") for e in all_ejecutivos]
    
    return render_template(
        "solicitudes.html",
        groups=groups_page,
        total_files=total_files,
        total_folios=total_folios,
        start_index=start_index,
        end_index=end_index,
        page=page,
        total_pages=total_pages,
        total=total_folios,
        per_page=per_page,
        ejecutivos=ejecutivos,
        clients=sorted(clients_list),
        client_filter=client_filter,
        file_type=file_type
    )


@app.route("/api/assign-folio", methods=["POST"])
@login_required
@role_required(ROLE_SUPERVISOR)
def assign_folio():
    data = request.get_json()
    folio = data.get("folio")
    ejecutivo = data.get("ejecutivo")

    if not folio or not ejecutivo:
        return jsonify({"error": "Datos inválidos"}), 400

    assignments = load_assignments()
    updated = False
    now_iso = datetime.now(timezone.utc).isoformat()
    assigned_by = session.get("username")

    for assignment in assignments:
        if assignment.get("folio") != folio:
            continue
        assignment["assigned_to"] = ejecutivo
        assignment["assigned_at"] = now_iso
        assignment["assigned_by"] = assigned_by
        assignment["status"] = STATUS_ASSIGNED
        assignment["status_updated_at"] = now_iso
        assignment["status_updated_by"] = assigned_by
        updated = True

    if not updated:
        return jsonify({"error": "Folio no encontrado"}), 404

    save_assignments(assignments)
    return jsonify({"status": "ok"})


@app.route("/api/assign-image", methods=["POST"])
@login_required
@role_required(ROLE_SUPERVISOR)
def assign_image():
    data = request.get_json()
    filename = data.get("filename")
    ejecutivo = data.get("ejecutivo")
    client = data.get("client")
    folder = data.get("folder")
    
    if not filename or not ejecutivo or not client or not folder:
        return jsonify({"error": "Datos inválidos"}), 400
    
    file_path = os.path.join(folder, filename)
    
    assignments = load_assignments()
    existing = next((a for a in assignments if a.get("file_path") == file_path), None)
    
    if existing:
        existing["assigned_to"] = ejecutivo
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
            "assigned_to": ejecutivo,
            "assigned_by": session.get("username"),
            "assigned_at": datetime.now(timezone.utc).isoformat(),
            "status": STATUS_ASSIGNED,
            "folio": folio,
            "status_updated_at": datetime.now(timezone.utc).isoformat(),
            "status_updated_by": session.get("username")
        })
    
    save_assignments(assignments)
    return jsonify({"status": "ok"})


@app.route("/ejecutivo")
@login_required
@role_required(ROLE_EJECUTIVO)
def ejecutivo_panel():
    username = session.get("username")
    assignments = load_assignments()
    
    # Filtrar solo las asignaciones de este ejecutivo
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
        "ejecutivo.html",
        images=assigned_images,
        total_assignments=total_assignments,
        pending_count=pending_count,
        completed_count=completed_count,
        stats={
            "total": total_assignments,
            "pending": pending_count,
            "completed": completed_count
        },
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
@role_required(ROLE_EJECUTIVO)
def image_editor():
    """Página del editor de imágenes para ejecutivos"""
    filename = request.args.get("filename")
    file_path = request.args.get("file_path")
    client = request.args.get("client")
    
    if not filename or not file_path or not client:
        return "Parámetros inválidos", 400
    
    # Verificar que el archivo está asignado al ejecutivo actual
    username = session.get("username")
    assignments = load_assignments()
    assignment = next((a for a in assignments if a.get("file_path") == file_path and a.get("assigned_to") == username), None)
    
    if not assignment:
        return "Archivo no asignado a este ejecutivo", 403

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
    if role != ROLE_SUPERVISOR and role != ROLE_EJECUTIVO:
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

    commits = load_commits()
    entry = find_commit_entry(
        commits,
        filename=filename,
        file_path=assignment.get("file_path") if assignment else None
    )
    comments = entry.get("comments", []) if entry else []
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
    
    # Verificar permisos: ejecutivo o supervisor
    if role not in [ROLE_EJECUTIVO, ROLE_SUPERVISOR]:
        return jsonify({"error": "No autorizado"}), 403
    
    # Si es ejecutivo, debe ser el asignado
    if role == ROLE_EJECUTIVO and assignment.get("assigned_to") != username:
        return jsonify({"error": "No autorizado"}), 403
    
    commits = load_commits()
    entry = find_commit_entry(
        commits,
        filename=assignment.get("filename"),
        file_path=assignment.get("file_path")
    )
    if not entry:
        entry = {
            "filename": assignment.get("filename"),
            "file_path": assignment.get("file_path"),
            "comments": []
        }
        commits.append(entry)

    entry.setdefault("comments", []).append({
        "author": username,
        "text": text,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "role": role
    })
    
    save_commits(commits)
    return jsonify({"status": "ok"})


@app.route("/api/update-assignment-status", methods=["POST"])
@login_required
@role_required(ROLE_EJECUTIVO)
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
@role_required(ROLE_EJECUTIVO)
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
    
    # Verificar que el archivo está asignado al ejecutivo
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
    
    # Obtener información del archivo
    file_path_value = assignment.get("file_path")
    file_size = None
    if file_path_value and os.path.exists(file_path_value):
        try:
            file_size = os.path.getsize(file_path_value)
        except OSError:
            file_size = None
    
    # Obtener nombre del cliente
    client_username = assignment.get("client")
    client_info = get_client(client_username)
    client_name = client_info.get("name") if (client_info and client_info.get("name")) else client_username
    
    # Obtener fecha de carga
    upload_date = assignment.get("uploaded_at")
    if upload_date:
        try:
            # Convertir de ISO format a fecha legible
            dt = datetime.fromisoformat(upload_date.replace('Z', '+00:00'))
            upload_date = dt.strftime("%d/%m/%Y %H:%M")
        except:
            pass
    
    # Generar URL de la imagen
    image_url = url_for("serve_file_by_path", file_path=file_path_value) if file_path_value else ""
    
    return render_template("view_image.html",
                         filename=filename,
                         file_path=file_path_value,
                         client=client_username,
                         client_name=client_name,
                         file_size=file_size,
                         upload_date=upload_date,
                         image_url=image_url,
                         status=normalize_status(assignment.get("status"), assignment.get("assigned_to")),
                         folio=assignment.get("folio"),
                         comments=(
                             find_commit_entry(
                                 load_commits(),
                                 filename=assignment.get("filename"),
                                 file_path=file_path_value
                             ) or {}
                         ).get("comments", []),
                         assigned_to=assignment.get("assigned_to"),
                         assigned_at=assignment.get("assigned_at"),
                         assigned_by=assignment.get("assigned_by"),
                         role=role)


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
