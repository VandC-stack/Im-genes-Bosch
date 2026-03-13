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


def sanitize_filename(name: str) -> Optional[str]:
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


def parse_iso_date(value: Optional[str]):
    """Parsea un string ISO 8601 a datetime"""
    if not value:
        return None
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def normalize_cycle_value(value) -> int:
    """Normaliza el valor de ciclo a entero positivo."""
    try:
        cycle = int(value)
    except (TypeError, ValueError):
        return 1
    return cycle if cycle > 0 else 1


def get_max_cycle(assignments: list, folio: Optional[str] = None) -> int:
    """Obtiene el ciclo maximo de un folio a partir de sus assignments."""
    cycles = []
    for assignment in assignments:
        if folio is not None and assignment.get("folio") != folio:
            continue
        cycles.append(normalize_cycle_value(assignment.get("ciclo_actual", 1)))
    return max(cycles) if cycles else 1


def count_client_comments(solicitud: Optional[dict]) -> int:
    """Cuenta comentarios o ediciones registradas por el cliente en el historial."""
    if not isinstance(solicitud, dict):
        return 0

    client_username = solicitud.get("client")
    total = 0
    for entry in solicitud.get("historial", []):
        if not isinstance(entry, dict):
            continue

        entry_type = entry.get("tipo")
        if entry_type == "edicion_cliente":
            total += 1
            continue

        if entry_type != "comentario":
            continue

        entry_role = normalize_role(entry.get("rol")) if entry.get("rol") else ""
        entry_author = entry.get("usuario") or entry.get("autor")
        if entry_role == ROLE_CLIENTE or (client_username and entry_author == client_username):
            total += 1

    return total


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


def format_file_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{round(size_bytes / 1024)} KB"
    return f"{round(size_bytes / (1024 * 1024), 1)} MB"


def can_access_solicitud(solicitud: dict, role: str, username: Optional[str]) -> bool:
    if not isinstance(solicitud, dict):
        return False
    if role == ROLE_CLIENTE:
        return solicitud.get("client") == username
    return role in {ROLE_SUPERVISOR, ROLE_EJECUTIVO, ROLE_BOSCH}


def get_attachment_folder_for_solicitud(solicitud: dict, folio: str) -> str:
    client_username = solicitud.get("client")
    base_folder = get_upload_folder(client_username)
    folder = os.path.join(base_folder, "_comentarios", folio)
    os.makedirs(folder, exist_ok=True)
    return folder


def normalize_comment_attachments(attachments: list, folio: str) -> list:
    normalized = []
    for attachment in attachments:
        if not isinstance(attachment, dict):
            continue

        nombre = os.path.basename(str(attachment.get("nombre", "")).strip())
        ext = str(attachment.get("ext", "")).strip().lower()
        if not ext and "." in nombre:
            ext = nombre.rsplit(".", 1)[1].lower()

        item: dict[str, object] = {
            "nombre": nombre or "archivo",
            "ext": ext,
            "size": str(attachment.get("size", "")).strip()
        }

        attachment_id = str(attachment.get("id", "")).strip()
        if attachment_id:
            item["id"] = attachment_id

        stored_name = str(attachment.get("stored_name", "")).strip()
        if stored_name:
            item["stored_name"] = stored_name

        file_path = str(attachment.get("file_path", "")).strip()
        if file_path:
            item["file_path"] = file_path

        size_bytes = attachment.get("size_bytes")
        if isinstance(size_bytes, int) and size_bytes >= 0:
            item["size_bytes"] = size_bytes

        if item.get("id"):
            item["url"] = url_for("download_solicitud_attachment", folio=folio, attachment_id=item["id"])
        elif item.get("file_path"):
            item["url"] = url_for("serve_file_by_path", file_path=item["file_path"])

        normalized.append(item)

    return normalized


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
        
        # Inicializar ciclo_actual si tiene folio y no existe el campo
        if assignment.get("folio") and "ciclo_actual" not in assignment:
            assignment["ciclo_actual"] = 1
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
                    mtime = datetime.fromtimestamp(stats.st_mtime, tz=timezone.utc)
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
                mtime = datetime.fromtimestamp(stats.st_mtime, tz=timezone.utc)
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
                mtime = datetime.fromtimestamp(stats.st_mtime, tz=timezone.utc)
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


@app.route("/historial/<folio>")
@login_required
def historial(folio):
    """Vista de historial detallado de una solicitud"""
    # Verificar acceso: clientes solo ven sus solicitudes, ejecutivos y supervisores ven todas
    username = session.get("username")
    role = normalize_role(session.get("role"))

    back_url = url_for("dashboard")
    back_label = "Volver al Dashboard"
    if role == ROLE_EJECUTIVO:
        back_url = url_for("ejecutivo_panel")
        back_label = "Volver al Panel"
    elif role == ROLE_SUPERVISOR:
        back_url = url_for("solicitudes")
        back_label = "Volver a Solicitudes"
    
    if role == ROLE_CLIENTE:
        # Verificar que la solicitud pertenece al cliente
        requests_data = load_service_requests()
        solicitud = next((r for r in requests_data if r.get("folio") == folio), None)
        if not solicitud or solicitud.get("client") != username:
            abort(403)
    
    return render_template(
        "historial.html",
        username=session.get("username"),
        folio=folio,
        back_url=back_url,
        back_label=back_label
    )


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
        if is_safe_next(next_url):
            assert next_url is not None
            safe_next_url = next_url
        else:
            safe_next_url = url_for("welcome") if session["role"] == ROLE_CLIENTE else url_for("index")
        return redirect(safe_next_url)

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

        created_at = parse_iso_date(req.get("created_at"))
        completion_dates = [parse_iso_date(a.get("status_updated_at")) for a in linked]
        completion_dates = [d for d in completion_dates if d]
        completed_at = max(completion_dates) if completion_dates else None

        # Obtener el ciclo máximo de los assignments vinculados
        ciclo_actual = get_max_cycle(linked)

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
            created_at = parse_iso_date(a.get("uploaded_at")) or created_at
            if created_at:
                break

        completion_dates = [parse_iso_date(a.get("status_updated_at")) for a in linked]
        completion_dates = [d for d in completion_dates if d]
        completed_at = max(completion_dates) if completion_dates else None

        # Obtener el ciclo máximo de los assignments vinculados
        ciclo_actual = get_max_cycle(linked)

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


@app.route("/api/solicitud/<folio>", methods=["GET"])
@login_required
def get_solicitud(folio):
    """Obtener detalles completos de una solicitud"""
    username = session.get("username")
    role = normalize_role(session.get("role"))
    requests_data = load_service_requests()

    # Buscar la solicitud
    solicitud = next((r for r in requests_data if r.get("folio") == folio), None)

    if not solicitud:
        return jsonify({"error": "Solicitud no encontrada"}), 404

    if role == ROLE_CLIENTE and solicitud.get("client") != username:
        return jsonify({"error": "No autorizado"}), 403
    
    # Obtener ciclo desde assignments
    assignments = load_assignments()
    linked = [a for a in assignments if a.get("folio") == folio]
    ciclo_actual = get_max_cycle(linked)
    
    # Leer estatus directamente de service_requests (fuente única de verdad)
    estatus = solicitud.get("estatus", "PENDIENTE")

    files = []
    for entry in solicitud.get("files", []):
        if not isinstance(entry, dict):
            continue
        file_path = entry.get("file_path")
        filename = entry.get("filename") or (os.path.basename(file_path) if file_path else "")
        original_name = entry.get("original_name")
        if file_path:
            url = url_for("serve_file_by_path", file_path=file_path)
        else:
            url = url_for("serve_file", filename=filename) if filename else ""
        files.append({
            "filename": filename,
            "original_name": original_name,
            "file_path": file_path,
            "url": url,
            "is_image": is_image_extension(filename) if filename else False
        })
    
    return jsonify({
        "folio": folio,
        "client": solicitud.get("client", ""),
        "tipo_servicio": solicitud.get("tipo_servicio", ""),
        "nombre_proyecto": solicitud.get("nombre_proyecto", ""),
        "norma": solicitud.get("norma", ""),
        "num_skus": solicitud.get("num_skus", ""),
        "medidas": solicitud.get("medidas", ""),
        "prioridad": solicitud.get("prioridad", ""),
        "importador": solicitud.get("importador", ""),
        "marca": solicitud.get("marca", ""),
        "pais_origen": solicitud.get("pais_origen", ""),
        "contenido": solicitud.get("contenido", ""),
        "ciclo_actual": ciclo_actual,
        "estatus": estatus,
        "fecha_recepcion": solicitud.get("created_at"),
        "fecha_envio": solicitud.get("completed_at"),
        "historial": solicitud.get("historial", []),
        "created_at": solicitud.get("created_at"),
        "files": files
    })


@app.route("/api/solicitud/<folio>/edit", methods=["POST"])
@login_required
@role_required(ROLE_CLIENTE)
def edit_solicitud(folio):
    """Editar una solicitud y guardar en el historial"""
    username = session.get("username")
    requests_data = load_service_requests()
    
    # Buscar la solicitud
    req_index = None
    solicitud = None
    for i, r in enumerate(requests_data):
        if r.get("folio") == folio and r.get("client") == username:
            req_index = i
            solicitud = r
            break
    
    if solicitud is None:
        return jsonify({"error": "Solicitud no encontrada"}), 404
    
    # Obtener datos de la edición
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
    comentario_edicion = request.form.get("comentario_edicion", "").strip()
    
    if not comentario_edicion:
        return jsonify({"error": "Debe proporcionar un comentario de la edición"}), 400

    assignments = load_assignments()
    files_list = solicitud.setdefault("files", [])
    upload_folder = get_upload_folder(username)

    imagenes_reemplazadas = []
    for key in request.files:
        if not key.startswith("replace_file_"):
            continue
        replacement = request.files.get(key)
        if not replacement or not replacement.filename:
            continue

        idx = key.split("_")[-1]
        target_path = request.form.get(f"replace_target_{idx}", "").strip()
        if not target_path:
            continue

        target_entry = next((f for f in files_list if f.get("file_path") == target_path), None)
        if not target_entry:
            return jsonify({"error": "Imagen a reemplazar no encontrada"}), 400

        target_filename = target_entry.get("filename") or os.path.basename(target_path)
        if not target_filename or not is_image_extension(target_filename):
            return jsonify({"error": "Solo se pueden reemplazar imágenes"}), 400

        if not is_image_extension(replacement.filename):
            return jsonify({"error": "La imagen de reemplazo debe ser una imagen válida"}), 400

        target_ext = target_filename.rsplit(".", 1)[1].lower() if "." in target_filename else ""
        replace_ext = replacement.filename.rsplit(".", 1)[1].lower() if "." in replacement.filename else ""
        if target_ext and replace_ext and target_ext != replace_ext:
            return jsonify({"error": "La imagen de reemplazo debe conservar la extensión original"}), 400

        if not os.path.exists(target_path):
            return jsonify({"error": "Archivo original no encontrado"}), 400

        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        replacement.save(target_path)

        imagenes_reemplazadas.append({
            "file_path": target_path,
            "filename": target_filename,
            "anterior": target_entry.get("original_name"),
            "nuevo": replacement.filename
        })
        target_entry["original_name"] = replacement.filename

    imagenes_agregadas = []
    history_entries = []
    new_files = request.files.getlist("file")
    for file in new_files:
        if not file or not file.filename:
            continue
        if not is_allowed_extension(file.filename):
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

        files_list.append({
            "filename": filename,
            "original_name": file.filename,
            "file_path": file_path
        })

        imagenes_agregadas.append({
            "file_path": file_path,
            "filename": filename,
            "original_name": file.filename
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
    
    # Detectar cambios
    cambios = {}
    if tipo_servicio and tipo_servicio != solicitud.get("tipo_servicio"):
        cambios["tipo_servicio"] = {"viejo": solicitud.get("tipo_servicio"), "nuevo": tipo_servicio}
    if nombre_proyecto and nombre_proyecto != solicitud.get("nombre_proyecto"):
        cambios["nombre_proyecto"] = {"viejo": solicitud.get("nombre_proyecto"), "nuevo": nombre_proyecto}
    if norma and norma != solicitud.get("norma"):
        cambios["norma"] = {"viejo": solicitud.get("norma"), "nuevo": norma}
    if num_skus and num_skus != solicitud.get("num_skus"):
        cambios["num_skus"] = {"viejo": solicitud.get("num_skus"), "nuevo": num_skus}
    if medidas and medidas != solicitud.get("medidas"):
        cambios["medidas"] = {"viejo": solicitud.get("medidas"), "nuevo": medidas}
    if prioridad and prioridad != solicitud.get("prioridad"):
        cambios["prioridad"] = {"viejo": solicitud.get("prioridad"), "nuevo": prioridad}
    if importador and importador != solicitud.get("importador"):
        cambios["importador"] = {"viejo": solicitud.get("importador"), "nuevo": importador}
    if marca and marca != solicitud.get("marca"):
        cambios["marca"] = {"viejo": solicitud.get("marca"), "nuevo": marca}
    if pais_origen and pais_origen != solicitud.get("pais_origen"):
        cambios["pais_origen"] = {"viejo": solicitud.get("pais_origen"), "nuevo": pais_origen}
    if contenido and contenido != solicitud.get("contenido"):
        cambios["contenido"] = {"viejo": solicitud.get("contenido"), "nuevo": contenido}
    
    if not cambios and not imagenes_reemplazadas and not imagenes_agregadas:
        return jsonify({"error": "No hay cambios que guardar"}), 400
    
    # Actualizar solicitud
    if tipo_servicio:
        solicitud["tipo_servicio"] = tipo_servicio
    if nombre_proyecto:
        solicitud["nombre_proyecto"] = nombre_proyecto
    if norma:
        solicitud["norma"] = norma
    if num_skus:
        solicitud["num_skus"] = num_skus
    if medidas:
        solicitud["medidas"] = medidas
    if prioridad:
        solicitud["prioridad"] = prioridad
    if importador:
        solicitud["importador"] = importador
    if marca:
        solicitud["marca"] = marca
    if pais_origen:
        solicitud["pais_origen"] = pais_origen
    if contenido:
        solicitud["contenido"] = contenido
    
    # Agregar al historial
    historial = solicitud.setdefault("historial", [])
    historial.append({
        "tipo": "edicion_cliente",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "usuario": username,
        "comentario": comentario_edicion,
        "cambios": cambios,
        "imagenes_reemplazadas": imagenes_reemplazadas,
        "imagenes_agregadas": imagenes_agregadas
    })
    
    # Incrementar ciclo en los assignments vinculados
    for assignment in assignments:
        if assignment.get("folio") == folio:
            ciclo_actual = normalize_cycle_value(assignment.get("ciclo_actual", 1))
            assignment["ciclo_actual"] = ciclo_actual + 1
            assignment["last_edited_at"] = datetime.now(timezone.utc).isoformat()
            assignment["last_edited_by"] = username
    
    if req_index is None:
        return jsonify({"error": "Solicitud no encontrada"}), 404

    # Guardar cambios
    requests_data[req_index] = solicitud
    save_service_requests(requests_data)
    if history_entries:
        append_history(history_entries)
    save_assignments(assignments)
    
    return jsonify({
        "status": "ok",
        "message": "Solicitud actualizada correctamente",
        "ciclo_nuevo": get_max_cycle(assignments, folio)
    })


@app.route("/api/solicitud/<folio>/historial", methods=["GET"])
@login_required
def get_solicitud_historial(folio):
    """Obtener el historial completo de una solicitud"""
    username = session.get("username")
    role = normalize_role(session.get("role"))
    requests_data = load_service_requests()
    
    # Buscar la solicitud
    solicitud = None
    for r in requests_data:
        if r.get("folio") == folio:
            # Verificar permiso: cliente solo ve su propia
            if role == ROLE_CLIENTE and r.get("client") != username:
                return jsonify({"error": "No autorizado"}), 403
            solicitud = r
            break
    
    if solicitud is None:
        return jsonify({"error": "Solicitud no encontrada"}), 404
    
    # Obtener assignments vinculados para calcular cambios de estado
    assignments = load_assignments()
    linked = [a for a in assignments if a.get("folio") == folio]
    
    # Función para calcular estado a partir de statuses
    def calc_status(statuses):
        if not statuses:
            return "PENDIENTE"
        if all(s in {STATUS_ACCEPTED, STATUS_REJECTED} for s in statuses):
            return "FINALIZADO"
        if any(s == STATUS_IN_REVIEW for s in statuses):
            return "EN REVISIÓN"
        if any(s == STATUS_ASSIGNED for s in statuses):
            return "EN PROCESO"
        return "PENDIENTE"
    
    # Construir historial con evento inicial
    historial_formateado = []
    
    # Evento inicial: Solicitud recibida
    created_at = solicitud.get("created_at")
    if created_at:
        try:
            if 'T' in created_at:
                dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            else:
                dt = datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S")
            fecha_str = dt.strftime("%Y-%m-%d %H:%M")
        except:
            fecha_str = created_at
    else:
        fecha_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    
    historial_formateado.append({
        "id": 0,
        "tipo": "evento",
        "fecha": fecha_str,
        "autor": "Sistema",
        "rol": "system",
        "icono": "<img src='/static/document.svg' style='width:16px; height:16px;'>",
        "texto": f"Solicitud {folio} recibida",
        "estatus_anterior": None,
        "estatus_nuevo": "PENDIENTE"
    })
    
    # Generar eventos de cambio de estado a partir de assignments
    if linked:
        # Encontrar cuando el estado cambió a "EN PROCESO" (primer assignment)
        first_assignment = min(linked, key=lambda a: parse_iso_date(a.get("assigned_at")) or datetime.min)
        if first_assignment.get("assigned_at"):
            try:
                if 'T' in first_assignment.get("assigned_at", ""):
                    dt = datetime.fromisoformat(first_assignment.get("assigned_at").replace('Z', '+00:00'))
                else:
                    dt = datetime.strptime(first_assignment.get("assigned_at"), "%Y-%m-%d %H:%M:%S")
                fecha_str = dt.strftime("%Y-%m-%d %H:%M")
                historial_formateado.append({
                    "id": len(historial_formateado),
                    "tipo": "evento",
                    "fecha": fecha_str,
                    "autor": "Sistema",
                    "rol": "system",
                    "icono": "🔄",
                    "texto": "Cambio de estatus",
                    "estatus_anterior": "PENDIENTE",
                    "estatus_nuevo": "EN PROCESO"
                })
            except:
                pass
        
        # Buscar cambios adicionales de estado
        # Si hay algún assignment en revisión, generar evento
        in_review = [a for a in linked if normalize_status(a.get("status"), a.get("assigned_to")) == STATUS_IN_REVIEW]
        if in_review:
            review_assignment = min(in_review, key=lambda a: parse_iso_date(a.get("status_updated_at")) or datetime.min)
            if review_assignment.get("status_updated_at"):
                try:
                    if 'T' in review_assignment.get("status_updated_at", ""):
                        dt = datetime.fromisoformat(review_assignment.get("status_updated_at").replace('Z', '+00:00'))
                    else:
                        dt = datetime.strptime(review_assignment.get("status_updated_at"), "%Y-%m-%d %H:%M:%S")
                    fecha_str = dt.strftime("%Y-%m-%d %H:%M")
                    historial_formateado.append({
                        "id": len(historial_formateado),
                        "tipo": "evento",
                        "fecha": fecha_str,
                        "autor": review_assignment.get("status_updated_by", "Sistema"),
                        "rol": "ejecutivo",
                        "icono": "🔄",
                        "texto": "Cambio de estatus",
                        "estatus_anterior": "EN PROCESO",
                        "estatus_nuevo": "EN REVISIÓN"
                    })
                except:
                    pass
        
        # Si hay algún assignment finalizado, generar evento
        finalized = [a for a in linked if normalize_status(a.get("status"), a.get("assigned_to")) in {STATUS_ACCEPTED, STATUS_REJECTED}]
        if finalized:
            final_assignment = min(finalized, key=lambda a: parse_iso_date(a.get("status_updated_at")) or datetime.min)
            if final_assignment.get("status_updated_at"):
                try:
                    if 'T' in final_assignment.get("status_updated_at", ""):
                        dt = datetime.fromisoformat(final_assignment.get("status_updated_at").replace('Z', '+00:00'))
                    else:
                        dt = datetime.strptime(final_assignment.get("status_updated_at"), "%Y-%m-%d %H:%M:%S")
                    fecha_str = dt.strftime("%Y-%m-%d %H:%M")
                    
                    # Determinar estatus anterior
                    estatus_anterior = "EN PROCESO"
                    if in_review:
                        estatus_anterior = "EN REVISIÓN"
                    
                    historial_formateado.append({
                        "id": len(historial_formateado),
                        "tipo": "evento",
                        "fecha": fecha_str,
                        "autor": final_assignment.get("status_updated_by", "Sistema"),
                        "rol": "ejecutivo",
                        "icono": "🔄",
                        "texto": "Cambio de estatus",
                        "estatus_anterior": estatus_anterior,
                        "estatus_nuevo": "FINALIZADO"
                    })
                except:
                    pass
    
    # Agregar entradas del historial
    historial_raw = solicitud.get("historial", [])
    for idx, entry in enumerate(historial_raw, start=1):
        if entry.get("tipo") == "edicion_cliente":
            historial_formateado.append({
                "id": len(historial_formateado),
                "tipo": "comentario",
                "fecha": entry.get("timestamp", "").split("T")[0].replace("-", "-") if "T" in entry.get("timestamp", "") else entry.get("timestamp", ""),
                "autor": entry.get("usuario", "Cliente"),
                "rol": "cliente",
                "texto": entry.get("comentario", ""),
                "archivos": []
            })
        elif entry.get("tipo") == "comentario":
            archivos = normalize_comment_attachments(entry.get("archivos", []), folio)
            historial_formateado.append({
                "id": len(historial_formateado),
                "tipo": "comentario",
                "fecha": entry.get("timestamp", ""),
                "autor": entry.get("autor", "Usuario"),
                "rol": entry.get("rol", "cliente"),
                "texto": entry.get("texto", ""),
                "archivos": archivos
            })
        elif entry.get("tipo") == "cambio_estatus":
            historial_formateado.append({
                "id": len(historial_formateado),
                "tipo": "evento",
                "fecha": entry.get("timestamp", ""),
                "autor": entry.get("usuario", "Supervisor"),
                "rol": entry.get("rol", "supervisor"),
                "icono": "🔄",
                "texto": f"Cambio de estatus",
                "estatus_anterior": entry.get("estatus_anterior"),
                "estatus_nuevo": entry.get("estatus_nuevo")
            })
    
    return jsonify({"historial": historial_formateado})


@app.route("/api/solicitud/<folio>/comentarios", methods=["POST"])
@login_required
def add_solicitud_comentario(folio):
    """Agregar un comentario a una solicitud"""
    username = session.get("username")
    role = normalize_role(session.get("role"))
    requests_data = load_service_requests()
    
    # Buscar la solicitud
    req_index = None
    solicitud = None
    for i, r in enumerate(requests_data):
        if r.get("folio") == folio:
            # Verificar permiso: cliente solo comenta la suya, supervisor cualquiera
            if role == ROLE_CLIENTE and r.get("client") != username:
                return jsonify({"error": "No autorizado"}), 403
            solicitud = r
            req_index = i
            break
    
    if solicitud is None:
        return jsonify({"error": "Solicitud no encontrada"}), 404
    
    data = request.get_json() or {}
    texto = data.get("texto", "").strip()
    archivos = normalize_comment_attachments(data.get("archivos", []), folio)
    
    if not texto and not archivos:
        return jsonify({"error": "Comentario vacío"}), 400
    
    # Crear entrada de historial
    historial = solicitud.setdefault("historial", [])
    historial.append({
        "id": len(historial),
        "tipo": "comentario",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "usuario": username,
        "autor": username,
        "rol": role,
        "texto": texto,
        "archivos": archivos
    })
    
    if req_index is None:
        return jsonify({"error": "Solicitud no encontrada"}), 404

    # Guardar
    requests_data[req_index] = solicitud
    save_service_requests(requests_data)
    
    return jsonify({"status": "ok", "message": "Comentario agregado"})


@app.route("/api/solicitud/<folio>/adjuntos", methods=["POST"])
@login_required
def upload_solicitud_attachments(folio):
    """Subir adjuntos para comentarios de una solicitud"""
    username = session.get("username")
    role = normalize_role(session.get("role"))
    requests_data = load_service_requests()

    solicitud = next((r for r in requests_data if r.get("folio") == folio), None)
    if not solicitud:
        return jsonify({"error": "Solicitud no encontrada"}), 404

    if not can_access_solicitud(solicitud, role, username):
        return jsonify({"error": "No autorizado"}), 403

    files = request.files.getlist("files")
    if not files:
        single = request.files.get("file")
        if single:
            files = [single]

    if not files:
        return jsonify({"error": "No se enviaron archivos"}), 400

    attachment_folder = get_attachment_folder_for_solicitud(solicitud, folio)
    uploaded = []

    for file_obj in files:
        if not file_obj or not file_obj.filename:
            continue

        original_name = os.path.basename(file_obj.filename)
        if not is_allowed_extension(original_name):
            return jsonify({"error": f"Extensión no permitida: {original_name}"}), 400

        base_name, extension = os.path.splitext(original_name)
        safe_base = sanitize_filename(base_name) or "archivo"
        extension = extension.lower()

        stored_name = (
            f"{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_"
            f"{secrets.token_hex(6)}_{safe_base}{extension}"
        )
        full_path = os.path.join(attachment_folder, stored_name)
        file_obj.save(full_path)

        size_bytes = os.path.getsize(full_path)
        attachment_id = secrets.token_hex(10)
        uploaded.append({
            "id": attachment_id,
            "nombre": original_name,
            "ext": extension.lstrip("."),
            "size": format_file_size(size_bytes),
            "size_bytes": size_bytes,
            "stored_name": stored_name,
            "file_path": full_path,
            "url": url_for("download_solicitud_attachment", folio=folio, attachment_id=attachment_id)
        })

    if not uploaded:
        return jsonify({"error": "No se recibieron adjuntos válidos"}), 400

    return jsonify({"status": "ok", "archivos": uploaded})


@app.route("/api/solicitud/<folio>/adjuntos/<attachment_id>", methods=["GET"])
@login_required
def download_solicitud_attachment(folio, attachment_id):
    """Descargar adjunto ligado a comentarios de una solicitud"""
    username = session.get("username")
    role = normalize_role(session.get("role"))
    requests_data = load_service_requests()

    solicitud = next((r for r in requests_data if r.get("folio") == folio), None)
    if not solicitud:
        return jsonify({"error": "Solicitud no encontrada"}), 404

    if not can_access_solicitud(solicitud, role, username):
        return jsonify({"error": "No autorizado"}), 403

    attachment = None
    for entry in solicitud.get("historial", []):
        if entry.get("tipo") != "comentario":
            continue
        for file_data in entry.get("archivos", []):
            if not isinstance(file_data, dict):
                continue
            if str(file_data.get("id", "")).strip() == attachment_id:
                attachment = file_data
                break
        if attachment:
            break

    if not attachment:
        return jsonify({"error": "Adjunto no encontrado"}), 404

    file_path = str(attachment.get("file_path", "")).strip()
    if not file_path or not os.path.exists(file_path):
        return jsonify({"error": "Archivo no disponible"}), 404

    directory = os.path.dirname(file_path)
    filename = os.path.basename(file_path)
    download_name = str(attachment.get("nombre") or filename)
    return send_from_directory(directory, filename, as_attachment=True, download_name=download_name, max_age=0)


@app.route("/api/solicitud/<folio>/estatus", methods=["POST"])
@login_required
@role_required(ROLE_SUPERVISOR)
def update_solicitud_estatus(folio):
    """Cambiar el estatus de una solicitud (solo supervisor)"""
    username = session.get("username")
    requests_data = load_service_requests()
    
    # Buscar la solicitud
    req_index = None
    solicitud = None
    for i, r in enumerate(requests_data):
        if r.get("folio") == folio:
            solicitud = r
            req_index = i
            break
    
    if solicitud is None:
        return jsonify({"error": "Solicitud no encontrada"}), 404
    
    data = request.get_json() or {}
    nuevo_estatus = data.get("estatus", "").strip().upper()
    comentario = data.get("comentario", "").strip()
    
    estatus_validos = ["PENDIENTE", "EN PROCESO", "EN REVISIÓN", "FINALIZADO", "CANCELADO"]
    if nuevo_estatus not in estatus_validos:
        return jsonify({"error": "Estatus inválido"}), 400
    
    estatus_anterior = solicitud.get("estatus", "PENDIENTE")
    if estatus_anterior == nuevo_estatus:
        return jsonify({"error": "El estatus es el mismo"}), 400
    
    # Actualizar solicitud
    solicitud["estatus"] = nuevo_estatus
    
    # Crear entrada de historial
    historial = solicitud.setdefault("historial", [])
    historial.append({
        "tipo": "cambio_estatus",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "usuario": username,
        "rol": "supervisor",
        "texto": comentario,
        "estatus_anterior": estatus_anterior,
        "estatus_nuevo": nuevo_estatus
    })
    
    if req_index is None:
        return jsonify({"error": "Solicitud no encontrada"}), 404

    # Guardar
    requests_data[req_index] = solicitud
    save_service_requests(requests_data)
    
    return jsonify({"status": "ok", "message": "Estatus actualizado", "nuevo_estatus": nuevo_estatus})


@app.route("/api/assignment/<file_path>/action", methods=["POST"])
@login_required
def add_assignment_action(file_path):
    """Agregar una acción al historial (solo ejecutivo)"""
    role = normalize_role(session.get("role"))
    if role not in {ROLE_EJECUTIVO, ROLE_SUPERVISOR}:
        return jsonify({"error": "No autorizado"}), 403
    
    action_type = request.json.get("action_type")  # "cambio_estado", "comentario", etc.
    comentario = request.json.get("comentario", "")
    nuevo_estado = request.json.get("nuevo_estado")
    
    assignments = load_assignments()
    assignment = None
    for a in assignments:
        if a.get("file_path") == file_path:
            assignment = a
            break
    
    if not assignment:
        return jsonify({"error": "Assignment no encontrado"}), 404
    
    # Crear entrada de historial
    historial = assignment.setdefault("historial_acciones", [])
    entrada = {
        "tipo": action_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "usuario": session.get("username"),
        "comentario": comentario
    }
    
    # Si es cambio de estado, incrementar ciclo
    if action_type == "cambio_estado" and nuevo_estado:
        entrada["nuevo_estado"] = nuevo_estado
        assignment["status"] = nuevo_estado
        assignment["status_updated_at"] = datetime.now(timezone.utc).isoformat()
        assignment["status_updated_by"] = session.get("username")
        
        # Incrementar ciclo
        ciclo_actual = assignment.get("ciclo_actual", 1)
        assignment["ciclo_actual"] = ciclo_actual + 1
    
    historial.append(entrada)
    save_assignments(assignments)
    
    return jsonify({"status": "ok", "ciclo_nuevo": assignment.get("ciclo_actual", 1)})


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
    
    # Supervisor y Bosch: pueden servir archivos de cualquier cliente
    if role in {ROLE_SUPERVISOR, ROLE_BOSCH}:
        config = load_config()
        for client_name, client_data in config.get("clients", {}).items():
            folder = client_data.get("folder")
            if not folder:
                continue
            file_path = os.path.join(folder, filename)
            if os.path.exists(file_path):
                return send_from_directory(folder, filename)
    
    # Cliente/Ejecutivo: solo puede servir sus propios archivos
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
    
    # Supervisor y Bosch: pueden acceder a todos los archivos
    if role in {ROLE_SUPERVISOR, ROLE_BOSCH}:
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


def can_access_file_path(file_path: str, role: str, username: Optional[str]) -> bool:
    if not file_path:
        return False

    if role in {ROLE_SUPERVISOR, ROLE_BOSCH}:
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

    if role == ROLE_BOSCH:
        images = list_images(username, query or None, date_from, date_to, all_clients=False)
        bosch_items = []
        for img in images:
            status = normalize_status(img.get("status"), None)
            bosch_items.append({
                "code": (img.get("folio") or "").upper(),
                "name": img.get("name", ""),
                "status": status,
                "type": "imagen" if img.get("is_image") else "documento",
                "date": img.get("modified").isoformat() if img.get("modified") else "",
                "url": img.get("url", ""),
                "ext": img.get("ext", "")
            })

        return render_template(
            "bosch_galery.html",
            username=username,
            items=bosch_items
        )

    back_url = url_for("index")
    if role == ROLE_SUPERVISOR:
        back_url = url_for("solicitudes")
    elif role == ROLE_EJECUTIVO:
        back_url = url_for("ejecutivo_panel")
    
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
        current_folder=get_upload_folder(username),
        back_url=back_url
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
    assignments = load_assignments()
    cycle_by_folio = {}
    for assignment in assignments:
        folio = assignment.get("folio")
        if not folio:
            continue
        cycle_by_folio[folio] = max(
            cycle_by_folio.get(folio, 1),
            normalize_cycle_value(assignment.get("ciclo_actual", 1))
        )
    comments_by_folio = {
        folio: count_client_comments(request_data)
        for folio, request_data in requests_by_folio.items()
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
                mtime = datetime.fromtimestamp(stats.st_mtime, tz=timezone.utc)
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
                "nombre_proyecto": request_data.get("nombre_proyecto") if request_data else "",
                "assigned_to": entry.get("assigned_to") if entry.get("assigned_to") else None,
                "ciclo_actual": cycle_by_folio.get(folio, 1),
                "comentarios_cliente": comments_by_folio.get(folio, 0)
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

    # Incluir solicitudes sin archivos adjuntos (solo formulario de texto)
    for folio, request_data in requests_by_folio.items():
        if folio in grouped:
            continue
        client = request_data.get("client", "")
        if client_filter and client != client_filter:
            continue
        try:
            created_at_str = request_data.get("created_at", "")
            latest_dt = (
                datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
                if created_at_str
                else datetime.now(timezone.utc)
            )
        except Exception:
            latest_dt = datetime.now(timezone.utc)
        grouped[folio] = {
            "folio": folio,
            "client": client,
            "files": [],
            "latest_modified": latest_dt,
            "image_count": 0,
            "document_count": 0,
            "assigned_count": 0,
            "norma": request_data.get("norma", ""),
            "nombre_proyecto": request_data.get("nombre_proyecto", ""),
            "assigned_to": None,
            "ciclo_actual": cycle_by_folio.get(folio, 1),
            "comentarios_cliente": comments_by_folio.get(folio, 0),
        }

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
    requests_by_folio = {
        r.get("folio"): r for r in load_service_requests() if r.get("folio")
    }
    cycle_by_folio = {}
    for assignment in my_assignments:
        folio = assignment.get("folio")
        if not folio:
            continue
        cycle_by_folio[folio] = max(
            cycle_by_folio.get(folio, 1),
            normalize_cycle_value(assignment.get("ciclo_actual", 1))
        )
    
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
            mtime = datetime.fromtimestamp(stats.st_mtime, tz=timezone.utc)
            
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
                "ciclo_actual": cycle_by_folio.get(assignment.get("folio"), 1),
                "comentarios_cliente": count_client_comments(requests_by_folio.get(assignment.get("folio"))),
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
