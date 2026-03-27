from flask import Flask, request, render_template, jsonify, send_from_directory, redirect, url_for, abort, session, send_file
import os
import json
from datetime import datetime, timezone, timedelta
import re
import secrets
import hmac
import time
import logging
from threading import Lock
from functools import wraps
from werkzeug.security import check_password_hash
from typing import Optional

# =========================
# PROTECCIÓN
# =========================
_login_attempts: dict = {}   # {ip: {"count": int, "locked_until": float, "last_attempt": float}}
_login_lock = Lock()

LOGIN_MAX_ATTEMPTS = 4        # intentos antes de bloquear
LOGIN_LOCKOUT_SECONDS = 300   # 5 minutos de bloqueo
LOGIN_WINDOW_SECONDS = 600    # ventana de 10 min para contar intentos

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
_security_log = logging.getLogger("security")


def _get_client_ip() -> str:
    """Obtiene la IP real del cliente respetando proxies confiables."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _is_ip_locked(ip: str) -> tuple[bool, int]:
    """Devuelve (bloqueado, segundos_restantes)."""
    with _login_lock:
        data = _login_attempts.get(ip)
        if not data:
            return False, 0
        locked_until = data.get("locked_until", 0)
        if locked_until and time.time() < locked_until:
            remaining = int(locked_until - time.time())
            return True, remaining
        return False, 0


def _record_failed_attempt(ip: str, username: str) -> int:
    """Registra un intento fallido. Devuelve intentos restantes antes de bloqueo."""
    now = time.time()
    with _login_lock:
        data = _login_attempts.setdefault(ip, {"count": 0, "locked_until": 0, "last_attempt": 0})
        # Resetear contador si la ventana de tiempo expiró
        if now - data["last_attempt"] > LOGIN_WINDOW_SECONDS:
            data["count"] = 0
        data["count"] += 1
        data["last_attempt"] = now
        remaining = max(0, LOGIN_MAX_ATTEMPTS - data["count"])
        if data["count"] >= LOGIN_MAX_ATTEMPTS:
            data["locked_until"] = now + LOGIN_LOCKOUT_SECONDS
            _security_log.warning(
                "IP BLOQUEADA tras %d intentos fallidos | ip=%s usuario='%s'",
                data["count"], ip, username
            )
        else:
            _security_log.warning(
                "Intento fallido de login | ip=%s usuario='%s' intentos=%d",
                ip, username, data["count"]
            )
        return remaining


def _clear_attempts(ip: str):
    with _login_lock:
        _login_attempts.pop(ip, None)


def _generate_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def _validate_csrf(token: str) -> bool:
    expected = session.get("csrf_token")
    if not expected or not token:
        return False
    return hmac.compare_digest(expected, token)

def _is_production_env() -> bool:
    env = str(os.environ.get("APP_ENV") or os.environ.get("FLASK_ENV") or "").strip().lower()
    return env in {"prod", "production"}


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(str(raw).strip())
        return value if value > 0 else default
    except ValueError:
        return default


def _load_secret_key() -> str:
    secret_key = str(os.environ.get("APP_SECRET_KEY", "")).strip()
    if secret_key and secret_key.lower() != "change-me" and len(secret_key) >= 32:
        return secret_key

    if _is_production_env():
        raise RuntimeError(
            "APP_SECRET_KEY no es segura o no esta definida. "
            "Configura una clave aleatoria de al menos 32 caracteres en produccion."
        )

    # En desarrollo permitimos una clave temporal para no bloquear el arranque.
    _security_log.warning(
        "APP_SECRET_KEY no configurada/segura. Se usa una clave temporal y las sesiones "
        "se invalidaran al reiniciar."
    )
    return secrets.token_hex(32)

app = Flask(__name__)
app.secret_key = _load_secret_key()
app.config.update(
    MAX_CONTENT_LENGTH=500 * 1024 * 1024,  # 500 MB
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=os.environ.get("SESSION_COOKIE_SAMESITE", "Lax"),
    SESSION_COOKIE_SECURE=_env_bool("SESSION_COOKIE_SECURE", _is_production_env()),
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=_env_int("SESSION_TTL_MINUTES", 60)),
)

CONFIG_FILE = "config.json"
USERS_FILE = "Users.json"
HISTORY_FILE = "upload_history.json"
ASSIGNMENTS_FILE = "assignments.json"
SERVICE_REQUESTS_FILE = "service_requests.json"
AUDIT_TRAIL_FILE = "audit_trail.json"
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
REQ_STATUS_PENDING = "PENDIENTE"
REQ_STATUS_IN_PROGRESS = "EN PROCESO"
REQ_STATUS_MISSING_INFO = "FALTA INFORMACION"
REQ_STATUS_REJECTED = "RECHAZADO"
REQ_STATUS_FINISHED = "FINALIZADO"
REQ_STATUS_CANCELED = "CANCELADO"
VALID_STATUSES = {
    STATUS_UPLOADED,
    STATUS_ASSIGNED,
    STATUS_IN_REVIEW,
    STATUS_ACCEPTED,
    STATUS_REJECTED
}
VALID_REQUEST_STATUSES = {
    REQ_STATUS_PENDING,
    REQ_STATUS_IN_PROGRESS,
    REQ_STATUS_MISSING_INFO,
    REQ_STATUS_REJECTED,
    REQ_STATUS_FINISHED,
    REQ_STATUS_CANCELED,
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


def save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=4, ensure_ascii=False)


def build_admin_users_list():
    """Build unified admin user list from config.json and Users.json."""
    users_list = []

    config = load_config()
    clients = config.get("clients", {})
    for username, data in clients.items():
        users_list.append({
            "username": username,
            "display_name": data.get("nombre") or username,
            "role": data.get("role", "Cliente"),
            "folder": data.get("folder", ""),
            "normas": data.get("normas", ""),
            "empresa": data.get("empresa", ""),
            "email": data.get("email", ""),
            "telefono": data.get("telefono", ""),
            "source": "config",
        })

    for user in load_users():
        username = str(user.get("FIRMA") or "").strip()
        if not username:
            continue
        users_list.append({
            "username": username,
            "display_name": str(user.get("NOMBRE") or username).strip(),
            "role": user.get("PUESTO", "Ejecutivo"),
            "folder": "",
            "normas": user.get("NORMAS", "") or "",
            "empresa": user.get("EMPRESA", "") or "",
            "email": user.get("CORREO", "") or "",
            "telefono": user.get("TELEFONO", "") or "",
            "source": "users",
        })

    return users_list


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
    if not filename:
        return False
    safe_name = os.path.basename(str(filename)).strip()
    if not safe_name:
        return False
    return "." in safe_name and bool(safe_name.rsplit(".", 1)[1].strip())


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


def normalize_service_token(value: Optional[str]) -> str:
    token = str(value or "").strip().lower()
    token = token.replace("á", "a").replace("é", "e").replace("í", "i")
    token = token.replace("ó", "o").replace("ú", "u").replace("ü", "u")
    token = token.replace("ñ", "n")
    return re.sub(r"\s+", "", token)


def requires_design_details(tipo_servicio_string: Optional[str]) -> bool:
    if not tipo_servicio_string:
        return False
    tokens = re.split(r'[;,]', str(tipo_servicio_string))
    return any(normalize_service_token(token) == "diseno" for token in tokens)


MEDIDAS_REQUIRED_NORMA_PREFIXES = (
    "NOM-051",
    "NOM-189",
    "NOM-141",
    "NOM-142",
)


def requires_medidas_surface(normas_string: Optional[str]) -> bool:
    """Returns True when selected normas require surface measurements."""
    normas = parse_normas(normas_string)
    for norma in normas:
        if any(norma.startswith(prefix) for prefix in MEDIDAS_REQUIRED_NORMA_PREFIXES):
            return True
    return False


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


def load_audit_trail():
    """Carga el registro de auditoría."""
    if not os.path.exists(AUDIT_TRAIL_FILE):
        return []
    try:
        with open(AUDIT_TRAIL_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def save_audit_trail(data):
    """Guarda el registro de auditoría."""
    with open(AUDIT_TRAIL_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def log_audit_trail(action: str, user: str, details: Optional[dict] = None):
    """
    Registra una acción crítica en el audit trail.
    
    Args:
        action: Tipo de acción (e.g., 'asign_folio', 'change_status', 'create_user')
        user: Usuario que realizó la acción
        details: Información adicional sobre la acción
    """
    if details is None:
        details = {}
    try:
        audit = load_audit_trail()
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "user": str(user or "unknown"),
            "ip": _get_client_ip(),
            "details": details
        }
        audit.append(entry)
        save_audit_trail(audit)
        _security_log.info(
            "AUDIT | action=%s | user=%s | ip=%s | details=%s",
            action, user, entry["ip"], json.dumps(details)
        )
    except Exception as e:
        _security_log.error("Error registrando audit trail: %s", str(e))


def get_comments_for_assignment(assignment: dict) -> list[dict]:
    """Obtiene comentarios de una asignacion a partir del historial de la solicitud."""
    if not isinstance(assignment, dict):
        return []

    folio = assignment.get("folio")
    if not folio:
        return []

    requests_data = load_service_requests()
    solicitud = next((r for r in requests_data if r.get("folio") == folio), None)
    if not solicitud:
        return []

    comments = []
    for entry in solicitud.get("historial", []):
        if not isinstance(entry, dict) or entry.get("tipo") != "comentario":
            continue

        comments.append({
            "author": entry.get("autor") or entry.get("usuario") or "Usuario",
            "role": normalize_role(entry.get("rol")) if entry.get("rol") else "",
            "text": entry.get("texto", ""),
            "timestamp": entry.get("timestamp")
        })

    return comments


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


def get_deliverable_folder_for_solicitud(solicitud: dict, folio: str) -> str:
    client_username = solicitud.get("client")
    base_folder = get_upload_folder(client_username)
    folder = os.path.join(base_folder, "_entregables", folio)
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


def normalize_request_status(value: Optional[str]) -> str:
    if not value:
        return ""
    normalized = str(value).strip().upper().replace("Á", "A")
    if normalized == "FALTA INFORMACION":
        return REQ_STATUS_MISSING_INFO
    if normalized == "RECHAZADO":
        return REQ_STATUS_REJECTED
    return normalized


def request_status_from_assignments(statuses: list[str]) -> str:
    if not statuses:
        return REQ_STATUS_PENDING
    if statuses and all(s == STATUS_ACCEPTED for s in statuses):
        return REQ_STATUS_FINISHED
    if statuses and all(s == STATUS_REJECTED for s in statuses):
        return REQ_STATUS_REJECTED
    if any(s == STATUS_ACCEPTED for s in statuses) and any(s == STATUS_REJECTED for s in statuses):
        return REQ_STATUS_MISSING_INFO
    if any(s == STATUS_REJECTED for s in statuses):
        return REQ_STATUS_MISSING_INFO
    if any(s == STATUS_IN_REVIEW for s in statuses):
        return REQ_STATUS_IN_PROGRESS
    if any(s == STATUS_ASSIGNED for s in statuses):
        return REQ_STATUS_IN_PROGRESS
    return REQ_STATUS_PENDING


def resolved_request_status(request_data: dict, linked_assignments: list[dict]) -> str:
    explicit_status = normalize_request_status(request_data.get("estatus"))
    if explicit_status in VALID_REQUEST_STATUSES:
        return explicit_status
    linked_statuses = [normalize_status(a.get("status"), a.get("assigned_to")) for a in linked_assignments]
    return request_status_from_assignments(linked_statuses)


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


def list_images(username=None, name_filter=None, date_from=None, date_to=None, all_clients=False, role=None):
    entries = []
    assignments = load_assignments()
    assignments_by_path = {
        a.get("file_path"): a for a in assignments if a.get("file_path")
    }
    existing_folios = {a.get("folio") for a in assignments if a.get("folio")}
    client_info = get_client(username) if username else None
    is_bosch_user = normalize_role((client_info or {}).get("role")) == ROLE_BOSCH
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
    elif role == ROLE_EJECUTIVO:
        # Ejecutivo: listar imágenes de sus folios asignados
        ejecutivo_assignments = [
            a for a in assignments
            if str(a.get("assigned_to", "")).strip() == username and a.get("file_path")
        ]
        
        for assignment in ejecutivo_assignments:
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
                    folio = None if is_bosch_user else generate_folio(existing_folios)
                    if folio:
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


def _default_post_login_route(role: str) -> str:
    return url_for("welcome") if role == ROLE_CLIENTE else url_for("index")


def _is_next_allowed_for_role(next_url: Optional[str], role: str) -> bool:
    if not is_safe_next(next_url):
        return False

    assert next_url is not None
    restricted_prefixes = {
        "/admin": {ROLE_SUPERVISOR},
        "/dashboard-admin": {ROLE_SUPERVISOR},
        "/dashboard-ejecutivo": {ROLE_EJECUTIVO},
        "/dashboard": {ROLE_CLIENTE},
    }

    for prefix, allowed_roles in restricted_prefixes.items():
        if next_url == prefix or next_url.startswith(prefix + "/"):
            return role in allowed_roles

    return True


# Prevenir caché de páginas protegidas
@app.after_request
def add_no_cache_headers(response):
    """Añade headers de cache y seguridad HTTP en todas las respuestas."""
    if 'Cache-Control' not in response.headers:
        # No cachear páginas HTML para prevenir acceso después de logout
        if response.content_type and 'text/html' in response.content_type:
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, private'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'

    # Security headers base
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')

    # CSP conservadora para reducir XSS sin romper templates existentes.
    response.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self'; "
        "base-uri 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'self'; "
        "img-src 'self' data: blob:; "
        "font-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; "
        "form-action 'self'"
    )

    if _is_production_env() and request.is_secure:
        response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
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
        return redirect(url_for("dashboard_admin"))
    elif role == ROLE_EJECUTIVO:
        return redirect(url_for("dashboard_ejecutivo"))
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
        return redirect(url_for("dashboard_admin"))
    if role == ROLE_EJECUTIVO:
        return redirect(url_for("dashboard_ejecutivo"))
    if role == ROLE_BOSCH:
        return redirect(url_for("index"))

    return render_template("welcome.html", username=session.get("username"))


@app.route("/dashboard")
@login_required
@role_required(ROLE_CLIENTE)
def dashboard():
    """Vista principal del cliente con resumen de solicitudes"""
    return render_template(
        "dashboard.html",
        username=session.get("username"),
        is_admin=False,
        is_ejecutivo=False,
        ejecutivos=[]
    )


@app.route("/dashboard-ejecutivo")
@login_required
@role_required(ROLE_EJECUTIVO)
def dashboard_ejecutivo():
    """Vista principal exclusiva para ejecutivos."""
    return render_template(
        "dashboard.html",
        username=session.get("username"),
        is_admin=False,
        is_ejecutivo=True,
        ejecutivos=[]
    )


@app.route("/dashboard-admin")
@login_required
@role_required(ROLE_SUPERVISOR)
def dashboard_admin():
    """Vista principal exclusiva para administración/supervisor"""
    ejecutivos = [
        {
            "firma": item.get("firma"),
            "nombre": item.get("nombre"),
        }
        for item in get_compatible_ejecutivos(None)
        if str(item.get("puesto", "")).strip().lower() == "ejecutivo"
    ]
    return render_template(
        "dashboard.html",
        username=session.get("username"),
        is_admin=True,
        is_ejecutivo=False,
        ejecutivos=ejecutivos
    )


@app.route("/captura")
@login_required
@role_required(ROLE_CLIENTE)
def captura():
    """Formulario para crear una nueva solicitud"""
    return render_template("captura.html", username=session.get("username"))


@app.route("/editar/<folio>")
@login_required
@role_required(ROLE_CLIENTE)
def editar_solicitud_page(folio):
    """Página dedicada para edición de solicitudes del cliente."""
    username = session.get("username")
    requests_data = load_service_requests()
    solicitud = next((r for r in requests_data if r.get("folio") == folio), None)
    if not solicitud or solicitud.get("client") != username:
        abort(403)

    return render_template("editar_solicitud.html", username=username, folio=folio)


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
        back_url = url_for("dashboard_admin")
        back_label = "Volver al Dashboard"
    
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
    csrf_token = _generate_csrf_token()

    if request.method == "POST":
        ip = _get_client_ip()

        # ── 1. Verificar CSRF ──────────────────────────────────────────────
        form_csrf = request.form.get("csrf_token", "")
        if not _validate_csrf(form_csrf):
            _security_log.warning("Token CSRF inválido | ip=%s", ip)
            return render_template(
                "login.html",
                error="Solicitud inválida. Recarga la página e inténtalo de nuevo.",
                next=request.form.get("next") or request.args.get("next"),
                csrf_token=csrf_token,
            )

        # ── 2. Verificar bloqueo por IP ────────────────────────────────────
        locked, wait_seconds = _is_ip_locked(ip)
        if locked:
            minutes = (wait_seconds + 59) // 60
            return render_template(
                "login.html",
                error=f"Demasiados intentos fallidos. Espera {minutes} minuto{'s' if minutes != 1 else ''} antes de intentarlo de nuevo.",
                next=request.form.get("next") or request.args.get("next"),
                csrf_token=csrf_token,
            )

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        next_url = request.form.get("next") or request.args.get("next")

        # ── 3. Validar credenciales ────────────────────────────────────────
        client = get_client(username)
        if not client or not verify_password(client.get("password", ""), password):
            remaining = _record_failed_attempt(ip, username)
            if remaining == 0:
                minutes = (LOGIN_LOCKOUT_SECONDS + 59) // 60
                error_msg = f"Cuenta bloqueada por demasiados intentos. Espera {minutes} minuto{'s' if minutes != 1 else ''}."
            elif remaining <= 2:
                error_msg = f"Cliente o contraseña inválidos. Te quedan {remaining} intento{'s' if remaining != 1 else ''}."
            else:
                error_msg = "Cliente o contraseña inválidos."
            return render_template(
                "login.html",
                error=error_msg,
                next=next_url,
                csrf_token=csrf_token,
            )

        # ── 4. Login exitoso ───────────────────────────────────────────────
        _clear_attempts(ip)
        session.regenerate() if hasattr(session, "regenerate") else session.clear() or session.update({})
        user_role = normalize_role(client.get("role"))
        session["username"] = username
        session["role"] = user_role
        _generate_csrf_token()   # nuevo token tras login

        if _is_next_allowed_for_role(next_url, user_role):
            assert next_url is not None
            safe_next_url = next_url
        else:
            safe_next_url = _default_post_login_route(user_role)
        return redirect(safe_next_url)

    return render_template("login.html", error=None, next=request.args.get("next", ""), csrf_token=csrf_token)


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
    role = normalize_role(session.get("role"))
    is_bosch_user = role == ROLE_BOSCH
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
            if (not assignment.get("folio")) and (not is_bosch_user):
                folio = generate_folio(existing_folios)
                existing_folios.add(folio)
                assignment["folio"] = folio
        else:
            folio = None if is_bosch_user else generate_folio(existing_folios)
            if folio:
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
@role_required(ROLE_CLIENTE, ROLE_SUPERVISOR, ROLE_EJECUTIVO)
def api_solicitudes():
    username = session.get("username")
    role = normalize_role(session.get("role"))

    if request.method == "POST":
        if role != ROLE_CLIENTE:
            return jsonify({"error": "No autorizado"}), 403

        tipo_servicio = request.form.get("tipo_servicio", "").strip()
        nombre_proyecto = request.form.get("nombre_proyecto", "").strip()[:80]
        norma = request.form.get("norma", "").strip()
        num_skus = request.form.get("num_skus", "").strip()
        medidas = request.form.get("medidas", "").strip()
        prioridad = request.form.get("prioridad", "").strip()
        importador = request.form.get("importador", "").strip()[:80]
        marca = request.form.get("marca", "").strip()[:80]
        pais_origen = request.form.get("pais_origen", "").strip()[:80]
        contenido = request.form.get("contenido", "").strip()[:720]

        if not tipo_servicio or not nombre_proyecto or not prioridad:
            return jsonify({"error": "Datos incompletos"}), 400

        if requires_design_details(tipo_servicio):
            if not all([importador, marca, pais_origen, contenido]):
                return jsonify({
                    "error": "Importador, marca, pais de origen y contenido son obligatorios para el servicio de diseno"
                }), 400

        if requires_medidas_surface(norma) and not medidas:
            return jsonify({
                "error": "Medidas de superficie principal es obligatorio para NOM-051, NOM-189, NOM-141 y NOM-142"
            }), 400

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

    tipo_map = {
        "consultoria": "Consultoria",
        "constancia": "Constancia",
        "diseno": "Diseño"
    }
    modalidad_map = {"urgente": "URGENTE", "regular": "REGULAR"}

    def get_ejecutivos_for_dashboard(norma_value: Optional[str]) -> list:
        """Filtro para dashboard admin: una norma => match exacto; varias normas => match por cualquiera."""
        required_normas = parse_normas(norma_value)
        candidates = []
        for user in load_users():
            if str(user.get("PUESTO", "")).strip().lower() != "ejecutivo":
                continue
            firma = str(user.get("FIRMA") or "").strip()
            nombre = str(user.get("NOMBRE") or firma).strip()
            user_normas = parse_normas(user.get("NORMAS"))

            if not required_normas:
                candidates.append({"firma": firma, "nombre": nombre})
                continue

            # Si hay varias normas en la solicitud, ampliamos por intersección (cualquiera).
            if user_normas.intersection(required_normas):
                candidates.append({"firma": firma, "nombre": nombre})

        candidates.sort(key=lambda x: x.get("nombre", ""))
        return candidates

    requests_data = load_service_requests()
    requests_by_folio = {r.get("folio"): r for r in requests_data if r.get("folio")}
    compatible_cache = {}
    assignments = load_assignments()

    if role == ROLE_SUPERVISOR:
        client_requests = list(requests_data)
        client_assignments = list(assignments)
    elif role == ROLE_EJECUTIVO:
        client_assignments = [
            a for a in assignments
            if str(a.get("assigned_to") or "").strip() == username
        ]
        assigned_folios = {a.get("folio") for a in client_assignments if a.get("folio")}
        client_requests = [
            r for r in requests_data
            if r.get("folio") in assigned_folios
        ]
    else:
        client_requests = [r for r in requests_data if r.get("client") == username]
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
        client_username = req.get("client") or ""
        client_profile = get_client(client_username) if client_username else {}
        empresa = req.get("empresa") or (client_profile.get("empresa") if isinstance(client_profile, dict) else "") or ""
        assigned_set = {str(a.get("assigned_to") or "").strip() for a in linked if a.get("assigned_to")}
        assigned_to = None if not assigned_set else (next(iter(assigned_set)) if len(assigned_set) == 1 else "Varios")
        status_label = resolved_request_status(req, linked)

        created_at = parse_iso_date(req.get("created_at"))
        completion_dates = [parse_iso_date(a.get("status_updated_at")) for a in linked]
        completion_dates = [d for d in completion_dates if d]
        completed_at = max(completion_dates) if completion_dates else None

        # Obtener el ciclo máximo de los assignments vinculados
        ciclo_actual = get_max_cycle(linked)
        norma_value = req.get("norma") or ""
        norma_key = str(norma_value).strip().upper()
        if role == ROLE_SUPERVISOR:
            if norma_key not in compatible_cache:
                compatible_cache[norma_key] = get_ejecutivos_for_dashboard(norma_value)
            compatible_ejecutivos = compatible_cache[norma_key]
        else:
            compatible_ejecutivos = []

        solicitudes.append({
            "fecha": req.get("created_at"),
            "folio": folio,
            "client": client_username or "—",
            "empresa": empresa,
            "tipo": tipo_map.get(req.get("tipo_servicio"), req.get("tipo_servicio") or "—"),
            "modalidad": modalidad_map.get(req.get("prioridad"), (req.get("prioridad") or "").upper() or "—"),
            "proyecto": req.get("nombre_proyecto") or "—",
            "estatus": status_label,
            "assigned_to": assigned_to,
            "fechaEnvio": completed_at.isoformat() if completed_at else None,
            "ciclo": ciclo_actual,
            "norma": req.get("norma"),
            "num_skus": req.get("num_skus"),
            "medidas": req.get("medidas"),
            "prioridad": req.get("prioridad"),
            "importador": req.get("importador"),
            "marca": req.get("marca"),
            "pais_origen": req.get("pais_origen"),
            "contenido": req.get("contenido"),
            "compatible_ejecutivos": compatible_ejecutivos,
        })

    for folio, linked in assignments_by_folio.items():
        if folio in used_folios:
            continue

        assigned_set = {str(a.get("assigned_to") or "").strip() for a in linked if a.get("assigned_to")}
        assigned_to = None if not assigned_set else (next(iter(assigned_set)) if len(assigned_set) == 1 else "Varios")
        status_label = request_status_from_assignments([
            normalize_status(a.get("status"), a.get("assigned_to")) for a in linked
        ])

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
        request_data = requests_by_folio.get(folio)
        norma_value = request_data.get("norma") if request_data else ""
        norma_key = str(norma_value).strip().upper()
        if role == ROLE_SUPERVISOR:
            if norma_key not in compatible_cache:
                compatible_cache[norma_key] = get_ejecutivos_for_dashboard(norma_value)
            compatible_ejecutivos = compatible_cache[norma_key]
        else:
            compatible_ejecutivos = []

        project_hint = linked[0].get("filename") if linked else "—"
        assignment_client = linked[0].get("client") if linked else ""
        assignment_client_profile = get_client(assignment_client) if assignment_client else {}
        empresa = (assignment_client_profile.get("empresa") if isinstance(assignment_client_profile, dict) else "") or ""
        solicitudes.append({
            "fecha": created_at.isoformat() if created_at else None,
            "folio": folio,
            "client": assignment_client or "—",
            "empresa": empresa,
            "tipo": "Archivo",
            "modalidad": "REGULAR",
            "proyecto": f"Archivo: {project_hint}",
            "estatus": status_label,
            "assigned_to": assigned_to,
            "fechaEnvio": completed_at.isoformat() if completed_at else None,
            "ciclo": ciclo_actual,
            "norma": "",
            "num_skus": "",
            "medidas": "",
            "prioridad": "regular",
            "importador": "",
            "marca": "",
            "pais_origen": "",
            "contenido": "",
            "compatible_ejecutivos": compatible_ejecutivos,
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
    
    # Mantener compatibilidad con registros antiguos: si no hay estatus explícito, derivarlo de assignments.
    estatus = normalize_request_status(solicitud.get("estatus"))
    if estatus not in VALID_REQUEST_STATUSES:
        estatus = request_status_from_assignments([
            normalize_status(a.get("status"), a.get("assigned_to")) for a in linked
        ])

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
        "files": files,
        "entregable_final": solicitud.get("entregable_final")
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

    assignments = load_assignments()
    linked_assignments = [a for a in assignments if a.get("folio") == folio]
    statuses = [normalize_status(a.get("status"), a.get("assigned_to")) for a in linked_assignments]
    explicit_estatus = normalize_request_status(solicitud.get("estatus"))
    esta_finalizada = explicit_estatus == REQ_STATUS_FINISHED or (
        statuses and all(s == STATUS_ACCEPTED for s in statuses)
    )
    if esta_finalizada:
        return jsonify({"error": "No se puede editar una solicitud con estatus FINALIZADO"}), 403
    
    # Obtener datos de la edición
    tipo_servicio = request.form.get("tipo_servicio", "").strip()
    nombre_proyecto = request.form.get("nombre_proyecto", "").strip()[:80]
    norma = request.form.get("norma", "").strip()
    num_skus = request.form.get("num_skus", "").strip()
    medidas = request.form.get("medidas", "").strip()
    prioridad = request.form.get("prioridad", "").strip()
    importador = request.form.get("importador", "").strip()[:80]
    marca = request.form.get("marca", "").strip()[:80]
    pais_origen = request.form.get("pais_origen", "").strip()[:80]
    contenido = request.form.get("contenido", "").strip()[:720]
    comentario_edicion = request.form.get("comentario_edicion", "").strip()[:240]

    norma_efectiva = norma if norma else str(solicitud.get("norma", "")).strip()
    medidas_efectivas = medidas if medidas else str(solicitud.get("medidas", "")).strip()
    tipo_servicio_efectivo = tipo_servicio if tipo_servicio else str(solicitud.get("tipo_servicio", "")).strip()
    importador_efectivo = importador if importador else str(solicitud.get("importador", "")).strip()
    marca_efectiva = marca if marca else str(solicitud.get("marca", "")).strip()
    pais_origen_efectivo = pais_origen if pais_origen else str(solicitud.get("pais_origen", "")).strip()
    contenido_efectivo = contenido if contenido else str(solicitud.get("contenido", "")).strip()

    if requires_design_details(tipo_servicio_efectivo):
        if not all([importador_efectivo, marca_efectiva, pais_origen_efectivo, contenido_efectivo]):
            return jsonify({
                "error": "Importador, marca, pais de origen y contenido son obligatorios para el servicio de diseno"
            }), 400

    if requires_medidas_surface(norma_efectiva) and not medidas_efectivas:
        return jsonify({
            "error": "Medidas de superficie principal es obligatorio para NOM-051, NOM-189, NOM-141 y NOM-142"
        }), 400
    
    if not comentario_edicion:
        return jsonify({"error": "Debe proporcionar un comentario de la edición"}), 400

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
    
    # Capturar ciclo antes de incrementar para registrarlo en historial.
    ciclo_anterior = get_max_cycle(assignments, folio)

    # Agregar al historial
    historial = solicitud.setdefault("historial", [])
    historial_entry = {
        "tipo": "edicion_cliente",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "usuario": username,
        "comentario": comentario_edicion,
        "cambios": cambios,
        "imagenes_reemplazadas": imagenes_reemplazadas,
        "imagenes_agregadas": imagenes_agregadas
    }
    historial.append(historial_entry)
    
    # Incrementar ciclo en los assignments vinculados
    for assignment in assignments:
        if assignment.get("folio") == folio:
            ciclo_actual = normalize_cycle_value(assignment.get("ciclo_actual", 1))
            assignment["ciclo_actual"] = ciclo_actual + 1
            assignment["last_edited_at"] = datetime.now(timezone.utc).isoformat()
            assignment["last_edited_by"] = username

    ciclo_nuevo = get_max_cycle(assignments, folio)
    historial_entry["ciclo_anterior"] = ciclo_anterior
    historial_entry["ciclo_nuevo"] = ciclo_nuevo
    
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
        "ciclo_nuevo": ciclo_nuevo
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
        return request_status_from_assignments(statuses)
    
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
        "texto": f"Proyecto {folio} recibido",
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
                        "estatus_anterior": REQ_STATUS_IN_PROGRESS,
                        "estatus_nuevo": REQ_STATUS_IN_PROGRESS
                    })
                except:
                    pass

        # Si hay assignments rechazados, reflejar el estatus resultante del folio
        rejected = [a for a in linked if normalize_status(a.get("status"), a.get("assigned_to")) == STATUS_REJECTED]
        if rejected:
            linked_statuses = [normalize_status(a.get("status"), a.get("assigned_to")) for a in linked]
            rejected_request_status = request_status_from_assignments(linked_statuses)
            rejected_assignment = max(rejected, key=lambda a: parse_iso_date(a.get("status_updated_at")) or datetime.min)
            if rejected_assignment.get("status_updated_at"):
                try:
                    if 'T' in rejected_assignment.get("status_updated_at", ""):
                        dt = datetime.fromisoformat(rejected_assignment.get("status_updated_at").replace('Z', '+00:00'))
                    else:
                        dt = datetime.strptime(rejected_assignment.get("status_updated_at"), "%Y-%m-%d %H:%M:%S")
                    fecha_str = dt.strftime("%Y-%m-%d %H:%M")
                    historial_formateado.append({
                        "id": len(historial_formateado),
                        "tipo": "evento",
                        "fecha": fecha_str,
                        "autor": rejected_assignment.get("status_updated_by", "Sistema"),
                        "rol": "ejecutivo",
                        "icono": "🔄",
                        "texto": "Cambio de estatus",
                        "estatus_anterior": REQ_STATUS_IN_PROGRESS,
                        "estatus_nuevo": rejected_request_status
                    })
                except:
                    pass
        
        # Si todos están aceptados, generar evento de finalización
        accepted = [a for a in linked if normalize_status(a.get("status"), a.get("assigned_to")) == STATUS_ACCEPTED]
        if linked and len(accepted) == len(linked):
            final_assignment = max(accepted, key=lambda a: parse_iso_date(a.get("status_updated_at")) or datetime.min)
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
                        estatus_anterior = "EN PROCESO"
                    
                    historial_formateado.append({
                        "id": len(historial_formateado),
                        "tipo": "evento",
                        "fecha": fecha_str,
                        "autor": final_assignment.get("status_updated_by", "Sistema"),
                        "rol": "ejecutivo",
                        "icono": "🔄",
                        "texto": "Cambio de estatus",
                        "estatus_anterior": REQ_STATUS_IN_PROGRESS,
                        "estatus_nuevo": REQ_STATUS_FINISHED
                    })
                except:
                    pass
    
    # Agregar entradas del historial
    historial_raw = solicitud.get("historial", [])
    ciclo_tracker = 1
    campo_labels = {
        "tipo_servicio": "Tipo de servicio",
        "nombre_proyecto": "Nombre del proyecto",
        "norma": "Norma",
        "num_skus": "SKU / Modelos",
        "medidas": "Medidas",
        "prioridad": "Prioridad",
        "importador": "Importador",
        "marca": "Marca",
        "pais_origen": "Pais de origen",
        "contenido": "Contenido",
    }
    for idx, entry in enumerate(historial_raw, start=1):
        if entry.get("tipo") == "edicion_cliente":
            ciclo_anterior = normalize_cycle_value(entry.get("ciclo_anterior", ciclo_tracker))
            ciclo_nuevo = normalize_cycle_value(entry.get("ciclo_nuevo", ciclo_anterior + 1))
            if ciclo_nuevo <= ciclo_anterior:
                ciclo_nuevo = ciclo_anterior + 1
            ciclo_tracker = ciclo_nuevo

            timestamp = entry.get("timestamp", "")
            fecha_valor = timestamp.replace("T", " ")[:16] if "T" in timestamp else timestamp

            autor = entry.get("usuario", "Cliente")
            motivo = str(entry.get("comentario") or "").strip()

            cambios = entry.get("cambios") or {}
            for campo, detalle in cambios.items():
                if not isinstance(detalle, dict):
                    continue
                etiqueta = campo_labels.get(campo, campo.replace("_", " ").title())
                viejo = str(detalle.get("viejo") or "").strip() or "(vacio)"
                nuevo = str(detalle.get("nuevo") or "").strip() or "(vacio)"
                historial_formateado.append({
                    "id": len(historial_formateado),
                    "tipo": "evento",
                    "subtipo": "dato_actualizado",
                    "fecha": fecha_valor,
                    "autor": autor,
                    "rol": "cliente",
                    "campo": etiqueta,
                    "valor_anterior": viejo,
                    "valor_nuevo": nuevo,
                    "motivo": motivo,
                    "texto": f"{etiqueta}: {viejo} -> {nuevo}",
                    "estatus_anterior": None,
                    "estatus_nuevo": None
                })

            for reemplazo in entry.get("imagenes_reemplazadas", []) or []:
                if not isinstance(reemplazo, dict):
                    continue
                anterior = str(
                    reemplazo.get("anterior")
                    or reemplazo.get("filename")
                    or "Imagen anterior"
                ).strip()
                nuevo = str(reemplazo.get("nuevo") or reemplazo.get("filename") or "Imagen nueva").strip()
                historial_formateado.append({
                    "id": len(historial_formateado),
                    "tipo": "evento",
                    "subtipo": "imagen_reemplazada",
                    "fecha": fecha_valor,
                    "autor": autor,
                    "rol": "cliente",
                    "campo": "Imagen",
                    "valor_anterior": anterior,
                    "valor_nuevo": nuevo,
                    "motivo": motivo,
                    "texto": f"Imagen reemplazada: {anterior} -> {nuevo}",
                    "estatus_anterior": None,
                    "estatus_nuevo": None
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
                "texto": entry.get("texto") or "Cambio de estatus",
                "estatus_anterior": entry.get("estatus_anterior"),
                "estatus_nuevo": entry.get("estatus_nuevo")
            })
        elif entry.get("tipo") == "entregable_final_subido":
            historial_formateado.append({
                "id": len(historial_formateado),
                "tipo": "evento",
                "fecha": entry.get("timestamp", ""),
                "autor": entry.get("usuario", "Sistema"),
                "rol": entry.get("rol", "ejecutivo"),
                "icono": "📦",
                "texto": entry.get("texto") or "Entregable final ZIP cargado",
                "estatus_anterior": None,
                "estatus_nuevo": None
            })
    
    historial_relevante = [
        h for h in historial_formateado
        if str(h.get("subtipo") or "").lower() in {"dato_actualizado", "imagen_reemplazada", "archivo_reemplazado"}
    ]

    return jsonify({"historial": historial_relevante})


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
@role_required(ROLE_SUPERVISOR, ROLE_EJECUTIVO)
def update_solicitud_estatus(folio):
    """Cambiar el estatus de una solicitud (supervisor o ejecutivo asignado)."""
    username = session.get("username")
    role = normalize_role(session.get("role"))
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

    if role == ROLE_EJECUTIVO:
        assignments = load_assignments()
        has_access = any(
            a.get("folio") == folio and str(a.get("assigned_to") or "").strip() == username
            for a in assignments
        )
        if not has_access:
            return jsonify({"error": "No autorizado para cambiar este estatus"}), 403
    
    data = request.get_json() or {}
    nuevo_estatus = normalize_request_status(data.get("estatus", ""))
    comentario = data.get("comentario", "").strip()

    estatus_validos = [
        REQ_STATUS_PENDING,
        REQ_STATUS_IN_PROGRESS,
        REQ_STATUS_MISSING_INFO,
        REQ_STATUS_REJECTED,
        REQ_STATUS_FINISHED,
        REQ_STATUS_CANCELED,
    ]
    if nuevo_estatus not in estatus_validos:
        return jsonify({"error": "Estatus inválido"}), 400

    estatus_anterior = normalize_request_status(solicitud.get("estatus")) or REQ_STATUS_PENDING
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
        "rol": role,
        "texto": comentario,
        "estatus_anterior": estatus_anterior,
        "estatus_nuevo": nuevo_estatus
    })
    
    if req_index is None:
        return jsonify({"error": "Solicitud no encontrada"}), 404

    # Registrar en audit trail
    log_audit_trail(
        "change_estatus",
        username or "unknown",
        {"folio": folio, "old_status": estatus_anterior, "new_status": nuevo_estatus}
    )

    # Guardar
    requests_data[req_index] = solicitud
    save_service_requests(requests_data)
    
    return jsonify({"status": "ok", "message": "Estatus actualizado", "nuevo_estatus": nuevo_estatus})


@app.route("/api/solicitud/<folio>/entregable-final", methods=["POST"])
@login_required
@role_required(ROLE_EJECUTIVO, ROLE_SUPERVISOR)
def upload_final_deliverable(folio):
    username = session.get("username")
    role = normalize_role(session.get("role"))

    requests_data = load_service_requests()
    req_index = None
    solicitud = None
    for i, r in enumerate(requests_data):
        if r.get("folio") == folio:
            solicitud = r
            req_index = i
            break

    if solicitud is None or req_index is None:
        return jsonify({"error": "Solicitud no encontrada"}), 404

    if role == ROLE_EJECUTIVO:
        assignments = load_assignments()
        assigned = any(
            a.get("folio") == folio and a.get("assigned_to") == username
            for a in assignments
        )
        if not assigned:
            return jsonify({"error": "No autorizado para esta solicitud"}), 403

    uploaded_files = request.files.getlist("files[]")
    if not uploaded_files or all(not f.filename for f in uploaded_files):
        return jsonify({"error": "Se requiere al menos un archivo"}), 400

    deliverable_folder = get_deliverable_folder_for_solicitud(solicitud, folio)
    saved_files = []

    # Guardar archivos individuales
    for file in uploaded_files:
        if not file or not file.filename:
            continue

        if not is_allowed_extension(file.filename):
            continue

        original_name = os.path.basename(file.filename)
        stored_name = sanitize_filename(original_name) or f"file_{len(saved_files)}"
        file_path = os.path.join(deliverable_folder, stored_name)

        # Evitar duplicados
        counter = 1
        base_name, ext = (stored_name.rsplit(".", 1) if "." in stored_name else (stored_name, ""))
        while os.path.exists(file_path):
            if ext:
                stored_name = f"{base_name}_{counter}.{ext}"
            else:
                stored_name = f"{base_name}_{counter}"
            file_path = os.path.join(deliverable_folder, stored_name)
            counter += 1

        try:
            file.save(file_path)
            size_bytes = os.path.getsize(file_path)
            relative_path = os.path.relpath(file_path, get_upload_folder(solicitud.get("client")))
            saved_files.append({
                "original_name": original_name,
                "stored_name": stored_name,
                "file_path": file_path,
                "relative_path": relative_path,
                "size_bytes": size_bytes,
                "uploaded_at": datetime.now(timezone.utc).isoformat()
            })
        except OSError:
            continue

    if not saved_files:
        return jsonify({"error": "No se pudo guardar ningún archivo"}), 500

    solicitud["entregable_final"] = {
        "files": saved_files,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "uploaded_by": username,
    }

    historial = solicitud.setdefault("historial", [])
    estatus_anterior = solicitud.get("estatus", "PENDIENTE")
    solicitud["estatus"] = "FINALIZADO"
    
    # Guardar cambios en service_requests
    requests_data[req_index] = solicitud
    save_service_requests(requests_data)

    historial.append({
        "tipo": "entregable_final_subido",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "usuario": username,
        "rol": role,
        "texto": f"Archivos finales entregados ({len(saved_files)} archivo(s))",
        "cantidad_archivos": len(saved_files),
    })
    if estatus_anterior != "FINALIZADO":
        historial.append({
            "tipo": "cambio_estatus",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "usuario": username,
            "rol": role,
            "texto": "Solicitud finalizada al entregar archivos finales",
            "estatus_anterior": estatus_anterior,
            "estatus_nuevo": "FINALIZADO"
        })

    requests_data[req_index] = solicitud
    save_service_requests(requests_data)

    return jsonify({
        "status": "ok",
        "message": f"Archivos finales entregados ({len(saved_files)} archivo(s))",
        "entregable_final": solicitud.get("entregable_final"),
    })


@app.route("/api/solicitud/<folio>/entregable-final/download", methods=["GET"])
@login_required
def download_final_deliverable(folio):
    import zipfile
    import io
    
    username = session.get("username")
    role = normalize_role(session.get("role"))

    requests_data = load_service_requests()
    solicitud = next((r for r in requests_data if r.get("folio") == folio), None)
    if not solicitud:
        return jsonify({"error": "Solicitud no encontrada"}), 404

    if not can_access_solicitud(solicitud, role, username):
        return jsonify({"error": "No autorizado"}), 403

    explicit_status_final = normalize_request_status(solicitud.get("estatus")) == REQ_STATUS_FINISHED
    assignments = load_assignments()
    linked = [a for a in assignments if a.get("folio") == folio]
    linked_statuses = [normalize_status(a.get("status"), a.get("assigned_to")) for a in linked]
    derived_status_final = bool(linked_statuses) and all(s == STATUS_ACCEPTED for s in linked_statuses)

    if not (explicit_status_final or derived_status_final):
        return jsonify({"error": "El entregable solo se puede descargar cuando la solicitud está FINALIZADA"}), 400

    entregable = solicitud.get("entregable_final") or {}
    files_list = entregable.get("files", [])
    
    if not files_list:
        return jsonify({"error": "No hay archivos finales disponibles"}), 404

    # Crear ZIP en memoria
    zip_buffer = io.BytesIO()
    try:
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            for file_info in files_list:
                file_path = str(file_info.get("file_path") or "").strip()
                
                # Si file_path no existe, intentar con relative_path
                if not file_path or not os.path.exists(file_path):
                    relative_path = str(file_info.get("relative_path") or "").strip()
                    if relative_path:
                        client_folder = get_upload_folder(solicitud.get("client"))
                        file_path = os.path.join(client_folder, relative_path)
                
                if file_path and os.path.exists(file_path):
                    arcname = file_info.get("original_name") or os.path.basename(file_path)
                    zf.write(file_path, arcname=arcname)
        
        zip_buffer.seek(0)
    except Exception as e:
        return jsonify({"error": f"Error al crear ZIP: {str(e)}"}), 500

    download_name = f"entregable_{folio}.zip"
    return send_file(
        zip_buffer,
        mimetype="application/zip",
        as_attachment=True,
        download_name=download_name,
        max_age=0
    )


@app.route("/api/solicitud/<folio>/cliente-archivos/download", methods=["GET"])
@login_required
def download_client_uploaded_files(folio):
    import io
    import zipfile

    username = session.get("username")
    role = normalize_role(session.get("role"))

    requests_data = load_service_requests()
    solicitud = next((r for r in requests_data if r.get("folio") == folio), None)
    if not solicitud:
        return jsonify({"error": "Solicitud no encontrada"}), 404

    if not can_access_solicitud(solicitud, role, username):
        return jsonify({"error": "No autorizado"}), 403

    if role == ROLE_EJECUTIVO:
        assignments = load_assignments()
        has_access = any(
            a.get("folio") == folio and str(a.get("assigned_to") or "").strip() == username
            for a in assignments
        )
        if not has_access:
            return jsonify({"error": "No autorizado para esta solicitud"}), 403

    files_list = solicitud.get("files", [])
    if not isinstance(files_list, list) or not files_list:
        return jsonify({"error": "No hay archivos del cliente para descargar"}), 404

    zip_buffer = io.BytesIO()
    written = 0
    used_names = set()

    try:
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_info in files_list:
                if not isinstance(file_info, dict):
                    continue

                file_path = str(file_info.get("file_path") or "").strip()
                if not file_path or not os.path.exists(file_path):
                    continue

                arcname = (
                    str(file_info.get("original_name") or "").strip()
                    or str(file_info.get("filename") or "").strip()
                    or os.path.basename(file_path)
                )

                if not arcname:
                    arcname = os.path.basename(file_path)

                if arcname in used_names:
                    base, ext = os.path.splitext(arcname)
                    counter = 1
                    candidate = f"{base}_{counter}{ext}"
                    while candidate in used_names:
                        counter += 1
                        candidate = f"{base}_{counter}{ext}"
                    arcname = candidate

                zf.write(file_path, arcname=arcname)
                used_names.add(arcname)
                written += 1

        if written == 0:
            return jsonify({"error": "No se encontraron archivos disponibles para descargar"}), 404

        zip_buffer.seek(0)
    except Exception as e:
        return jsonify({"error": f"Error al crear ZIP: {str(e)}"}), 500

    download_name = f"cliente_archivos_{folio}.zip"
    return send_file(
        zip_buffer,
        mimetype="application/zip",
        as_attachment=True,
        download_name=download_name,
        max_age=0
    )


@app.route("/api/file/replace", methods=["POST"])
@login_required
@role_required(ROLE_CLIENTE)
def replace_gallery_file():
    """Permite al cliente reemplazar un archivo desde la galería, incrementando el ciclo."""
    username = session.get("username")
    target_path = request.form.get("file_path", "").strip()
    new_file = request.files.get("file")

    if not target_path or not new_file or not new_file.filename:
        return jsonify({"error": "Datos incompletos"}), 400

    if not is_allowed_extension(new_file.filename):
        return jsonify({"error": "Tipo de archivo no permitido"}), 400

    assignments = load_assignments()
    assignment = next((a for a in assignments if a.get("file_path") == target_path), None)
    if not assignment:
        return jsonify({"error": "Archivo no encontrado"}), 404

    if assignment.get("client") != username:
        return jsonify({"error": "No autorizado"}), 403

    current_status = normalize_status(assignment.get("status"), assignment.get("assigned_to"))
    if current_status == STATUS_ACCEPTED:
        return jsonify({"error": "No se puede reemplazar un archivo aceptado"}), 400

    old_ext = os.path.splitext(target_path)[1].lower()
    new_ext = os.path.splitext(new_file.filename)[1].lower()
    if old_ext and new_ext and old_ext != new_ext:
        return jsonify({"error": f"El archivo debe conservar la extensión original ({old_ext})"}), 400

    if not os.path.exists(target_path):
        return jsonify({"error": "Archivo no encontrado en disco"}), 404

    new_file.save(target_path)

    folio = assignment.get("folio")
    assignment["status"] = STATUS_UPLOADED
    assignment["uploaded_at"] = datetime.now(timezone.utc).isoformat()

    # Incrementar ciclo_actual en todos los assignments del mismo folio
    for a in assignments:
        if a.get("folio") == folio:
            ciclo_current = normalize_cycle_value(a.get("ciclo_actual", 1))
            a["ciclo_actual"] = ciclo_current + 1
            a["last_edited_at"] = datetime.now(timezone.utc).isoformat()
            a["last_edited_by"] = username

    save_assignments(assignments)

    append_history([{
        "filename": os.path.basename(target_path),
        "original_name": new_file.filename,
        "folder": os.path.dirname(target_path),
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "url": url_for("serve_file_by_path", file_path=target_path),
        "username": username
    }])

    return jsonify({
        "status": "ok",
        "url": url_for("serve_file_by_path", file_path=target_path)
    })


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
    
    # Registrar en audit trail
    log_audit_trail(
        "assignment_action",
        session.get("username") or "unknown",
        {"file_path": file_path, "action_type": action_type}
    )
    
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
            folio = img.get("folio")
            bosch_items.append({
                "name": img.get("name", ""),
                "status": status,
                "type": "imagen" if img.get("is_image") else "documento",
                "date": img.get("modified").isoformat() if img.get("modified") else "",
                "url": img.get("url", ""),
                "detail_url": url_for("historial", folio=folio) if folio else "",
                "ext": img.get("ext", "")
            })

        return render_template(
            "bosch_galery.html",
            username=username,
            items=bosch_items
        )

    back_url = url_for("dashboard")
    if role == ROLE_SUPERVISOR:
        back_url = url_for("dashboard_admin")
    elif role == ROLE_EJECUTIVO:
        back_url = url_for("ejecutivo_panel")
    elif role == ROLE_BOSCH:
        back_url = url_for("index")
    
    # Supervisor: ve todas las imágenes de todos los clientes; Ejecutivo: ve imágenes de sus folios asignados
    all_clients = (role == ROLE_SUPERVISOR)
    images = list_images(username, query or None, date_from, date_to, all_clients=all_clients, role=role)

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
        back_url=back_url,
        username=username,
        role=role
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

    # Registrar en audit trail
    log_audit_trail(
        "assign_folio",
        str(assigned_by or "unknown"),
        {"folio": folio, "assigned_to": ejecutivo}
    )

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
    return redirect(url_for("dashboard_ejecutivo"))


@app.route("/admin")
@login_required
@role_required(ROLE_SUPERVISOR)
def admin_users():
    users_list = build_admin_users_list()
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
    normas = data.get("normas", "")
    if normas is None:
        normas = ""
    normas = str(normas).strip()
    empresa = str(data.get("empresa") or "").strip()
    email = str(data.get("email") or "").strip()
    telefono = str(data.get("telefono") or "").strip()
    nombre = str(data.get("nombre") or username).strip()
    normalized_role = normalize_role(role)
    
    if not username:
        return jsonify({"error": "El nombre de usuario es requerido"}), 400
    if not password:
        return jsonify({"error": "La contraseña es requerida"}), 400
    if not folder and normalized_role in {ROLE_CLIENTE, ROLE_BOSCH}:
        return jsonify({"error": "La ruta de carpeta es requerida para clientes"}), 400
    
    config = load_config()
    existing_usernames = {str(item.get("FIRMA") or "").strip().lower() for item in load_users() if item.get("FIRMA")}
    
    if username in config.get("clients", {}) or username.strip().lower() in existing_usernames:
        return jsonify({"error": "El usuario ya existe"}), 400

    if normalized_role in {ROLE_CLIENTE, ROLE_BOSCH}:
        config["clients"][username] = {
            "password": password,
            "folder": folder,
            "role": role,
            "normas": normas,
            "empresa": empresa,
            "email": email,
            "telefono": telefono,
            "nombre": nombre,
        }

        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
    else:
        users = load_users()
        users.append({
            "NOMBRE": nombre,
            "CORREO": email or None,
            "TELEFONO": telefono or None,
            "EMPRESA": empresa or None,
            "FIRMA": username,
            "PUESTO": role,
            "CONTRASEÑA": password,
            "NORMAS": normas or None,
        })
        save_users(users)

    # Registrar en audit trail
    log_audit_trail(
        "create_user",
        session.get("username") or "unknown",
        {"username": username, "role": role, "source": "config" if normalized_role in {ROLE_CLIENTE, ROLE_BOSCH} else "users"}
    )

    return jsonify({"status": "ok"})


@app.route("/api/edit-user", methods=["POST"])
@login_required
@role_required(ROLE_SUPERVISOR)
def edit_user():
    data = request.get_json()
    username = data.get("username", "").strip()

    if not username:
        return jsonify({"error": "Usuario requerido"}), 400

    config = load_config()
    if username in config.get("clients", {}):
        user_data = config["clients"][username]

        new_password = str(data.get("password") or "").strip()
        if new_password:
            user_data["password"] = new_password

        for field in ("empresa", "email", "telefono", "normas", "folder", "nombre"):
            value = data.get(field)
            if value is not None:
                user_data[field] = str(value).strip()

        config["clients"][username] = user_data
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4, ensure_ascii=False)

        return jsonify({"status": "ok"})

    users = load_users()
    updated = False
    for user in users:
        if str(user.get("FIRMA") or "").strip() != username:
            continue

        new_password = str(data.get("password") or "").strip()
        if new_password:
            user["CONTRASEÑA"] = new_password

        if data.get("role") is not None:
            role_value = str(data.get("role") or "").strip().lower()
            if role_value in {ROLE_EJECUTIVO, ROLE_SUPERVISOR}:
                user["PUESTO"] = "Ejecutivo" if role_value == ROLE_EJECUTIVO else "Supervisor"

        if data.get("nombre") is not None:
            user["NOMBRE"] = str(data.get("nombre") or "").strip() or username
        if data.get("empresa") is not None:
            user["EMPRESA"] = str(data.get("empresa") or "").strip() or None
        if data.get("email") is not None:
            user["CORREO"] = str(data.get("email") or "").strip() or None
        if data.get("telefono") is not None:
            user["TELEFONO"] = str(data.get("telefono") or "").strip() or None
        if data.get("normas") is not None:
            user["NORMAS"] = str(data.get("normas") or "").strip() or None
        updated = True
        break

    if not updated:
        return jsonify({"error": "Usuario no encontrado"}), 404

    # Registrar en audit trail
    log_audit_trail(
        "edit_user",
        session.get("username") or "unknown",
        {"username": username}
    )

    save_users(users)
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

    if username in config.get("clients", {}):
        del config["clients"][username]

        # Registrar en audit trail
        log_audit_trail(
            "delete_user",
            session.get("username") or "unknown",
            {"username": username, "source": "config"}
        )

        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4, ensure_ascii=False)

        return jsonify({"status": "ok"})

    users = load_users()
    filtered_users = [user for user in users if str(user.get("FIRMA") or "").strip() != username]
    if len(filtered_users) == len(users):
        return jsonify({"error": "Usuario no encontrado"}), 404

    # Registrar en audit trail
    log_audit_trail(
        "delete_user",
        session.get("username") or "unknown",
        {"username": username, "source": "users"}
    )

    save_users(filtered_users)
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

    # Registrar en audit trail
    log_audit_trail(
        "update_assignment_status",
        username or "unknown",
        {"file_path": file_path, "new_status": new_status}
    )

    save_assignments(assignments)

    folio = assignment.get("folio")
    if folio:
        requests_data = load_service_requests()
        req_index = next((i for i, r in enumerate(requests_data) if r.get("folio") == folio), None)
        if req_index is not None:
            solicitud = requests_data[req_index]
            linked = [a for a in assignments if a.get("folio") == folio]
            linked_statuses = [normalize_status(a.get("status"), a.get("assigned_to")) for a in linked]
            nuevo_estatus = request_status_from_assignments(linked_statuses)
            estatus_anterior = normalize_request_status(solicitud.get("estatus")) or REQ_STATUS_PENDING
            if nuevo_estatus != estatus_anterior:
                solicitud["estatus"] = nuevo_estatus
                historial = solicitud.setdefault("historial", [])
                historial.append({
                    "tipo": "cambio_estatus",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "usuario": username,
                    "rol": ROLE_EJECUTIVO,
                    "texto": "Estatus actualizado por revisión de archivos",
                    "estatus_anterior": estatus_anterior,
                    "estatus_nuevo": nuevo_estatus,
                })
                requests_data[req_index] = solicitud
                save_service_requests(requests_data)

    return jsonify({"status": "ok", "new_status": new_status})


@app.route("/api/solicitud/<folio>/bulk-status", methods=["POST"])
@login_required
@role_required(ROLE_EJECUTIVO, ROLE_SUPERVISOR)
def update_bulk_folio_status(folio):
    """Aceptar o rechazar en general todas las asignaciones de un folio."""
    username = session.get("username")
    role = normalize_role(session.get("role"))
    data = request.get_json() or {}
    new_status = str(data.get("status", "")).strip().lower()

    if new_status not in [STATUS_ACCEPTED, STATUS_REJECTED]:
        return jsonify({"error": "Datos inválidos"}), 400

    requests_data = load_service_requests()
    req_index = None
    solicitud = None
    for i, item in enumerate(requests_data):
        if item.get("folio") == folio:
            solicitud = item
            req_index = i
            break

    if solicitud is None or req_index is None:
        return jsonify({"error": "Solicitud no encontrada"}), 404

    assignments = load_assignments()
    if role == ROLE_SUPERVISOR:
        linked = [assignment for assignment in assignments if assignment.get("folio") == folio]
    else:
        linked = [
            assignment for assignment in assignments
            if assignment.get("folio") == folio and assignment.get("assigned_to") == username
        ]

    if not linked:
        return jsonify({"error": "No hay archivos asignados para este folio"}), 404

    now_iso = datetime.now(timezone.utc).isoformat()
    for assignment in linked:
        assignment["status"] = new_status
        assignment["status_updated_at"] = now_iso
        assignment["status_updated_by"] = username

    estatus_anterior = normalize_request_status(solicitud.get("estatus")) or REQ_STATUS_PENDING
    solicitud["estatus"] = request_status_from_assignments([
        normalize_status(assignment.get("status"), assignment.get("assigned_to")) for assignment in linked
    ])
    historial = solicitud.setdefault("historial", [])
    historial.append({
        "tipo": "cambio_estatus",
        "timestamp": now_iso,
        "usuario": username,
        "rol": role,
        "texto": f"Solicitud marcada de forma general como {new_status}",
        "estatus_anterior": estatus_anterior,
        "estatus_nuevo": solicitud["estatus"]
    })

    requests_data[req_index] = solicitud
    save_service_requests(requests_data)
    save_assignments(assignments)

    return jsonify({
        "status": "ok",
        "new_status": new_status,
        "affected": len(linked),
        "solicitud_estatus": solicitud["estatus"]
    })


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

        folio = assignment.get("folio")
        if folio:
            requests_data = load_service_requests()
            req_index = next((i for i, r in enumerate(requests_data) if r.get("folio") == folio), None)
            if req_index is not None:
                solicitud = requests_data[req_index]
                linked = [a for a in assignments if a.get("folio") == folio]
                linked_statuses = [normalize_status(a.get("status"), a.get("assigned_to")) for a in linked]
                nuevo_estatus = request_status_from_assignments(linked_statuses)
                estatus_anterior = normalize_request_status(solicitud.get("estatus")) or REQ_STATUS_PENDING
                if nuevo_estatus != estatus_anterior:
                    solicitud["estatus"] = nuevo_estatus
                    historial = solicitud.setdefault("historial", [])
                    historial.append({
                        "tipo": "cambio_estatus",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "usuario": username,
                        "rol": ROLE_EJECUTIVO,
                        "texto": "Estatus actualizado por reemplazo de archivo",
                        "estatus_anterior": estatus_anterior,
                        "estatus_nuevo": nuevo_estatus,
                    })
                    requests_data[req_index] = solicitud
                    save_service_requests(requests_data)
        
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
    
    # Permisos: supervisor ve todo, cliente solo ve sus propias asignaciones, ejecutivo ve sus asignaciones
    if role in {ROLE_CLIENTE, ROLE_BOSCH}:
        if assignment.get("client") != username:
            return "No autorizado", 403
    elif role == ROLE_EJECUTIVO:
        # Ejecutivo solo ve archivos de sus folios asignados
        folio = assignment.get("folio")
        if folio:
            my_assignments = [a for a in assignments if a.get("folio") == folio and str(a.get("assigned_to", "")).strip() == username]
            if not my_assignments:
                return "No autorizado", 403
        else:
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
                         comments=get_comments_for_assignment(assignment),
                         assigned_to=assignment.get("assigned_to"),
                         assigned_at=assignment.get("assigned_at"),
                         assigned_by=assignment.get("assigned_by"),
                         role=role)


@app.errorhandler(403)
def handle_forbidden(error):
    return render_template("403.html"), 403


@app.errorhandler(404)
def handle_not_found(error):
    return render_template("404.html"), 404


@app.errorhandler(500)
def handle_internal_server_error(error):
    app.logger.exception("Error interno no controlado: %s", error)
    return render_template("500.html"), 500


# =========================
# MAIN
# =========================
if __name__ == "__main__":
    # Ocultar versión real de Werkzeug/Python en el header Server
    from werkzeug.serving import WSGIRequestHandler
    WSGIRequestHandler.server_version = "GEPI"
    WSGIRequestHandler.sys_version = ""

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        threaded=True
    )