# GEPI - Gestión de Evidencias y Procesos de Inspección

Sistema integral de gestión de evidencias fotográficas y documentales para procesos de inspección, control de calidad y seguimiento de proyectos.

## Descripción

GEPI es una plataforma completa desarrollada en Flask que permite gestionar el ciclo completo de evidencias digitales en procesos de inspección:

- **Carga de archivos**: Soporta imágenes (`png`, `jpg`, `jpeg`, `gif`, `webp`) y documentos (`pdf`, `doc`, `docx`, `xls`, `xlsx`, `ppt`, `pptx`, `txt`, `csv`)
- **Sistema de roles**: Clientes, Ejecutivos y Supervisores con permisos diferenciados
- **Asignación de tareas**: Los supervisores pueden asignar evidencias a ejecutivos específicos
- **Editor de imágenes integrado**: Los ejecutivos pueden editar y anotar imágenes directamente en la plataforma
- **Gestión multi-cliente**: Cada cliente tiene su carpeta independiente y control de acceso
- **Filtros avanzados**: Búsqueda por cliente, tipo de archivo, fechas y más

## Características principales

### 🔐 Sistema de autenticación y roles
- **Clientes**: Pueden subir evidencias y ver solo sus propios archivos
- **Ejecutivos**: Reciben asignaciones, editan imágenes y gestionan evidencias asignadas
- **Supervisores**: Administran usuarios, asignan tareas y tienen acceso completo al sistema

### 📁 Gestión de archivos
- Carga múltiple de archivos con nombres personalizables
- Soporte para imágenes y documentos (PDF, Word, Excel, PowerPoint, etc.)
- Carpetas independientes por cliente
- Historial de cargas con metadatos

### ![Editor](static/imagen.svg) Editor de imágenes
- Herramientas de dibujo y anotación
- Marcadores y señalizaciones
- Recorte y ajustes básicos
- Guardado directo en el servidor

### 📊 Panel de supervisión
- Vista consolidada de todas las evidencias
- Filtros por cliente y tipo de archivo
- Asignación de tareas a ejecutivos
- Seguimiento del estado de las evidencias
- Sistema de paginación para grandes volúmenes

### 🔍 Panel de ejecutivo
- Vista de evidencias asignadas
- Edición y anotación de imágenes
- Actualización del estado de las tareas

## Contenido del repositorio

- `app.py`: Servidor Flask con todas las rutas y lógica de negocio
- `config.json`: Configuración de clientes, roles y carpetas
- `assignments.json`: Base de datos de asignaciones de tareas
- `upload_history.json`: Historial de cargas de archivos
- `requirements.txt`: Dependencias de Python
- `templates/`: Vistas HTML del sistema
  - `index.html`: Interfaz de carga para clientes
  - `login.html`: Página de inicio de sesión
  - `admin.html`: Gestión de usuarios (supervisor)
  - `admin_ruta.html`: Configuración de carpetas (supervisor)
  - `solicitudes.html`: Panel principal del supervisor
  - `ejecutivo.html`: Panel de trabajo del ejecutivo
  - `gallery.html`: Galería de archivos
  - `image_editor.html`: Editor de imágenes
  - `view_image.html`: Visualizador de imágenes
- `static/`: Recursos estáticos (CSS, JavaScript, imágenes)
- `uploads/`: Carpeta por defecto para archivos subidos

## Prerequisitos

- Python 3.8+ instalado
- Navegador web moderno (Chrome, Firefox, Edge)
- (Opcional) ngrok para exponer el servidor localmente

## Instalación y ejecución

### Windows (PowerShell)

```powershell
# Clonar o descargar el repositorio
cd ruta/al/proyecto

# Crear entorno virtual
python -m venv venv

# Activar entorno (PowerShell)
.\venv\Scripts\Activate.ps1

# Instalar dependencias
pip install -r requirements.txt

# Ejecutar la aplicación
python app.py
```

### Linux/macOS

```bash
# Clonar o descargar el repositorio
cd ruta/al/proyecto

# Crear entorno virtual
python3 -m venv venv

# Activar entorno
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt

# Ejecutar la aplicación
python app.py
```

La aplicación se ejecuta por defecto en `http://0.0.0.0:5000`.

### Exponer con ngrok (opcional)

Si quieres exponer el servidor para acceso remoto o pruebas desde dispositivos móviles:

```powershell
ngrok http 5000
```

ngrok te dará una URL pública (ej: `https://abc123.ngrok.io`) que redirige a tu servidor local.

## Configuración

### Archivo `config.json`

GEPI soporta múltiples clientes con autenticación y carpetas independientes. El archivo `config.json` se crea automáticamente la primera vez que ejecutas la aplicación.

**Estructura recomendada:**

```json
{
  "destination_folder": "uploads/",
  "clients": {
    "admin_supervisor": {
      "password": "pbkdf2:sha256:600000$abc123...",
      "role": "Supervisor",
      "folder": "C:/Evidencias/Admin"
    },
    "ejecutivo_1": {
      "password": "pbkdf2:sha256:600000$def456...",
      "role": "Ejecutivo",
      "folder": "C:/Evidencias/Ejecutivo1"
    },
    "cliente_empresa_a": {
      "password": "pbkdf2:sha256:600000$ghi789...",
      "role": "Cliente",
      "folder": "C:/Evidencias/ClienteA"
    }
  }
}
```

### Roles disponibles

- **`Supervisor`**: Acceso completo, gestión de usuarios, asignación de tareas
- **`Ejecutivo`**: Acceso a evidencias asignadas, edición de imágenes
- **`Cliente`**: Carga de evidencias, acceso solo a sus propios archivos

### Generación de contraseñas seguras

Es **altamente recomendado** usar contraseñas hasheadas en lugar de texto plano:

**PowerShell:**
```powershell
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('MiContraseñaSegura'))"
```

**Linux/macOS:**
```bash
python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('MiContraseñaSegura'))"
```

Copia el hash generado y úsalo en el campo `password` del `config.json`.

### Crear usuarios desde la interfaz

Los supervisores pueden crear nuevos usuarios directamente desde el panel de administración en `/admin` sin necesidad de editar el archivo JSON manualmente.
## Uso del sistema

### 1. Inicio de sesión
Accede a `http://localhost:5000` y usa tus credenciales para iniciar sesión. Serás redirigido automáticamente al panel correspondiente a tu rol.

### 2. Cliente - Cargar evidencias
- Selecciona archivos (imágenes o documentos)
- Opcionalmente personaliza los nombres
- Haz clic en "Subir archivos"
- Los archivos se guardan en tu carpeta asignada

### 3. Supervisor - Gestionar evidencias
- Accede a `/solicitudes` para ver todas las evidencias
- Usa los filtros para buscar por cliente o tipo de archivo
- Selecciona un ejecutivo en el dropdown
- Haz clic en "Asignar" para asignar la evidencia
- Administra usuarios en `/admin`

### 4. Ejecutivo - Procesar evidencias
- Accede a `/ejecutivo` para ver tus asignaciones
- Haz clic en una evidencia para abrirla
- Usa el editor integrado para anotar imágenes
- Guarda los cambios directamente en el servidor

## Rutas principales

| Ruta | Acceso | Descripción |
|------|--------|-------------|
| `/` | Público | Redirige al login |
| `/login` | Público | Página de inicio de sesión |
| `/index` | Autenticado | Panel principal del cliente |
| `/gallery` | Autenticado | Galería de archivos del usuario |
| `/solicitudes` | Supervisor | Panel de gestión de evidencias |
| `/ejecutivo` | Ejecutivo | Panel de evidencias asignadas |
| `/admin` | Supervisor | Administración de usuarios |
| `/admin/ruta` | Supervisor | Configuración de carpetas |
| `/upload` | Autenticado | API para subir archivos (POST) |
| `/files/<filename>` | Autenticado | Servir archivos |

## Seguridad y buenas prácticas

### ⚠️ Importante para producción

1. **Cambia la SECRET_KEY**: En `app.py`, configura una clave secreta segura:
   ```python
   app.secret_key = "tu-clave-super-secreta-aqui"
   ```
   O mejor aún, usa una variable de entorno:
   ```python
   app.secret_key = os.environ.get("APP_SECRET_KEY", "fallback-key")
   ```

2. **Usa HTTPS**: Nunca uses HTTP en producción. Implementa SSL/TLS con certificados válidos.

3. **Contraseñas hasheadas**: Siempre usa `werkzeug.security.generate_password_hash()` para almacenar contraseñas.

4. **Permisos de archivos**: Asegúrate de que las carpetas de destino tengan permisos adecuados (lectura/escritura para la aplicación, pero no accesibles públicamente).

5. **Límites de tamaño**: Considera implementar límites de tamaño de archivo para evitar ataques de denegación de servicio:
   ```python
   app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB máximo
   ```

6. **WSGI Server**: Para producción, usa un servidor WSGI como `gunicorn` (Linux) o `waitress` (Windows):
   ```bash
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:5000 app:app
   ```

7. **Backups**: Implementa una estrategia de respaldos periódicos para `config.json`, `assignments.json` y las carpetas de evidencias.

8. **Logs**: Configura logging apropiado para monitorear accesos y detectar problemas:
   ```python
   import logging
   logging.basicConfig(level=logging.INFO)
   ```

## Solución de problemas

### Error: "Puerto 5000 ya está en uso"
Cambia el puerto en `app.py`:
```python
app.run(host="0.0.0.0", port=8080)
```

### Error: "Permission denied" al guardar archivos
Verifica que el usuario que ejecuta la aplicación tenga permisos de escritura en las carpetas de destino.

### Las imágenes no se muestran
Verifica que la ruta en `config.json` exista y sea accesible. Usa rutas absolutas.

### Olvido de contraseña
Como administrador, edita `config.json` y genera un nuevo hash de contraseña:
```bash
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('nuevacontraseña'))"
```

## Desarrollo y contribución

### Estructura del código

- **Autenticación**: Decoradores `@login_required` y `@role_required`
- **Roles**: Sistema basado en constantes `ROLE_CLIENTE`, `ROLE_INSPECTOR`, `ROLE_SUPERVISOR`
- **Archivos**: Funciones `is_allowed_extension()`, `is_image_extension()`, `sanitize_filename()`
- **Configuración**: Funciones `load_config()`, `save_config()`, `get_client()`
- **Asignaciones**: Funciones `load_assignments()`, `save_assignments()`, `get_assignment()`

### Agregar nuevas características

El código está modularizado para facilitar extensiones. Algunos puntos de extensión:

- **Nuevos roles**: Agregar en `ALLOWED_ROLES` y actualizar decoradores
- **Nuevos tipos de archivo**: Modificar `ALLOWED_EXTENSIONS`
- **APIs**: Agregar rutas con prefijo `/api/`
- **Notificaciones**: Implementar webhooks o emails en eventos clave

## Licencia

Este proyecto es de código abierto y puede ser utilizado, modificado y distribuido libremente.

## Soporte

Para reportar problemas, solicitar características o contribuir al proyecto, contacta al equipo de desarrollo.

---

**GEPI** - Gestión de Evidencias y Procesos de Inspección  
Desarrollado con ❤️ para optimizar procesos de inspección y control de calidad
