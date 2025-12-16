# Bossh - Simple Flask Uploader

Pequeña aplicación Flask para subir imágenes y configurar la carpeta de destino.

## Descripción

- Proyecto minimalista que permite subir imágenes (`png`, `jpg`, `jpeg`, `gif`) mediante `POST /upload` y cambiar la ruta de guardado vía `/admin/ruta`.

## Contenido del repositorio

- `app.py` : servidor Flask.
- `config.json` : configuración simple (ruta de destino).
- `templates/` : vistas HTML (`index.html`, `admin_ruta.html`).
- `uploads/` : carpeta por defecto donde se guardan los archivos subidos.

## Prerequisitos

- Python 3.8+ instalado.
- (Opcional) ngrok para exponer localmente el servidor.

## Instalación y ejecución (PowerShell en Windows)

```powershell
# Crear entorno virtual
python -m venv venv
# Activar entorno (PowerShell)
.\venv\Scripts\Activate.ps1
# Instalar dependencias
pip install -r requirements.txt
# Ejecutar la app
python app.py

```

La aplicación se ejecuta por defecto en `http://0.0.0.0:5000`.

**Exponer con ngrok (rápido)**
Si quieres exponer el servidor para pruebas desde internet (por ejemplo para pruebas con móviles):

```powershell
ngrok http 5000
```

ngrok te dará una URL pública que redirige a tu servidor local.

**`config.json`**

- Si no existe, la app usa `"uploads/"` por defecto.

- Ejemplo mínimo de `config.json`:

```json
{
  "destination_folder": "uploads/"
}

```

- Puedes cambiar la ruta desde la interfaz en `/admin/ruta` o editando `config.json`.
**Notas y buenas prácticas**

- Asegúrate de que la carpeta de destino tenga permisos de escritura.
- Esta aplicación es un ejemplo; para producción añade validación adicional, límites de tamaño, autenticación y protección CSRF.
- Para desplegar en producción, considera un WSGI server (por ejemplo `gunicorn` en Linux) y servir archivos estáticos de forma segura
