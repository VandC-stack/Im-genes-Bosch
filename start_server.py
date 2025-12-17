import subprocess
import time
import requests
import sys
import os
import threading

from app import app


def get_base_path():
    if getattr(sys, "frozen", False):
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))


def get_existing_ngrok_url():
    try:
        r = requests.get("http://127.0.0.1:4040/api/tunnels", timeout=2)
        tunnels = r.json().get("tunnels", [])
        if tunnels:
            return tunnels[0]["public_url"]
    except:
        return None
    return None


def start_ngrok_async(port=5000):
    """
    Usa ngrok existente si ya está activo.
    Solo inicia uno nuevo si no hay túnel.
    """
    existing_url = get_existing_ngrok_url()
    if existing_url:
        print("\nNgrok ya estaba activo.")
        print("URL publica disponible:")
        print(existing_url)
        print("\nPanel publico de configuracion:")
        print(f"{existing_url}/admin/ruta")
        return

    base_path = get_base_path()
    ngrok_path = os.path.join(base_path, "ngrok.exe")

    if not os.path.exists(ngrok_path):
        print("[WARN] ngrok.exe no encontrado. Solo modo local.")
        return

    print("Iniciando tunel publico (ngrok)...")

    subprocess.Popen(
        [ngrok_path, "http", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW
    )

    for _ in range(30):
        try:
            url = get_existing_ngrok_url()
            if url:
                print("\nURL PUBLICA DISPONIBLE:")
                print(url)

                print("\nPanel publico de configuracion:")
                print(f"{url}/admin/ruta")
                return
        except:
            time.sleep(1)

    print("[WARN] No se pudo obtener URL publica de ngrok.")
    print("[WARN] El servidor local sigue funcionando.")


if __name__ == "__main__":
    print("Iniciando BosshUploader\n")

    threading.Thread(
        target=start_ngrok_async,
        daemon=True
    ).start()

    print("Servidor local activo en:")
    print("http://localhost:5000")

    print("\nPanel local de configuracion:")
    print("http://localhost:5000/admin/ruta")

    print("\nCierra esta ventana para detener el servidor\n")

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        threaded=True
    )
