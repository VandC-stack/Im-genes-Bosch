import subprocess
import time
import requests
import sys
import os

from app import app


def get_base_path():
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))


def start_ngrok(port=5000):
    base_path = get_base_path()
    ngrok_path = os.path.join(base_path, "ngrok.exe")

    if not os.path.exists(ngrok_path):
        print("ERROR: ngrok.exe no encontrado")
        print("Ruta buscada:", ngrok_path)
        input("Presiona ENTER para cerrar...")
        sys.exit(1)

    print("Iniciando tunel publico (ngrok)...")

    subprocess.Popen(
        [ngrok_path, "http", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW
    )

    for _ in range(25):
        try:
            r = requests.get("http://127.0.0.1:4040/api/tunnels", timeout=2)
            tunnels = r.json().get("tunnels", [])
            if tunnels:
                public_url = tunnels[0]["public_url"]

                print("\nURL PUBLICA DISPONIBLE:")
                print(public_url)

                print("\nPanel de configuracion de ruta:")
                print(f"{public_url}/admin/ruta")

                print("\nEnvio de imagenes activo")
                return public_url
        except:
            time.sleep(1)

    print("ERROR: No se pudo obtener la URL publica de ngrok")
    input("Presiona ENTER para cerrar...")
    sys.exit(1)


if __name__ == "__main__":
    print("Iniciando BosshUploader\n")

    public_url = start_ngrok(port=5000)

    print("\nServidor local activo en http://localhost:5000")
    print("Panel local de configuracion:")
    print("http://localhost:5000/admin/ruta")

    print("\nCierra esta ventana para detener el servidor\n")

    #  Flask multihilo (estable y rápido)
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        threaded=True
    )
