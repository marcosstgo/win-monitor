"""
Vigil Tray App
- Corre el agente en background
- Se esconde en el system tray
- Auto-inicio con Windows
- Auto-update desde GitHub Releases
"""
import sys
import os
import traceback

# Log de arranque — atrapa cualquier crash antes del sistema de log propio
_BOOT_LOG = os.path.join(os.environ.get("APPDATA","C:\\Temp"), "Vigil", "boot.log")
os.makedirs(os.path.dirname(_BOOT_LOG), exist_ok=True)
def _boot_log(msg):
    with open(_BOOT_LOG, "a") as f:
        f.write(msg + "\n")

try:
    _boot_log("=== Vigil arrancando ===")

    import json
    import threading
    import time
    import winreg
    import tempfile
    import subprocess
    import requests
    import ctypes
    from pathlib import Path
    from datetime import datetime

    _boot_log("imports stdlib OK")

    import pystray
    _boot_log("pystray OK")
    from PIL import Image, ImageDraw
    from PIL import ImageTk
    _boot_log("PIL OK")
    import tkinter as tk
    from tkinter import ttk, messagebox
    _boot_log("tkinter OK")

    # Importar agente
    sys.path.insert(0, str(Path(getattr(sys, '_MEIPASS', Path(__file__).parent))))
    from agent import run_ps
    _boot_log("agent OK")

    # Ocultar consola
    try:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except Exception:
        pass

except Exception as e:
    _boot_log(f"ERROR EN ARRANQUE: {e}\n{traceback.format_exc()}")
    sys.exit(1)

# ── Single instance (mutex global) ───────────────────────────────────────────
_MUTEX_NAME = "Global\\VIGILSingleInstance"
_mutex_handle = None

def acquire_single_instance() -> bool:
    """Crea un mutex global. Retorna True si somos la única instancia, False si ya hay una."""
    global _mutex_handle
    _mutex_handle = ctypes.windll.kernel32.CreateMutexW(None, False, _MUTEX_NAME)
    err = ctypes.windll.kernel32.GetLastError()
    ERROR_ALREADY_EXISTS = 183
    if err == ERROR_ALREADY_EXISTS:
        if _mutex_handle:
            ctypes.windll.kernel32.CloseHandle(_mutex_handle)
            _mutex_handle = None
        return False
    return True

# ── Constantes ────────────────────────────────────────────────────────────────
VERSION      = "1.2.4"
APP_NAME     = "Vigil"
CONFIG_DIR   = Path(os.environ["APPDATA"]) / "Vigil"
CONFIG_FILE  = CONFIG_DIR / "config.json"
STATE_FILE   = CONFIG_DIR / "agent_state.json"
LOG_FILE     = CONFIG_DIR / "vigil.log"
AUTORUN_KEY  = r"Software\Microsoft\Windows\CurrentVersion\Run"
EXE_PATH     = Path(sys.executable if getattr(sys, "frozen", False) else sys.argv[0]).resolve()


# ── Config ────────────────────────────────────────────────────────────────────
def load_config():
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return {}

def save_config(cfg):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

def load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {}

def save_state(s):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(s))

# ── Log ───────────────────────────────────────────────────────────────────────
_log_lock = threading.Lock()
def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    with _log_lock:
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass

# ── Auto-inicio Windows ───────────────────────────────────────────────────────
def set_autorun(enabled: bool):
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTORUN_KEY, 0, winreg.KEY_SET_VALUE)
        if enabled:
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, str(EXE_PATH))
        else:
            try:
                winreg.DeleteValue(key, APP_NAME)
            except FileNotFoundError:
                pass
        winreg.CloseKey(key)
    except Exception as e:
        log(f"autorun error: {e}")

def get_autorun() -> bool:
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTORUN_KEY, 0, winreg.KEY_READ)
        winreg.QueryValueEx(key, APP_NAME)
        winreg.CloseKey(key)
        return True
    except FileNotFoundError:
        return False

# ── Icono ─────────────────────────────────────────────────────────────────────
import math as _math

def make_icon(color="#00e475", size=64):
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    s, pad = size, size * 0.06
    ring = max(1, int(s * 0.05))

    # Fondo círculo oscuro
    draw.ellipse([pad, pad, s - pad, s - pad], fill=(18, 18, 18, 255))
    # Anillo exterior del color indicado
    draw.ellipse([pad, pad, s - pad, s - pad], outline=color, width=ring)

    # Ojo (almendra)
    cx, cy = s / 2, s / 2
    ew, eh = s * 0.52, s * 0.26
    steps  = 48
    top_pts, bot_pts = [], []
    for i in range(steps + 1):
        t   = i / steps
        ang = _math.pi * t
        x   = cx + ew / 2 * _math.cos(_math.pi - ang)
        top_pts.append((x, cy - eh / 2 * _math.sin(ang) * 1.1))
        bot_pts.append((x, cy + eh / 2 * _math.sin(ang) * 1.1))

    lw = max(1, int(s * 0.05))
    draw.polygon(top_pts + list(reversed(bot_pts)), fill=(*bytes.fromhex(color.lstrip("#")), 35))
    draw.line(top_pts, fill=color, width=lw)
    draw.line(bot_pts, fill=color, width=lw)

    # Pupila
    pr = s * 0.13
    r, g, b = bytes.fromhex(color.lstrip("#"))
    draw.ellipse([cx - pr, cy - pr, cx + pr, cy + pr], fill=(r, g, b, 255))
    # Reflejo
    rr = pr * 0.38
    draw.ellipse([cx - pr * 0.28 - rr, cy - pr * 0.28 - rr,
                  cx - pr * 0.28 + rr, cy - pr * 0.28 + rr],
                 fill=(255, 255, 255, 200))
    return img

ICON_GREEN  = make_icon("#00e475")  # Conectado
ICON_YELLOW = make_icon("#fabd00")  # Enviando
ICON_RED    = make_icon("#ff4444")  # Error
ICON_GREY   = make_icon("#888888")  # Sin config / iniciando

# ── Setup dialog (primer arranque) ────────────────────────────────────────────
def show_setup() -> dict:
    """Muestra el dialog de configuración y retorna el config guardado. Bloqueante."""
    result = {}
    root = tk.Tk()
    root.title("Vigil — Configuración")
    root.geometry("400x260")
    root.resizable(False, False)
    root.configure(bg="#131313")

    # Icono de la ventana y taskbar
    try:
        if getattr(sys, "frozen", False):
            ico = Path(sys._MEIPASS) / "vigil.ico"
        else:
            ico = Path(__file__).parent / "vigil.ico"
        if ico.exists():
            root.iconbitmap(str(ico))
        else:
            # Fallback: usar la imagen PIL como icono
            photo = ImageTk.PhotoImage(ICON_GREEN.resize((32, 32)))
            root.iconphoto(True, photo)
    except Exception:
        pass

    root.update_idletasks()
    x = (root.winfo_screenwidth()  - 400) // 2
    y = (root.winfo_screenheight() - 260) // 2
    root.geometry(f"400x260+{x}+{y}")

    tk.Label(root, text="Vigil", font=("Segoe UI", 22, "bold"),
             bg="#131313", fg="#00e475").pack(pady=(20, 2))
    tk.Label(root, text="Monitor de sistema Windows",
             font=("Segoe UI", 10), bg="#131313", fg="#888").pack()

    frame = tk.Frame(root, bg="#131313")
    frame.pack(fill="x", padx=30, pady=20)

    tk.Label(frame, text="Clave secreta", font=("Segoe UI", 9),
             bg="#131313", fg="#aaa").pack(anchor="w")

    secret_var = tk.StringVar()
    entry = tk.Entry(frame, textvariable=secret_var, font=("Segoe UI", 11),
                     bg="#201f1f", fg="#e5e2e1", insertbackground="#e5e2e1",
                     relief="flat", bd=6)
    entry.pack(fill="x", pady=(4, 0), ipady=4)
    entry.focus()

    err_label = tk.Label(frame, text="", font=("Segoe UI", 9),
                         bg="#131313", fg="#ff6b6b")
    err_label.pack(anchor="w", pady=(4, 0))

    def on_ok(event=None):
        secret = secret_var.get().strip()
        if len(secret) < 6:
            err_label.config(text="Clave demasiado corta")
            return
        cfg = load_config()
        cfg["secret"] = secret
        cfg["server_url"] = "https://marcossantiago.com/win-monitor"
        save_config(cfg)
        result.update(cfg)
        root.quit()   # sale del mainloop sin destruir todavía

    btn = tk.Button(frame, text="Guardar y comenzar", command=on_ok,
                    font=("Segoe UI", 10, "bold"), bg="#00e475", fg="#003918",
                    relief="flat", bd=0, cursor="hand2", pady=8)
    btn.pack(fill="x", pady=(14, 0))
    entry.bind("<Return>", on_ok)

    root.mainloop()
    try:
        root.destroy()
    except Exception:
        pass
    return result

# ── Auto-update ───────────────────────────────────────────────────────────────
def check_update(cfg, icon):
    try:
        url = cfg.get("server_url", "").rstrip("/") + "/api/version"
        r = requests.get(url, params={"secret": cfg["secret"]}, timeout=10)
        if r.status_code != 200:
            return
        data = r.json()
        latest  = data.get("version", VERSION)
        dl_url  = data.get("download_url", "")
        if latest <= VERSION or not dl_url:
            return

        log(f"Update disponible: {latest}")
        # Descargar en background
        def do_update():
            try:
                icon.notify(f"Actualizando Vigil a v{latest}...", APP_NAME)
                tmp = Path(tempfile.gettempdir()) / f"vigil-update-{latest}.exe"
                with requests.get(dl_url, stream=True, timeout=120) as resp:
                    resp.raise_for_status()
                    with open(tmp, "wb") as f:
                        for chunk in resp.iter_content(8192):
                            f.write(chunk)
                # Reemplazar y reiniciar
                bat = Path(tempfile.gettempdir()) / "vigil_update.bat"
                bat.write_text(
                    f'@echo off\n'
                    f'timeout /t 2 /nobreak >nul\n'
                    f'copy /y "{tmp}" "{EXE_PATH}"\n'
                    f'start "" "{EXE_PATH}"\n'
                    f'del "%~f0"\n'
                )
                subprocess.Popen(["cmd", "/c", str(bat)], creationflags=0x08000000)
                icon.stop()
            except Exception as e:
                log(f"Update error: {e}")
                icon.notify(f"Error al actualizar: {e}", APP_NAME)

        threading.Thread(target=do_update, daemon=True).start()

    except Exception as e:
        log(f"check_update error: {e}")

# ── Agente loop ───────────────────────────────────────────────────────────────
_stop_event  = threading.Event()
_status      = {"last": None, "events": 0, "error": None}

def agent_loop(cfg, icon_ref):
    state = load_state()
    server_url = cfg.get("server_url", "").rstrip("/") + "/api/events"
    secret     = cfg.get("secret", "")

    while not _stop_event.is_set():
        try:
            all_events, metrics = run_ps()
            new_events = []
            for e in all_events:
                log_name = e.get("LogName", "")
                rid = int(e.get("RecordId", 0))
                if rid > state.get(log_name, 0):
                    new_events.append(e)
            for e in new_events:
                log_name = e.get("LogName", "")
                rid = int(e.get("RecordId", 0))
                state[log_name] = max(state.get(log_name, 0), rid)

            # Enviar con el secret del usuario
            payload = {
                "secret":  secret,
                "metrics": metrics,
                "events": [{
                    "time_created": e["TimeCreated"],
                    "event_id":     int(e["EventId"]),
                    "level":        int(e["Level"]),
                    "level_name":   e["LevelName"],
                    "log_name":     e["LogName"],
                    "provider":     e["Provider"],
                    "message":      e["Message"],
                } for e in new_events]
            }
            resp = requests.post(server_url, json=payload, timeout=20)
            resp.raise_for_status()
            result = resp.json()
            save_state(state)

            _status["last"]   = datetime.now()
            _status["events"] = result.get("received", 0)
            _status["error"]  = None
            if icon_ref[0]:
                icon_ref[0].icon = ICON_GREEN
            log(f"+{result.get('received',0)} eventos | RAM {metrics.get('mem_percent','?')}% | CPU {metrics.get('cpu_percent','?')}%")

        except Exception as e:
            _status["error"] = str(e)
            if icon_ref[0]:
                icon_ref[0].icon = ICON_RED
            log(f"Error: {e}")

        _stop_event.wait(60)

# ── Tray ──────────────────────────────────────────────────────────────────────
def build_menu(cfg, icon_ref):
    import webbrowser

    def open_dashboard():
        url = cfg.get("server_url", "").rstrip("/") + f"/?secret={cfg.get('secret','')}"
        webbrowser.open(url)

    def toggle_autorun(item):
        enabled = not get_autorun()
        set_autorun(enabled)

    def show_status():
        last = _status["last"]
        err  = _status["error"]
        if err:
            msg = f"Error: {err}"
        elif last:
            msg = f"OK — último envío {last.strftime('%H:%M:%S')}\nEventos enviados: {_status['events']}"
        else:
            msg = "Iniciando..."
        # Correr en thread propio para no bloquear el loop de mensajes de pystray
        threading.Thread(
            target=lambda: ctypes.windll.user32.MessageBoxW(0, msg, "Vigil — Estado", 0x40),
            daemon=True
        ).start()

    def quit_app():
        _stop_event.set()
        if icon_ref[0]:
            icon_ref[0].stop()

    return pystray.Menu(
        pystray.MenuItem("Abrir dashboard",   open_dashboard, default=True),
        pystray.MenuItem("Estado",            show_status),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Inicio con Windows",toggle_autorun,
                         checked=lambda item: get_autorun()),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(f"Vigil v{VERSION}", None, enabled=False),
        pystray.MenuItem("Salir",             quit_app),
    )

def start_tray(cfg):
    icon_ref = [None]

    def setup(icon):
        icon_ref[0] = icon
        icon.visible = True
        # Iniciar agente
        t = threading.Thread(target=agent_loop, args=(cfg, icon_ref), daemon=True)
        t.start()
        # Verificar update
        threading.Thread(target=check_update, args=(cfg, icon), daemon=True).start()

    icon = pystray.Icon(
        APP_NAME,
        ICON_GREY,
        APP_NAME,
        menu=build_menu(cfg, icon_ref),
    )
    icon.run(setup)

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    if not acquire_single_instance():
        ctypes.windll.user32.MessageBoxW(
            0,
            "Vigil ya está corriendo en el system tray.",
            "Vigil",
            0x40  # MB_ICONINFORMATION
        )
        return

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    set_autorun(True)  # Auto-registrar en startup al primer arranque

    cfg = load_config()

    if not cfg.get("secret"):
        cfg = show_setup()
        if not cfg.get("secret"):
            return  # Usuario cerró sin configurar

    start_tray(cfg)

if __name__ == "__main__":
    main()
