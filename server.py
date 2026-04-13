import os, sqlite3, threading, time, secrets, string
import urllib.request, urllib.parse
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Optional
import anthropic

app = FastAPI()

API_SECRET       = os.environ.get("API_SECRET", "changeme")
CLAUDE_API_KEY   = os.environ.get("CLAUDE_API_KEY", "")
DB_PATH          = os.environ.get("DB_PATH", "/home/corillo-adm/win-monitor/monitor.db")
BASE_PATH        = "/win-monitor"
TELEGRAM_TOKEN   = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

# Cooldowns para no spamear Telegram (key → epoch del último envío)
_tg_sent: dict = {}

# ── Event ID sets por categoría
BSOD_IDS    = {41, 1001, 6008}
DISK_IDS    = {7, 11, 51, 52, 55, 57, 153, 157, 158, 244}
SERVICE_IDS = {7022, 7023, 7024, 7031, 7034, 7038, 7040}
GPU_IDS     = {4101, 14, 13, 204}
NET_IDS     = {1014, 4227, 4231, 10317, 10400, 4001, 8003, 8004, 27}
DRIVER_IDS  = {219, 411, 5, 7026, 15, 20003}
POWER_IDS   = {42, 107, 566, 12, 505, 506}
UPDATE_IDS  = {19, 20, 43, 44, 16, 17, 25}
SEC_IDS     = {4625, 4648, 4719, 4740, 4771, 4776, 4625}

# ── Provider keyword maps
_DISK_PROV    = {"disk","volmgr","ntfs","storport","storahci","nvme","stornvme","iastoravc","partmgr","cdrom","scsi"}
_GPU_PROV     = {"nvidia","nvlddmkm","display","dxgkrnl","dxgmms","igfx","amdkmdap","atikmdag","atikmpag"}
_NET_PROV     = {"tcpip","netbt","dnsclient","dns","ndis","netlogon","nsi","wlan","wlanautoconfig","wifi","dhcp","netadapter","rpc"}
_DRIVER_PROV  = {"pnp","pnpmgr","plugplay","hal","acpimsft","filters","mup","bowser"}
_POWER_PROV   = {"kernel-power","acpi","battery","sleepstudy","powercfg"}
_UPDATE_PROV  = {"windowsupdateclient","wuauserv","trustedinstaller","msiinstaller","servicing","cbshandler"}
_SEC_PROV     = {"microsoft-windows-security","schannel","lsasrv","netlogon","kerberos","sam","audit"}
_AV_PROV      = {"defender","msmpeng","windefend","malwarebytes","eset","avast","avg","norton","mcafee","crowdstrike"}
_KERNEL_PROV  = {"kernel-general","kernel-process","kernel-pnp","kernel-eventtracing","kernel"}
_BROWSER_APPS = {"chrome","brave","firefox","msedge","opera","vivaldi","chromium"}

# ── DB ───────────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            received_at  TEXT NOT NULL,
            time_created TEXT NOT NULL,
            event_id     INTEGER NOT NULL,
            level        INTEGER NOT NULL,
            level_name   TEXT NOT NULL,
            log_name     TEXT NOT NULL,
            provider     TEXT NOT NULL,
            message      TEXT NOT NULL,
            analysis     TEXT,
            category     TEXT,
            hostname     TEXT,
            username     TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_time ON events(time_created);
        CREATE INDEX IF NOT EXISTS idx_evt  ON events(event_id);
        CREATE INDEX IF NOT EXISTS idx_prov ON events(provider);

        CREATE TABLE IF NOT EXISTS snapshots (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            received_at       TEXT NOT NULL,
            hostname          TEXT,
            username          TEXT,
            mem_total_mb      INTEGER,
            mem_free_mb       INTEGER,
            mem_percent       REAL,
            cpu_percent       REAL,
            uptime_minutes    INTEGER,
            gpu_temp          INTEGER,
            gpu_percent       INTEGER,
            gpu_vram_used_mb  INTEGER,
            gpu_vram_total_mb INTEGER,
            cpu_temp          INTEGER,
            disk_read_mbps    REAL,
            disk_write_mbps   REAL,
            smart_disks       TEXT,
            browser_crashes   INTEGER,
            disks             TEXT
        );

        CREATE TABLE IF NOT EXISTS incidents (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at    TEXT NOT NULL,
            bsod_event_id INTEGER NOT NULL,
            chain_ids     TEXT,
            analysis      TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_inc_bsod ON incidents(bsod_event_id);

        CREATE TABLE IF NOT EXISTS service_analyses (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at   TEXT NOT NULL,
            service_name TEXT NOT NULL,
            category     TEXT,
            crash_count  INTEGER,
            analysis     TEXT,
            action       TEXT,
            severity     TEXT DEFAULT 'high',
            resolved     INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_svc_name ON service_analyses(service_name);
        CREATE INDEX IF NOT EXISTS idx_svc_time ON service_analyses(created_at);

        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            name       TEXT NOT NULL,
            email      TEXT,
            secret     TEXT NOT NULL UNIQUE,
            active     INTEGER DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_user_secret ON users(secret);
    """)
    conn.commit()
    conn.close()

init_db()

# ── Migraciones
def migrate_db():
    conn = get_db()

    # Columnas nuevas en snapshots
    snap_cols = {row[1] for row in conn.execute("PRAGMA table_info(snapshots)").fetchall()}
    for col, typ in [
        ("gpu_percent","INTEGER"),("gpu_vram_used_mb","INTEGER"),
        ("gpu_vram_total_mb","INTEGER"),("disk_read_mbps","REAL"),
        ("disk_write_mbps","REAL"),("smart_disks","TEXT"),
        ("browser_crashes","INTEGER"),("user_id","INTEGER"),
    ]:
        if col not in snap_cols:
            conn.execute(f"ALTER TABLE snapshots ADD COLUMN {col} {typ}")

    # user_id en events
    ev_cols = {row[1] for row in conn.execute("PRAGMA table_info(events)").fetchall()}
    if "user_id" not in ev_cols:
        conn.execute("ALTER TABLE events ADD COLUMN user_id INTEGER")

    # Crear usuario marc0 si no existe (migra datos existentes)
    marc0 = conn.execute("SELECT id FROM users WHERE secret=?", (API_SECRET,)).fetchone()
    if not marc0:
        now = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(
            "INSERT INTO users (created_at,name,email,secret) VALUES (?,?,?,?)",
            (now, "marc0", "marc0@vigil", API_SECRET)
        )
        marc0_id = cur.lastrowid
        # Asignar eventos y snapshots existentes a marc0
        conn.execute("UPDATE events    SET user_id=? WHERE user_id IS NULL", (marc0_id,))
        conn.execute("UPDATE snapshots SET user_id=? WHERE user_id IS NULL", (marc0_id,))
    conn.commit()
    conn.close()

migrate_db()

def recategorize_db():
    """Re-categoriza eventos existentes con la lógica nueva."""
    conn = get_db()
    rows = conn.execute("SELECT id, event_id, provider, message FROM events").fetchall()
    updated = 0
    for row in rows:
        new_cat = categorize(row["event_id"], row["provider"] or "", row["message"] or "")
        conn.execute("UPDATE events SET category=? WHERE id=?", (new_cat, row["id"]))
        updated += 1
    conn.commit()
    conn.close()
    return updated

# ── Helpers ──────────────────────────────────────────────────────────────────
def categorize(event_id: int, provider: str, message: str = "") -> str:
    """Clasifica un evento por categoría usando ID, proveedor y contenido del mensaje.
    Prioridad: BSOD > GPU(prov) > DISCO > GPU(id) > RED > DRIVER > ENERGIA > ACTUALIZACION >
               SEGURIDAD > ANTIVIRUS > KERNEL > SERVICIO > BROWSER > APP_CRASH > SISTEMA
    Nota: proveedor GPU tiene prioridad sobre IDs de disco para casos como nvlddmkm ID 153.
    """
    p = provider.lower()
    m = message.lower()

    # 1. BSOD — prioridad máxima
    if event_id in BSOD_IDS or "bugcheck" in m or "bug check" in m:
        return "BSOD"

    # 2. GPU — proveedor GPU tiene prioridad sobre IDs de disco compartidos (ej: nvlddmkm ID 153)
    if any(k in p for k in _GPU_PROV):
        return "GPU"

    # 3. DISCO — hardware de almacenamiento
    if event_id in DISK_IDS or any(k in p for k in _DISK_PROV):
        return "DISCO"

    # 4. GPU — por ID (sin proveedor GPU explícito)
    if event_id in GPU_IDS:
        return "GPU"

    # 4. RED — conectividad y protocolos de red
    if event_id in NET_IDS or any(k in p for k in _NET_PROV):
        return "RED"

    # 5. DRIVER — fallos de carga de drivers genéricos
    if event_id in DRIVER_IDS or any(k in p for k in _DRIVER_PROV):
        return "DRIVER"

    # 6. ENERGIA — apagados, suspensión, energía inesperada
    if event_id in POWER_IDS or any(k in p for k in _POWER_PROV):
        return "ENERGIA"

    # 7. ACTUALIZACION — Windows Update y MSI installs
    if event_id in UPDATE_IDS or any(k in p for k in _UPDATE_PROV):
        return "ACTUALIZACION"

    # 8. SEGURIDAD — fallos de autenticación, auditoría
    if event_id in SEC_IDS or any(k in p for k in _SEC_PROV):
        return "SEGURIDAD"

    # 9. ANTIVIRUS — Defender y otros AV
    if any(k in p for k in _AV_PROV):
        return "ANTIVIRUS"

    # 10. KERNEL — componentes del núcleo
    if any(k in p for k in _KERNEL_PROV) or "kernel" in p:
        return "KERNEL"

    # 11. SERVICIO — con reclasificación por mensaje
    if event_id in SERVICE_IDS:
        if any(b in m for b in _BROWSER_APPS):
            return "BROWSER"
        if any(k in m for k in ("network", "dns", "dhcp", "wlan", "wifi", "ethernet")):
            return "RED"
        if any(k in m for k in ("update", "wuauserv", "trustedinstaller")):
            return "ACTUALIZACION"
        if any(k in m for k in ("defender", "antivirus", "msmpeng")):
            return "ANTIVIRUS"
        if any(k in m for k in ("nvidia", "display", "gpu", "dxgi")):
            return "GPU"
        return "SERVICIO"

    # 12. BROWSER — crashes de browsers (event 1000/1002 con app conocida)
    if event_id in (1000, 1002) and any(b in m for b in _BROWSER_APPS):
        return "BROWSER"

    # 13. APP_CRASH — cualquier otro crash de aplicación
    if event_id in (1000, 1002, 1005, 1026):
        return "APP_CRASH"

    # 14. SISTEMA — fallback
    return "SISTEMA"

def run_incident_analysis(inc_id: int, bsod: dict, chain: list):
    """Genera el análisis Claude para un incidente dado."""
    if not CLAUDE_API_KEY:
        return
    chain_text = "\n".join(
        f"  {i+1}. [{e['time_created'][11:19]}] {e.get('category') or 'SIS'} — "
        f"{e['provider']} (ID {e['event_id']}): {e['message'][:200]}"
        for i, e in enumerate(chain)
    ) or "  (sin eventos previos en la ventana de 15 min)"

    prompt = f"""Eres un experto en diagnóstico de Windows. Analiza este incidente del MSI Trident X2 (gaming desktop, Windows 11).

EVENTO FINAL — BSOD:
  Tiempo   : {bsod['time_created']}
  Proveedor: {bsod['provider']}
  Event ID : {bsod['event_id']}
  Mensaje  : {bsod['message'][:400]}

CADENA DE EVENTOS PREVIOS (15 min antes):
{chain_text}

Responde en español con este formato exacto:
**Causa raíz:** (1-2 líneas — qué evento inició la cascada)
**Cadena de fallo:** (explica cómo un evento llevó al siguiente)
**Veredicto:** (hardware / software / driver / indefinido)
**Acción concreta:** (qué hacer exactamente para evitar que se repita)"""

    client = anthropic.Anthropic(api_key=CLAUDE_API_KEY)
    try:
        resp = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=600,
            messages=[{"role": "user", "content": prompt}]
        )
        conn = get_db()
        conn.execute("UPDATE incidents SET analysis=? WHERE id=?", (resp.content[0].text, inc_id))
        conn.commit()
        conn.close()
    except Exception:
        pass


def auto_incident(bsod_db_id: int):
    """Cuando llega un BSOD, crea el incidente y analiza la cadena.

    Un crash genera múltiples eventos (ej: 41 al caer + 1001/BugCheck al reiniciar).
    Se evita crear incidentes duplicados buscando uno existente en ventana ±15 min.
    El evento 1001 (BugCheck) contiene el stop code exacto — si llega después del 41,
    se usa su mensaje para el análisis en lugar del 41 si el incidente aún no tiene análisis.
    """
    conn = get_db()
    existing = conn.execute(
        "SELECT id, analysis FROM incidents WHERE bsod_event_id=?", (bsod_db_id,)
    ).fetchone()

    bsod = conn.execute("SELECT * FROM events WHERE id=?", (bsod_db_id,)).fetchone()
    if not bsod:
        conn.close(); return
    bsod = dict(bsod)

    chain = conn.execute("""
        SELECT * FROM events
        WHERE time_created BETWEEN datetime(?, '-15 minutes') AND ?
          AND id != ?
        ORDER BY time_created ASC
    """, (bsod["time_created"], bsod["time_created"], bsod_db_id)).fetchall()
    chain = [dict(e) for e in chain]

    if existing:
        inc_id = existing["id"]
        # Si ya existe pero no tiene análisis, generarlo
        if not existing["analysis"]:
            conn.close()
            run_incident_analysis(inc_id, bsod, chain)
        else:
            conn.close()
        return

    # Buscar incidente cercano del mismo crash (ventana ±15 min) para evitar duplicados.
    # Ocurre cuando event 41 (Critical, al caer) y event 1001/BugCheck (Information, al reiniciar)
    # llegan en el mismo batch — ambos disparan auto_incident pero son la misma caída.
    nearby = conn.execute("""
        SELECT i.id, i.analysis, e2.event_id as trigger_eid
        FROM incidents i
        JOIN events e2 ON e2.id = i.bsod_event_id
        WHERE e2.time_created BETWEEN datetime(?, '-15 minutes')
                                  AND datetime(?, '+15 minutes')
        ORDER BY i.id DESC LIMIT 1
    """, (bsod["time_created"], bsod["time_created"])).fetchone()

    if nearby:
        # Ya existe un incidente de esta caída. Si el evento actual es 1001 (BugCheck,
        # contiene stop code) y el incidente no tiene análisis aún, generarlo con este contexto.
        if not nearby["analysis"] and bsod["event_id"] == 1001:
            conn.close()
            run_incident_analysis(nearby["id"], bsod, chain)
        else:
            conn.close()
        return

    # Crear nuevo incidente
    chain_ids = ",".join(str(e["id"]) for e in chain)
    cur = conn.execute(
        "INSERT INTO incidents (created_at, bsod_event_id, chain_ids) VALUES (?,?,?)",
        (datetime.now(timezone.utc).isoformat(), bsod_db_id, chain_ids)
    )
    inc_id = cur.lastrowid
    conn.commit()
    conn.close()

    run_incident_analysis(inc_id, bsod, chain)


def analyze_service_crash(service_name: str, category: str, crash_count: int, crash_events: list, detail_events: list):
    """Usa Claude para diagnosticar un crash loop de servicio y generar solución específica."""
    if not CLAUDE_API_KEY:
        return
    # No re-analizar si ya hay un análisis reciente (última hora)
    conn = get_db()
    recent = conn.execute("""
        SELECT id FROM service_analyses
        WHERE service_name=? AND created_at > datetime('now','-1 hour')
        ORDER BY id DESC LIMIT 1
    """, (service_name,)).fetchone()
    if recent:
        conn.close()
        return
    conn.close()

    # Construir contexto para Claude
    crashes_text = "\n".join(
        f"  [{e['time_created'][11:19]}] {e['message'][:200]}"
        for e in crash_events[:5]
    )
    details_text = "\n".join(
        f"  [{e['time_created'][11:19]}] ID={e['event_id']} {e['provider']}: {e['message'][:300]}"
        for e in detail_events[:8]
    ) or "  (sin logs de detalle disponibles)"

    prompt = f"""Eres un experto en diagnóstico de Windows. El servicio "{service_name}" (categoría: {category}) ha crasheado {crash_count} veces en las últimas horas en un MSI Trident X2 (Windows 11 25H2, RTX 4090).

EVENTOS DE CRASH (Service Control Manager):
{crashes_text}

LOGS DE DETALLE DEL SERVICIO (logs operacionales):
{details_text}

Responde en español con este formato exacto:
**Causa raíz:** (1-2 líneas — qué está causando el crash específicamente)
**Diagnóstico:** (qué archivo, recurso, o condición lo desencadena)
**Solución:** (comandos o pasos exactos y concretos para resolver — sé específico con rutas, comandos, etc.)
**Urgencia:** (crítico / alto / medio / bajo)"""

    client = anthropic.Anthropic(api_key=CLAUDE_API_KEY)
    try:
        resp = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )
        analysis_text = resp.content[0].text

        # Extraer la solución del análisis para mostrarla en el issue
        action = service_name + ": ver análisis"
        import re as _re2
        sol_match = _re2.search(r'\*\*Solución:\*\*\s*(.+?)(?:\*\*|$)', analysis_text, _re2.DOTALL)
        if sol_match:
            action = sol_match.group(1).strip()[:300]

        urg_match = _re2.search(r'\*\*Urgencia:\*\*\s*(\w+)', analysis_text, _re2.IGNORECASE)
        severity = "high"
        if urg_match:
            u = urg_match.group(1).lower()
            severity = "critical" if "crít" in u else "medium" if "medio" in u else "low" if "bajo" in u else "high"

        conn2 = get_db()
        conn2.execute("""
            INSERT INTO service_analyses (created_at, service_name, category, crash_count, analysis, action, severity)
            VALUES (?,?,?,?,?,?,?)
        """, (datetime.now(timezone.utc).isoformat(), service_name, category, crash_count, analysis_text, action, severity))
        conn2.commit()
        conn2.close()
    except Exception:
        pass


def auto_analyze(event_id_db: int):
    """Analiza automáticamente eventos críticos en background."""
    conn = get_db()
    row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id_db,)).fetchone()
    if not row or row["analysis"]:
        conn.close()
        return
    event = dict(row)

    # Buscar eventos relacionados 30 min antes
    related = conn.execute("""
        SELECT event_id, provider, level_name, message
        FROM events
        WHERE time_created BETWEEN datetime(?, '-30 minutes') AND ?
          AND id != ?
        ORDER BY time_created ASC
        LIMIT 10
    """, (event["time_created"], event["time_created"], event_id_db)).fetchall()
    conn.close()

    context = ""
    if related:
        context = "\n\nEventos previos (30 min antes):\n" + "\n".join(
            f"- [{r['level_name']}] {r['provider']} (ID {r['event_id']}): {r['message'][:150]}"
            for r in related
        )

    client = anthropic.Anthropic(api_key=CLAUDE_API_KEY)
    try:
        resp = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=500,
            messages=[{"role": "user", "content": f"""Eres un experto en diagnóstico de Windows. Analiza este evento del sistema MSI Trident X2 (gaming desktop, Windows 11).

Evento principal:
- Tiempo: {event['time_created']}
- Log: {event['log_name']}
- Proveedor: {event['provider']}
- Event ID: {event['event_id']}
- Nivel: {event['level_name']}
- Categoría: {event['category']}
- Mensaje: {event['message'][:800]}
{context}

Responde en español, conciso (máx 200 palabras):
**Qué es:** (1 línea)
**Causa probable:** (1-2 líneas, considera los eventos previos si los hay)
**Acción recomendada:** (1-2 líneas concretas, o "Monitorear" si no es urgente)"""}]
        )
        analysis = resp.content[0].text
        conn2 = get_db()
        conn2.execute("UPDATE events SET analysis = ? WHERE id = ?", (analysis, event_id_db))
        conn2.commit()
        conn2.close()
    except Exception:
        pass

# ── Models ───────────────────────────────────────────────────────────────────
class WinEvent(BaseModel):
    time_created: str
    event_id: int
    level: int
    level_name: str
    log_name: str
    provider: str
    message: str

class Metrics(BaseModel):
    hostname: Optional[str] = None
    username: Optional[str] = None
    mem_total_mb: Optional[int] = None
    mem_free_mb: Optional[int] = None
    mem_percent: Optional[float] = None
    cpu_percent: Optional[float] = None
    uptime_minutes: Optional[int] = None
    gpu_temp: Optional[int] = None
    gpu_percent: Optional[int] = None
    gpu_vram_used_mb: Optional[int] = None
    gpu_vram_total_mb: Optional[int] = None
    cpu_temp: Optional[int] = None
    disk_read_mbps: Optional[float] = None
    disk_write_mbps: Optional[float] = None
    smart_disks: Optional[str] = None
    browser_crashes: Optional[int] = None
    disks: Optional[str] = None

class EventBatch(BaseModel):
    secret: str
    metrics: Optional[Metrics] = None
    events: List[WinEvent]

# ── Auth ─────────────────────────────────────────────────────────────────────
# ── Telegram ─────────────────────────────────────────────────────────────────
def send_telegram(text: str, key: str = "", cooldown: int = 300):
    """Envía mensaje a Telegram. key+cooldown evitan spam del mismo evento."""
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    if key:
        now = time.time()
        if now - _tg_sent.get(key, 0) < cooldown:
            return
        _tg_sent[key] = now
    try:
        url  = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        data = urllib.parse.urlencode({
            "chat_id":    TELEGRAM_CHAT_ID,
            "text":       text,
            "parse_mode": "HTML"
        }).encode()
        urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=10)
    except Exception:
        pass

def notify_event(event: dict, category: str, hostname: str = ""):
    """Decide si un evento merece notificación y la envía."""
    eid   = event.get("event_id", 0)
    level = event.get("level", 9)
    prov  = event.get("provider", "")
    msg   = (event.get("message", "") or "")[:200]
    t     = (event.get("time_created", "") or "")[:16].replace("T", " ")
    host  = hostname or "MSI Trident X2"

    # BSOD — prioridad máxima, cooldown 10 min
    if eid in BSOD_IDS:
        text = (
            f"🔴 <b>VIGIL — BSOD</b>\n"
            f"<b>{host}</b>\n\n"
            f"Event {eid} · {prov}\n"
            f"<code>{t}</code>\n\n"
            f"{msg}\n\n"
            f"→ Revisa <code>C:\\Windows\\Minidump</code>"
        )
        send_telegram(text, key=f"bsod-{t}", cooldown=600)
        return

    # Crítico nivel 1
    if level == 1:
        icon = "🔴" if category in ("DISCO","GPU","DRIVER") else "⚠️"
        text = (
            f"{icon} <b>VIGIL — Crítico [{category}]</b>\n"
            f"<b>{host}</b>\n\n"
            f"{prov} · ID {eid}\n"
            f"<code>{t}</code>\n\n"
            f"{msg}"
        )
        send_telegram(text, key=f"crit-{eid}-{t}", cooldown=300)
        return

    # Error de disco nivel 2
    if level == 2 and category == "DISCO":
        text = (
            f"💾 <b>VIGIL — Error de Disco [{category}]</b>\n"
            f"<b>{host}</b>\n\n"
            f"{prov} · ID {eid}\n"
            f"<code>{t}</code>\n\n"
            f"{msg}"
        )
        send_telegram(text, key=f"disk-{eid}-{t}", cooldown=600)
        return

    # GPU error nivel 2
    if level == 2 and category == "GPU":
        text = (
            f"🎮 <b>VIGIL — Error de GPU</b>\n"
            f"<b>{host}</b>\n\n"
            f"{prov} · ID {eid}\n"
            f"<code>{t}</code>\n\n"
            f"{msg}"
        )
        send_telegram(text, key=f"gpu-{eid}-{t}", cooldown=600)

def notify_crash_loop(svc_name: str, count: int, action: str, hostname: str = "", ai: bool = False):
    """Notifica cuando un servicio entra en crash loop."""
    host  = hostname or "MSI Trident X2"
    label = "🤖 IA" if ai else "→"
    text  = (
        f"🔁 <b>VIGIL — Crash Loop</b>\n"
        f"<b>{host}</b>\n\n"
        f"<b>{svc_name}</b> se detuvo <b>{count}x</b> en 6h\n\n"
        f"{label} {action[:300]}"
    )
    send_telegram(text, key=f"loop-{svc_name.lower()}", cooldown=1800)

# ── Auth & Users ─────────────────────────────────────────────────────────────
def make_secret() -> str:
    alphabet = string.ascii_lowercase + string.digits
    token = "".join(secrets.choice(alphabet) for _ in range(14))
    return f"vigil-{token}"

def get_user(secret: str) -> dict:
    """Retorna el usuario dado su secret, o lanza 401."""
    conn = get_db()
    row  = conn.execute(
        "SELECT id, name, email FROM users WHERE secret=? AND active=1", (secret,)
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"id": row["id"], "name": row["name"], "email": row["email"]}

def auth(secret: str):
    """Compatibilidad — solo valida, no retorna usuario."""
    get_user(secret)

# ── API ──────────────────────────────────────────────────────────────────────
@app.post("/api/events")
def receive_events(batch: EventBatch, bg: BackgroundTasks):
    user = get_user(batch.secret)
    uid  = user["id"]
    conn = get_db()
    now  = datetime.now(timezone.utc).isoformat()
    count = 0
    auto_ids = []

    # Guardar snapshot de métricas
    if batch.metrics:
        m = batch.metrics
        conn.execute("""
            INSERT INTO snapshots (received_at,hostname,username,mem_total_mb,mem_free_mb,
                mem_percent,cpu_percent,uptime_minutes,gpu_temp,gpu_percent,gpu_vram_used_mb,
                gpu_vram_total_mb,cpu_temp,disk_read_mbps,disk_write_mbps,smart_disks,
                browser_crashes,disks,user_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (now, m.hostname, m.username, m.mem_total_mb, m.mem_free_mb,
              m.mem_percent, m.cpu_percent, m.uptime_minutes, m.gpu_temp, m.gpu_percent,
              m.gpu_vram_used_mb, m.gpu_vram_total_mb, m.cpu_temp, m.disk_read_mbps,
              m.disk_write_mbps, m.smart_disks, m.browser_crashes, m.disks, uid))

    for e in batch.events:
        cat = categorize(e.event_id, e.provider, e.message)
        cur = conn.execute("""
            INSERT INTO events (received_at,time_created,event_id,level,level_name,
                log_name,provider,message,category,hostname,username,user_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (now, e.time_created, e.event_id, e.level, e.level_name,
              e.log_name, e.provider, e.message[:3000], cat,
              batch.metrics.hostname if batch.metrics else None,
              batch.metrics.username if batch.metrics else None, uid))
        count += 1
        # Auto-analizar BSODs y disk errors críticos
        # BSOD IDs (ej: 1001/BugCheck) pueden ser level=4 (Information) — se incluyen explícitamente
        AUTO_ANALYZE_CATS = {"BSOD","DISCO","GPU","DRIVER","RED","ENERGIA","ANTIVIRUS","BROWSER","SERVICIO"}
        if e.event_id in BSOD_IDS or (e.level <= 2 and cat in AUTO_ANALYZE_CATS):
            auto_ids.append(cur.lastrowid)
        # Correlación de incidente para BSODs
        if e.event_id in BSOD_IDS:
            bg.add_task(auto_incident, cur.lastrowid)
        # Notificaciones Telegram
        if e.level <= 2 or e.event_id in BSOD_IDS:
            host = batch.metrics.hostname if batch.metrics else ""
            bg.add_task(notify_event, {
                "event_id": e.event_id, "level": e.level,
                "provider": e.provider, "message": e.message,
                "time_created": e.time_created
            }, cat, host)

    conn.commit()
    conn.close()

    for eid in auto_ids:
        bg.add_task(auto_analyze, eid)

    return {"received": count}

@app.get("/api/events")
def list_events(secret: str = Query(...), limit: int = 100, offset: int = 0,
                level: Optional[int] = None, log_name: Optional[str] = None,
                category: Optional[str] = None):
    user = get_user(secret)
    uid  = user["id"]
    conn = get_db()
    where  = ["user_id = ?"]
    params = [uid]
    if level:
        where.append("level <= ?"); params.append(level)
    if log_name:
        where.append("log_name = ?"); params.append(log_name)
    if category:
        where.append("category = ?"); params.append(category)
    w     = "WHERE " + " AND ".join(where)
    rows  = conn.execute(f"SELECT * FROM events {w} ORDER BY id DESC LIMIT ? OFFSET ?",
                         params + [limit, offset]).fetchall()
    total = conn.execute(f"SELECT COUNT(*) FROM events {w}", params).fetchone()[0]
    conn.close()
    return {"total": total, "events": [dict(r) for r in rows]}

@app.get("/api/stats")
def stats(secret: str = Query(...)):
    user  = get_user(secret)
    uid   = user["id"]
    conn  = get_db()
    today = datetime.now().strftime("%Y-%m-%d")
    snap  = conn.execute("SELECT * FROM snapshots WHERE user_id=? ORDER BY id DESC LIMIT 1", (uid,)).fetchone()
    s = {
        "total":          conn.execute("SELECT COUNT(*) FROM events WHERE user_id=?", (uid,)).fetchone()[0],
        "critical_today": conn.execute("SELECT COUNT(*) FROM events WHERE user_id=? AND level=1 AND time_created LIKE ?", (uid, f"{today}%")).fetchone()[0],
        "errors_today":   conn.execute("SELECT COUNT(*) FROM events WHERE user_id=? AND level=2 AND time_created LIKE ?", (uid, f"{today}%")).fetchone()[0],
        "warnings_today": conn.execute("SELECT COUNT(*) FROM events WHERE user_id=? AND level=3 AND time_created LIKE ?", (uid, f"{today}%")).fetchone()[0],
        "bsods_today":    conn.execute("SELECT COUNT(*) FROM events WHERE user_id=? AND event_id IN (41,1001) AND time_created LIKE ?", (uid, f"{today}%")).fetchone()[0],
        "snapshot":       dict(snap) if snap else None,
    }
    conn.close()
    return s

@app.get("/api/issues")
def get_issues(secret: str = Query(...)):
    """Detecta patrones problemáticos activos."""
    user = get_user(secret)
    uid  = user["id"]
    conn = get_db()
    issues = []

    # BSODs en las últimas 24h
    bsod_count = conn.execute(
        "SELECT COUNT(*) FROM events WHERE user_id=? AND event_id IN (41,1001,6008) AND time_created > datetime('now','-24 hours')", (uid,)
    ).fetchone()[0]
    if bsod_count >= 1:
        last_bsod = conn.execute(
            "SELECT time_created, message FROM events WHERE user_id=? AND event_id IN (41,1001) ORDER BY id DESC LIMIT 1", (uid,)
        ).fetchone()
        issues.append({
            "severity": "critical",
            "type":     "BSOD",
            "title":    f"{bsod_count} BSOD(s) en 24h",
            "detail":   last_bsod["message"][:200] if last_bsod else "",
            "action":   "Revisa minidump y eventos de disco/driver previos"
        })

    # Servicio crasheando en loop (3+ veces en 2h)
    # Acciones conocidas por servicio
    SERVICE_ACTIONS = {
        "windows search":        ("Reconstruir índice: detener WSearch, borrar C:\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows, reiniciar WSearch", "high"),
        "wsearch":               ("Reconstruir índice: detener WSearch, borrar C:\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows, reiniciar WSearch", "high"),
        "windows update":        ("Ejecutar: sfc /scannow y DISM /RestoreHealth. Revisar C:\\Windows\\Logs\\WindowsUpdate", "high"),
        "wuauserv":              ("Ejecutar: sfc /scannow y DISM /RestoreHealth. Revisar C:\\Windows\\Logs\\WindowsUpdate", "high"),
        "windows defender":      ("MpCmdRun.exe -RemoveDefinitions -All && -SignatureUpdate", "medium"),
        "windefend":             ("MpCmdRun.exe -RemoveDefinitions -All && -SignatureUpdate", "medium"),
        "nvidia":                ("Reinstalar driver NVIDIA limpio con DDU en Safe Mode", "high"),
        "wmi":                   ("winmgmt /resetrepository en cmd admin", "high"),
        "winmgmt":               ("winmgmt /resetrepository en cmd admin", "high"),
        "print spooler":         ("net stop spooler, borrar C:\\Windows\\System32\\spool\\PRINTERS\\*, net start spooler", "medium"),
        "spooler":               ("net stop spooler, borrar C:\\Windows\\System32\\spool\\PRINTERS\\*, net start spooler", "medium"),
        "superfetch":            ("Deshabilitar SysMain si tienes SSD: services.msc → SysMain → Disabled", "low"),
        "sysmain":               ("Deshabilitar SysMain si tienes SSD: services.msc → SysMain → Disabled", "low"),
        "dhcp":                  ("ipconfig /release && ipconfig /renew. Revisar adaptador de red", "high"),
        "dns":                   ("ipconfig /flushdns. Revisar configuración de red", "medium"),
    }

    import re as _re
    loops = conn.execute("""
        SELECT event_id, message, COUNT(*) as cnt,
               MAX(time_created) as last_seen, MIN(id) as first_id
        FROM events
        WHERE user_id=? AND event_id IN (7031,7034,7023,7024)
          AND time_created > datetime('now','-6 hours')
        GROUP BY event_id, message
        HAVING COUNT(*) >= 3
        ORDER BY cnt DESC
        LIMIT 10
    """, (uid,)).fetchall()
    seen_services = set()
    for row in loops:
        msg = row["message"] or ""
        m = _re.search(r"The (.+?) service (terminated|crashed|stopped)", msg, _re.IGNORECASE)
        svc_name = m.group(1).strip() if m else "Servicio desconocido"
        svc_cat  = categorize(row["event_id"], "Service Control Manager", msg)
        svc_key  = svc_name.lower()
        if svc_key in seen_services:
            continue
        seen_services.add(svc_key)

        # Buscar análisis previo de Claude para este servicio
        claude_analysis = conn.execute("""
            SELECT action, analysis, severity FROM service_analyses
            WHERE service_name=? ORDER BY id DESC LIMIT 1
        """, (svc_name,)).fetchone()

        if claude_analysis and claude_analysis["action"]:
            action   = claude_analysis["action"]
            severity = claude_analysis["severity"] or "high"
            has_ai   = True
        else:
            # Fallback a acciones conocidas
            action = next(
                (act for key, (act, _) in SERVICE_ACTIONS.items() if key in svc_key),
                f"Revisar logs operacionales de '{svc_name}'. Ejecutar sfc /scannow como admin."
            )
            severity = next(
                (sev for key, (_, sev) in SERVICE_ACTIONS.items() if key in svc_key),
                "high"
            )
            has_ai = False

        # Recopilar eventos de detalle relacionados para análisis Claude en background
        crash_evts = conn.execute("""
            SELECT time_created, message FROM events
            WHERE user_id=? AND event_id IN (7031,7034,7023,7024)
              AND message LIKE ? AND time_created > datetime('now','-6 hours')
            ORDER BY id DESC LIMIT 5
        """, (uid, f"%{svc_name}%")).fetchall()
        crash_evts = [dict(e) for e in crash_evts]

        # Buscar logs operacionales del mismo servicio (Defender, WMI, etc.)
        detail_evts = conn.execute("""
            SELECT time_created, event_id, provider, message FROM events
            WHERE user_id=? AND category IN ('ANTIVIRUS','DRIVER','ACTUALIZACION','RED','SERVICIO')
              AND event_id NOT IN (7031,7034,7023,7024)
              AND time_created > datetime('now','-6 hours')
            ORDER BY id DESC LIMIT 10
        """, (uid,)).fetchall()
        detail_evts = [dict(e) for e in detail_evts]

        if not has_ai and len(crash_evts) >= 3:
            threading.Thread(
                target=analyze_service_crash,
                args=(svc_name, svc_cat, row["cnt"], crash_evts, detail_evts),
                daemon=True
            ).start()

        # Notificación Telegram para crash loops
        threading.Thread(
            target=notify_crash_loop,
            args=(svc_name, row["cnt"], action, "", has_ai),
            daemon=True
        ).start()

        issues.append({
            "severity":  severity,
            "type":      "CRASH_LOOP",
            "title":     f"{svc_name} se detuvo {row['cnt']}x en 6h",
            "detail":    claude_analysis["analysis"] if (has_ai and claude_analysis and claude_analysis["analysis"]) else (msg[:150] if msg else "Loop de reinicios detectado"),
            "action":    action,
            "ai_analyzed": has_ai
        })

    # App crashes en loop (3+ veces en 2h, event 1000)
    app_loops = conn.execute("""
        SELECT message, COUNT(*) as cnt
        FROM events
        WHERE user_id=? AND event_id = 1000
          AND time_created > datetime('now','-2 hours')
        GROUP BY message
        HAVING COUNT(*) >= 3
        ORDER BY cnt DESC
        LIMIT 5
    """, (uid,)).fetchall()
    for row in app_loops:
        msg = row["message"] or ""
        m = _re.search(r"Faulting application name: ([^,\r\n]+)", msg)
        app_name = m.group(1).strip() if m else "Aplicación desconocida"
        exc_m = _re.search(r"Exception code: (0x[0-9a-fA-F]+)", msg)
        mod_m = _re.search(r"Faulting module name: ([^,\r\n]+)", msg)
        detail = f"Módulo: {mod_m.group(1).strip() if mod_m else '?'} | Excepción: {exc_m.group(1) if exc_m else '?'}"
        issues.append({
            "severity":    "high",
            "type":        "CRASH_LOOP",
            "title":       f"{app_name} crasheó {row['cnt']}x en 2h",
            "detail":      detail,
            "action":      f"Reinstalar {app_name} o revisar extensiones/plugins. Verificar dumps en %LOCALAPPDATA%\\CrashDumps",
            "ai_analyzed": False
        })

    # Errores de disco en las últimas 24h
    disk_errors = conn.execute(
        "SELECT COUNT(*) FROM events WHERE user_id=? AND category='DISCO' AND time_created > datetime('now','-24 hours')", (uid,)
    ).fetchone()[0]
    if disk_errors >= 3:
        issues.append({
            "severity": "critical",
            "type":     "DISK",
            "title":    f"{disk_errors} errores de disco en 24h",
            "detail":   "Posible fallo de hardware en disco",
            "action":   "Ejecuta CHKDSK y verifica S.M.A.R.T."
        })

    # GPU/Driver errors
    gpu_errors = conn.execute(
        "SELECT COUNT(*) FROM events WHERE user_id=? AND category='GPU' AND time_created > datetime('now','-24 hours')", (uid,)
    ).fetchone()[0]
    if gpu_errors >= 2:
        issues.append({
            "severity": "medium",
            "type":     "GPU",
            "title":    f"{gpu_errors} errores de GPU/driver en 24h",
            "detail":   "Driver NVIDIA inestable",
            "action":   "Reinstala driver limpio sin GeForce Experience"
        })

    # Antivirus crasheando
    av_errors = conn.execute(
        "SELECT COUNT(*) FROM events WHERE user_id=? AND category='ANTIVIRUS' AND time_created > datetime('now','-6 hours')", (uid,)
    ).fetchone()[0]
    if av_errors >= 2:
        issues.append({
            "severity": "medium",
            "type":     "ANTIVIRUS",
            "title":    f"Windows Defender crasheó {av_errors}x en 6h",
            "detail":   "Definiciones corruptas o motor inestable",
            "action":   "MpCmdRun.exe -RemoveDefinitions -All && -SignatureUpdate"
        })

    # RED — errores de red repetidos
    net_errors = conn.execute(
        "SELECT COUNT(*) FROM events WHERE user_id=? AND category='RED' AND time_created > datetime('now','-2 hours')", (uid,)
    ).fetchone()[0]
    if net_errors >= 3:
        last_net = conn.execute(
            "SELECT provider, message FROM events WHERE user_id=? AND category='RED' ORDER BY id DESC LIMIT 1", (uid,)
        ).fetchone()
        issues.append({
            "severity": "medium",
            "type":     "RED",
            "title":    f"{net_errors} errores de red en 2h",
            "detail":   last_net["message"][:150] if last_net else "",
            "action":   "Verificar adaptador de red, ipconfig /release+renew, revisar DNS"
        })

    # DRIVER — fallo al cargar driver
    driver_errors = conn.execute(
        "SELECT COUNT(*), message FROM events WHERE user_id=? AND category='DRIVER' AND time_created > datetime('now','-24 hours') LIMIT 1", (uid,)
    ).fetchone()
    if driver_errors and driver_errors[0] >= 1:
        issues.append({
            "severity": "high",
            "type":     "DRIVER",
            "title":    f"{driver_errors[0]} fallo(s) de driver en 24h",
            "detail":   driver_errors[1][:150] if driver_errors[1] else "",
            "action":   "Revisar Device Manager → buscar triángulos amarillos. Actualizar o reinstalar driver."
        })

    # ENERGIA — apagados inesperados (que no sean BSODs)
    power_events = conn.execute(
        "SELECT COUNT(*) FROM events WHERE user_id=? AND category='ENERGIA' AND time_created > datetime('now','-24 hours')", (uid,)
    ).fetchone()[0]
    if power_events >= 2:
        issues.append({
            "severity": "medium",
            "type":     "ENERGIA",
            "title":    f"{power_events} eventos de energía anómalos en 24h",
            "detail":   "Posible fallo de fuente de poder o configuración de energía",
            "action":   "Revisar Event ID 41/6008. Verificar fuente de poder y configuración de suspensión."
        })

    # BROWSER — crashes de browsers
    browser_crashes = conn.execute(
        "SELECT COUNT(*), message FROM events WHERE user_id=? AND category='BROWSER' AND time_created > datetime('now','-24 hours') LIMIT 1", (uid,)
    ).fetchone()
    if browser_crashes and browser_crashes[0] >= 3:
        issues.append({
            "severity": "medium",
            "type":     "BROWSER",
            "title":    f"{browser_crashes[0]} crashes de browser en 24h",
            "detail":   browser_crashes[1][:150] if browser_crashes[1] else "",
            "action":   "Deshabilitar extensiones (--disable-extensions) para aislar la causa. Reinstalar si persiste."
        })

    # SEGURIDAD — fallos de autenticación repetidos
    sec_events = conn.execute(
        "SELECT COUNT(*) FROM events WHERE user_id=? AND category='SEGURIDAD' AND event_id=4625 AND time_created > datetime('now','-1 hours')", (uid,)
    ).fetchone()[0]
    if sec_events >= 5:
        issues.append({
            "severity": "critical",
            "type":     "SEGURIDAD",
            "title":    f"{sec_events} fallos de login en 1h",
            "detail":   "Posible ataque de fuerza bruta o usuario bloqueado",
            "action":   "Revisar Security log → Event 4625. Verificar intentos de acceso remoto (RDP/SSH)."
        })

    # ACTUALIZACION — fallos de update
    update_fails = conn.execute(
        "SELECT COUNT(*) FROM events WHERE user_id=? AND category='ACTUALIZACION' AND level <= 2 AND time_created > datetime('now','-24 hours')", (uid,)
    ).fetchone()[0]
    if update_fails >= 1:
        issues.append({
            "severity": "low",
            "type":     "ACTUALIZACION",
            "title":    f"{update_fails} error(es) de Windows Update en 24h",
            "detail":   "Actualización fallida",
            "action":   "Ejecutar: DISM /Online /Cleanup-Image /RestoreHealth && sfc /scannow"
        })

    conn.close()
    return {"issues": issues}

@app.get("/api/patterns")
def get_patterns(secret: str = Query(...)):
    """Top proveedores/eventos con más errores recientes."""
    auth(secret)
    conn = get_db()
    rows = conn.execute("""
        SELECT provider, event_id, category, COUNT(*) as cnt,
               MAX(time_created) as last_seen
        FROM events
        WHERE time_created > datetime('now', '-24 hours')
        GROUP BY provider, event_id
        HAVING COUNT(*) >= 2
        ORDER BY cnt DESC
        LIMIT 15
    """).fetchall()
    conn.close()
    return {"patterns": [dict(r) for r in rows]}

@app.get("/api/incidents")
def get_incidents(secret: str = Query(...)):
    auth(secret)
    conn = get_db()
    incidents = conn.execute("""
        SELECT i.*, e.time_created, e.event_id, e.message, e.provider
        FROM incidents i
        JOIN events e ON e.id = i.bsod_event_id
        ORDER BY i.id DESC LIMIT 20
    """).fetchall()

    result = []
    for inc in incidents:
        inc = dict(inc)
        chain = []
        if inc["chain_ids"]:
            ids = inc["chain_ids"].split(",")
            placeholders = ",".join("?" * len(ids))
            chain = conn.execute(
                f"SELECT id, time_created, category, provider, event_id, level_name, message FROM events WHERE id IN ({placeholders}) ORDER BY time_created ASC",
                ids
            ).fetchall()
            chain = [dict(e) for e in chain]
        inc["chain"] = chain
        result.append(inc)

    conn.close()
    return {"incidents": result}

@app.post("/api/incidents/{inc_id}/analyze")
def analyze_incident_manual(inc_id: int, secret: str = Query(...)):
    auth(secret)
    conn = get_db()
    inc = conn.execute("SELECT * FROM incidents WHERE id=?", (inc_id,)).fetchone()
    if not inc:
        raise HTTPException(404)
    inc = dict(inc)

    # Si ya tiene análisis, devolverlo
    if inc.get("analysis"):
        conn.close()
        return {"analysis": inc["analysis"]}

    # Obtener BSOD y cadena
    bsod = conn.execute("SELECT * FROM events WHERE id=?", (inc["bsod_event_id"],)).fetchone()
    if not bsod:
        conn.close()
        raise HTTPException(404, "BSOD event not found")
    bsod = dict(bsod)

    chain = []
    if inc.get("chain_ids"):
        ids = inc["chain_ids"].split(",")
        placeholders = ",".join("?" * len(ids))
        chain = conn.execute(
            f"SELECT * FROM events WHERE id IN ({placeholders}) ORDER BY time_created ASC", ids
        ).fetchall()
        chain = [dict(e) for e in chain]
    conn.close()

    # Generar análisis sincrónicamente para que el usuario vea la respuesta
    run_incident_analysis(inc_id, bsod, chain)

    conn2 = get_db()
    updated = conn2.execute("SELECT analysis FROM incidents WHERE id=?", (inc_id,)).fetchone()
    conn2.close()
    return {"analysis": updated["analysis"] if updated and updated["analysis"] else "Sin análisis disponible"}

@app.post("/api/analyze/{event_id}")
def analyze_event(event_id: int, secret: str = Query(...)):
    auth(secret)
    conn = get_db()
    row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    event = dict(row)
    conn.close()

    if event.get("analysis"):
        return {"analysis": event["analysis"]}

    auto_analyze(event_id)

    conn2 = get_db()
    updated = conn2.execute("SELECT analysis FROM events WHERE id = ?", (event_id,)).fetchone()
    conn2.close()
    return {"analysis": updated["analysis"] if updated and updated["analysis"] else "Sin análisis disponible"}

@app.delete("/api/events")
def clear_events(secret: str = Query(...)):
    auth(secret)
    conn = get_db()
    conn.execute("DELETE FROM events")
    conn.execute("DELETE FROM snapshots")
    conn.commit()
    conn.close()
    return {"ok": True}

@app.post("/api/recategorize")
def recategorize(secret: str = Query(...)):
    """Re-categoriza todos los eventos existentes con la lógica actual."""
    auth(secret)
    updated = recategorize_db()
    return {"updated": updated}

@app.get("/api/service_analyses")
def list_service_analyses(secret: str = Query(...)):
    """Retorna todos los diagnósticos AI de servicios crasheados."""
    auth(secret)
    conn = get_db()
    rows = conn.execute("""
        SELECT * FROM service_analyses ORDER BY id DESC LIMIT 50
    """).fetchall()
    conn.close()
    return {"analyses": [dict(r) for r in rows]}

# ── Admin ────────────────────────────────────────────────────────────────────
def require_admin(secret: str):
    """Solo el usuario marc0 (el que tiene API_SECRET) puede usar endpoints admin."""
    if secret != API_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

@app.get("/api/admin/users")
def admin_list_users(secret: str = Query(...)):
    require_admin(secret)
    conn = get_db()
    rows = conn.execute("""
        SELECT u.id, u.name, u.email, u.active, u.created_at,
               COUNT(DISTINCT e.id)  AS total_events,
               COUNT(DISTINCT s.id)  AS total_snapshots,
               MAX(e.received_at)    AS last_event
        FROM users u
        LEFT JOIN events    e ON e.user_id = u.id
        LEFT JOIN snapshots s ON s.user_id = u.id
        GROUP BY u.id
        ORDER BY u.id
    """).fetchall()
    conn.close()
    return {"users": [dict(r) for r in rows]}

@app.patch("/api/admin/users/{user_id}")
def admin_update_user(user_id: int, secret: str = Query(...),
                      active: Optional[int] = Query(default=None),
                      name: Optional[str] = Query(default=None)):
    require_admin(secret)
    conn = get_db()
    user = conn.execute("SELECT id FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        conn.close()
        raise HTTPException(404, "Usuario no encontrado")
    if active is not None:
        conn.execute("UPDATE users SET active=? WHERE id=?", (active, user_id))
    if name:
        conn.execute("UPDATE users SET name=? WHERE id=?", (name.strip()[:60], user_id))
    conn.commit()
    updated = conn.execute("SELECT id, name, email, active, created_at FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return dict(updated)

@app.delete("/api/admin/users/{user_id}")
def admin_delete_user(user_id: int, secret: str = Query(...)):
    require_admin(secret)
    conn = get_db()
    user = conn.execute("SELECT id, name FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        conn.close()
        raise HTTPException(404, "Usuario no encontrado")
    # No permitir borrar al admin (marc0)
    if user["name"] == "marc0":
        conn.close()
        raise HTTPException(400, "No se puede eliminar al usuario admin")
    conn.execute("DELETE FROM events    WHERE user_id=?", (user_id,))
    conn.execute("DELETE FROM snapshots WHERE user_id=?", (user_id,))
    conn.execute("DELETE FROM users     WHERE id=?",      (user_id,))
    conn.commit()
    conn.close()
    return {"ok": True, "deleted": user_id}

# ── Registro ─────────────────────────────────────────────────────────────────
@app.get("/register", response_class=HTMLResponse)
def register_page():
    return REGISTER_HTML.replace("__BASE__", BASE_PATH)

@app.post("/api/register")
def register(name: str = Query(...), email: str = Query(default="")):
    name = name.strip()
    if not name or len(name) < 2:
        raise HTTPException(400, "Nombre requerido (mínimo 2 caracteres)")
    secret = make_secret()
    now    = datetime.now(timezone.utc).isoformat()
    conn   = get_db()
    try:
        conn.execute(
            "INSERT INTO users (created_at, name, email, secret) VALUES (?,?,?,?)",
            (now, name[:60], email[:120], secret)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(409, "Error al crear usuario")
    conn.close()
    return {"secret": secret, "name": name, "dashboard": f"{BASE_PATH}/?secret={secret}"}

REGISTER_HTML = r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vigil — Crear cuenta</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: #0e0e0e;
  color: #e5e2e1;
  font-family: "Space Grotesk", sans-serif;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
}

/* ── Card ── */
.card {
  width: 100%;
  max-width: 460px;
  background: #161616;
  border: 1px solid #262626;
  border-radius: 20px;
  padding: 48px 44px 52px;
  box-shadow: 0 24px 64px rgba(0,0,0,.55);
}

/* ── Logo ── */
.logo {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 36px;
}
.logo-text {
  font-size: 22px;
  font-weight: 700;
  color: #00e475;
  letter-spacing: -.4px;
}

/* ── Headings ── */
.heading { font-size: 24px; font-weight: 700; letter-spacing: -.3px; margin-bottom: 8px; }
.subheading { font-size: 14px; color: #6b7280; line-height: 1.6; margin-bottom: 36px; }

/* ── Field ── */
.field { margin-bottom: 22px; }
.field label {
  display: block;
  font-size: 12px;
  font-weight: 600;
  color: #9ca3af;
  text-transform: uppercase;
  letter-spacing: .6px;
  margin-bottom: 9px;
}
.field label span { color: #4b5563; font-weight: 400; text-transform: none; letter-spacing: 0; }
.field input {
  display: block;
  width: 100%;
  background: #1e1e1e;
  border: 1.5px solid #2e2e2e;
  color: #e5e2e1;
  border-radius: 10px;
  padding: 14px 18px;
  font-family: "Space Grotesk", sans-serif;
  font-size: 15px;
  outline: none;
  transition: border-color .15s, box-shadow .15s;
}
.field input:focus {
  border-color: #00e475;
  box-shadow: 0 0 0 3px rgba(0,228,117,.1);
}
.field input::placeholder { color: #3f3f3f; }
.field-error {
  font-size: 12px;
  color: #ffb4ab;
  margin-top: 7px;
  display: none;
}

/* ── Button ── */
.btn-primary {
  display: block;
  width: 100%;
  background: #00e475;
  color: #003918;
  font-family: "Space Grotesk", sans-serif;
  font-size: 15px;
  font-weight: 700;
  border: none;
  border-radius: 10px;
  padding: 15px 24px;
  cursor: pointer;
  letter-spacing: .2px;
  transition: filter .15s, transform .1s;
  margin-top: 10px;
}
.btn-primary:hover { filter: brightness(1.08); }
.btn-primary:active { transform: scale(.98); }
.btn-primary:disabled { opacity: .4; cursor: not-allowed; transform: none; filter: none; }

.err-general {
  font-size: 13px;
  color: #ffb4ab;
  text-align: center;
  margin-top: 12px;
  display: none;
}

/* ── Result ── */
#result-section { display: none; }
.success-icon {
  width: 56px;
  height: 56px;
  border-radius: 50%;
  background: rgba(0,228,117,.1);
  border: 1.5px solid #00e47555;
  display: flex;
  align-items: center;
  justify-content: center;
  margin: 0 auto 20px;
}
.success-icon svg { width: 26px; height: 26px; }
.result-title { font-size: 22px; font-weight: 700; color: #00e475; text-align: center; margin-bottom: 6px; }
.result-sub { font-size: 13px; color: #6b7280; text-align: center; margin-bottom: 32px; line-height: 1.5; }

.secret-label {
  font-size: 11px;
  font-weight: 600;
  color: #6b7280;
  text-transform: uppercase;
  letter-spacing: .6px;
  margin-bottom: 10px;
}
.secret-box {
  background: #0a1a0f;
  border: 1.5px solid #00e47544;
  border-radius: 12px;
  padding: 18px 22px;
  font-size: 15px;
  color: #00e475;
  word-break: break-all;
  letter-spacing: .4px;
  font-weight: 500;
  line-height: 1.5;
}
.copy-row {
  display: flex;
  justify-content: flex-end;
  margin-top: 10px;
}
.btn-copy {
  background: transparent;
  border: 1.5px solid #2e2e2e;
  color: #6b7280;
  border-radius: 8px;
  padding: 7px 18px;
  font-family: "Space Grotesk", sans-serif;
  font-size: 13px;
  cursor: pointer;
  transition: border-color .15s, color .15s;
}
.btn-copy:hover { border-color: #00e475; color: #00e475; }

.btn-dash {
  display: block;
  width: 100%;
  background: #00e475;
  color: #003918;
  font-family: "Space Grotesk", sans-serif;
  font-size: 15px;
  font-weight: 700;
  border: none;
  border-radius: 10px;
  padding: 15px 24px;
  cursor: pointer;
  text-align: center;
  text-decoration: none;
  transition: filter .15s;
  margin-top: 28px;
}
.btn-dash:hover { filter: brightness(1.08); }

/* ── Footer ── */
.footer { text-align: center; margin-top: 22px; font-size: 12px; color: #333; }
</style>
</head>
<body>

<div class="card">

  <!-- Logo -->
  <div class="logo">
    <svg width="28" height="28" viewBox="0 0 64 64" fill="none">
      <circle cx="32" cy="32" r="28" fill="#131313" stroke="#00e475" stroke-width="2.5"/>
      <ellipse cx="32" cy="32" rx="17" ry="8.5" fill="#00e47510" stroke="#00e475" stroke-width="2"/>
      <circle cx="32" cy="32" r="7" fill="#00e475"/>
      <circle cx="29" cy="29" r="2.5" fill="white" opacity=".75"/>
    </svg>
    <span class="logo-text">Vigil</span>
  </div>

  <!-- Formulario -->
  <div id="form-section">
    <h1 class="heading">Crear cuenta</h1>
    <p class="subheading">Genera tu clave secreta para empezar a monitorear tu PC.</p>

    <div class="field">
      <label for="inp-name">Nombre de usuario</label>
      <input id="inp-name" type="text" placeholder="ej. marc0" maxlength="60" autocomplete="off" spellcheck="false">
      <div class="field-error" id="err-name"></div>
    </div>

    <div class="field">
      <label for="inp-email">Email <span>(opcional)</span></label>
      <input id="inp-email" type="email" placeholder="ej. yo@ejemplo.com" maxlength="120">
    </div>

    <button class="btn-primary" id="btn-register" onclick="doRegister()">Crear cuenta</button>
    <div class="err-general" id="err-general"></div>
  </div>

  <!-- Resultado -->
  <div id="result-section">
    <div class="success-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="#00e475" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="20 6 9 17 4 12"/>
      </svg>
    </div>
    <div class="result-title">¡Cuenta creada!</div>
    <p class="result-sub">Guarda tu clave secreta — no se puede recuperar después.</p>

    <div class="secret-label">Tu clave secreta</div>
    <div class="secret-box" id="result-secret"></div>
    <div class="copy-row">
      <button class="btn-copy" onclick="copySecret()">Copiar clave</button>
    </div>

    <a id="dash-link" href="#" class="btn-dash">Ir al dashboard →</a>
  </div>

</div>

<div class="footer">Vigil &mdash; monitor de sistema para Windows</div>

<script>
const BASE = "__BASE__";

async function doRegister() {
  const name  = document.getElementById("inp-name").value.trim();
  const email = document.getElementById("inp-email").value.trim();
  const btn   = document.getElementById("btn-register");
  const errN  = document.getElementById("err-name");
  const errG  = document.getElementById("err-general");

  errN.style.display = "none";
  errG.style.display = "none";

  if (name.length < 2) {
    errN.textContent = "Mínimo 2 caracteres.";
    errN.style.display = "block";
    document.getElementById("inp-name").focus();
    return;
  }

  btn.disabled = true;
  btn.textContent = "Creando cuenta…";

  try {
    const params = new URLSearchParams({ name });
    if (email) params.set("email", email);
    const res  = await fetch(`${BASE}/api/register?${params}`, { method: "POST" });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Error al registrar");

    document.getElementById("result-secret").textContent = data.secret;
    document.getElementById("dash-link").href = data.dashboard;
    document.getElementById("form-section").style.display = "none";
    document.getElementById("result-section").style.display = "block";

  } catch(e) {
    errG.textContent = e.message;
    errG.style.display = "block";
    btn.disabled = false;
    btn.textContent = "Crear cuenta";
  }
}

function copySecret() {
  const txt = document.getElementById("result-secret").textContent;
  navigator.clipboard.writeText(txt).then(() => {
    const btn = event.currentTarget;
    btn.textContent = "¡Copiado!";
    btn.style.borderColor = "#00e475";
    btn.style.color = "#00e475";
    setTimeout(() => {
      btn.textContent = "Copiar clave";
      btn.style.borderColor = "";
      btn.style.color = "";
    }, 1800);
  });
}

document.getElementById("inp-name").addEventListener("keydown", e => {
  if (e.key === "Enter") doRegister();
});

document.getElementById("inp-name").focus();
</script>
</body>
</html>
"""

CLIENT_VERSION = "1.1.0"
CLIENT_DOWNLOAD_URL = "https://github.com/marcosstgo/vigil/releases/download/v1.1.0/Vigil.exe"

@app.get("/api/version")
def get_version():
    """Versión actual del cliente disponible para auto-update."""
    return {
        "version":      CLIENT_VERSION,
        "download_url": CLIENT_DOWNLOAD_URL,
    }

# ── Landing page ──────────────────────────────────────────────────────────────
@app.get("/vigil", response_class=HTMLResponse)
@app.get("/vigil/", response_class=HTMLResponse)
def landing():
    return LANDING_HTML.replace("__BASE__", BASE_PATH)

LANDING_HTML = r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vigil — Monitor de PC para Windows</title>
<meta name="description" content="Vigil monitorea tu PC en tiempo real: eventos, hardware, crashes y diagnóstico con IA. Gratis.">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@400,0&display=swap" rel="stylesheet">
<script src="https://cdn.tailwindcss.com"></script>
<script>
tailwind.config = {
  theme: {
    extend: {
      colors: { brand: "#00e475", dark: "#0e0e0e", surface: "#161616", card: "#1a1a1a" },
      fontFamily: { grotesk: ["Space Grotesk", "sans-serif"] }
    }
  }
}
</script>
<style>
  *, body { font-family: "Space Grotesk", sans-serif; }
  .glow { box-shadow: 0 0 40px #00e47533, 0 0 80px #00e47511; }
  .card-hover { transition: transform .2s, box-shadow .2s; }
  .card-hover:hover { transform: translateY(-4px); box-shadow: 0 8px 32px #00e47522; }
  .step-line::after {
    content: "";
    position: absolute;
    top: 2.5rem;
    left: calc(50% + 2.5rem);
    width: calc(100% - 5rem);
    height: 1px;
    background: linear-gradient(90deg, #00e47555, transparent);
  }
  .eye-logo {
    display: inline-block;
    width: 2.5rem;
    height: 2.5rem;
  }
</style>
</head>
<body class="bg-dark text-white min-h-screen">

<!-- NAV -->
<nav class="fixed top-0 left-0 right-0 z-50 bg-dark/80 backdrop-blur-md border-b border-white/5">
  <div class="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
    <div class="flex items-center gap-2">
      <svg width="32" height="32" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="32" cy="32" r="28" fill="#121212" stroke="#00e475" stroke-width="3"/>
        <ellipse cx="32" cy="32" rx="17" ry="8.5" fill="#00e47508" stroke="#00e475" stroke-width="2"/>
        <circle cx="32" cy="32" r="6" fill="#00e475"/>
        <circle cx="29.5" cy="29.5" r="2" fill="white" opacity=".7"/>
      </svg>
      <span class="text-xl font-semibold tracking-tight">Vigil</span>
    </div>
    <div class="flex items-center gap-6 text-sm text-white/60">
      <a href="#features" class="hover:text-white transition-colors">Características</a>
      <a href="#how" class="hover:text-white transition-colors">Cómo funciona</a>
      <a href="__BASE__/register" class="bg-brand text-[#003918] font-semibold px-5 py-2 rounded-lg hover:brightness-110 transition-all">
        Crear cuenta
      </a>
    </div>
  </div>
</nav>

<!-- HERO -->
<section class="pt-40 pb-28 px-6 text-center relative overflow-hidden">
  <!-- Background glow -->
  <div class="absolute inset-0 flex items-center justify-center pointer-events-none">
    <div class="w-[600px] h-[600px] rounded-full bg-brand/5 blur-3xl"></div>
  </div>

  <!-- Eye SVG large -->
  <div class="relative flex justify-center mb-8">
    <div class="glow rounded-full p-1">
      <svg width="88" height="88" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="32" cy="32" r="28" fill="#131313" stroke="#00e475" stroke-width="2.5"/>
        <ellipse cx="32" cy="32" rx="17" ry="8.5" fill="#00e47510" stroke="#00e475" stroke-width="2"/>
        <circle cx="32" cy="32" r="7" fill="#00e475"/>
        <circle cx="29" cy="29" r="2.5" fill="white" opacity=".75"/>
      </svg>
    </div>
  </div>

  <h1 class="text-5xl md:text-7xl font-bold tracking-tight mb-6 leading-none">
    Tu PC,<br>
    <span class="text-brand">siempre bajo control.</span>
  </h1>
  <p class="text-lg md:text-xl text-white/50 max-w-xl mx-auto mb-10 leading-relaxed">
    Vigil monitorea eventos, hardware y crashes de tu PC con Windows en tiempo real —
    con diagnóstico por IA y alertas en Telegram.
  </p>
  <div class="flex flex-col sm:flex-row gap-4 justify-center">
    <a href="__BASE__/register"
       class="bg-brand text-[#003918] font-bold text-lg px-10 py-4 rounded-xl hover:brightness-110 transition-all shadow-lg shadow-brand/20">
      Crear cuenta gratis
    </a>
    <a href="#how"
       class="bg-white/5 border border-white/10 text-white font-medium text-lg px-10 py-4 rounded-xl hover:bg-white/10 transition-all">
      Ver cómo funciona
    </a>
  </div>
</section>

<!-- FEATURES -->
<section id="features" class="py-24 px-6">
  <div class="max-w-6xl mx-auto">
    <h2 class="text-3xl md:text-4xl font-bold text-center mb-4">Todo lo que necesitas ver</h2>
    <p class="text-white/40 text-center mb-16 text-lg">Sin agentes pesados. Sin configuración compleja.</p>

    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">

      <div class="card-hover bg-card border border-white/5 rounded-2xl p-7">
        <div class="w-12 h-12 rounded-xl bg-brand/10 flex items-center justify-center mb-5">
          <span class="material-symbols-outlined text-brand text-2xl">event_note</span>
        </div>
        <h3 class="text-lg font-semibold mb-2">Eventos del sistema</h3>
        <p class="text-white/45 text-sm leading-relaxed">
          Captura errores críticos, advertencias y eventos de seguridad del Event Log de Windows
          en tiempo real, clasificados en 14 categorías.
        </p>
      </div>

      <div class="card-hover bg-card border border-white/5 rounded-2xl p-7">
        <div class="w-12 h-12 rounded-xl bg-brand/10 flex items-center justify-center mb-5">
          <span class="material-symbols-outlined text-brand text-2xl">memory</span>
        </div>
        <h3 class="text-lg font-semibold mb-2">Hardware en tiempo real</h3>
        <p class="text-white/45 text-sm leading-relaxed">
          CPU, RAM, disco y red monitoreados cada minuto. Histórico de snapshots para
          detectar tendencias y cuellos de botella.
        </p>
      </div>

      <div class="card-hover bg-card border border-white/5 rounded-2xl p-7">
        <div class="w-12 h-12 rounded-xl bg-brand/10 flex items-center justify-center mb-5">
          <span class="material-symbols-outlined text-brand text-2xl">warning</span>
        </div>
        <h3 class="text-lg font-semibold mb-2">Detección de BSODs</h3>
        <p class="text-white/45 text-sm leading-relaxed">
          Detecta pantallas azules con su stop code exacto (0x1E, 0x7E…) usando los eventos
          BugCheck y Kernel-Power del Event Log.
        </p>
      </div>

      <div class="card-hover bg-card border border-white/5 rounded-2xl p-7">
        <div class="w-12 h-12 rounded-xl bg-brand/10 flex items-center justify-center mb-5">
          <span class="material-symbols-outlined text-brand text-2xl">psychology</span>
        </div>
        <h3 class="text-lg font-semibold mb-2">Diagnóstico con IA</h3>
        <p class="text-white/45 text-sm leading-relaxed">
          Claude analiza crashes de servicios y errores críticos y explica qué pasó
          y cómo resolverlo — en lenguaje claro, no en código hexadecimal.
        </p>
      </div>

      <div class="card-hover bg-card border border-white/5 rounded-2xl p-7">
        <div class="w-12 h-12 rounded-xl bg-brand/10 flex items-center justify-center mb-5">
          <span class="material-symbols-outlined text-brand text-2xl">notifications</span>
        </div>
        <h3 class="text-lg font-semibold mb-2">Alertas en Telegram</h3>
        <p class="text-white/45 text-sm leading-relaxed">
          Recibe notificaciones instantáneas en tu teléfono cuando tu PC tiene un evento
          crítico — sin abrir el dashboard.
        </p>
      </div>

      <div class="card-hover bg-card border border-white/5 rounded-2xl p-7">
        <div class="w-12 h-12 rounded-xl bg-brand/10 flex items-center justify-center mb-5">
          <span class="material-symbols-outlined text-brand text-2xl">group</span>
        </div>
        <h3 class="text-lg font-semibold mb-2">Multi-usuario</h3>
        <p class="text-white/45 text-sm leading-relaxed">
          Cada cuenta tiene sus propios datos aislados. Monitorea varias PCs desde un
          solo dashboard o gestiona equipos de trabajo.
        </p>
      </div>

    </div>
  </div>
</section>

<!-- HOW IT WORKS -->
<section id="how" class="py-24 px-6 bg-surface">
  <div class="max-w-5xl mx-auto">
    <h2 class="text-3xl md:text-4xl font-bold text-center mb-4">Listo en 3 pasos</h2>
    <p class="text-white/40 text-center mb-20 text-lg">Sin servidores propios. Sin configuración de red.</p>

    <div class="grid grid-cols-1 md:grid-cols-3 gap-10 relative">

      <div class="relative flex flex-col items-center text-center step-line">
        <div class="w-16 h-16 rounded-2xl bg-brand/10 border border-brand/30 flex items-center justify-center mb-6 text-brand font-bold text-2xl glow">
          1
        </div>
        <h3 class="text-lg font-semibold mb-2">Crear cuenta</h3>
        <p class="text-white/45 text-sm leading-relaxed">
          Regístrate y obtén tu clave secreta única en segundos.
          Sin correo de confirmación, sin tarjeta.
        </p>
      </div>

      <div class="relative flex flex-col items-center text-center step-line">
        <div class="w-16 h-16 rounded-2xl bg-brand/10 border border-brand/30 flex items-center justify-center mb-6 text-brand font-bold text-2xl">
          2
        </div>
        <h3 class="text-lg font-semibold mb-2">Instalar el cliente</h3>
        <p class="text-white/45 text-sm leading-relaxed">
          Descarga Vigil.exe, ejecútalo e ingresa tu clave.
          Se instala solo en el inicio de Windows.
        </p>
      </div>

      <div class="flex flex-col items-center text-center">
        <div class="w-16 h-16 rounded-2xl bg-brand/10 border border-brand/30 flex items-center justify-center mb-6 text-brand font-bold text-2xl">
          3
        </div>
        <h3 class="text-lg font-semibold mb-2">Ver el dashboard</h3>
        <p class="text-white/45 text-sm leading-relaxed">
          Accede al dashboard desde cualquier dispositivo y
          mantente al tanto de todo lo que pasa en tu PC.
        </p>
      </div>

    </div>
  </div>
</section>

<!-- STATS / TRUST BAR -->
<section class="py-16 px-6 border-y border-white/5">
  <div class="max-w-4xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-8 text-center">
    <div>
      <div class="text-3xl font-bold text-brand mb-1">14</div>
      <div class="text-white/40 text-sm">categorías de eventos</div>
    </div>
    <div>
      <div class="text-3xl font-bold text-brand mb-1">60s</div>
      <div class="text-white/40 text-sm">intervalo de reporte</div>
    </div>
    <div>
      <div class="text-3xl font-bold text-brand mb-1">0</div>
      <div class="text-white/40 text-sm">configuración requerida</div>
    </div>
    <div>
      <div class="text-3xl font-bold text-brand mb-1">100%</div>
      <div class="text-white/40 text-sm">gratis</div>
    </div>
  </div>
</section>

<!-- CTA FINAL -->
<section class="py-28 px-6 text-center relative overflow-hidden">
  <div class="absolute inset-0 flex items-center justify-center pointer-events-none">
    <div class="w-[500px] h-[300px] rounded-full bg-brand/5 blur-3xl"></div>
  </div>
  <h2 class="text-4xl md:text-5xl font-bold mb-6 relative">
    Empieza a ver lo que<br>
    <span class="text-brand">tu PC realmente hace.</span>
  </h2>
  <p class="text-white/45 mb-10 text-lg max-w-md mx-auto relative">
    Gratis. Sin instalación de servidor. Listo en menos de 2 minutos.
  </p>
  <a href="__BASE__/register"
     class="relative bg-brand text-[#003918] font-bold text-xl px-14 py-5 rounded-2xl hover:brightness-110 transition-all shadow-xl shadow-brand/25 inline-block">
    Crear cuenta gratis
  </a>
</section>

<!-- FOOTER -->
<footer class="py-10 px-6 border-t border-white/5 text-center text-white/25 text-sm">
  <div class="flex items-center justify-center gap-2 mb-3">
    <svg width="20" height="20" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="32" cy="32" r="28" fill="#131313" stroke="#00e475" stroke-width="3"/>
      <ellipse cx="32" cy="32" rx="17" ry="8.5" fill="#00e47508" stroke="#00e475" stroke-width="2"/>
      <circle cx="32" cy="32" r="6" fill="#00e475"/>
    </svg>
    <span class="text-white/50 font-medium">Vigil</span>
  </div>
  <p>Monitor de sistema para Windows &middot; Hecho con Python + FastAPI + IA</p>
</footer>

</body>
</html>"""

# ── Dashboard ─────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def dashboard(secret: str = Query(...)):
    auth(secret)
    return HTML.replace("__SECRET__", secret).replace("__BASE__", BASE_PATH)

HTML = r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vigil — MSI Trident X2</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600&family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap" rel="stylesheet">
<script src="https://cdn.tailwindcss.com"></script>
<script>
tailwind.config = {
  theme: {
    extend: {
      colors: {
        "primary":                  "#00e475",
        "on-primary":               "#003918",
        "secondary":                "#fabd00",
        "secondary-dim":            "#ffdf9e",
        "error":                    "#ffb4ab",
        "error-container":          "#93000a",
        "on-error-container":       "#ffdad6",
        "surface":                  "#131313",
        "surface-dim":              "#0e0e0e",
        "surface-container-low":    "#1c1b1b",
        "surface-container":        "#201f1f",
        "surface-container-high":   "#2a2a2a",
        "surface-container-highest":"#353534",
        "on-surface":               "#e5e2e1",
        "on-surface-variant":       "#c6c6cb",
        "outline-variant":          "#45474b",
      },
      fontFamily: {
        headline: ["Space Grotesk","sans-serif"],
        body:     ["Inter","sans-serif"],
      },
      borderRadius: {
        DEFAULT: "0.125rem",
        lg: "0.25rem",
        xl: "0.5rem",
        "2xl": "0.75rem",
        full: "9999px",
      }
    }
  }
}
</script>
<style>
.material-symbols-outlined{font-variation-settings:'FILL' 0,'wght' 400,'GRAD' 0,'opsz' 24;font-family:'Material Symbols Outlined'}
body{background:#131313;color:#e5e2e1;font-family:'Inter',sans-serif}

/* Category badge colours — dynamic JS classes */
.bc-BSOD      {background:#1e0a4a;color:#c084fc}
.bc-DISCO     {background:#051528;color:#60a5fa}
.bc-SERVICIO  {background:#051a14;color:#34d399}
.bc-GPU       {background:#1a1800;color:#facc15}
.bc-ANTIVIRUS {background:#180518;color:#e879f9}
.bc-APP_CRASH {background:#2d0505;color:#f87171}
.bc-KERNEL    {background:#1a0a00;color:#fb923c}
.bc-SISTEMA   {background:#111120;color:#475569}
.bc-RED       {background:#021a2a;color:#38bdf8}
.bc-DRIVER    {background:#1a0f00;color:#f97316}
.bc-ENERGIA   {background:#1a1500;color:#fde047}
.bc-ACTUALIZACION{background:#001a14;color:#4ade80}
.bc-SEGURIDAD {background:#2a0505;color:#fca5a5}
.bc-BROWSER   {background:#001a1a;color:#2dd4bf}
.bc-System    {background:#13104a;color:#818cf8}
.bc-Application{background:#03211a;color:#34d399}

/* Sparkline */
.sparkline{display:flex;align-items:flex-end;gap:2px;height:60px}
.sparkbar{flex:1;border-radius:2px 2px 0 0;min-height:3px;transition:height .4s,background .2s}

/* Analysis row */
.arow-box{border-left:2px solid #4338ca;margin:0 16px 10px;padding:10px 14px;
  color:#94a3b8;font-size:11px;line-height:1.75;white-space:pre-wrap;
  background:#0f0f1a;border-radius:0 4px 4px 0;font-family:'Inter',sans-serif}

/* Issue detail expand */
.issue-detail{max-height:0;overflow:hidden;transition:max-height .35s ease}
.issue-detail.open{max-height:400px}

/* Incident body */
.inc-body{display:none}
.inc-body.open{display:block}

/* AI badge */
.ai-badge{background:#1e1b4b;color:#a5b4fc;border-radius:3px;padding:1px 6px;
  font-size:9px;font-weight:700;letter-spacing:.3px;vertical-align:middle}

/* Modal */
.modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.85);z-index:200;
  align-items:center;justify-content:center}
.modal.open{display:flex}

/* Scrollbar */
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#353534;border-radius:2px}

/* Dotted bg texture */
.dot-texture{
  background-image:radial-gradient(#00e475 0.5px,transparent 0.5px);
  background-size:24px 24px;
}

@keyframes pulse2{0%,100%{opacity:1}50%{opacity:.3}}
.live-pulse{animation:pulse2 2s infinite}
</style>
</head>
<body class="min-h-screen flex overflow-hidden bg-surface text-on-surface">

<!-- Dot-grid texture -->
<div class="fixed inset-0 pointer-events-none opacity-[0.025] z-[-1] dot-texture"></div>

<!-- ═══ LEFT SIDEBAR ═══ -->
<aside class="h-screen w-60 fixed left-0 top-0 bg-surface-container-low flex flex-col p-5 pt-7 z-50"
       style="border-right:1px solid rgba(69,71,75,.25)">

  <!-- Logo -->
  <div class="mb-6">
    <h1 class="text-base font-black text-primary tracking-tighter font-headline leading-none">VIGIL</h1>
    <p class="text-[9px] font-headline uppercase tracking-widest text-on-surface-variant mt-1" style="opacity:.4">MSI TRIDENT X2 · marc0</p>
  </div>

  <!-- Live status pill -->
  <div class="flex items-center gap-2.5 mb-6 px-3 py-2.5 rounded-xl bg-surface-container" style="border:1px solid rgba(69,71,75,.2)">
    <span class="w-2 h-2 rounded-full bg-primary live-pulse flex-shrink-0" id="dot-live"></span>
    <div class="min-w-0">
      <p class="text-[9px] font-mono uppercase text-on-surface-variant leading-none mb-0.5" style="opacity:.4">Estado</p>
      <p class="text-xs font-headline font-bold text-on-surface truncate" id="status-text">Conectando…</p>
    </div>
  </div>

  <!-- Nav -->
  <nav class="space-y-1">
    <a class="flex items-center gap-3 p-2.5 rounded-xl font-headline uppercase text-xs tracking-widest text-primary"
       style="background:rgba(0,228,117,.08);border-left:2px solid #00e475" href="#">
      <span class="material-symbols-outlined text-[18px]">dashboard</span>Dashboard
    </a>
    <a class="flex items-center gap-3 p-2.5 rounded-xl font-headline uppercase text-xs tracking-widest transition-all cursor-pointer"
       style="color:rgba(198,198,203,.6)" href="#sec-events"
       onmouseover="this.style.background='rgba(32,31,31,1)';this.style.color='#e5e2e1'"
       onmouseout="this.style.background='';this.style.color='rgba(198,198,203,.6)'">
      <span class="material-symbols-outlined text-[18px]">terminal</span>Eventos
    </a>
    <a class="flex items-center gap-3 p-2.5 rounded-xl font-headline uppercase text-xs tracking-widest transition-all cursor-pointer"
       style="color:rgba(198,198,203,.6)" href="#sec-hw"
       onmouseover="this.style.background='rgba(32,31,31,1)';this.style.color='#e5e2e1'"
       onmouseout="this.style.background='';this.style.color='rgba(198,198,203,.6)'">
      <span class="material-symbols-outlined text-[18px]">memory</span>Hardware
    </a>
    <a class="flex items-center gap-3 p-2.5 rounded-xl font-headline uppercase text-xs tracking-widest transition-all cursor-pointer"
       style="color:rgba(198,198,203,.6)" href="#sec-incidents"
       onmouseover="this.style.background='rgba(32,31,31,1)';this.style.color='#e5e2e1'"
       onmouseout="this.style.background='';this.style.color='rgba(198,198,203,.6)'">
      <span class="material-symbols-outlined text-[18px]">crisis_alert</span>Incidentes
    </a>
  </nav>

  <!-- Stats -->
  <div class="mt-auto pt-4" style="border-top:1px solid rgba(69,71,75,.2)">
    <div class="grid grid-cols-2 gap-1.5 mb-1.5">
      <div class="bg-surface-container rounded-lg p-2.5 text-center">
        <p class="text-[9px] font-mono uppercase mb-1" style="color:rgba(198,198,203,.4)">BSODs</p>
        <p class="text-xl font-headline font-bold" style="color:#c084fc" id="s-bsod">—</p>
      </div>
      <div class="bg-surface-container rounded-lg p-2.5 text-center">
        <p class="text-[9px] font-mono uppercase mb-1" style="color:rgba(198,198,203,.4)">Críticos</p>
        <p class="text-xl font-headline font-bold text-error" id="s-crit">—</p>
      </div>
      <div class="bg-surface-container rounded-lg p-2.5 text-center">
        <p class="text-[9px] font-mono uppercase mb-1" style="color:rgba(198,198,203,.4)">Errores</p>
        <p class="text-xl font-headline font-bold" style="color:#fb923c" id="s-err">—</p>
      </div>
      <div class="bg-surface-container rounded-lg p-2.5 text-center">
        <p class="text-[9px] font-mono uppercase mb-1" style="color:rgba(198,198,203,.4)">Warnings</p>
        <p class="text-xl font-headline font-bold text-secondary" id="s-warn">—</p>
      </div>
    </div>
    <div class="bg-surface-container rounded-lg p-2.5 text-center mb-2">
      <p class="text-[9px] font-mono uppercase mb-1" style="color:rgba(198,198,203,.4)">Total Eventos</p>
      <p class="text-sm font-headline font-bold text-on-surface-variant" id="s-tot">—</p>
    </div>
    <div class="bg-surface-container rounded-lg p-2.5 text-center mb-2" id="s-browser-box">
      <p class="text-[9px] font-mono uppercase mb-1" style="color:rgba(198,198,203,.4)">Browser Crashes 24h</p>
      <p class="text-sm font-headline font-bold" id="s-browser" style="color:#38bdf8">—</p>
    </div>
    <p class="text-[9px] text-center font-mono" style="color:rgba(198,198,203,.25)" id="s-upd">—</p>
  </div>
</aside>

<!-- ═══ MAIN ═══ -->
<main class="flex-1 min-h-screen flex flex-col" style="margin-left:240px">

  <!-- TOP HEADER -->
  <header class="fixed top-0 right-0 z-40 flex justify-between items-center px-8 py-3.5"
          style="left:240px;background:rgba(19,19,19,.85);backdrop-filter:blur(16px);
                 border-bottom:1px solid rgba(69,71,75,.2)">
    <div class="flex items-center gap-5">
      <h2 class="text-xl font-black tracking-tighter text-primary font-headline">DASHBOARD</h2>
      <div class="flex items-center gap-2">
        <div class="w-1.5 h-1.5 rounded-full bg-primary live-pulse"></div>
        <span class="text-[10px] font-mono uppercase" style="color:rgba(198,198,203,.4)">Live</span>
      </div>
    </div>
    <div class="flex items-center gap-3">
      <span class="text-[10px] font-mono" style="color:rgba(198,198,203,.3)" id="upd-hdr">—</span>
      <button onclick="load()"
        class="text-[10px] font-headline font-bold tracking-widest uppercase py-2 px-4 rounded-full bg-surface-container-high text-on-surface transition-all"
        onmouseover="this.style.background='#00e475';this.style.color='#003918'"
        onmouseout="this.style.background='';this.style.color=''">↻ Refresh</button>
      <button onclick="toggleAR()" id="btn-ar"
        class="text-[10px] font-headline font-bold tracking-widest uppercase py-2 px-4 rounded-full bg-surface-container-high text-on-surface transition-all"
        onmouseover="this.style.background='#00e475';this.style.color='#003918'"
        onmouseout="this.style.background='';this.style.color=''">Auto 30s</button>
    </div>
  </header>

  <!-- SCROLLABLE CANVAS -->
  <div class="overflow-y-auto space-y-10 p-8 pb-16" style="margin-top:57px;height:calc(100vh - 57px)">

    <!-- ── SECTION: Alerts ── -->
    <section>
      <div class="flex justify-between items-end mb-5 pl-0.5">
        <h2 class="font-headline text-[10px] uppercase tracking-[.3em] text-on-surface-variant" style="opacity:.5">Problemas Detectados</h2>
        <span class="text-[10px] font-mono text-error" id="issues-status" style="display:none">STATUS: ATTENTION REQUIRED</span>
      </div>
      <!-- OK state -->
      <div id="ok-bar" class="flex items-center gap-3 bg-surface-container-low rounded-xl p-5"
           style="border-left:2px solid #00e475">
        <span class="material-symbols-outlined text-primary" style="font-variation-settings:'FILL' 1">check_circle</span>
        <span class="text-sm text-on-surface-variant font-body">Sin problemas activos detectados</span>
      </div>
      <!-- Issues grid -->
      <div id="issues-list" class="grid gap-5" style="display:none;grid-template-columns:repeat(auto-fill,minmax(280px,1fr))"></div>
    </section>

    <!-- ── SECTION: Hardware ── -->
    <section id="sec-hw">
      <div class="flex items-center gap-4 mb-6">
        <h2 class="font-headline text-lg font-bold text-on-surface">Hardware Vitality</h2>
        <div class="flex-1 h-px" style="background:rgba(69,71,75,.15)"></div>
        <div class="flex items-center gap-2">
          <div class="w-2 h-2 rounded-full bg-primary live-pulse"></div>
          <span class="text-[10px] font-mono uppercase" style="color:rgba(198,198,203,.4)">Live Feed</span>
        </div>
      </div>

      <!-- Row 1: CPU · RAM · GPU -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-5">

        <!-- CPU -->
        <div class="bg-surface-container-low rounded-xl p-7 relative overflow-hidden">
          <div class="flex justify-between items-start mb-7">
            <div>
              <p class="text-[10px] font-headline font-black uppercase tracking-widest text-on-surface-variant" style="opacity:.5">CPU Usage</p>
              <h4 class="text-4xl font-headline font-light text-primary mt-1.5" id="cpu-val-big">—<span class="text-lg ml-1 opacity-50">%</span></h4>
            </div>
            <span class="material-symbols-outlined text-5xl" style="color:rgba(53,53,52,1)">memory</span>
          </div>
          <div class="sparkline mb-3" id="cpu-spark"></div>
          <div class="flex justify-between text-[9px] font-mono" style="color:rgba(198,198,203,.25)">
            <span>−6 MIN</span><span>NOW</span>
          </div>
        </div>

        <!-- RAM -->
        <div class="bg-surface-container-low rounded-xl p-7 relative overflow-hidden">
          <div class="flex justify-between items-start mb-7">
            <div>
              <p class="text-[10px] font-headline font-black uppercase tracking-widest text-on-surface-variant" style="opacity:.5">RAM</p>
              <h4 class="text-4xl font-headline font-light text-secondary mt-1.5">
                <span id="ram-used-big">—</span><span class="text-lg ml-1 opacity-50">GB</span>
              </h4>
            </div>
            <span class="material-symbols-outlined text-5xl" style="color:rgba(53,53,52,1)">storage</span>
          </div>
          <div class="w-full h-2 rounded-full overflow-hidden mb-5 bg-surface-container-high">
            <div id="ram-bar" class="h-full rounded-full transition-all duration-500"
                 style="width:0%;background:linear-gradient(90deg,#fabd00,#ffdf9e);box-shadow:0 0 8px rgba(250,189,0,.35)"></div>
          </div>
          <div class="grid grid-cols-3 gap-1 text-center">
            <div>
              <p class="text-[9px] font-mono mb-1" style="color:rgba(198,198,203,.35)">USADO</p>
              <p class="text-xs font-bold text-on-surface" id="ram-pct">—</p>
            </div>
            <div>
              <p class="text-[9px] font-mono mb-1" style="color:rgba(198,198,203,.35)">LIBRE</p>
              <p class="text-xs font-bold text-on-surface" id="ram-free">—</p>
            </div>
            <div>
              <p class="text-[9px] font-mono mb-1" style="color:rgba(198,198,203,.35)">TOTAL</p>
              <p class="text-xs font-bold text-on-surface" id="ram-total">—</p>
            </div>
          </div>
        </div>

        <!-- GPU -->
        <div class="bg-surface-container-low rounded-xl p-7 relative overflow-hidden">
          <div class="flex justify-between items-start mb-7">
            <div>
              <p class="text-[10px] font-headline font-black uppercase tracking-widest text-on-surface-variant" style="opacity:.5">GPU Load · RTX 4090</p>
              <h4 class="text-4xl font-headline font-light text-on-surface mt-1.5">
                <span id="gpu-val-big">—</span><span class="text-lg ml-1 opacity-50">%</span>
              </h4>
            </div>
            <span class="material-symbols-outlined text-5xl" style="color:rgba(53,53,52,1)">view_in_ar</span>
          </div>
          <div class="space-y-3">
            <div class="flex justify-between text-xs font-mono">
              <span style="color:rgba(198,198,203,.5)">Temperatura</span>
              <span class="font-bold text-on-surface" id="gpu-temp-lbl">—</span>
            </div>
            <div class="w-full h-1.5 rounded-full overflow-hidden bg-surface-container-high">
              <div id="gpu-temp-bar" class="h-full rounded-full transition-all" style="width:0%;background:rgba(0,228,117,.5)"></div>
            </div>
            <div class="flex justify-between text-xs font-mono">
              <span style="color:rgba(198,198,203,.5)">VRAM</span>
              <span class="font-bold text-on-surface" id="gpu-vram-lbl">—</span>
            </div>
            <div class="w-full h-1.5 rounded-full overflow-hidden bg-surface-container-high">
              <div id="gpu-vram-bar" class="h-full rounded-full transition-all" style="width:0%;background:rgba(0,228,117,.5)"></div>
            </div>
          </div>
          <div class="mt-5 text-center">
            <span class="text-[10px] font-headline uppercase tracking-widest font-bold" id="gpu-status-lbl" style="color:#00e475">—</span>
          </div>
        </div>
      </div>

      <!-- Row 2: Temps · Disk I/O · S.M.A.R.T. · Disks -->
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-5">
        <div class="bg-surface-container-low rounded-xl p-5">
          <p class="text-[10px] font-headline font-black uppercase tracking-widest text-on-surface-variant mb-4" style="opacity:.5">Temperatura</p>
          <div class="grid grid-cols-2 gap-3" id="temps-grid">
            <span class="text-xs col-span-2" style="color:rgba(198,198,203,.3)">Sin datos</span>
          </div>
        </div>
        <div class="bg-surface-container-low rounded-xl p-5">
          <p class="text-[10px] font-headline font-black uppercase tracking-widest text-on-surface-variant mb-4" style="opacity:.5">Disk I/O</p>
          <div id="diskio-metrics"><span class="text-xs" style="color:rgba(198,198,203,.3)">Sin datos</span></div>
        </div>
        <div class="bg-surface-container-low rounded-xl p-5">
          <p class="text-[10px] font-headline font-black uppercase tracking-widest text-on-surface-variant mb-4" style="opacity:.5">S.M.A.R.T.</p>
          <div id="smart-list"><span class="text-xs" style="color:rgba(198,198,203,.3)">Sin datos</span></div>
        </div>
        <div class="bg-surface-container-low rounded-xl p-5">
          <p class="text-[10px] font-headline font-black uppercase tracking-widest text-on-surface-variant mb-4" style="opacity:.5">Almacenamiento</p>
          <div id="disks-list"><span class="text-xs" style="color:rgba(198,198,203,.3)">Esperando datos…</span></div>
        </div>
      </div>
    </section>

    <!-- ── SECTION: Incidents ── -->
    <section id="sec-incidents" style="display:none">
      <div class="flex items-center gap-4 mb-5">
        <h2 class="font-headline text-lg font-bold text-on-surface">Incidentes — Correlación de causas</h2>
        <div class="flex-1 h-px" style="background:rgba(69,71,75,.15)"></div>
      </div>
      <div id="incidents-list" class="space-y-3"></div>
    </section>

    <!-- ── SECTION: Events Table ── -->
    <section id="sec-events">
      <div class="flex justify-between items-center mb-5 flex-wrap gap-3">
        <h2 class="font-headline text-lg font-bold text-on-surface">System Events</h2>
        <div class="flex items-center gap-2 flex-wrap">
          <div class="flex rounded-lg overflow-hidden" style="border:1px solid rgba(69,71,75,.25)">
            <select id="fl" onchange="load()"
              class="bg-surface-container-high border-none px-3 py-2 text-[10px] font-headline uppercase tracking-widest text-on-surface focus:outline-none focus:ring-1"
              style="focus-ring-color:#00e475">
              <option value="">Todos</option>
              <option value="1">Críticos</option>
              <option value="2">Errores+</option>
              <option value="3">Warnings+</option>
            </select>
            <select id="flog" onchange="load()"
              class="bg-surface-container border-none border-l px-3 py-2 text-[10px] font-headline uppercase tracking-widest text-on-surface focus:outline-none"
              style="border-color:rgba(69,71,75,.25)">
              <option value="">Todos los logs</option>
              <option value="System">System</option>
              <option value="Application">Application</option>
            </select>
            <select id="fcat" onchange="load()"
              class="bg-surface-container border-none border-l px-3 py-2 text-[10px] font-headline uppercase tracking-widest text-on-surface focus:outline-none"
              style="border-color:rgba(69,71,75,.25)">
              <option value="">Categorías</option>
              <optgroup label="Sistema">
                <option value="BSOD">BSOD</option><option value="KERNEL">Kernel</option>
                <option value="ENERGIA">Energía</option><option value="DRIVER">Driver</option>
              </optgroup>
              <optgroup label="Hardware">
                <option value="DISCO">Disco</option><option value="GPU">GPU</option>
              </optgroup>
              <optgroup label="Software">
                <option value="SERVICIO">Servicio</option><option value="APP_CRASH">App Crash</option>
                <option value="BROWSER">Browser</option><option value="ACTUALIZACION">Actualización</option>
              </optgroup>
              <optgroup label="Red &amp; Seguridad">
                <option value="RED">Red</option><option value="SEGURIDAD">Seguridad</option>
                <option value="ANTIVIRUS">Antivirus</option>
              </optgroup>
              <option value="SISTEMA">Sistema</option>
            </select>
          </div>
          <span class="text-[10px] font-mono" style="color:rgba(198,198,203,.35)" id="ev-count"></span>
        </div>
      </div>

      <div class="bg-surface-container-low rounded-xl overflow-hidden">
        <table class="w-full text-left border-collapse min-w-[760px]">
          <thead>
            <tr class="text-[10px] font-headline uppercase tracking-widest text-on-surface-variant"
                style="border-bottom:1px solid rgba(69,71,75,.15);opacity:.55">
              <th class="px-6 py-5 font-medium">Tiempo</th>
              <th class="px-4 py-5 font-medium">Nivel</th>
              <th class="px-4 py-5 font-medium">Categoría</th>
              <th class="px-4 py-5 font-medium">ID</th>
              <th class="px-4 py-5 font-medium">Proveedor</th>
              <th class="px-5 py-5 font-medium">Mensaje</th>
              <th class="px-6 py-5 font-medium text-right">Análisis</th>
            </tr>
          </thead>
          <tbody id="tbody"></tbody>
        </table>
        <div id="empty" class="py-16 text-center text-sm font-body" style="display:none;color:rgba(198,198,203,.2)">
          Sin eventos registrados.
        </div>
      </div>
    </section>

  </div><!-- /canvas -->
</main>

<!-- MODAL -->
<div class="modal" id="modal">
  <div class="bg-surface-container-low rounded-xl p-6 max-w-2xl w-11/12 max-h-[80vh] overflow-y-auto"
       style="border:1px solid rgba(69,71,75,.25)">
    <div class="flex justify-between items-center mb-4">
      <h3 class="text-primary font-headline font-bold" id="mt">Evento</h3>
      <button onclick="closeM()" style="color:rgba(198,198,203,.4);font-size:20px;line-height:1;background:none;border:none;cursor:pointer">✕</button>
    </div>
    <pre class="text-xs leading-relaxed font-mono whitespace-pre-wrap" style="color:rgba(198,198,203,.55)" id="mb"></pre>
  </div>
</div>

<script>
const S = "__SECRET__", B = "__BASE__";
let arTimer = null, arOn = false;
let expanded = new Set();
let cpuHistory = [];

const api  = p => fetch(B+p+(p.includes("?")?"&":"?")+"secret="+S).then(r=>r.json());
const post = p => fetch(B+p+(p.includes("?")?"&":"?")+"secret="+S,{method:"POST"}).then(r=>r.json());
const esc  = s => (s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");

function fmt(t) {
  if (!t) return "—";
  const d = new Date(t);
  return d.toLocaleDateString("en-US",{month:"2-digit",day:"2-digit"}) + " " +
         d.toLocaleTimeString("en-US",{hour:"2-digit",minute:"2-digit",hour12:true});
}
function fmtTime(t) {
  if (!t) return "—";
  return new Date(t).toLocaleTimeString("en-US",{hour:"2-digit",minute:"2-digit",second:"2-digit",hour12:true});
}

/* ── Health ──────────────────────────────────────────────────────── */
function renderHealth(s) {
  if (!s) return;

  /* CPU sparkline */
  const cpu = s.cpu_percent ?? 0;
  cpuHistory.push(cpu);
  if (cpuHistory.length > 12) cpuHistory.shift();
  document.getElementById("cpu-val-big").innerHTML =
    `${cpu}<span class="text-lg ml-1 opacity-50">%</span>`;
  const spark = document.getElementById("cpu-spark");
  const maxV = Math.max(...cpuHistory, 10);
  spark.innerHTML = cpuHistory.map(v => {
    const h = Math.max((v/maxV)*100, 4);
    const bg = v>90?"rgba(255,180,171,.75)":v>75?"rgba(250,189,0,.6)":"rgba(0,228,117,.3)";
    const hv = v>90?"#ffb4ab":v>75?"#fabd00":"#00e475";
    return `<div class="sparkbar" style="height:${h}%;background:${bg}"
      onmouseenter="this.style.background='${hv}'"
      onmouseleave="this.style.background='${bg}'"></div>`;
  }).join("");

  /* RAM */
  const mp = s.mem_percent ?? 0;
  const usedGB = ((s.mem_total_mb - s.mem_free_mb)/1024).toFixed(1);
  document.getElementById("ram-used-big").textContent = usedGB;
  document.getElementById("ram-bar").style.width = mp + "%";
  document.getElementById("ram-pct").textContent  = mp + "%";
  document.getElementById("ram-free").textContent  = (s.mem_free_mb/1024).toFixed(1) + "G";
  document.getElementById("ram-total").textContent = (s.mem_total_mb/1024).toFixed(0) + "G";

  /* GPU */
  if (s.gpu_percent != null) {
    document.getElementById("gpu-val-big").textContent = s.gpu_percent;
    const tc = (s.gpu_temp ?? 0);
    const tcColor = tc>80?"#ffb4ab":tc>70?"#fabd00":"#00e475";
    document.getElementById("gpu-temp-lbl").textContent  = tc + "°C";
    document.getElementById("gpu-temp-lbl").style.color  = tcColor;
    document.getElementById("gpu-temp-bar").style.width  = Math.min(tc,100) + "%";
    document.getElementById("gpu-temp-bar").style.background = tcColor.replace(")",", .55)").replace("rgb","rgba");
    if (s.gpu_vram_used_mb && s.gpu_vram_total_mb) {
      const vp = Math.round(s.gpu_vram_used_mb/s.gpu_vram_total_mb*100);
      document.getElementById("gpu-vram-lbl").textContent = `${(s.gpu_vram_used_mb/1024).toFixed(1)}/${(s.gpu_vram_total_mb/1024).toFixed(0)}G`;
      document.getElementById("gpu-vram-bar").style.width = vp + "%";
    }
    const gStatus = s.gpu_percent > 90 ? "High Load" : s.gpu_percent > 50 ? "Active" : "Nominal";
    document.getElementById("gpu-status-lbl").textContent = "System " + gStatus;
  }

  /* Temps */
  const tg = document.getElementById("temps-grid");
  let th = "";
  if (s.gpu_temp) {
    const c = s.gpu_temp>80?"#ffb4ab":s.gpu_temp>70?"#fabd00":"#00e475";
    th += `<div class="bg-surface-container rounded-xl p-3 text-center">
      <p class="text-[9px] font-mono mb-1" style="color:rgba(198,198,203,.35)">GPU</p>
      <p class="text-xl font-headline font-bold" style="color:${c}">${s.gpu_temp}<span class="text-xs opacity-50">°C</span></p>
    </div>`;
  }
  if (s.cpu_temp) {
    const c = s.cpu_temp>85?"#ffb4ab":s.cpu_temp>75?"#fabd00":"#00e475";
    th += `<div class="bg-surface-container rounded-xl p-3 text-center">
      <p class="text-[9px] font-mono mb-1" style="color:rgba(198,198,203,.35)">CPU</p>
      <p class="text-xl font-headline font-bold" style="color:${c}">${s.cpu_temp}<span class="text-xs opacity-50">°C</span></p>
    </div>`;
  }
  tg.innerHTML = th || '<span class="text-xs col-span-2" style="color:rgba(198,198,203,.3)">Sin datos</span>';

  /* Disk I/O */
  if (s.disk_read_mbps != null || s.disk_write_mbps != null) {
    const rd = s.disk_read_mbps??0, wr = s.disk_write_mbps??0;
    const mx = Math.max(rd, wr, 50);
    document.getElementById("diskio-metrics").innerHTML = `
      <div class="space-y-3">
        <div>
          <div class="flex justify-between text-[11px] font-mono mb-1.5">
            <span style="color:rgba(198,198,203,.45)">Lectura</span>
            <span class="font-bold" style="color:#38bdf8">${rd.toFixed(1)} MB/s</span>
          </div>
          <div class="w-full h-1.5 rounded-full overflow-hidden bg-surface-container-high">
            <div class="h-full rounded-full transition-all" style="width:${Math.min(rd/mx*100,100)}%;background:#38bdf8"></div>
          </div>
        </div>
        <div>
          <div class="flex justify-between text-[11px] font-mono mb-1.5">
            <span style="color:rgba(198,198,203,.45)">Escritura</span>
            <span class="font-bold" style="color:#f472b6">${wr.toFixed(1)} MB/s</span>
          </div>
          <div class="w-full h-1.5 rounded-full overflow-hidden bg-surface-container-high">
            <div class="h-full rounded-full transition-all" style="width:${Math.min(wr/mx*100,100)}%;background:#f472b6"></div>
          </div>
        </div>
      </div>`;
  }

  /* S.M.A.R.T. */
  if (s.smart_disks) {
    let sh = "";
    s.smart_disks.split(";").forEach(d => {
      d = d.trim(); if (!d) return;
      const p = d.split("|"); if (p.length < 3) return;
      const name = p[0].trim(), health = p[2]?.trim()||"Unknown";
      const hcls = health==="Healthy"  ? "background:rgba(0,228,117,.1);color:#00e475" :
                   health==="Warning"  ? "background:rgba(250,189,0,.1);color:#fabd00" :
                   health==="Unhealthy"? "background:rgba(147,0,10,.2);color:#ffb4ab"  :
                                         "background:rgba(32,31,31,1);color:rgba(198,198,203,.4)";
      sh += `<div class="flex items-center gap-2 mb-3 last:mb-0">
        <span class="text-xs flex-1 truncate" style="color:rgba(198,198,203,.5)" title="${esc(name)}">${name.length>18?name.slice(0,16)+"…":name}</span>
        <span class="text-[9px] font-bold font-headline px-2 py-0.5 rounded-full" style="${hcls}">${health}</span>
      </div>`;
    });
    document.getElementById("smart-list").innerHTML = sh || '<span class="text-xs" style="color:rgba(198,198,203,.3)">Sin datos</span>';
  }

  /* Discos */
  if (s.disks) {
    let dh = "";
    s.disks.split(";").forEach(d => {
      d = d.trim(); if (!d) return;
      const p = d.split("|"); if (p.length < 3) return;
      const pct = parseFloat(p[2]);
      const bc = pct>90?"#ffb4ab":pct>75?"#fabd00":"#00e475";
      dh += `<div class="mb-4 last:mb-0">
        <div class="flex justify-between text-[11px] font-mono mb-1.5">
          <span style="color:rgba(198,198,203,.5)">${p[0]}${p[3]?" "+p[3]:""}</span>
          <span class="font-bold text-on-surface">${p[1]}</span>
        </div>
        <div class="w-full h-1.5 rounded-full overflow-hidden bg-surface-container-high">
          <div class="h-full rounded-full transition-all" style="width:${pct}%;background:${bc}"></div>
        </div>
      </div>`;
    });
    if (dh) document.getElementById("disks-list").innerHTML = dh;
  }

  /* Uptime sidebar */
  const uh = Math.floor((s.uptime_minutes||0)/60), um = (s.uptime_minutes||0)%60;
  document.getElementById("status-text").textContent = `Uptime ${uh}h ${um}m`;
}

/* ── Issues ──────────────────────────────────────────────────────── */
function renderIssues(issues) {
  const ok  = document.getElementById("ok-bar");
  const lst = document.getElementById("issues-list");
  const stEl= document.getElementById("issues-status");
  if (!issues || !issues.length) {
    ok.style.display=""; lst.style.display="none"; stEl.style.display="none"; return;
  }
  ok.style.display="none"; lst.style.display=""; stEl.style.display="";

  lst.innerHTML = issues.map((i, idx) => {
    const border = i.severity==="critical"?"#ffb4ab":i.severity==="high"?"#fb923c":i.severity==="medium"?"#fabd00":"#00e475";
    const icon   = {BSOD:"emergency_home",DISK:"hard_drive",GPU:"view_in_ar",RED:"wifi_off",
                    BROWSER:"web",ENERGIA:"bolt",SEGURIDAD:"lock_open",ANTIVIRUS:"security",
                    CRASH_LOOP:"restart_alt",DRIVER:"extension",ACTUALIZACION:"system_update"}[i.type] || "warning";
    const gradFrom = i.severity==="critical"?"rgba(255,180,171,.06)":i.severity==="high"?"rgba(251,146,60,.06)":
                     i.severity==="medium"?"rgba(250,189,0,.06)":"rgba(0,228,117,.06)";

    const aiBadge = i.ai_analyzed ? `<span class="ai-badge ml-1">IA</span>` : "";
    const detailId = `idtl-${idx}`;
    const toggleHtml = i.ai_analyzed
      ? `<button onclick="toggleDetail('${detailId}',this)"
           class="text-[10px] font-headline uppercase tracking-widest mt-3 block transition-colors"
           style="color:rgba(0,228,117,.6)">▶ Ver diagnóstico completo</button>`
      : "";
    const detailHtml = i.ai_analyzed && i.detail
      ? `<div class="issue-detail mt-2 text-[11px] leading-relaxed font-mono rounded-lg p-3" id="${detailId}"
             style="background:rgba(32,31,31,.8);color:rgba(198,198,203,.55)">${esc(i.detail)}</div>`
      : "";

    return `
    <div class="rounded-xl p-6 relative overflow-hidden" style="background:#1c1b1b;border-left:2px solid ${border}">
      <div style="position:absolute;inset:0;background:linear-gradient(135deg,${gradFrom},transparent);pointer-events:none"></div>
      <div class="flex justify-between items-start mb-4">
        <span class="material-symbols-outlined" style="color:${border};font-variation-settings:'FILL' 1">${icon}</span>
        <span class="text-[9px] font-mono" style="color:rgba(198,198,203,.3)">${i.type}</span>
      </div>
      <h3 class="font-headline font-bold text-base text-on-surface mb-2">${esc(i.title)}</h3>
      <p class="text-xs leading-relaxed" style="color:rgba(198,198,203,.55)">${aiBadge} ${esc(i.action)}</p>
      ${detailHtml}${toggleHtml}
    </div>`;
  }).join("");
}

function toggleDetail(id, btn) {
  const d = document.getElementById(id);
  if (!d) return;
  const open = d.classList.toggle("open");
  btn.textContent = (open?"▼ ":"▶ ") + "Ver diagnóstico completo";
}

/* ── Incidents ───────────────────────────────────────────────────── */
function renderIncidents(incidents) {
  const sec = document.getElementById("sec-incidents");
  const lst = document.getElementById("incidents-list");
  if (!incidents || !incidents.length) { sec.style.display="none"; return; }
  sec.style.display="";

  lst.innerHTML = incidents.map(inc => {
    const chainHtml = (inc.chain||[]).map(e => `
      <div class="flex items-center gap-3 py-2.5" style="border-bottom:1px solid rgba(69,71,75,.08)">
        <span class="text-[10px] font-mono w-16 flex-shrink-0" style="color:rgba(198,198,203,.3)">${fmtTime(e.time_created)}</span>
        <span class="bc-${e.category||'SISTEMA'} px-2 py-0.5 rounded text-[9px] font-bold flex-shrink-0">${e.category||'SIS'}</span>
        <span class="text-xs truncate" style="color:rgba(198,198,203,.45)">${esc(e.provider)} — ${esc((e.message||"").substring(0,80))}</span>
      </div>`).join("") ||
      `<p class="text-xs py-3" style="color:rgba(198,198,203,.3)">Sin eventos previos en la ventana de 15 min</p>`;

    const analysisHtml = inc.analysis
      ? `<div class="mt-4 text-xs leading-relaxed font-mono whitespace-pre-wrap pl-4" style="border-left:2px solid #4338ca;color:rgba(198,198,203,.55)">${esc(inc.analysis)}</div>`
      : `<button onclick="analyzeIncident(${inc.id},this)" class="mt-4 text-[10px] font-headline font-bold tracking-widest uppercase py-2 px-4 rounded-full transition-all"
             style="background:#1e1b4b;color:#a5b4fc">Analizar cadena con Claude</button>`;

    return `
    <div class="rounded-xl overflow-hidden" style="background:#1c1b1b;border:1px solid rgba(69,71,75,.2)">
      <div class="flex items-center gap-4 px-6 py-4 cursor-pointer transition-colors"
           style="hover:background:#201f1f" onclick="toggleInc(${inc.id})"
           onmouseover="this.style.background='#201f1f'" onmouseout="this.style.background=''">
        <span class="text-[9px] font-headline font-bold uppercase tracking-widest px-2 py-1 rounded-full"
              style="background:#1e0a4a;color:#c084fc">BSOD</span>
        <span class="text-xs font-mono" style="color:rgba(198,198,203,.35)">${fmt(inc.time_created)}</span>
        <span class="text-sm text-on-surface flex-1">Event ${inc.event_id} — ${inc.chain.length} evento(s) previo(s)</span>
        <span id="inc-arrow-${inc.id}" class="transition-transform" style="color:rgba(198,198,203,.3);font-size:13px">▶</span>
      </div>
      <div class="inc-body px-6 pb-5" id="inc-body-${inc.id}">
        <div class="pt-3">${chainHtml}</div>
        <div id="inc-analysis-${inc.id}">${analysisHtml}</div>
      </div>
    </div>`;
  }).join("");
}

function toggleInc(id) {
  const b = document.getElementById("inc-body-"+id), a = document.getElementById("inc-arrow-"+id);
  const open = b.classList.toggle("open");
  if (a) a.style.transform = open ? "rotate(90deg)" : "";
}

function analyzeIncident(incId, btn) {
  btn.disabled=true; btn.textContent="Analizando…";
  post("/api/incidents/"+incId+"/analyze").then(r => {
    const box = document.getElementById("inc-analysis-"+incId);
    if (r.analysis) {
      box.innerHTML = `<div class="mt-4 text-xs leading-relaxed font-mono whitespace-pre-wrap pl-4"
        style="border-left:2px solid #4338ca;color:rgba(198,198,203,.55)">${esc(r.analysis)}</div>`;
    } else { btn.disabled=false; btn.textContent="Reintentar"; }
  }).catch(()=>{btn.disabled=false;btn.textContent="Error";});
}

/* ── Events Table ────────────────────────────────────────────────── */
function load() {
  const lvl = document.getElementById("fl").value;
  const log = document.getElementById("flog").value;
  const cat = document.getElementById("fcat").value;
  let path = "/api/events?limit=100";
  if (lvl) path += "&level="+lvl;
  if (log) path += "&log_name="+encodeURIComponent(log);
  if (cat) path += "&category="+encodeURIComponent(cat);

  Promise.all([api(path), api("/api/stats"), api("/api/issues"), api("/api/incidents")])
  .then(([data, s, iss, incs]) => {
    /* Status */
    document.getElementById("dot-live").style.background = "#00e475";

    /* Sidebar stats */
    document.getElementById("s-bsod").textContent = s.bsods_today ?? "—";
    document.getElementById("s-crit").textContent = s.critical_today ?? "—";
    document.getElementById("s-err").textContent  = s.errors_today ?? "—";
    document.getElementById("s-warn").textContent = s.warnings_today ?? "—";
    document.getElementById("s-tot").textContent  = s.total ?? "—";

    /* Browser crashes */
    const bc = s.snapshot?.browser_crashes;
    const bcEl = document.getElementById("s-browser");
    bcEl.textContent = bc != null ? bc : "—";
    bcEl.style.color = (bc > 0) ? "#38bdf8" : "rgba(198,198,203,.4)";

    /* Timestamps */
    const now = new Date().toLocaleTimeString("en-US",{hour:"2-digit",minute:"2-digit",second:"2-digit",hour12:true});
    document.getElementById("upd-hdr").textContent = now;
    document.getElementById("s-upd").textContent   = "Updated " + now;

    if (s.snapshot) renderHealth(s.snapshot);
    renderIssues(iss.issues);
    renderIncidents(incs.incidents);

    /* Events table */
    const events = data.events || [];
    document.getElementById("ev-count").textContent = events.length ? `${events.length} eventos` : "";
    document.getElementById("empty").style.display  = events.length ? "none" : "";

    const tbody = document.getElementById("tbody");
    tbody.innerHTML = "";
    events.forEach(e => {
      const lvlStyle = e.level===1
        ? "background:rgba(147,0,10,.25);color:#ffb4ab"
        : e.level===2
          ? "background:rgba(45,18,0,.5);color:#fb923c"
          : "background:rgba(250,189,0,.1);color:#fabd00";

      const tr = document.createElement("tr");
      tr.id = "row-"+e.id;
      tr.style.cssText = "border-bottom:1px solid rgba(69,71,75,.08);transition:background .15s;cursor:default";
      tr.addEventListener("mouseover",()=>tr.style.background="#201f1f");
      tr.addEventListener("mouseout", ()=>tr.style.background="");

      const msg = esc((e.message||"").substring(0,110));
      tr.innerHTML = `
        <td class="px-6 py-4 font-mono text-xs whitespace-nowrap" style="color:rgba(198,198,203,.35)">${fmt(e.time_created)}</td>
        <td class="px-4 py-4">
          <span class="px-2 py-1 rounded-full text-[10px] font-bold font-headline uppercase" style="${lvlStyle}">${e.level_name}</span>
        </td>
        <td class="px-4 py-4">
          <span class="bc-${e.category||'SISTEMA'} px-2 py-0.5 rounded text-[10px] font-bold">${e.category||'SIS'}</span>
        </td>
        <td class="px-4 py-4 text-xs font-mono" style="color:rgba(198,198,203,.35)">${e.event_id}</td>
        <td class="px-4 py-4 text-xs max-w-[130px] truncate" style="color:#5b21b6" title="${esc(e.provider)}">${esc(e.provider)}</td>
        <td class="px-5 py-4 text-xs max-w-xs truncate" style="color:rgba(198,198,203,.45);cursor:pointer"
            onclick="showMsg(${e.id},${JSON.stringify(e.message)})"
            onmouseover="this.style.color='#e5e2e1'" onmouseout="this.style.color='rgba(198,198,203,.45)'"
            >${msg}${(e.message||"").length>110?"…":""}</td>
        <td class="px-6 py-4 text-right">
          <button id="btn-${e.id}" onclick="analyze(${e.id})" data-done="${e.analysis?'1':'0'}"
            class="text-[10px] font-headline font-bold uppercase tracking-widest py-1.5 px-3 rounded-full transition-all opacity-0"
            style="${e.analysis?"background:rgba(0,228,117,.12);color:#00e475":"background:#2a2a2a;color:rgba(198,198,203,.6)"}">${e.analysis?"Ver":"Analizar"}</button>
        </td>`;

      /* Show analyze btn on row hover */
      tr.addEventListener("mouseover",()=>{const b=document.getElementById("btn-"+e.id);if(b)b.style.opacity="1"});
      tr.addEventListener("mouseout", ()=>{const b=document.getElementById("btn-"+e.id);if(b&&!document.getElementById("ar-"+e.id))b.style.opacity="0"});

      tbody.appendChild(tr);
      if (expanded.has(e.id) && e.analysis) insertArow(e.id, e.analysis);
    });
  })
  .catch(() => {
    document.getElementById("dot-live").style.background = "#ffb4ab";
  });
}

function insertArow(id, text) {
  if (document.getElementById("ar-"+id)) return;
  const ref = document.getElementById("row-"+id);
  if (!ref) return;
  const ar = document.createElement("tr");
  ar.id = "ar-"+id;
  ar.innerHTML = `<td colspan="7" style="padding:0"><div class="arow-box">${esc(text)}</div></td>`;
  ref.after(ar);
  const btn = document.getElementById("btn-"+id);
  if (btn) btn.style.opacity = "1";
}

function analyze(id) {
  const ar = document.getElementById("ar-"+id);
  if (ar) { ar.remove(); expanded.delete(id); const btn=document.getElementById("btn-"+id); if(btn)btn.style.opacity="0"; return; }
  expanded.add(id);
  const btn = document.getElementById("btn-"+id);
  if (btn && btn.dataset.done==="1") {
    post("/api/analyze/"+id).then(r => { if (r.analysis) insertArow(id, r.analysis); });
    return;
  }
  if (btn) { btn.disabled=true; btn.textContent="…"; }
  post("/api/analyze/"+id).then(r => {
    if (btn) { btn.disabled=false; btn.textContent="Ver"; btn.dataset.done="1"; btn.style.cssText="background:rgba(0,228,117,.12);color:#00e475"; }
    if (r.analysis) insertArow(id, r.analysis);
  }).catch(()=>{ if(btn){btn.disabled=false;btn.textContent="!";} });
}

function showMsg(id, text) {
  document.getElementById("mt").textContent = "Evento #"+id;
  document.getElementById("mb").textContent = text;
  document.getElementById("modal").classList.add("open");
}
function closeM() { document.getElementById("modal").classList.remove("open"); }
document.getElementById("modal").addEventListener("click", e=>{if(e.target===document.getElementById("modal"))closeM();});

function toggleAR() {
  const btn = document.getElementById("btn-ar");
  if (arOn) {
    clearInterval(arTimer); arOn=false;
    btn.style.background=""; btn.style.color="";
  } else {
    arTimer=setInterval(load,30000); arOn=true;
    btn.style.background="#00e475"; btn.style.color="#003918";
  }
}

load();
</script>
</body>
</html>"""
