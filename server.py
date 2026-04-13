import os, sqlite3, threading
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Optional
import anthropic

app = FastAPI()

API_SECRET    = os.environ.get("API_SECRET", "changeme")
CLAUDE_API_KEY = os.environ.get("CLAUDE_API_KEY", "")
DB_PATH       = os.environ.get("DB_PATH", "/home/corillo-adm/win-monitor/monitor.db")
BASE_PATH     = "/win-monitor"

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
    """)
    conn.commit()
    conn.close()

init_db()

# ── Migraciones (añade columnas nuevas a snapshots si no existen)
def migrate_db():
    conn = get_db()
    existing = {row[1] for row in conn.execute("PRAGMA table_info(snapshots)").fetchall()}
    new_cols = [
        ("gpu_percent",       "INTEGER"),
        ("gpu_vram_used_mb",  "INTEGER"),
        ("gpu_vram_total_mb", "INTEGER"),
        ("disk_read_mbps",    "REAL"),
        ("disk_write_mbps",   "REAL"),
        ("smart_disks",       "TEXT"),
        ("browser_crashes",   "INTEGER"),
    ]
    for col, typ in new_cols:
        if col not in existing:
            conn.execute(f"ALTER TABLE snapshots ADD COLUMN {col} {typ}")
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
    Prioridad: BSOD > DISCO > GPU > RED > DRIVER > ENERGIA > ACTUALIZACION >
               SEGURIDAD > ANTIVIRUS > KERNEL > BROWSER > SERVICIO > APP_CRASH > SISTEMA
    """
    p = provider.lower()
    m = message.lower()

    # 1. BSOD — prioridad máxima
    if event_id in BSOD_IDS or "bugcheck" in m or "bug check" in m:
        return "BSOD"

    # 2. DISCO — hardware de almacenamiento
    if event_id in DISK_IDS or any(k in p for k in _DISK_PROV):
        return "DISCO"

    # 3. GPU — tarjeta gráfica y display drivers
    if event_id in GPU_IDS or any(k in p for k in _GPU_PROV):
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
    """Cuando llega un BSOD, crea el incidente y analiza la cadena."""
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
def auth(secret: str):
    if secret != API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")

# ── API ──────────────────────────────────────────────────────────────────────
@app.post("/api/events")
def receive_events(batch: EventBatch, bg: BackgroundTasks):
    auth(batch.secret)
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
                browser_crashes,disks)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (now, m.hostname, m.username, m.mem_total_mb, m.mem_free_mb,
              m.mem_percent, m.cpu_percent, m.uptime_minutes, m.gpu_temp, m.gpu_percent,
              m.gpu_vram_used_mb, m.gpu_vram_total_mb, m.cpu_temp, m.disk_read_mbps,
              m.disk_write_mbps, m.smart_disks, m.browser_crashes, m.disks))

    for e in batch.events:
        cat = categorize(e.event_id, e.provider, e.message)
        cur = conn.execute("""
            INSERT INTO events (received_at,time_created,event_id,level,level_name,
                log_name,provider,message,category,hostname,username)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (now, e.time_created, e.event_id, e.level, e.level_name,
              e.log_name, e.provider, e.message[:3000], cat,
              batch.metrics.hostname if batch.metrics else None,
              batch.metrics.username if batch.metrics else None))
        count += 1
        # Auto-analizar BSODs y disk errors críticos
        AUTO_ANALYZE_CATS = {"BSOD","DISCO","GPU","DRIVER","RED","ENERGIA","ANTIVIRUS","BROWSER","SERVICIO"}
        if e.level <= 2 and (cat in AUTO_ANALYZE_CATS or e.event_id in BSOD_IDS):
            auto_ids.append(cur.lastrowid)
        # Correlación de incidente para BSODs
        if e.event_id in BSOD_IDS:
            bg.add_task(auto_incident, cur.lastrowid)

    conn.commit()
    conn.close()

    for eid in auto_ids:
        bg.add_task(auto_analyze, eid)

    return {"received": count}

@app.get("/api/events")
def list_events(secret: str = Query(...), limit: int = 100, offset: int = 0,
                level: Optional[int] = None, log_name: Optional[str] = None,
                category: Optional[str] = None):
    auth(secret)
    conn = get_db()
    where, params = [], []
    if level:
        where.append("level <= ?"); params.append(level)
    if log_name:
        where.append("log_name = ?"); params.append(log_name)
    if category:
        where.append("category = ?"); params.append(category)
    w = ("WHERE " + " AND ".join(where)) if where else ""
    rows  = conn.execute(f"SELECT * FROM events {w} ORDER BY id DESC LIMIT ? OFFSET ?",
                         params + [limit, offset]).fetchall()
    total = conn.execute(f"SELECT COUNT(*) FROM events {w}", params).fetchone()[0]
    conn.close()
    return {"total": total, "events": [dict(r) for r in rows]}

@app.get("/api/stats")
def stats(secret: str = Query(...)):
    auth(secret)
    conn = get_db()
    today = datetime.now().strftime("%Y-%m-%d")
    snap  = conn.execute("SELECT * FROM snapshots ORDER BY id DESC LIMIT 1").fetchone()
    s = {
        "total":           conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        "critical_today":  conn.execute("SELECT COUNT(*) FROM events WHERE level=1 AND time_created LIKE ?", (f"{today}%",)).fetchone()[0],
        "errors_today":    conn.execute("SELECT COUNT(*) FROM events WHERE level=2 AND time_created LIKE ?", (f"{today}%",)).fetchone()[0],
        "warnings_today":  conn.execute("SELECT COUNT(*) FROM events WHERE level=3 AND time_created LIKE ?", (f"{today}%",)).fetchone()[0],
        "bsods_today":     conn.execute("SELECT COUNT(*) FROM events WHERE event_id IN (41,1001) AND time_created LIKE ?", (f"{today}%",)).fetchone()[0],
        "last_event":      conn.execute("SELECT received_at FROM events ORDER BY id DESC LIMIT 1").fetchone(),
        "snapshot":        dict(snap) if snap else None,
    }
    if s["last_event"]: s["last_event"] = s["last_event"][0]
    conn.close()
    return s

@app.get("/api/issues")
def get_issues(secret: str = Query(...)):
    """Detecta patrones problemáticos activos."""
    auth(secret)
    conn = get_db()
    issues = []

    # BSODs en las últimas 24h
    bsod_count = conn.execute(
        "SELECT COUNT(*) FROM events WHERE event_id IN (41,1001,6008) AND time_created > datetime('now','-24 hours')"
    ).fetchone()[0]
    if bsod_count >= 1:
        last_bsod = conn.execute(
            "SELECT time_created, message FROM events WHERE event_id IN (41,1001) ORDER BY id DESC LIMIT 1"
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
        WHERE event_id IN (7031,7034,7023,7024)
          AND time_created > datetime('now','-6 hours')
        GROUP BY event_id, message
        HAVING COUNT(*) >= 3
        ORDER BY cnt DESC
        LIMIT 10
    """).fetchall()
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
            WHERE event_id IN (7031,7034,7023,7024)
              AND message LIKE ? AND time_created > datetime('now','-6 hours')
            ORDER BY id DESC LIMIT 5
        """, (f"%{svc_name}%",)).fetchall()
        crash_evts = [dict(e) for e in crash_evts]

        # Buscar logs operacionales del mismo servicio (Defender, WMI, etc.)
        detail_evts = conn.execute("""
            SELECT time_created, event_id, provider, message FROM events
            WHERE category IN ('ANTIVIRUS','DRIVER','ACTUALIZACION','RED','SERVICIO')
              AND event_id NOT IN (7031,7034,7023,7024)
              AND time_created > datetime('now','-6 hours')
            ORDER BY id DESC LIMIT 10
        """).fetchall()
        detail_evts = [dict(e) for e in detail_evts]

        if not has_ai and len(crash_evts) >= 3:
            threading.Thread(
                target=analyze_service_crash,
                args=(svc_name, svc_cat, row["cnt"], crash_evts, detail_evts),
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
        WHERE event_id = 1000
          AND time_created > datetime('now','-2 hours')
        GROUP BY message
        HAVING COUNT(*) >= 3
        ORDER BY cnt DESC
        LIMIT 5
    """).fetchall()
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
        "SELECT COUNT(*) FROM events WHERE category='DISCO' AND time_created > datetime('now','-24 hours')"
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
        "SELECT COUNT(*) FROM events WHERE category='GPU' AND time_created > datetime('now','-24 hours')"
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
        "SELECT COUNT(*) FROM events WHERE category='ANTIVIRUS' AND time_created > datetime('now','-6 hours')"
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
        "SELECT COUNT(*) FROM events WHERE category='RED' AND time_created > datetime('now','-2 hours')"
    ).fetchone()[0]
    if net_errors >= 3:
        last_net = conn.execute(
            "SELECT provider, message FROM events WHERE category='RED' ORDER BY id DESC LIMIT 1"
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
        "SELECT COUNT(*), message FROM events WHERE category='DRIVER' AND time_created > datetime('now','-24 hours') LIMIT 1"
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
        "SELECT COUNT(*) FROM events WHERE category='ENERGIA' AND time_created > datetime('now','-24 hours')"
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
        "SELECT COUNT(*), message FROM events WHERE category='BROWSER' AND time_created > datetime('now','-24 hours') LIMIT 1"
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
        "SELECT COUNT(*) FROM events WHERE category='SEGURIDAD' AND event_id=4625 AND time_created > datetime('now','-1 hours')"
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
        "SELECT COUNT(*) FROM events WHERE category='ACTUALIZACION' AND level <= 2 AND time_created > datetime('now','-24 hours')"
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
<title>Windows Monitor — MSI Trident X2</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#09090f;color:#e2e8f0;font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;min-height:100vh}

/* ── HEADER ── */
.hdr{background:#0f0f17;border-bottom:1px solid #1a1a28;padding:0 24px;height:48px;display:flex;align-items:center;gap:16px;position:sticky;top:0;z-index:10}
.hdr-title{font-size:13px;font-weight:700;color:#a78bfa;letter-spacing:.4px}
.hdr-sub{color:#374151;font-size:11px}
.hdr-right{margin-left:auto;display:flex;align-items:center;gap:12px}
.upd{color:#374151;font-size:11px}
.btn-sm{background:#1a1a28;color:#94a3b8;border:1px solid #252535;border-radius:4px;padding:4px 10px;font-size:11px;cursor:pointer;font-family:inherit}
.btn-sm:hover{background:#252535}
.btn-sm.on{background:#3730a3;color:#a5b4fc;border-color:#4338ca}
.dot{width:6px;height:6px;border-radius:50%;background:#22c55e;display:inline-block;animation:pulse 2.5s infinite}
.dot.off{background:#f87171;animation:none}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}

/* ── LAYOUT ── */
.page{display:grid;grid-template-columns:280px 1fr;grid-template-rows:auto 1fr;gap:0;height:calc(100vh - 48px)}
.sidebar{grid-column:1;grid-row:1/3;background:#0c0c14;border-right:1px solid #1a1a28;overflow-y:auto;padding:16px 14px;display:flex;flex-direction:column;gap:14px}
.main{grid-column:2;grid-row:1/3;overflow:auto;display:flex;flex-direction:column}

/* ── SIDEBAR — Health cards ── */
.s-section{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:#374151;margin-bottom:6px;padding-left:2px}

.health-card{background:#111120;border:1px solid #1a1a28;border-radius:8px;padding:12px 14px}
.health-card .hc-label{font-size:10px;color:#475569;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px}
.metric-row{display:flex;align-items:center;gap:8px;margin-bottom:7px}
.metric-row:last-child{margin-bottom:0}
.metric-name{font-size:11px;color:#64748b;width:56px;flex-shrink:0}
.bar-wrap{flex:1;background:#1a1a28;border-radius:3px;height:5px;overflow:hidden}
.bar-fill{height:100%;border-radius:3px;transition:width .4s}
.bar-ok{background:#22c55e}
.bar-warn{background:#f59e0b}
.bar-danger{background:#ef4444}
.metric-val{font-size:11px;font-weight:600;width:52px;text-align:right;flex-shrink:0}
.val-ok{color:#94a3b8}
.val-warn{color:#f59e0b}
.val-danger{color:#ef4444}

.temp-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:2px}
.temp-box{background:#0f0f1a;border:1px solid #1a1a28;border-radius:6px;padding:8px 10px;text-align:center}
.temp-box .tb-label{font-size:10px;color:#475569;margin-bottom:4px}
.temp-box .tb-val{font-size:20px;font-weight:700}
.temp-box .tb-unit{font-size:11px;color:#475569}

.stat-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px}
.stat-box{background:#0f0f1a;border:1px solid #1a1a28;border-radius:6px;padding:8px 10px}
.stat-box .sb-label{font-size:10px;color:#475569;letter-spacing:.4px}
.stat-box .sb-val{font-size:18px;font-weight:700;margin-top:2px}
.sb-bsod    .sb-val{color:#c084fc}
.sb-crit    .sb-val{color:#f87171}
.sb-err     .sb-val{color:#fb923c}
.sb-warn    .sb-val{color:#fbbf24}
.sb-tot     .sb-val{color:#64748b}
.sb-browser .sb-val{color:#38bdf8}
.sb-uptime  .sb-val{font-size:13px;color:#94a3b8;margin-top:4px}

/* AI badge */
.ai-badge{background:#1e1b4b;color:#a5b4fc;border-radius:3px;padding:1px 6px;font-size:9px;font-weight:700;letter-spacing:.3px;vertical-align:middle}
.issue-detail{font-size:10px;color:#374151;margin-top:3px;font-style:italic;overflow:hidden;max-height:0;transition:max-height .3s}
.issue-detail.open{max-height:200px}
.issue-toggle{font-size:10px;color:#4338ca;cursor:pointer;margin-top:4px;display:inline-block}
.issue-toggle:hover{color:#818cf8}

/* Smart health badges */
.smart-row{display:flex;align-items:center;gap:6px;margin-bottom:5px;font-size:11px}
.smart-row:last-child{margin-bottom:0}
.smart-name{color:#475569;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.smart-type{color:#374151;font-size:10px}
.smart-badge{padding:1px 7px;border-radius:3px;font-size:10px;font-weight:700}
.sh-healthy{background:#052010;color:#34d399}
.sh-warning{background:#221a00;color:#fbbf24}
.sh-unhealthy{background:#2d0505;color:#f87171}
.sh-unknown{background:#111120;color:#475569}

/* Disk I/O */
.io-row{display:flex;align-items:center;gap:8px;margin-bottom:6px}
.io-row:last-child{margin-bottom:0}
.io-label{font-size:11px;color:#64748b;width:48px;flex-shrink:0}
.io-bar-wrap{flex:1;background:#1a1a28;border-radius:3px;height:5px;overflow:hidden}
.io-bar{height:100%;border-radius:3px;transition:width .4s;min-width:2px}
.io-read{background:#38bdf8}
.io-write{background:#f472b6}
.io-val{font-size:11px;font-weight:600;color:#94a3b8;width:60px;text-align:right;flex-shrink:0}

/* ── MAIN — Issues ── */
.issues-bar{padding:12px 20px;border-bottom:1px solid #1a1a28}
.issues-bar .ib-title{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:#374151;margin-bottom:8px}
.issues-list{display:flex;flex-direction:row;flex-wrap:wrap;gap:8px}
.issue{display:flex;align-items:flex-start;gap:10px;background:#0f0f1a;border:1px solid;border-radius:7px;padding:9px 14px;flex:1;min-width:240px;max-width:420px}
.issue.critical{border-color:#7f1d1d;background:#150505}
.issue.high    {border-color:#7c2d12;background:#140a03}
.issue.medium  {border-color:#713f12;background:#130f02}
.issue.low     {border-color:#1e3a1e;background:#030f03}
.issue-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0;margin-top:4px}
.critical .issue-dot{background:#f87171}
.high     .issue-dot{background:#fb923c}
.medium   .issue-dot{background:#fbbf24}
.low      .issue-dot{background:#4ade80}
.issue-body{flex:1}
.issue-title{font-size:12px;font-weight:600;margin-bottom:3px}
.critical .issue-title{color:#f87171}
.high     .issue-title{color:#fb923c}
.medium   .issue-title{color:#fbbf24}
.low      .issue-title{color:#4ade80}
.issue-action{font-size:11px;color:#475569}

.ok-bar{padding:10px 20px;border-bottom:1px solid #1a1a28;display:flex;align-items:center;gap:8px}
.ok-bar .ok-dot{width:7px;height:7px;border-radius:50%;background:#22c55e}
.ok-bar span{color:#475569;font-size:12px}

/* ── Incidents ── */
.incidents-bar{padding:12px 20px;border-bottom:1px solid #1a1a28}
.incidents-bar .sec-title{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:#374151;margin-bottom:8px}
.incident-card{background:#0f0f1a;border:1px solid #1e1a3a;border-radius:8px;margin-bottom:8px;overflow:hidden}
.incident-card:last-child{margin-bottom:0}
.inc-header{display:flex;align-items:center;gap:10px;padding:9px 14px;cursor:pointer;user-select:none}
.inc-header:hover{background:#13101f}
.inc-time{font-size:11px;color:#475569;white-space:nowrap}
.inc-badge{background:#1e0a4a;color:#c084fc;border-radius:3px;padding:2px 7px;font-size:10px;font-weight:700}
.inc-title{font-size:12px;color:#e2e8f0;flex:1}
.inc-arrow{color:#374151;font-size:11px;transition:transform .2s}
.inc-arrow.open{transform:rotate(90deg)}
.inc-body{display:none;padding:0 14px 12px}
.inc-body.open{display:block}
.inc-timeline{margin-bottom:10px}
.inc-event{display:flex;align-items:flex-start;gap:8px;padding:4px 0;border-bottom:1px solid #13131c}
.inc-event:last-child{border-bottom:none}
.inc-ev-time{font-size:10px;color:#374151;white-space:nowrap;width:48px;flex-shrink:0}
.inc-ev-cat{flex-shrink:0}
.inc-ev-msg{font-size:11px;color:#475569;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.inc-analysis{background:#111120;border-left:2px solid #4338ca;padding:8px 12px;font-size:12px;color:#94a3b8;line-height:1.7;white-space:pre-wrap;border-radius:0 4px 4px 0}
.inc-analyze-btn{background:#1e1b4b;color:#a5b4fc;border:1px solid #312e81;border-radius:4px;padding:4px 10px;font-size:11px;cursor:pointer;font-family:inherit;margin-top:8px}
.inc-analyze-btn:hover{background:#312e81}
.inc-analyze-btn.done{background:#022c22;color:#34d399;border-color:#065f46}

/* ── MAIN — Events ── */
.toolbar{display:flex;gap:8px;padding:10px 20px;border-bottom:1px solid #1a1a28;align-items:center;flex-wrap:wrap;background:#0c0c14;position:sticky;top:0;z-index:5}
.toolbar select{background:#111120;color:#94a3b8;border:1px solid #252535;border-radius:4px;padding:4px 8px;font-size:11px;cursor:pointer;font-family:inherit}
.toolbar select:focus{outline:none;border-color:#4338ca}
.ev-count{color:#374151;font-size:11px;margin-left:auto}

.twrap{flex:1;min-width:0}
table{width:100%;border-collapse:collapse;min-width:820px}
th{background:#0c0c14;color:#2d2d45;font-size:10px;text-transform:uppercase;letter-spacing:.5px;padding:7px 12px;text-align:left;border-bottom:1px solid #1a1a28;white-space:nowrap;position:sticky;top:41px;z-index:4}
tr.erow{border-bottom:1px solid #111120;cursor:default}
tr.erow:hover{background:#0f0f1a}
td{padding:7px 12px;vertical-align:middle}

/* badges */
.badge{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700;letter-spacing:.3px;white-space:nowrap}
.b-critical{background:#2d0505;color:#f87171}
.b-error   {background:#2d1200;color:#fb923c}
.b-warning {background:#221a00;color:#fbbf24}
.b-BSOD       {background:#1e0a4a;color:#c084fc}
.b-DISCO      {background:#051528;color:#60a5fa}
.b-SERVICIO   {background:#051a14;color:#34d399}
.b-GPU        {background:#1a1800;color:#facc15}
.b-ANTIVIRUS  {background:#180518;color:#e879f9}
.b-APP_CRASH  {background:#2d0505;color:#f87171}
.b-KERNEL     {background:#1a0a00;color:#fb923c}
.b-SISTEMA    {background:#111120;color:#475569}
.b-RED        {background:#021a2a;color:#38bdf8}
.b-DRIVER     {background:#1a0f00;color:#f97316}
.b-ENERGIA    {background:#1a1500;color:#fde047}
.b-ACTUALIZACION{background:#001a14;color:#4ade80}
.b-SEGURIDAD  {background:#2a0505;color:#fca5a5}
.b-BROWSER    {background:#001a1a;color:#2dd4bf}
.b-System      {background:#13104a;color:#818cf8}
.b-Application {background:#03211a;color:#34d399}

.time-col{color:#64748b;font-size:11px;white-space:nowrap}
.prov-col{color:#5b21b6;font-size:11px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.msg-col{color:#374151;max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:pointer;transition:color .15s}
.msg-col:hover{color:#e2e8f0}
.id-col{color:#374151;font-size:11px}

.btn-analyze{background:#13104a;color:#818cf8;border:1px solid #1e1b6e;border-radius:3px;padding:2px 8px;font-size:10px;cursor:pointer;white-space:nowrap;font-family:inherit}
.btn-analyze:hover{background:#1e1b6e}
.btn-analyze.done{background:#03211a;color:#34d399;border-color:#065f46}
.btn-analyze:disabled{opacity:.3;cursor:default}

.arow td{background:#0a0a12;padding:0}
.abox{border-left:2px solid #4338ca;margin:0 12px 8px;padding:8px 12px;color:#94a3b8;font-size:12px;line-height:1.7;white-space:pre-wrap;background:#0f0f1a;border-radius:0 4px 4px 0}

#empty{text-align:center;padding:60px;color:#252535}

/* ── MODAL ── */
.modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.8);z-index:100;align-items:center;justify-content:center}
.modal.open{display:flex}
.mbox{background:#0f0f1a;border:1px solid #1a1a28;border-radius:10px;padding:20px;max-width:600px;width:92%;max-height:80vh;overflow-y:auto}
.mbox-hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.mbox-hdr h3{color:#a78bfa;font-size:13px}
.mclose{background:none;border:none;color:#374151;font-size:18px;cursor:pointer;line-height:1}
.mclose:hover{color:#94a3b8}
.mbox pre{color:#64748b;font-size:11px;white-space:pre-wrap;line-height:1.7}

/* Responsive */
@media(max-width:900px){
  .page{grid-template-columns:1fr;grid-template-rows:auto auto 1fr}
  .sidebar{grid-column:1;grid-row:2;border-right:none;border-bottom:1px solid #1a1a28;flex-direction:row;flex-wrap:wrap;overflow-x:auto;padding:12px}
  .main{grid-column:1;grid-row:3}
  .health-card{min-width:200px}
}
</style>
</head>
<body>

<!-- HEADER -->
<div class="hdr">
  <span class="dot" id="dot"></span>
  <span class="hdr-title">Windows Monitor</span>
  <span class="hdr-sub">MSI Trident X2 · marc0</span>
  <div class="hdr-right">
    <span class="upd" id="upd"></span>
    <button class="btn-sm" onclick="load()">↻ Refresh</button>
    <button class="btn-sm" id="btn-ar" onclick="toggleAR()">Auto 30s</button>
  </div>
</div>

<div class="page">

  <!-- SIDEBAR -->
  <aside class="sidebar">

    <!-- Estadísticas del día -->
    <div>
      <div class="s-section">Hoy</div>
      <div class="stat-grid">
        <div class="stat-box sb-bsod"><div class="sb-label">BSODs</div><div class="sb-val" id="s-bsod">—</div></div>
        <div class="stat-box sb-crit"><div class="sb-label">Críticos</div><div class="sb-val" id="s-crit">—</div></div>
        <div class="stat-box sb-err" ><div class="sb-label">Errores</div><div class="sb-val" id="s-err">—</div></div>
        <div class="stat-box sb-warn"><div class="sb-label">Warnings</div><div class="sb-val" id="s-warn">—</div></div>
        <div class="stat-box sb-browser" style="grid-column:1/3"><div class="sb-label">Browser crashes 24h</div><div class="sb-val" id="s-browser">—</div></div>
        <div class="stat-box sb-tot" style="grid-column:1/3"><div class="sb-label">Total eventos</div><div class="sb-val" id="s-tot">—</div></div>
      </div>
    </div>

    <!-- Uptime -->
    <div class="health-card" id="uptime-card" style="display:none">
      <div class="hc-label">Sistema</div>
      <div id="uptime-val" style="font-size:12px;color:#64748b"></div>
    </div>

    <!-- RAM / CPU -->
    <div class="health-card">
      <div class="hc-label">Memoria &amp; CPU</div>
      <div id="mem-cpu">
        <div style="color:#252535;font-size:11px">Esperando datos…</div>
      </div>
    </div>

    <!-- GPU -->
    <div class="health-card" id="gpu-card" style="display:none">
      <div class="hc-label">GPU — RTX 4090</div>
      <div id="gpu-metrics"></div>
    </div>

    <!-- Temperaturas -->
    <div class="health-card" id="temps-card" style="display:none">
      <div class="hc-label">Temperatura</div>
      <div class="temp-grid" id="temps-grid"></div>
    </div>

    <!-- Disk I/O -->
    <div class="health-card" id="diskio-card" style="display:none">
      <div class="hc-label">Disk I/O</div>
      <div id="diskio-metrics"></div>
    </div>

    <!-- Discos -->
    <div class="health-card">
      <div class="hc-label">Discos</div>
      <div id="disks-list">
        <div style="color:#252535;font-size:11px">Esperando datos…</div>
      </div>
    </div>

    <!-- S.M.A.R.T. -->
    <div class="health-card" id="smart-card" style="display:none">
      <div class="hc-label">S.M.A.R.T. — Salud</div>
      <div id="smart-list"></div>
    </div>

  </aside>

  <!-- MAIN -->
  <main class="main">

    <!-- Issues / OK bar -->
    <div class="issues-bar" id="issues-bar" style="display:none">
      <div class="ib-title">Problemas detectados</div>
      <div class="issues-list" id="issues-list"></div>
    </div>
    <div class="ok-bar" id="ok-bar">
      <div class="ok-dot"></div>
      <span>Sin problemas activos detectados</span>
    </div>

    <!-- Incidentes (BSODs con cadena de causas) -->
    <div class="incidents-bar" id="incidents-bar" style="display:none">
      <div class="sec-title">Incidentes — Correlación de causas</div>
      <div id="incidents-list"></div>
    </div>

    <!-- Toolbar filtros -->
    <div class="toolbar">
      <select id="fl" onchange="load()">
        <option value="">Todos los niveles</option>
        <option value="1">Solo Críticos</option>
        <option value="2">Error o superior</option>
        <option value="3">Warning o superior</option>
      </select>
      <select id="flog" onchange="load()">
        <option value="">Todos los logs</option>
        <option value="System">System</option>
        <option value="Application">Application</option>
      </select>
      <select id="fcat" onchange="load()">
        <option value="">Todas las categorías</option>
        <optgroup label="── Sistema">
          <option value="BSOD">BSOD</option>
          <option value="KERNEL">Kernel</option>
          <option value="ENERGIA">Energía</option>
          <option value="DRIVER">Driver</option>
        </optgroup>
        <optgroup label="── Hardware">
          <option value="DISCO">Disco</option>
          <option value="GPU">GPU</option>
        </optgroup>
        <optgroup label="── Software">
          <option value="SERVICIO">Servicio</option>
          <option value="APP_CRASH">App Crash</option>
          <option value="BROWSER">Browser</option>
          <option value="ACTUALIZACION">Actualización</option>
        </optgroup>
        <optgroup label="── Red & Seguridad">
          <option value="RED">Red</option>
          <option value="SEGURIDAD">Seguridad</option>
          <option value="ANTIVIRUS">Antivirus</option>
        </optgroup>
        <option value="SISTEMA">Sistema</option>
      </select>
      <span class="ev-count" id="ev-count"></span>
    </div>

    <!-- Events table -->
    <div class="twrap">
      <table>
        <thead><tr>
          <th>Tiempo</th>
          <th>Nivel</th>
          <th>Categoría</th>
          <th>Log</th>
          <th>Proveedor</th>
          <th>ID</th>
          <th>Mensaje</th>
          <th>Análisis</th>
        </tr></thead>
        <tbody id="tbody"></tbody>
      </table>
      <div id="empty" style="display:none">Sin eventos registrados.</div>
    </div>

  </main>
</div>

<!-- Modal mensaje completo -->
<div class="modal" id="modal">
  <div class="mbox">
    <div class="mbox-hdr">
      <h3 id="mt">Evento</h3>
      <button class="mclose" onclick="closeM()">✕</button>
    </div>
    <pre id="mb"></pre>
  </div>
</div>

<script>
const S = "__SECRET__", B = "__BASE__";
let arTimer = null, expanded = new Set();

const api  = p => fetch(B+p+(p.includes("?")?"&":"?")+"secret="+S).then(r=>r.json());
const post = p => fetch(B+p+(p.includes("?")?"&":"?")+"secret="+S,{method:"POST"}).then(r=>r.json());

function bar(pct) {
  const cls = pct>90?"bar-danger":pct>75?"bar-warn":"bar-ok";
  const vc  = pct>90?"val-danger":pct>75?"val-warn":"val-ok";
  return {cls, vc};
}

function renderHealth(snap) {
  if (!snap) return;

  // Uptime
  const upH = Math.floor((snap.uptime_minutes||0)/60);
  const upM = (snap.uptime_minutes||0)%60;
  const uc  = document.getElementById("uptime-card");
  document.getElementById("uptime-val").textContent =
    `${snap.hostname||"?"} · ${snap.username||"?"} · Uptime: ${upH}h ${upM}m`;
  uc.style.display = "";

  // RAM + CPU
  const mc = snap.mem_percent||0, cc = snap.cpu_percent||0;
  const mb = bar(mc), cb = bar(cc);
  document.getElementById("mem-cpu").innerHTML = `
    <div class="metric-row">
      <span class="metric-name">RAM</span>
      <div class="bar-wrap"><div class="bar-fill ${mb.cls}" style="width:${mc}%"></div></div>
      <span class="metric-val ${mb.vc}">${mc}%</span>
    </div>
    <div class="metric-row">
      <span class="metric-name">CPU</span>
      <div class="bar-wrap"><div class="bar-fill ${cb.cls}" style="width:${Math.min(cc,100)}%"></div></div>
      <span class="metric-val ${cb.vc}">${cc}%</span>
    </div>`;

  // Temps
  const tg = document.getElementById("temps-grid");
  let thtml = "";
  if (snap.gpu_temp) {
    const tc = snap.gpu_temp>80?"val-danger":snap.gpu_temp>70?"val-warn":"val-ok";
    thtml += `<div class="temp-box"><div class="tb-label">GPU</div><div class="tb-val ${tc}">${snap.gpu_temp}<span class="tb-unit">°C</span></div></div>`;
  }
  if (snap.cpu_temp) {
    const tc = snap.cpu_temp>85?"val-danger":snap.cpu_temp>75?"val-warn":"val-ok";
    thtml += `<div class="temp-box"><div class="tb-label">CPU</div><div class="tb-val ${tc}">${snap.cpu_temp}<span class="tb-unit">°C</span></div></div>`;
  }
  if (thtml) { tg.innerHTML = thtml; document.getElementById("temps-card").style.display = ""; }

  // GPU — utilización + VRAM
  if (snap.gpu_percent != null || snap.gpu_vram_used_mb != null) {
    const gp = snap.gpu_percent ?? 0;
    const gb = bar(gp);
    let ghtml = `<div class="metric-row">
      <span class="metric-name">Uso</span>
      <div class="bar-wrap"><div class="bar-fill ${gb.cls}" style="width:${gp}%"></div></div>
      <span class="metric-val ${gb.vc}">${gp}%</span>
    </div>`;
    if (snap.gpu_vram_used_mb != null && snap.gpu_vram_total_mb) {
      const vp = Math.round((snap.gpu_vram_used_mb / snap.gpu_vram_total_mb) * 100);
      const vb = bar(vp);
      const usedGB = (snap.gpu_vram_used_mb / 1024).toFixed(1);
      const totGB  = (snap.gpu_vram_total_mb / 1024).toFixed(0);
      ghtml += `<div class="metric-row">
        <span class="metric-name">VRAM</span>
        <div class="bar-wrap"><div class="bar-fill ${vb.cls}" style="width:${vp}%"></div></div>
        <span class="metric-val ${vb.vc}">${usedGB}/${totGB}G</span>
      </div>`;
    }
    document.getElementById("gpu-metrics").innerHTML = ghtml;
    document.getElementById("gpu-card").style.display = "";
  }

  // Disk I/O
  if (snap.disk_read_mbps != null || snap.disk_write_mbps != null) {
    const rd = snap.disk_read_mbps ?? 0, wr = snap.disk_write_mbps ?? 0;
    const maxIO = Math.max(rd, wr, 50);
    const rdPct = Math.min((rd / maxIO) * 100, 100);
    const wrPct = Math.min((wr / maxIO) * 100, 100);
    document.getElementById("diskio-metrics").innerHTML = `
      <div class="io-row">
        <span class="io-label">Lectura</span>
        <div class="io-bar-wrap"><div class="io-bar io-read" style="width:${rdPct}%"></div></div>
        <span class="io-val">${rd.toFixed(1)} MB/s</span>
      </div>
      <div class="io-row">
        <span class="io-label">Escritura</span>
        <div class="io-bar-wrap"><div class="io-bar io-write" style="width:${wrPct}%"></div></div>
        <span class="io-val">${wr.toFixed(1)} MB/s</span>
      </div>`;
    document.getElementById("diskio-card").style.display = "";
  }

  // Discos
  if (snap.disks) {
    let dhtml = "";
    snap.disks.split(";").forEach(d => {
      d = d.trim(); if (!d) return;
      const p = d.split("|");
      if (p.length < 3) return;
      const pct = parseFloat(p[2]);
      const b = bar(pct);
      const label = p[0] + (p[3] ? " "+p[3] : "");
      dhtml += `<div class="metric-row">
        <span class="metric-name">${label}</span>
        <div class="bar-wrap"><div class="bar-fill ${b.cls}" style="width:${pct}%"></div></div>
        <span class="metric-val ${b.vc}">${p[1]}</span>
      </div>`;
    });
    if (dhtml) document.getElementById("disks-list").innerHTML = dhtml;
  }

  // S.M.A.R.T.
  if (snap.smart_disks) {
    let shtml = "";
    snap.smart_disks.split(";").forEach(d => {
      d = d.trim(); if (!d) return;
      const p = d.split("|");
      if (p.length < 3) return;
      const name   = p[0].trim();
      const mtype  = p[1]?.trim() || "";
      const health = p[2]?.trim() || "Unknown";
      const size   = p[3]?.trim() || "";
      const hcls   = health === "Healthy" ? "sh-healthy" :
                     health === "Warning"  ? "sh-warning"  :
                     health === "Unhealthy"? "sh-unhealthy": "sh-unknown";
      shtml += `<div class="smart-row">
        <span class="smart-name" title="${name}">${name.length>22?name.slice(0,20)+"…":name}</span>
        <span class="smart-type">${mtype} ${size}</span>
        <span class="smart-badge ${hcls}">${health}</span>
      </div>`;
    });
    if (shtml) {
      document.getElementById("smart-list").innerHTML = shtml;
      document.getElementById("smart-card").style.display = "";
    }
  }
}

function renderIssues(issues) {
  const bar  = document.getElementById("issues-bar");
  const ok   = document.getElementById("ok-bar");
  const list = document.getElementById("issues-list");
  if (!issues || !issues.length) {
    bar.style.display = "none"; ok.style.display = "flex"; return;
  }
  ok.style.display = "none"; bar.style.display = "";
  list.innerHTML = issues.map((i,idx) => {
    const aiBadge = i.ai_analyzed
      ? `<span class="ai-badge" title="Diagnóstico generado por Claude AI">IA</span> `
      : '';
    // For AI-analyzed issues, show a toggle to expand full analysis
    const detailId = `issue-detail-${idx}`;
    const toggleId = `issue-toggle-${idx}`;
    const toggleHtml = i.ai_analyzed
      ? `<span class="issue-toggle" id="${toggleId}" onclick="toggleIssueDetail('${detailId}','${toggleId}')">▶ Ver diagnóstico completo</span>`
      : '';
    const detailHtml = i.ai_analyzed && i.detail
      ? `<div class="issue-detail" id="${detailId}">${escHtml(i.detail)}</div>`
      : '';
    return `
    <div class="issue ${i.severity}">
      <div class="issue-dot"></div>
      <div class="issue-body">
        <div class="issue-title">${escHtml(i.title)}</div>
        <div class="issue-action">${aiBadge}→ ${escHtml(i.action)}</div>
        ${detailHtml}${toggleHtml}
      </div>
    </div>`;
  }).join("");
}

function toggleIssueDetail(detailId, toggleId) {
  const d = document.getElementById(detailId);
  const t = document.getElementById(toggleId);
  if (!d) return;
  const open = d.classList.toggle("open");
  if (t) t.textContent = (open ? "▼ " : "▶ ") + "Ver diagnóstico completo";
}

function escHtml(s) {
  return (s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

function renderIncidents(incidents) {
  const bar  = document.getElementById("incidents-bar");
  const list = document.getElementById("incidents-list");
  if (!incidents || !incidents.length) { bar.style.display = "none"; return; }
  bar.style.display = "";

  list.innerHTML = incidents.map(inc => {
    const t = fmt(inc.time_created);
    const chainHtml = (inc.chain||[]).map(e => `
      <div class="inc-event">
        <span class="inc-ev-time">${fmtTime(e.time_created)}</span>
        <span class="inc-ev-cat"><span class="badge b-${e.category||'SISTEMA'}">${e.category||'SIS'}</span></span>
        <span class="inc-ev-msg" title="${(e.message||"").replace(/"/g,"'")}">
          ${e.provider} — ${(e.message||"").substring(0,80)}
        </span>
      </div>`).join("") || '<div style="color:#374151;font-size:11px;padding:6px 0">Sin eventos previos en la ventana de 15 min</div>';

    const analysisHtml = inc.analysis
      ? `<div class="inc-analysis">${inc.analysis.replace(/</g,"&lt;")}</div>`
      : `<button class="inc-analyze-btn" onclick="analyzeIncident(${inc.id}, this)">Analizar cadena con Claude</button>`;

    return `
    <div class="incident-card">
      <div class="inc-header" onclick="toggleInc(${inc.id})">
        <span class="inc-badge">BSOD</span>
        <span class="inc-time">${t}</span>
        <span class="inc-title">Event ${inc.event_id} — ${inc.chain.length} evento(s) previo(s)</span>
        <span class="inc-arrow" id="inc-arrow-${inc.id}">▶</span>
      </div>
      <div class="inc-body" id="inc-body-${inc.id}">
        <div class="inc-timeline">${chainHtml}</div>
        <div id="inc-analysis-${inc.id}">${analysisHtml}</div>
      </div>
    </div>`;
  }).join("");
}

function toggleInc(id) {
  const body  = document.getElementById("inc-body-"+id);
  const arrow = document.getElementById("inc-arrow-"+id);
  const open  = body.classList.toggle("open");
  arrow.classList.toggle("open", open);
}

function analyzeIncident(incId, btn) {
  btn.disabled = true; btn.textContent = "Analizando…";
  post("/api/incidents/"+incId+"/analyze").then(r => {
    const box = document.getElementById("inc-analysis-"+incId);
    if (r.analysis) {
      box.innerHTML = `<div class="inc-analysis">${r.analysis.replace(/</g,"&lt;")}</div>`;
    } else {
      btn.disabled = false; btn.textContent = "Reintentar";
    }
  }).catch(() => { btn.disabled=false; btn.textContent="Error"; });
}

function fmt(t) {
  if (!t) return "—";
  const d = new Date(t);
  const date = d.toLocaleDateString("en-US", {month:"2-digit",day:"2-digit"});
  const time = d.toLocaleTimeString("en-US", {hour:"2-digit",minute:"2-digit",hour12:true});
  return `${date} ${time}`;
}
function fmtTime(t) {
  if (!t) return "—";
  const d = new Date(t);
  return d.toLocaleTimeString("en-US", {hour:"2-digit",minute:"2-digit",second:"2-digit",hour12:true});
}

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
    document.getElementById("dot").className = "dot";
    document.getElementById("s-bsod").textContent    = s.bsods_today ?? "—";
    document.getElementById("s-crit").textContent    = s.critical_today ?? "—";
    document.getElementById("s-err").textContent     = s.errors_today ?? "—";
    document.getElementById("s-warn").textContent    = s.warnings_today ?? "—";
    document.getElementById("s-tot").textContent     = s.total ?? "—";
    const bc = s.snapshot?.browser_crashes;
    const bcEl = document.getElementById("s-browser");
    bcEl.textContent = bc != null ? bc : "—";
    bcEl.style.color = bc > 0 ? "#38bdf8" : "#475569";
    document.getElementById("upd").textContent = new Date().toLocaleTimeString("en-US",{hour:"2-digit",minute:"2-digit",second:"2-digit",hour12:true});

    if (s.snapshot) renderHealth(s.snapshot);
    renderIssues(iss.issues);
    renderIncidents(incs.incidents);

    const events = data.events || [];
    document.getElementById("ev-count").textContent = events.length ? `${events.length} eventos` : "";
    document.getElementById("empty").style.display = events.length ? "none" : "block";

    const tbody = document.getElementById("tbody");
    tbody.innerHTML = "";
    events.forEach(e => {
      const tr = document.createElement("tr");
      tr.className = "erow"; tr.id = "row-"+e.id;
      const lvlBadge = `<span class="badge b-${e.level===1?"critical":e.level===2?"error":"warning"}">${e.level_name}</span>`;
      const catBadge = `<span class="badge b-${e.category||'SISTEMA'}">${e.category||'SIS'}</span>`;
      const logBadge = `<span class="badge b-${e.log_name}">${e.log_name}</span>`;
      const msg = (e.message||"").replace(/</g,"&lt;").substring(0,120);
      tr.innerHTML = `
        <td class="time-col">${fmt(e.time_created)}</td>
        <td>${lvlBadge}</td>
        <td>${catBadge}</td>
        <td>${logBadge}</td>
        <td class="prov-col" title="${e.provider}">${e.provider}</td>
        <td class="id-col">${e.event_id}</td>
        <td class="msg-col" onclick="showMsg(${e.id},${JSON.stringify(e.message)})">${msg}${e.message.length>120?"…":""}</td>
        <td><button class="btn-analyze ${e.analysis?'done':''}" id="btn-${e.id}" onclick="analyze(${e.id})">${e.analysis?"Ver":"Analizar"}</button></td>`;
      tbody.appendChild(tr);
      if (expanded.has(e.id) && e.analysis) insertArow(e.id, e.analysis);
    });
  })
  .catch(() => { document.getElementById("dot").className = "dot off"; });
}

function insertArow(id, text) {
  if (document.getElementById("ar-"+id)) return;
  const ref = document.getElementById("row-"+id);
  if (!ref) return;
  const ar = document.createElement("tr");
  ar.className = "arow"; ar.id = "ar-"+id;
  ar.innerHTML = `<td colspan="8"><div class="abox">${(text||"").replace(/</g,"&lt;")}</div></td>`;
  ref.after(ar);
}

function analyze(id) {
  const ar = document.getElementById("ar-"+id);
  if (ar) { ar.remove(); expanded.delete(id); return; }
  expanded.add(id);
  const btn = document.getElementById("btn-"+id);
  if (btn && btn.classList.contains("done")) {
    post("/api/analyze/"+id).then(r => { if (r.analysis) insertArow(id, r.analysis); });
    return;
  }
  if (btn) { btn.disabled=true; btn.textContent="…"; }
  post("/api/analyze/"+id).then(r => {
    if (btn) { btn.disabled=false; btn.textContent="Ver"; btn.classList.add("done"); }
    if (r.analysis) insertArow(id, r.analysis);
  }).catch(() => { if (btn) { btn.disabled=false; btn.textContent="!"; } });
}

function showMsg(id, text) {
  document.getElementById("mt").textContent = "Evento #"+id;
  document.getElementById("mb").textContent = text;
  document.getElementById("modal").classList.add("open");
}
function closeM() { document.getElementById("modal").classList.remove("open"); }
document.getElementById("modal").addEventListener("click", e => { if (e.target.id==="modal") closeM(); });

function toggleAR() {
  const btn = document.getElementById("btn-ar");
  if (arTimer) { clearInterval(arTimer); arTimer=null; btn.classList.remove("on"); }
  else { arTimer = setInterval(load, 30000); btn.classList.add("on"); }
}

load();
</script>
</body>
</html>"""
