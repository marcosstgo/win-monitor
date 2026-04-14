"""
Windows Event Log Monitor Agent v3
- Captura Critical/Error/Warning de System y Application
- Incluye metricas del sistema: RAM, CPU, disco, temperatura, uptime
- GPU: temperatura, utilizacion %, VRAM usada/total
- Disk I/O: MB/s de lectura y escritura en tiempo real
- S.M.A.R.T.: estado de salud de discos fisicos
- Browser crashes: conteo de .dmp de Chrome/Brave en ultimas 24h
- Detecta BSODs (41, 1001), disk errors (11, 7, 157), crashes de servicios (7031, 7034)
- Envia al servidor cada 60s, solo eventos nuevos
"""
import subprocess
import json
import time
import requests
from datetime import datetime
from pathlib import Path

SERVER_URL    = "https://marcossantiago.com/win-monitor/api/events"
API_SECRET    = "winmon-marc0-2026"
POLL_INTERVAL = 60
STATE_FILE    = Path(__file__).parent / "agent_state.json"

PS_SCRIPT = r"""
$results = @()

$targets = @(
    @{ Log = 'System';      MaxEvents = 300; MaxLevel = 3; FilterIds = $null },
    # BugCheck (1001) es Level=Information(4) — queda fuera del filtro normal (MaxLevel=3)
    # Se captura explicitamente para obtener el stop code exacto del BSOD (ej: 0x1E, 0x7E, etc.)
    @{ Log = 'System';      MaxEvents = 10;  MaxLevel = 5; FilterIds = @(1001) },
    @{ Log = 'Application'; MaxEvents = 200; MaxLevel = 2; FilterIds = $null },
    # Logs operacionales — capturan el detalle del "por que" crasheo un servicio
    @{ Log = 'Microsoft-Windows-Windows Defender/Operational';
       MaxEvents = 50; MaxLevel = 2;
       FilterIds = @(1006,1007,1008,5004,5007,5008,5009,5010,5012,3002,3007) },
    @{ Log = 'Microsoft-Windows-WindowsUpdateClient/Operational';
       MaxEvents = 30; MaxLevel = 2;
       FilterIds = @(20,25,31,34) },
    @{ Log = 'Microsoft-Windows-WLAN-AutoConfig/Operational';
       MaxEvents = 20; MaxLevel = 2; FilterIds = $null },
    @{ Log = 'Microsoft-Windows-Ntfs/Operational';
       MaxEvents = 20; MaxLevel = 2; FilterIds = $null },
    @{ Log = 'Microsoft-Windows-DriverFrameworks-UserMode/Operational';
       MaxEvents = 20; MaxLevel = 2; FilterIds = $null }
)

foreach ($t in $targets) {
    try {
        $raw = Get-WinEvent -LogName $t.Log -MaxEvents $t.MaxEvents -ErrorAction SilentlyContinue |
            Where-Object { $_.Level -gt 0 -and $_.Level -le $t.MaxLevel }
        if ($t.FilterIds) { $raw = $raw | Where-Object { $_.Id -in $t.FilterIds } }
        $events = $raw
        foreach ($e in $events) {
            $msg = ''
            try { $msg = $e.Message } catch {}
            if (-not $msg) { $msg = "(sin mensaje)" }
            $msg = ($msg -replace "`r`n|`r|`n", " ").Substring(0, [Math]::Min(3000, $msg.Length))
            $results += [PSCustomObject]@{
                RecordId    = [long]$e.RecordId
                TimeCreated = $e.TimeCreated.ToString("o")
                EventId     = $e.Id
                Level       = $e.Level
                LevelName   = $e.LevelDisplayName
                LogName     = $e.LogName
                Provider    = $e.ProviderName
                Message     = $msg
            }
        }
    } catch {}
}

# Metricas del sistema
$os      = Get-CimInstance -ClassName CIM_OperatingSystem -ErrorAction SilentlyContinue
$memTotal = [math]::Round($os.TotalVisibleMemorySize / 1024)
$memFree  = [math]::Round($os.FreePhysicalMemory / 1024)
$memPct   = [math]::Round((($memTotal - $memFree) / $memTotal) * 100, 1)
$uptime   = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalMinutes)

# CPU % via performance counter (mas confiable que Win32_Processor.LoadPercentage)
$cpuPct = $null
try {
    $perf = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq '_Total' } | Select-Object -First 1
    if ($perf) { $cpuPct = [int]$perf.PercentProcessorTime }
} catch {}
if ($null -eq $cpuPct) {
    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cpu) { $cpuPct = [int]$cpu.LoadPercentage }
    } catch {}
}

$diskList = @()
Get-Volume -ErrorAction SilentlyContinue |
    Where-Object { $_.DriveLetter -and $_.Size -gt 0 } |
    ForEach-Object {
        $pct = [math]::Round((($_.Size - $_.SizeRemaining) / $_.Size) * 100, 1)
        $diskList += "$($_.DriveLetter):|$([math]::Round($_.SizeRemaining/1GB,1))GB libre|$pct%|$($_.FileSystemLabel)"
    }

$gpuTemp      = $null
$gpuPercent   = $null
$gpuVramUsed  = $null
$gpuVramTotal = $null
$gpuName      = $null

# Nombre de GPU via Win32_VideoController (funciona con AMD, NVIDIA, Intel)
try {
    $vc = Get-CimInstance -ClassName Win32_VideoController -OperationTimeoutSec 5 -ErrorAction SilentlyContinue |
          Where-Object { $_.Name -notmatch 'Microsoft|Remote|Virtual|Basic' } |
          Select-Object -First 1
    if ($vc) { $gpuName = $vc.Name.Trim() }
} catch {}

# NVIDIA: temperatura, utilización y VRAM via nvidia-smi
try {
    $nvsmi = & "nvidia-smi" --query-gpu=temperature.gpu,utilization.gpu,memory.used,memory.total --format=csv,noheader,nounits 2>$null
    if ($nvsmi) {
        $parts = ($nvsmi.Trim()) -split ',\s*'
        if ($parts.Count -ge 4) {
            $gpuTemp      = [int]$parts[0]
            $gpuPercent   = [int]$parts[1]
            $gpuVramUsed  = [int]$parts[2]
            $gpuVramTotal = [int]$parts[3]
        }
    }
} catch {}

$cpuTemp = $null
# Metodo 1: MSAcpi_ThermalZoneTemperature — toma la zona mas caliente en rango razonable
try {
    $zones = Get-CimInstance -Namespace "root/WMI" -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue
    if ($zones) {
        $temps = $zones | ForEach-Object { [math]::Round($_.CurrentTemperature / 10.0 - 273.15) } |
                 Where-Object { $_ -gt 20 -and $_ -lt 120 }
        if ($temps) { $cpuTemp = ($temps | Measure-Object -Maximum).Maximum }
    }
} catch {}
# Metodo 2: ThermalZoneInformation performance counters
if ($null -eq $cpuTemp) {
    try {
        $tz2 = Get-CimInstance -ClassName Win32_PerfFormattedData_Counters_ThermalZoneInformation -ErrorAction SilentlyContinue |
               Select-Object -First 1
        if ($tz2 -and $tz2.Temperature -gt 273) { $cpuTemp = [int]$tz2.Temperature - 273 }
    } catch {}
}

# Disk I/O via WMI performance counters (instantaneo, sin espera)
$diskReadMBps  = $null
$diskWriteMBps = $null
try {
    $dp = Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -ErrorAction SilentlyContinue |
          Where-Object { $_.Name -eq '_Total' } | Select-Object -First 1
    if ($dp) {
        $diskReadMBps  = [math]::Round($dp.DiskReadBytesPersec  / 1MB, 2)
        $diskWriteMBps = [math]::Round($dp.DiskWriteBytesPersec / 1MB, 2)
    }
} catch {}

# S.M.A.R.T. — estado de salud de discos fisicos
$smartList = @()
try {
    Get-PhysicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
        $smartList += "$($_.FriendlyName)|$($_.MediaType)|$($_.HealthStatus)|$([math]::Round($_.Size/1GB,0))GB"
    }
} catch {}

# Browser crashes en las ultimas 24h (Chrome + Brave)
$browserCrashes = 0
try {
    $crashPaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Crashpad\reports",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Crashpad\reports"
    )
    $cutoff = (Get-Date).AddHours(-24)
    foreach ($cp in $crashPaths) {
        if (Test-Path $cp) {
            $browserCrashes += (Get-ChildItem $cp -Filter '*.dmp' -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt $cutoff }).Count
        }
    }
} catch {}

$metrics = [PSCustomObject]@{
    hostname          = $env:COMPUTERNAME
    username          = $env:USERNAME
    mem_total_mb      = $memTotal
    mem_free_mb       = $memFree
    mem_percent       = $memPct
    cpu_percent       = $cpuPct
    uptime_minutes    = $uptime
    gpu_name          = $gpuName
    gpu_temp          = $gpuTemp
    gpu_percent       = $gpuPercent
    gpu_vram_used_mb  = $gpuVramUsed
    gpu_vram_total_mb = $gpuVramTotal
    cpu_temp          = $cpuTemp
    disk_read_mbps    = $diskReadMBps
    disk_write_mbps   = $diskWriteMBps
    smart_disks       = ($smartList -join "; ")
    browser_crashes   = $browserCrashes
    disks             = ($diskList -join "; ")
}

@{ events = $results; metrics = $metrics } | ConvertTo-Json -Compress -Depth 5
"""

def run_ps():
    r = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", PS_SCRIPT],
        capture_output=True, text=True, timeout=60,
        creationflags=0x08000000  # CREATE_NO_WINDOW — evita que aparezca la ventana de PS
    )
    if not r.stdout.strip():
        return [], {}
    try:
        data = json.loads(r.stdout.strip())
        events  = data.get("events", [])
        metrics = data.get("metrics", {})
        if isinstance(events, dict):
            events = [events]
        return events, metrics
    except Exception as e:
        print(f"  parse error: {e}")
        return [], {}

def load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {}

def save_state(s):
    STATE_FILE.write_text(json.dumps(s))

def send(events, metrics):
    payload = {
        "secret":  API_SECRET,
        "metrics": metrics,
        "events": [{
            "time_created": e["TimeCreated"],
            "event_id":     int(e["EventId"]),
            "level":        int(e["Level"]),
            "level_name":   e["LevelName"],
            "log_name":     e["LogName"],
            "provider":     e["Provider"],
            "message":      e["Message"],
        } for e in events]
    }
    resp = requests.post(SERVER_URL, json=payload, timeout=20)
    resp.raise_for_status()
    return resp.json()

def run():
    print(f"[{datetime.now():%H:%M:%S}] Windows Monitor Agent v3 iniciado")
    state = load_state()

    while True:
        try:
            all_events, metrics = run_ps()
            new_events = []

            for e in all_events:
                log = e.get("LogName", "")
                rid = int(e.get("RecordId", 0))
                if rid > state.get(log, 0):
                    new_events.append(e)

            # Siempre enviar metricas (snapshot), aunque no haya eventos nuevos
            for e in new_events:
                log = e.get("LogName", "")
                rid = int(e.get("RecordId", 0))
                state[log] = max(state.get(log, 0), rid)
            result = send(new_events, metrics)
            save_state(state)
            if True:
                gpu_info = ""
                if metrics.get("gpu_percent") is not None:
                    gpu_info = f" | GPU {metrics.get('gpu_percent')}% {metrics.get('gpu_temp','?')}°C"
                bc = metrics.get("browser_crashes", 0) or 0
                bc_info = f" | Crashes {bc}" if bc > 0 else ""
                print(f"[{datetime.now():%H:%M:%S}] +{result.get('received',0)} eventos | "
                      f"RAM {metrics.get('mem_percent','?')}% | "
                      f"CPU {metrics.get('cpu_percent','?')}%{gpu_info}{bc_info} | "
                      f"Uptime {metrics.get('uptime_minutes','?')}m")

        except requests.exceptions.RequestException as e:
            print(f"[{datetime.now():%H:%M:%S}] Red: {e}")
        except Exception as e:
            print(f"[{datetime.now():%H:%M:%S}] Error: {e}")

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    run()
