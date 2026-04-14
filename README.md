# Vigil

Windows system monitor with a real-time web dashboard, AI-powered event diagnosis, and Telegram alerts.

![Dashboard](vigil_preview.png)

## Features

- **Real-time dashboard** — CPU, RAM, GPU load & temperature, disk I/O, uptime
- **Windows Event Log** — captures Critical/Error/Warning from System and Application logs
- **AI diagnosis** — automatic analysis of service crashes and BSODs
- **Telegram alerts** — instant notifications for critical events
- **Multi-machine** — monitor multiple PCs from a single dashboard
- **Hardware history** — 24h charts for CPU, RAM and temperature
- **S.M.A.R.T.** — physical disk health status
- **Auto-update** — client updates itself silently in the background
- **GPU support** — NVIDIA (nvidia-smi) and AMD/Intel (Windows performance counters)

## Installation

1. Download the latest `Vigil.exe` from [Releases](https://github.com/marcosstgo/vigil/releases/latest)
2. Run it — a setup dialog will appear on first launch
3. Enter your secret key and server URL
4. Vigil minimizes to the system tray and starts monitoring

## Getting started

Register a free account at [marcossantiago.com/vigil](https://marcossantiago.com/vigil) to get your secret key and access the dashboard.

## Dashboard

Access your dashboard at:
```
https://marcossantiago.com/win-monitor/?secret=YOUR_SECRET
```

## Self-hosting

### Requirements

- Python 3.11+
- Ubuntu / Debian server (or any Linux)

### Setup

```bash
git clone https://github.com/marcosstgo/vigil
cd vigil
python3 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn requests anthropic
uvicorn server:app --host 127.0.0.1 --port 8200
```

Configure environment variables:
```bash
export API_SECRET=your-secret-key
export CLAUDE_API_KEY=your-anthropic-key   # optional, for AI diagnosis
export DB_PATH=/path/to/monitor.db
```

## Building the client

```bash
pip install pyinstaller pystray pillow requests
pyinstaller --onefile --windowed --icon=vigil.ico --name=Vigil \
  --hidden-import=pystray._win32 --hidden-import=PIL._tkinter_finder \
  vigil_tray.py
```

## License

MIT

## Privacy

See [Privacy Policy](https://marcossantiago.com/vigil/privacy).
