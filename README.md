# WiFiGuard

WiFiGuard is a Flask-based cybersecurity dashboard for public WiFi safety checks and website security analysis.

It focuses on practical signals such as HTTPS reachability, SSL certificate validity, redirect behavior, DNS health, local ARP-based device discovery, and gateway consistency checks.

## Features

- Network safety scan with weighted risk scoring (`0-100`)
- Risk levels: `Safe`, `Moderate`, `Risky`, `Dangerous`
- Confidence level per scan (`High`, `Medium`, `Low`)
- Local network device detection:
  - ARP parsing with strict filtering
  - Quick/Full scan modes
  - MAC vendor lookup (API + local fallback)
  - Reverse DNS hostname lookup
  - Device fingerprinting (Router/Mobile/Laptop/Desktop/Generic)
  - New device detection between scans
- Website scanner:
  - HTTPS + HTTPS enforcement checks
  - SSL certificate validation
  - Redirect chain analysis
  - Security header checks on final response
- PDF report downloads for network and website scans
- Scan history with trend visualization

## Project Structure

- `app.py` - Flask app, scanning logic, API routes, PDF generators
- `templates/` - Jinja templates (dashboard, website, history, about)
- `static/` - JS/CSS frontend logic and UI styles
- `data/` - runtime scan/device/gateway state files
- `requirements.txt` - Python dependencies
- `render.yaml` / `Procfile` - deployment config

## Requirements

- Python `3.12+`
- Windows is currently best supported for ARP/ping device scanning (`arp`, `ping`, `ipconfig`, `route`)

Install:

```bash
pip install -r requirements.txt
```

## Run Locally

```bash
python app.py
```

App default URL:

- `http://127.0.0.1:5000`

## Deployment (Render)

This repo is prepared for Render deployment:

- `render.yaml` defines build/start settings
- `Procfile` includes production Gunicorn command
- `runtime.txt` pins Python version

Typical flow:

1. Push to GitHub
2. Create Render Blueprint/Web Service from this repo
3. Set environment variable:
   - `SECRET_KEY` (strong random value)
4. Deploy

## API Endpoints (high level)

- `POST /scan` - run network scan (`scan_mode: quick|full`)
- `GET /api/history` - recent scan history
- `GET /api/scan/<id>` - single scan details
- `GET /report/<id>` - network PDF report
- `POST /api/website-scan` - website scan
- `POST /api/website-report` - website PDF report
- `GET /health` - health check

## Disclaimer

This analysis is based on heuristic and connectivity checks. It does not guarantee complete network security.

