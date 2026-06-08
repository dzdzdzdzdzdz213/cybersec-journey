# 🛡️ ShieldWall — Network Security Monitor

A full-featured network security monitoring platform with packet capture, intrusion detection, traffic analysis, and a real-time dashboard.

## Architecture

```
shieldwall/
├── backend/          FastAPI + Scapy + SQLite
│   ├── main.py       API server & WebSocket
│   ├── capture.py    Packet capture engine
│   ├── detector.py   Signature-based IDS
│   ├── models.py     Data models & DB
│   └── rules/        Detection signatures
├── frontend/         React + Chart.js
│   └── src/          Dashboard & components
└── README.md
```

## Quick Start

### Backend
```bash
cd shieldwall/backend
pip install -r requirements.txt
python main.py
# API at http://localhost:8000
```

### Frontend
```bash
cd shieldwall/frontend
npm install
npm start
# UI at http://localhost:3000
```

## Features

- **Live packet capture** — capture and decode network traffic in real-time
- **Signature detection** — YAML-based rule engine for threat detection
- **Traffic analysis** — protocol breakdown, bandwidth stats, top talkers
- **Alert management** — severity scoring, acknowledgement, filtering
- **Real-time dashboard** — WebSocket-powered live updates with charts
- **PCAP export** — save captures for offline analysis
- **REST API** — full programmatic access to all data
