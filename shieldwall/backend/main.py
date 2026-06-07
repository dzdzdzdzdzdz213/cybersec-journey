import asyncio, json, uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from threading import Thread
from datetime import datetime

from models import init_db, save_packet, save_alert, get_alerts, get_packets, get_stats, get_timeline, ack_alert
from capture import PacketCapture
from detector import Detector

app = FastAPI(title="ShieldWall API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

conn = init_db()
detector = Detector()
capture = PacketCapture()

connected_clients = set()

def on_packet(pkt):
    save_packet(conn, pkt)
    alerts = detector.analyze(pkt)
    for alert in alerts:
        aid = save_alert(conn, alert)
        alert["id"] = aid
        asyncio.run(broadcast({"type": "alert", "data": alert}))
    asyncio.run(broadcast({
        "type": "packet",
        "data": {k: pkt[k] for k in ["timestamp","src","dst","protocol","length"]}
    }))

async def broadcast(msg):
    dead = set()
    for ws in connected_clients:
        try:
            await ws.send_json(msg)
        except Exception:
            dead.add(ws)
    connected_clients.difference_update(dead)

@app.on_event("startup")
async def startup():
    t = Thread(target=capture.start, args=(on_packet,), daemon=True)
    t.start()

@app.get("/api/stats")
def api_stats():
    return get_stats(conn)

@app.get("/api/timeline")
def api_timeline():
    return get_timeline(conn)

@app.get("/api/alerts")
def api_alerts(limit: int = 50, offset: int = 0, severity: str = None, ack: int = None):
    return get_alerts(conn, limit, offset, severity, ack)

@app.get("/api/packets")
def api_packets(limit: int = 50, offset: int = 0, protocol: str = None):
    return get_packets(conn, limit, offset, protocol)

@app.post("/api/alerts/{alert_id}/ack")
def api_ack(alert_id: int):
    return {"success": ack_alert(conn, alert_id)}

@app.get("/api/rules")
def api_rules():
    return detector.rules

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    connected_clients.add(ws)
    try:
        while True:
            data = await ws.receive_text()
    except WebSocketDisconnect:
        connected_clients.discard(ws)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
