import asyncio, json, uvicorn, time, os
from pathlib import Path
from contextlib import asynccontextmanager
from threading import Thread, Lock
from queue import Queue, Empty
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, Request, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List

from config import load_config, reload_config, get_config
from capture import PacketCapture
from plugins import PluginManager, DetectionContext
from outputs import OutputManager
from mitre import enrich_with_mitre, MITRE_TECHNIQUES, TACTICS_ORDER
import models

cfg = load_config()
conn = models.init_db(cfg)
detector = PluginManager(cfg)
outputs = OutputManager(cfg)
capture = PacketCapture(cfg)
connected_clients = set()
clients_lock = asyncio.Lock()

pkt_queue = Queue()
broadcast_queue = Queue()

# ----- Auth -----
security = HTTPBearer(auto_error=False)
api_keys = cfg.get("server", {}).get("auth", {}).get("api_keys", {})

async def verify_auth(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)):
    auth_cfg = cfg.get("server", {}).get("auth", {})
    if not auth_cfg.get("enabled", False):
        return True
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing credentials")
    token = credentials.credentials
    if token in api_keys.values():
        return True
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")

# ----- Rate Limiting -----
request_counts = {}
rate_lock = Lock()

def check_rate_limit(client_ip: str) -> bool:
    if not cfg.get("server", {}).get("rate_limit", {}).get("enabled", True):
        return True
    limit = cfg["server"]["rate_limit"]["requests_per_minute"]
    now = time.time()
    with rate_lock:
        if client_ip not in request_counts:
            request_counts[client_ip] = []
        request_counts[client_ip] = [t for t in request_counts[client_ip] if now - t < 60]
        if len(request_counts[client_ip]) >= limit:
            return False
        request_counts[client_ip].append(now)
    return True

@asynccontextmanager
async def lifespan(app: FastAPI):
    t1 = Thread(target=_run_capture, daemon=True)
    t2 = Thread(target=_run_processor, daemon=True)
    t3 = Thread(target=_run_config_watcher, daemon=True)
    t1.start(); t2.start(); t3.start()
    asyncio.create_task(_broadcast_loop())
    yield
    capture.stop()
    outputs.close()

app = FastAPI(title="ShieldWall API", lifespan=lifespan)

def _run_capture():
    capture.start(pkt_queue.put)

def _run_processor():
    ctx = DetectionContext(cfg)
    while True:
        try:
            pkt = pkt_queue.get(timeout=0.2)
            if not pkt: continue
            pkt["_now"] = time.time()
            models.save_packet(conn, pkt)
            outputs.write_packet(pkt)
            broadcast_queue.put({"type": "packet", "data": {k: pkt[k] for k in ["timestamp","src","dst","protocol","length"]}})
            alerts = detector.analyze(pkt, ctx)
            for alert in alerts:
                alert = enrich_with_mitre(alert, alert.get("mitre", []))
                models.save_alert(conn, alert)
                outputs.write_alert(alert)
                broadcast_queue.put({"type": "alert", "data": alert})
        except Empty:
            time.sleep(0.05)
        except Exception as e:
            print(f"[!] Processor error: {e}")
            time.sleep(1)

def _run_config_watcher():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(config_watcher())

async def _broadcast_loop():
    loop = asyncio.get_running_loop()
    while True:
        msg = await loop.run_in_executor(None, broadcast_queue.get)
        for ws in list(connected_clients):
            try:
                await ws.send_json(msg)
            except:
                connected_clients.discard(ws)
app.add_middleware(CORSMiddleware, allow_origins=cfg.get("server", {}).get("cors_origins", ["*"]), allow_methods=["*"], allow_headers=["*"])

# ----- Rate Limit Middleware -----
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if not check_rate_limit(request.client.host):
        return JSONResponse({"detail": "Rate limit exceeded"}, status_code=429)
    return await call_next(request)

async def config_watcher():
    if not cfg.get("detection", {}).get("hot_reload", True):
        return
    interval = cfg.get("detection", {}).get("reload_interval", 5)
    rules_dir = Path(cfg.get("detection", {}).get("rules_dir", "rules"))
    last_mtime = {}
    while True:
        try:
            for f in rules_dir.glob("*.yaml"):
                mtime = f.stat().st_mtime
                if f not in last_mtime or last_mtime[f] != mtime:
                    last_mtime[f] = mtime
                    print(f"[+] Rule file changed: {f}")
                    detector.reload()
        except Exception as e:
            print(f"[!] Config watcher error: {e}")
        await asyncio.sleep(interval)

# ----- Models -----
class RuleModel(BaseModel):
    name: str
    signature: str
    protocol: str = "any"
    port: str = "any"
    pattern: str
    severity: str
    description: str
    mitre: List[str] = []

class AlertAck(BaseModel):
    acknowledged: bool

# ----- API Routes -----
@app.get("/health")
def health():
    return {"status": "ok", "version": "2.0.0", "uptime": time.time() - start_time}

@app.get("/api/stats")
def api_stats(auth=Depends(verify_auth)):
    return models.get_stats(conn)

@app.get("/api/timeline")
def api_timeline(auth=Depends(verify_auth)):
    return models.get_timeline(conn)

@app.get("/api/alerts")
def api_alerts(limit: int = 50, offset: int = 0, severity: str = None, ack: int = None, auth=Depends(verify_auth)):
    return models.get_alerts(conn, limit, offset, severity, ack)

@app.get("/api/packets")
def api_packets(limit: int = 50, offset: int = 0, protocol: str = None, auth=Depends(verify_auth)):
    return models.get_packets(conn, limit, offset, protocol)

@app.post("/api/alerts/{alert_id}/ack")
def api_ack(alert_id: int, body: AlertAck, auth=Depends(verify_auth)):
    return {"success": models.ack_alert(conn, alert_id, body.acknowledged)}

@app.get("/api/rules")
def api_rules(auth=Depends(verify_auth)):
    return detector.plugins[0].__class__.__name__ if detector.plugins else []

@app.get("/api/plugins")
def api_plugins(auth=Depends(verify_auth)):
    return detector.list_plugins()

@app.get("/api/mitre")
def api_mitre(auth=Depends(verify_auth)):
    return {"techniques": MITRE_TECHNIQUES, "tactics": TACTICS_ORDER}

@app.post("/api/rules")
def api_add_rule(rule: RuleModel, auth=Depends(verify_auth)):
    # Write to rules dir
    import yaml
    rules_dir = Path(cfg.get("detection", {}).get("rules_dir", "rules"))
    rules_dir.mkdir(exist_ok=True)
    rule_file = rules_dir / f"{rule.signature}.yaml"
    with open(rule_file, "w") as f:
        yaml.dump(rule.dict(), f)
    detector.reload()
    return {"status": "created", "file": str(rule_file)}

@app.post("/api/config/reload")
def api_reload_config(auth=Depends(verify_auth)):
    reload_config()
    detector.reload()
    return {"status": "reloaded"}

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    async with clients_lock:
        connected_clients.add(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        async with clients_lock:
            connected_clients.discard(ws)

start_time = time.time()

if __name__ == "__main__":
    uvicorn.run(app, host=cfg.get("server", {}).get("host", "0.0.0.0"), port=cfg.get("server", {}).get("port", 8000))
