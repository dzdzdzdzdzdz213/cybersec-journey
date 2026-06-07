import sqlite3, json
from datetime import datetime

def init_db(config: dict = None) -> sqlite3.Connection:
    if config is None:
        config = {}
    path = config.get("storage", {}).get("sqlite", {}).get("path", "shieldwall.db")
    check_same = config.get("storage", {}).get("sqlite", {}).get("check_same_thread", False)
    wal = config.get("storage", {}).get("sqlite", {}).get("wal_mode", True)
    conn = sqlite3.connect(path, check_same_thread=check_same)
    if wal:
        conn.execute("PRAGMA journal_mode=WAL")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS packets(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, src TEXT, dst TEXT,
        sport INTEGER, dport INTEGER,
        protocol TEXT, length INTEGER, info TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, signature TEXT, severity TEXT,
        src TEXT, dst TEXT, protocol TEXT,
        description TEXT, acknowledged INTEGER DEFAULT 0,
        mitre TEXT DEFAULT '[]'
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS stats(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, total_packets INTEGER,
        total_bytes INTEGER, unique_srcs INTEGER,
        unique_dsts INTEGER, protocols TEXT
    )""")
    conn.commit()
    return conn

def save_packet(conn, pkt):
    c = conn.cursor()
    c.execute("INSERT INTO packets(timestamp,src,dst,sport,dport,protocol,length,info) VALUES(?,?,?,?,?,?,?,?)",
              (pkt["timestamp"], pkt["src"], pkt["dst"], pkt.get("sport"), pkt.get("dport"),
               pkt["protocol"], pkt["length"], pkt.get("info", "")))
    conn.commit()

def save_alert(conn, alert):
    c = conn.cursor()
    c.execute("""INSERT INTO alerts(timestamp,signature,severity,src,dst,protocol,description,mitre)
                 VALUES(?,?,?,?,?,?,?,?)""",
              (alert["timestamp"], alert["signature"], alert["severity"],
               alert["src"], alert["dst"], alert["protocol"],
               alert["description"], json.dumps(alert.get("mitre", []))))
    conn.commit()
    return c.lastrowid

def get_alerts(conn, limit=100, offset=0, severity=None, ack=None):
    c = conn.cursor()
    q = "SELECT * FROM alerts WHERE 1=1"
    params = []
    if severity:
        q += " AND severity=?"
        params.append(severity)
    if ack is not None:
        q += " AND acknowledged=?"
        params.append(ack)
    q += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    rows = c.execute(q, params).fetchall()
    return [{"id":r[0],"timestamp":r[1],"signature":r[2],"severity":r[3],
             "src":r[4],"dst":r[5],"protocol":r[6],"description":r[7],
             "acknowledged":bool(r[8]), "mitre": json.loads(r[9] or "[]")} for r in rows]

def get_packets(conn, limit=100, offset=0, protocol=None):
    c = conn.cursor()
    q = "SELECT * FROM packets WHERE 1=1"
    params = []
    if protocol:
        q += " AND protocol=?"
        params.append(protocol)
    q += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    rows = c.execute(q, params).fetchall()
    return [{"id":r[0],"timestamp":r[1],"src":r[2],"dst":r[3],
             "sport":r[4],"dport":r[5],"protocol":r[6],
             "length":r[7],"info":r[8]} for r in rows]

def get_stats(conn):
    c = conn.cursor()
    total = c.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
    alerts = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    open_alerts = c.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged=0").fetchone()[0]
    bytes_total = c.execute("SELECT SUM(length) FROM packets").fetchone()[0] or 0
    protocols = c.execute("SELECT protocol, COUNT(*) as c FROM packets GROUP BY protocol ORDER BY c DESC").fetchall()
    return {
        "total_packets": total, "total_alerts": alerts,
        "open_alerts": open_alerts, "total_bytes": bytes_total,
        "protocols": {p: c for p, c in protocols}
    }

def get_timeline(conn, interval="1m"):
    c = conn.cursor()
    rows = c.execute("""SELECT strftime('%Y-%m-%dT%H:%M', timestamp) as t,
                        COUNT(*) as c FROM packets
                        GROUP BY t ORDER BY t DESC LIMIT 60""").fetchall()
    return [{"time": r[0], "count": r[1]} for r in rows]

def ack_alert(conn, alert_id, acknowledged=True):
    c = conn.cursor()
    c.execute("UPDATE alerts SET acknowledged=? WHERE id=?", (1 if acknowledged else 0, alert_id))
    conn.commit()
    return c.rowcount > 0
