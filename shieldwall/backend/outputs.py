import json, socket, logging
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from datetime import datetime
import threading

class OutputSink(ABC):
    name: str = "base"

    @abstractmethod
    def write_alert(self, alert: Dict[str, Any]) -> bool:
        pass

    @abstractmethod
    def write_packet(self, pkt: Dict[str, Any]) -> bool:
        pass

    @abstractmethod
    def flush(self) -> None:
        pass

    @abstractmethod
    def close(self) -> None:
        pass

class SQLiteSink(OutputSink):
    name = "sqlite"

    def __init__(self, config: Dict[str, Any]):
        import sqlite3
        path = config.get("storage", {}).get("sqlite", {}).get("path", "shieldwall.db")
        check_same = config.get("storage", {}).get("sqlite", {}).get("check_same_thread", False)
        self.conn = sqlite3.connect(path, check_same_thread=check_same)
        self._init_tables()

    def _init_tables(self):
        c = self.conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS packets(
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, src TEXT, dst TEXT,
            sport INTEGER, dport INTEGER, protocol TEXT, length INTEGER, info TEXT
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, signature TEXT,
            severity TEXT, src TEXT, dst TEXT, protocol TEXT, description TEXT,
            acknowledged INTEGER DEFAULT 0, mitre TEXT
        )""")
        self.conn.commit()

    def write_alert(self, alert: Dict) -> bool:
        c = self.conn.cursor()
        c.execute("""INSERT INTO alerts(timestamp,signature,severity,src,dst,protocol,description,mitre)
                     VALUES(?,?,?,?,?,?,?,?)""",
                  (alert["timestamp"], alert["signature"], alert["severity"],
                   alert["src"], alert["dst"], alert["protocol"],
                   alert["description"], json.dumps(alert.get("mitre", []))))
        self.conn.commit()
        return True

    def write_packet(self, pkt: Dict) -> bool:
        c = self.conn.cursor()
        c.execute("""INSERT INTO packets(timestamp,src,dst,sport,dport,protocol,length,info)
                     VALUES(?,?,?,?,?,?,?,?)""",
                  (pkt["timestamp"], pkt["src"], pkt["dst"], pkt.get("sport"), pkt.get("dport"),
                   pkt["protocol"], pkt["length"], pkt.get("info", "")))
        self.conn.commit()
        return True

    def flush(self): pass
    def close(self): self.conn.close()

class ElasticsearchSink(OutputSink):
    name = "elasticsearch"

    def __init__(self, config: Dict[str, Any]):
        es_cfg = self._get_output_config(config, "elasticsearch")
        self.enabled = es_cfg.get("enabled", False)
        if not self.enabled:
            return
        from elasticsearch import Elasticsearch
        hosts = es_cfg.get("hosts", ["http://localhost:9200"])
        self.es = Elasticsearch(hosts, basic_auth=(es_cfg.get("username"), es_cfg.get("password")) if es_cfg.get("username") else None)
        self.index_prefix = es_cfg.get("index_prefix", "shieldwall")
        self.buffer = []
        self.bulk_size = es_cfg.get("bulk_size", 500)
        self._lock = threading.Lock()

    def _get_output_config(self, config: Dict, name: str) -> Dict:
        outputs = config.get("outputs", [])
        if isinstance(outputs, dict):
            return outputs.get(name, {})
        for out in outputs:
            if out.get("type") == name:
                return out
        return {}

    def _index_name(self, doctype: str) -> str:
        return f"{self.index_prefix}-{doctype}-{datetime.utcnow().strftime('%Y.%m.%d')}"

    def write_alert(self, alert: Dict) -> bool:
        if not self.enabled: return True
        with self._lock:
            self.buffer.append({"index": {"_index": self._index_name("alerts")}})
            self.buffer.append(alert)
            if len(self.buffer) >= self.bulk_size * 2:
                self._flush_buffer()
        return True

    def write_packet(self, pkt: Dict) -> bool:
        return True

    def _flush_buffer(self):
        if not self.buffer: return
        try:
            self.es.bulk(operations=self.buffer)
            self.buffer.clear()
        except Exception as e:
            print(f"[!] ES bulk error: {e}")

    def flush(self):
        self._flush_buffer()

    def close(self):
        self.flush()
        if self.enabled:
            self.es.close()

class SyslogSink(OutputSink):
    name = "syslog"

    def __init__(self, config: Dict[str, Any]):
        cfg = self._get_output_config(config, "syslog")
        self.enabled = cfg.get("enabled", False)
        if not self.enabled: return
        self.host = cfg.get("host", "localhost")
        self.port = cfg.get("port", 514)
        self.protocol = cfg.get("protocol", "udp")
        self.format = cfg.get("format", "rfc5424")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if self.protocol == "udp" else socket.SOCK_STREAM)
        if self.protocol == "tcp":
            self.sock.connect((self.host, self.port))

    def _get_output_config(self, config: Dict, name: str) -> Dict:
        outputs = config.get("outputs", [])
        if isinstance(outputs, dict):
            return outputs.get(name, {})
        for out in outputs:
            if out.get("type") == name:
                return out
        return {}

    def _format_msg(self, alert: Dict) -> bytes:
        if self.format == "json":
            return json.dumps(alert).encode() + b"\n"
        # RFC5424 simplified
        ts = alert.get("timestamp", datetime.utcnow().isoformat())
        return f"<14>1 {ts} shieldwall - - - {json.dumps(alert)}\n".encode()

    def write_alert(self, alert: Dict) -> bool:
        if not self.enabled: return True
        try:
            self.sock.sendto(self._format_msg(alert), (self.host, self.port))
        except Exception as e:
            print(f"[!] Syslog error: {e}")
        return True

    def write_packet(self, pkt: Dict) -> bool: return True
    def flush(self): pass
    def close(self): self.sock.close()

class WebhookSink(OutputSink):
    name = "webhook"

    def __init__(self, config: Dict[str, Any]):
        cfg = self._get_output_config(config, "webhook")
        self.enabled = cfg.get("enabled", False)
        if not self.enabled: return
        import requests
        self.url = cfg.get("url")
        self.method = cfg.get("method", "POST")
        self.headers = cfg.get("headers", {})
        self.timeout = cfg.get("timeout", 5)
        self.retry = cfg.get("retry", 3)
        self.session = requests.Session()

    def _get_output_config(self, config: Dict, name: str) -> Dict:
        outputs = config.get("outputs", [])
        if isinstance(outputs, dict):
            return outputs.get(name, {})
        for out in outputs:
            if out.get("type") == name:
                return out
        return {}

    def write_alert(self, alert: Dict) -> bool:
        if not self.enabled: return True
        for i in range(self.retry):
            try:
                self.session.request(self.method, self.url, json=alert, headers=self.headers, timeout=self.timeout)
                return True
            except Exception as e:
                if i == self.retry - 1:
                    print(f"[!] Webhook failed: {e}")
        return False

    def write_packet(self, pkt: Dict) -> bool: return True
    def flush(self): pass
    def close(self): self.session.close()

class OutputManager:
    def __init__(self, config: Dict[str, Any]):
        self.sinks: List[OutputSink] = []
        self._load_sinks(config)

    def _load_sinks(self, config: Dict[str, Any]):
        self.sinks.append(SQLiteSink(config))
        self.sinks.append(ElasticsearchSink(config))
        self.sinks.append(SyslogSink(config))
        self.sinks.append(WebhookSink(config))

    def write_alert(self, alert: Dict):
        for sink in self.sinks:
            try:
                sink.write_alert(alert)
            except Exception as e:
                print(f"[!] Sink {sink.name} error: {e}")

    def write_packet(self, pkt: Dict):
        for sink in self.sinks:
            try:
                sink.write_packet(pkt)
            except Exception as e:
                print(f"[!] Sink {sink.name} error: {e}")

    def flush(self):
        for sink in self.sinks:
            try:
                sink.flush()
            except Exception as e:
                print(f"[!] Sink {sink.name} flush error: {e}")

    def close(self):
        for sink in self.sinks:
            try:
                sink.close()
            except Exception as e:
                print(f"[!] Sink {sink.name} close error: {e}")
