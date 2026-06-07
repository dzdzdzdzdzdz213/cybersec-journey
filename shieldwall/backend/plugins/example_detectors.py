from plugins import DetectorPlugin, DetectionContext
from typing import Dict, List, Any

class PortScanDetector(DetectorPlugin):
    name = "port_scan"
    version = "1.0.0"
    description = "Detects port scanning via SYN packet frequency analysis"
    author = "ShieldWall"

    def __init__(self):
        self.threshold = 20
        self.window = 10

    def on_load(self, config: Dict[str, Any]) -> None:
        det = config.get("detection", {})
        self.threshold = det.get("port_scan_threshold", self.threshold)
        self.window = det.get("port_scan_window", self.window)

    def analyze(self, pkt: Dict[str, Any], ctx: DetectionContext) -> List[Dict[str, Any]]:
        if pkt.get("protocol") != "TCP" or "SYN" not in pkt.get("info", ""):
            return []

        key = f"{pkt.get('src')}->syn"
        now = ctx.config.get("_now", 0)

        if key not in ctx.connection_tracker:
            ctx.connection_tracker[key] = []

        ctx.connection_tracker[key].append(now)
        ctx.connection_tracker[key] = [t for t in ctx.connection_tracker[key] if now - t < self.window]

        if len(ctx.connection_tracker[key]) >= self.threshold:
            return [{
                "signature": "port_scan",
                "severity": "high",
                "src": pkt["src"],
                "dst": pkt["dst"],
                "protocol": pkt["protocol"],
                "description": f"Port scan from {pkt['src']} ({len(ctx.connection_tracker[key])} SYNs in {self.window}s)",
                "mitre": ["T1590", "T1595"]
            }]
        return []

class DNSTunnelDetector(DetectorPlugin):
    name = "dns_tunnel"
    version = "1.0.0"
    description = "Detects DNS tunneling via query length and entropy"
    author = "ShieldWall"

    def __init__(self):
        self.max_len = 200
        self.entropy_threshold = 3.5

    def analyze(self, pkt: Dict[str, Any], ctx: DetectionContext) -> List[Dict[str, Any]]:
        if pkt.get("protocol") != "UDP" or pkt.get("dport") != 53:
            return []

        length = pkt.get("length", 0)
        if length > self.max_len:
            return [{
                "signature": "dns_tunnel",
                "severity": "high",
                "src": pkt["src"],
                "dst": pkt["dst"],
                "protocol": pkt["protocol"],
                "description": f"Oversized DNS query ({length} bytes) from {pkt['src']} — possible tunneling",
                "mitre": ["T1071.004"]
            }]
        return []

class HTTPAttackDetector(DetectorPlugin):
    name = "http_attacks"
    version = "1.0.0"
    description = "Detects SQLi, XSS, and path traversal in HTTP traffic"
    author = "ShieldWall"

    SQLI_PATTERNS = ["union select", "or 1=1", "drop table", "insert into", "delete from", "' or '"]
    XSS_PATTERNS = ["<script", "onerror=", "onload=", "javascript:", "alert("]
    TRAVERSAL_PATTERNS = ["../", "..\\", "/etc/passwd", "c:\\windows"]

    def analyze(self, pkt: Dict[str, Any], ctx: DetectionContext) -> List[Dict[str, Any]]:
        if pkt.get("protocol") != "TCP" or pkt.get("dport") not in (80, 8080, 443):
            return []

        payload = pkt.get("info", "").lower()
        alerts = []

        for pat in self.SQLI_PATTERNS:
            if pat in payload:
                alerts.append({
                    "signature": "http_sqli",
                    "severity": "critical",
                    "src": pkt["src"],
                    "dst": pkt["dst"],
                    "protocol": pkt["protocol"],
                    "description": f"SQL injection attempt from {pkt['src']}: {pat}",
                    "mitre": ["T1190"]
                })
                break

        for pat in self.XSS_PATTERNS:
            if pat in payload:
                alerts.append({
                    "signature": "http_xss",
                    "severity": "high",
                    "src": pkt["src"],
                    "dst": pkt["dst"],
                    "protocol": pkt["protocol"],
                    "description": f"XSS attempt from {pkt['src']}: {pat}",
                    "mitre": ["T1190"]
                })
                break

        for pat in self.TRAVERSAL_PATTERNS:
            if pat in payload:
                alerts.append({
                    "signature": "path_traversal",
                    "severity": "high",
                    "src": pkt["src"],
                    "dst": pkt["dst"],
                    "protocol": pkt["protocol"],
                    "description": f"Path traversal from {pkt['src']}: {pat}",
                    "mitre": ["T1190"]
                })
                break

        return alerts
