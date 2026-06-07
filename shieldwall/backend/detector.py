import yaml, os
from datetime import datetime
from collections import defaultdict

RULES_FILE = os.path.join(os.path.dirname(__file__), "rules", "signatures.yaml")

class Detector:
    def __init__(self):
        self.rules = []
        self.load_rules()
        self.connections = defaultdict(list)
        self.packet_counts = defaultdict(int)
        self.byte_counts = defaultdict(int)
        self.window_start = datetime.now()

    def load_rules(self):
        if os.path.exists(RULES_FILE):
            with open(RULES_FILE) as f:
                data = yaml.safe_load(f)
                self.rules = data or []
        else:
            self.rules = []

    def analyze(self, pkt):
        alerts = []
        now = datetime.now()
        if (now - self.window_start).seconds > 60:
            self.packet_counts.clear()
            self.byte_counts.clear()
            self.connections.clear()
            self.window_start = now

        src = pkt.get("src", "")
        dst = pkt.get("dst", "")
        proto = pkt.get("protocol", "")
        port = pkt.get("dport", 0)
        length = pkt.get("length", 0)

        key = f"{src}>{dst}"
        self.packet_counts[key] += 1
        self.byte_counts[key] += length
        self.connections[key].append(now)

        for rule in self.rules:
            if not self._match_rule(rule, pkt):
                continue
            alerts.append({
                "timestamp": pkt["timestamp"],
                "signature": rule["signature"],
                "severity": rule["severity"],
                "src": src,
                "dst": dst,
                "protocol": proto,
                "description": rule["description"]
            })
        return alerts

    def _match_rule(self, rule, pkt):
        proto = pkt.get("protocol", "")
        port = pkt.get("dport", 0)
        length = pkt.get("length", 0)
        info = pkt.get("info", "")

        if rule.get("protocol") != "any" and rule.get("protocol") != proto:
            return False
        if rule.get("port") != "any":
            try:
                if int(rule["port"]) != port:
                    return False
            except ValueError:
                pass

        pattern = rule.get("pattern", "")
        if "length >" in pattern:
            val = int(pattern.split(">")[1].strip().split()[0])
            if length <= val:
                return False
        if "count >" in pattern:
            parts = pattern.split("count >")[1].strip().split(" in ")
            threshold = int(parts[0])
            window = int(parts[1].replace("s", ""))
            key = f"{pkt.get('src','')}>{pkt.get('dst','')}"
            recent = [t for t in self.connections[key]
                      if (datetime.now() - t).seconds < window]
            if len(recent) < threshold:
                return False
        if "payload contains" in pattern:
            terms = pattern.split("payload contains")[1].strip()
            if "'" in terms:
                terms = [t.strip().strip("'") for t in terms.split("'") if t.strip()]
                if not any(t.lower() in info.lower() for t in terms):
                    return False
        if "bytes >" in pattern:
            parts = pattern.split("bytes >")[1].strip().split(" in ")
            threshold = int(parts[0])
            window = int(parts[1].replace("s", ""))
            key = f"{pkt.get('src','')}>{pkt.get('dst','')}"
            recent_bytes = sum(b for k, b in self.byte_counts.items()
                              if k == key)
            if recent_bytes < threshold:
                return False
        if "flags == SYN" in pattern:
            if "SYN" not in info:
                return False
        return True
