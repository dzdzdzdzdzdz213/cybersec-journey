import socket, struct, time, random
from datetime import datetime
from typing import Optional, Callable

class PacketCapture:
    def __init__(self, config: dict):
        self.config = config
        cap_cfg = config.get("capture", {})
        self.interface = cap_cfg.get("interface")
        self.bpf_filter = cap_cfg.get("bpf_filter", "")
        self.promiscuous = cap_cfg.get("promiscuous", True)
        self.snaplen = cap_cfg.get("snaplen", 65535)
        self.buffer_size = cap_cfg.get("buffer_size", 16777216)
        self.use_npcap = cap_cfg.get("use_npcap", True)
        self.mock_mode = cap_cfg.get("mock_mode", False)
        self.mock_rate = cap_cfg.get("mock_rate", 10)
        self.running = False
        self.callback = None

    def start(self, callback: Callable):
        self.running = True
        self.callback = callback
        if self.mock_mode:
            self._generate_mock()
        else:
            self._capture()

    def stop(self):
        self.running = False

    def _capture(self):
        try:
            if self.use_npcap:
                self._capture_npcap()
            else:
                self._capture_raw()
        except Exception as e:
            print(f"[!] Capture failed: {e}. Falling back to mock.")
            self._generate_mock()

    def _capture_raw(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            if self.interface:
                s.bind((self.interface, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            if hasattr(socket, 'SIO_RCVALL') and self.promiscuous:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.buffer_size)
            s.settimeout(1.0)

            while self.running:
                try:
                    raw = s.recvfrom(self.snaplen)[0]
                    pkt = self._parse(raw)
                    if pkt and self.callback:
                        self.callback(pkt)
                except socket.timeout:
                    continue
                except Exception:
                    continue
            s.close()
        except Exception as e:
            print(f"[!] Raw socket failed: {e}")
            self._capture_pcap()

    def _capture_npcap(self):
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
            if self.use_npcap:
                conf.use_pcap = True
            filter_str = self.bpf_filter if self.bpf_filter else None
            sniff(iface=self.interface, prn=lambda p: self.callback(self._scapy_parse(p)),
                  filter=filter_str, store=False, promisc=self.promiscuous)
        except Exception as e:
            print(f"[!] Npcap/Scapy capture failed ({e}). Using mock data.")
            self._generate_mock()

    def _capture_pcap(self):
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP
            filter_str = self.bpf_filter if self.bpf_filter else None
            sniff(prn=lambda p: self.callback(self._scapy_parse(p)),
                  filter=filter_str, store=False, timeout=None)
        except Exception as e:
            print(f"[!] Packet capture failed ({e}). Using mock data.")
            self._generate_mock()

    def _generate_mock(self):
        protocols = ["TCP", "UDP", "ICMP"]
        sleep_time = 1.0 / max(self.mock_rate, 1)
        while self.running:
            pkt = {
                "timestamp": datetime.now().isoformat(),
                "src": f"192.168.1.{random.randint(1,254)}",
                "dst": f"10.0.0.{random.randint(1,254)}",
                "sport": random.randint(1024, 65535),
                "dport": random.choice([80, 443, 22, 53, 8080]),
                "protocol": random.choice(protocols),
                "length": random.randint(40, 1500),
                "info": random.choice(["SYN", "ACK", "GET / HTTP/1.1", ""])
            }
            if self.callback:
                self.callback(pkt)
            time.sleep(sleep_time)

    def _scapy_parse(self, pkt):
        try:
            if IP not in pkt:
                return None
            ts = datetime.fromtimestamp(float(pkt.time)).isoformat()
            result = {"timestamp": ts, "src": pkt[IP].src, "dst": pkt[IP].dst,
                      "length": len(pkt), "sport": 0, "dport": 0, "protocol": "OTHER", "info": ""}
            if TCP in pkt:
                result["protocol"] = "TCP"
                result["sport"] = pkt[TCP].sport
                result["dport"] = pkt[TCP].dport
                result["info"] = str(pkt[TCP].flags) if hasattr(pkt[TCP], 'flags') else ""
            elif UDP in pkt:
                result["protocol"] = "UDP"
                result["sport"] = pkt[UDP].sport
                result["dport"] = pkt[UDP].dport
            elif ICMP in pkt:
                result["protocol"] = "ICMP"
            return result
        except Exception:
            return None

    def _parse(self, raw):
        try:
            ver_ihl = raw[0]
            ihl = (ver_ihl & 0x0F) * 4
            header = struct.unpack("!BBHHHBBH4s4s", raw[:20])
            src = socket.inet_ntoa(header[8])
            dst = socket.inet_ntoa(header[9])
            proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
            proto = proto_map.get(header[6], "OTHER")
            length = header[2]
            info = ""
            sport, dport = 0, 0
            if proto == "TCP" and len(raw) > ihl + 2:
                sport, dport = struct.unpack("!HH", raw[ihl:ihl+4])
            elif proto == "UDP" and len(raw) > ihl + 2:
                sport, dport = struct.unpack("!HH", raw[ihl:ihl+4])
            return {
                "timestamp": datetime.now().isoformat(),
                "src": src, "dst": dst,
                "sport": sport, "dport": dport,
                "protocol": proto, "length": length, "info": info
            }
        except Exception:
            return None
