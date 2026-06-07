# 🛡️ Cybersec Journey

**50 cybersecurity projects** built across Python, PowerShell, Assembly, and HTML — covering cryptography, network security, forensics, red teaming, OSINT, malware analysis, and more.

---

## 📁 Project Index

### 🔐 Cryptography & Hashing
| # | Project | Language | Description |
|---|---------|----------|-------------|
| 1 | [cipher-vault](cipher-vault) | Python | Image steganography with AES-256 encryption |
| 2 | [hash-chain](hash-chain) | Python | Blockchain-style tamper-evident hash logging |
| 3 | [quantum-resistance](quantum-resistance) | Python | Post-quantum cryptography with lattice algorithms |
| 4 | [zero-knowledge-demo](zero-knowledge-demo) | Python | Zero-knowledge proof of identity |
| 5 | [polyalphabetic-cracker](polyalphabetic-cracker) | Python | Frequency analysis cipher cracking |

### 🌐 Network Security
| # | Project | Language | Description |
|---|---------|----------|-------------|
| 6 | [packet-sculptor](packet-sculptor) | Python | Raw TCP/UDP/ICMP packet crafting |
| 7 | [sniffle](sniffle) | Python | Packet sniffer with protocol filtering |
| 8 | [dns-tunnel](dns-tunnel) | Python | DNS tunneling for covert data exfiltration |
| 9 | [port-knock](port-knock) | Python | Port knocking authentication daemon |
| 10 | [honeypot-lite](honeypot-lite) | Python | Minimal TCP port honeypot |
| 11 | [cors-explorer](cors-explorer) | Python | CORS misconfiguration scanner |
| 12 | [network-timeline](network-timeline) | Python | PCAP traffic timeline analysis |

### 💻 Web Security
| # | Project | Language | Description |
|---|---------|----------|-------------|
| 13 | [xss-mirror](xss-mirror) | HTML | XSS payload testing sandbox |
| 14 | [sql-maze](sql-maze) | Python | SQL injection exploitation toolkit |
| 15 | [csrf-forge](csrf-forge) | HTML | CSRF PoC generator |
| 16 | [jwt-inspector](jwt-inspector) | Python | JWT decode & signature analysis |
| 17 | [phish-cast](phish-cast) | Python | Phishing simulation server |

### 🕵️ OSINT & Recon
| # | Project | Language | Description |
|---|---------|----------|-------------|
| 18 | [domain-fingerprint](domain-fingerprint) | Python | DNS & SSL fingerprinting |
| 19 | [subdomain-storm](subdomain-storm) | Python | Brute-force subdomain discovery |
| 20 | [email-trail](email-trail) | Python | Email header spoofing analysis |
| 21 | [social-mapper](social-mapper) | Python | Username correlation across platforms |
| 22 | [whois-oracle](whois-oracle) | Python | Historical WHOIS intelligence |

### 🔍 Forensics
| # | Project | Language | Description |
|---|---------|----------|-------------|
| 23 | [disk-whisper](disk-whisper) | Python | Raw disk forensics & partition carving |
| 24 | [file-carver](file-carver) | Python | Magic byte file carving |
| 25 | [memory-ghost](memory-ghost) | Python | Memory dump artifact extraction |
| 26 | [registry-time](registry-time) | PowerShell | Registry hive forensic timeline |
| 27 | [timeline-forge](timeline-forge) | Python | Super-timeline generation |
| 28 | [meta-extract](meta-extract) | Python | EXIF & document metadata extraction |

### 🦠 Malware Analysis
| # | Project | Language | Description |
|---|---------|----------|-------------|
| 29 | [binary-diff](binary-diff) | Python | Binary diffing for patch analysis |
| 30 | [yara-hunter](yara-hunter) | Python | YARA rule-based malware scanning |
| 31 | [behavioral-graph](behavioral-graph) | Python | MITRE ATT&CK behavioral mapping |
| 32 | [shellcode-analyzer](shellcode-analyzer) | Python | Shellcode disassembly & API resolution |
| 33 | [string-warden](string-warden) | Python | Binary string extraction & classification |
| 34 | [entropy-scanner](entropy-scanner) | Python | Entropy-based packed malware detection |
| 35 | [sandbox-dodge](sandbox-dodge) | Python | VM/debugger/sandbox detection |
| 36 | [asm-golf](asm-golf) | Assembly | Minimal shellcode (Windows + Linux) |

### 👺 Red Team
| # | Project | Language | Description |
|---|---------|----------|-------------|
| 37 | [c2-lite](c2-lite) | Python | Lightweight C2 server/client |
| 38 | [payload-factory](payload-factory) | Python | Multi-format staged payload generator |
| 39 | [lateral-move](lateral-move) | PowerShell | WinRM/WMI/PsExec lateral movement |
| 40 | [pivot-track](pivot-track) | Python | Network pivot path mapping |
| 41 | [token-stealer](token-stealer) | Python | Windows access token analysis |
| 42 | [mac-chameleon](mac-chameleon) | PowerShell | MAC address spoofing |

### 🔧 System Security
| # | Project | Language | Description |
|---|---------|----------|-------------|
| 43 | [env-scout](env-scout) | PowerShell | Environment variable secret scanner |
| 44 | [config-hardener](config-hardener) | PowerShell | Windows security configuration hardening |
| 45 | [api-monitor](api-monitor) | Python | Windows API call tracking |
| 46 | [vuln-patch](vuln-patch) | Python | Windows patch auditing via WMI |
| 47 | [log-weaver](log-weaver) | Python | Multi-source log correlation |
| 48 | [cookie-monster](cookie-monster) | Python | Browser cookie parsing & auditing |
| 49 | [password-oracle](password-oracle) | Python | Password strength estimation |
| 50 | [key-cadet](key-cadet) | Python | Keystroke dynamics biometrics |

---

## 🏗️ ShieldWall — Network Security Monitor

The flagship project in this repository. A full network monitoring platform with:
- **Packet capture** engine (Scapy/pcap-based)
- **Signature-based IDS** with custom rules
- **Real-time traffic analysis** and visualization
- **Alert management** with severity scoring
- **React dashboard** with live metrics

[See ShieldWall docs →](shieldwall/README.md)

---

## 🚀 Quick Start

Each project folder has its own README with run instructions. Most Python projects run with:
```bash
cd <project>
python <script>.py [args]
```

PowerShell projects:
```powershell
.\<script>.ps1 -Flag Value
```

---

## 📊 Stats

- **50 projects** across 5 languages
- **20+ cybersecurity domains** covered
- **~15,000+ lines** of security tooling

---

*Built with curiosity. For learning and education.*
