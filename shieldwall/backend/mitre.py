MITRE_TECHNIQUES = {
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery", "platforms": ["Linux", "Windows", "macOS"]},
    "T1049": {"name": "System Network Connections Discovery", "tactic": "Discovery"},
    "T1057": {"name": "Process Discovery", "tactic": "Discovery"},
    "T1069": {"name": "Permission Groups Discovery", "tactic": "Discovery"},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery"},
    "T1090": {"name": "Proxy", "tactic": "Command and Control"},
    "T1095": {"name": "Non-Application Layer Protocol", "tactic": "Command and Control"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1203": {"name": "Exploitation for Client Execution", "tactic": "Execution"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    "T1566": {"name": "Phishing", "tactic": "Initial Access"},
    "T1571": {"name": "Non-Standard Port", "tactic": "Command and Control"},
    "T1573": {"name": "Encrypted Channel", "tactic": "Command and Control"},
    "T1590": {"name": "Active Scanning", "tactic": "Reconnaissance"},
    "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control", "sub": {
        "T1071.001": "Web Protocols", "T1071.002": "File Transfer Protocols",
        "T1071.003": "Mail Protocols", "T1071.004": "DNS"
    }},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1041": {"name": "Exfiltration Over Command and Control Channel", "tactic": "Exfiltration"},
    "T1020": {"name": "Automated Exfiltration", "tactic": "Exfiltration"},
    "T1005": {"name": "Data from Local System", "tactic": "Collection"},
    "T1039": {"name": "Data from Network Shared Drive", "tactic": "Collection"},
    "T1080": {"name": "Taint Shared Content", "tactic": "Lateral Movement"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1550": {"name": "Use Alternate Authentication Material", "tactic": "Credential Access"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1555": {"name": "Credentials from Password Stores", "tactic": "Credential Access"},
    "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access"},
    "T1056": {"name": "Input Capture", "tactic": "Credential Access"},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion"},
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion"},
    "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion"},
    "T1497": {"name": "Virtualization/Sandbox Evasion", "tactic": "Defense Evasion"},
}

TACTICS_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact"
]

def enrich_with_mitre(alert: Dict, techniques: List[str]) -> Dict:
    enriched = alert.copy()
    mitre = []
    for tid in techniques:
        tech = MITRE_TECHNIQUES.get(tid)
        if tech:
            mitre.append({"id": tid, "name": tech["name"], "tactic": tech["tactic"]})
    if mitre:
        enriched["mitre"] = mitre
    return enriched

def get_technique(tid: str) -> Dict:
    return MITRE_TECHNIQUES.get(tid, {})

def get_techniques_by_tactic(tactic: str) -> List[Dict]:
    return [{"id": k, **v} for k, v in MITRE_TECHNIQUES.items() if v.get("tactic") == tactic]
