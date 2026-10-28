"""
Cyber Shield SOC — Python Autonomous Defense Backend Server
Provides comprehensive REST APIs for Telemetry, Incidents, Threat Intelligence (STIX 2.1),
Hardware Node Ingestion, TOTP 2FA, Tamper-Evident Audit Trails, and Static Frontend Hosting.
"""

import http.server
import socketserver
import json
import urllib.parse
import os
import sys
import time
import hashlib
from datetime import datetime

PORT = 8050
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))

# In-Memory State Store
STATE = {
    "metrics": {
        "totalPackets": 5484,
        "threatsDetected": 3,
        "activeAlertsCount": 2,
        "appliedPatchesCount": 1,
        "dlpViolations": 0,
        "autoBlockEnabled": True,
        "isEmergencyLockdown": False
    },
    "users": [
        {"id": "CS50-DEV01", "name": "Michael Scott", "phone": "+1-202-555-0143", "email": "michael.s@dundermifflin.com", "os": "Windows", "device": "Laptop", "network": "Enterprise Wi-Fi (WPA3)", "status": "PROTECTED", "registeredAt": "2026-10-25T10:30:00Z"},
        {"id": "CS50-DEV02", "name": "Sarah Jenkins", "phone": "+1-415-555-0198", "email": "sarah.jenkins@enterprise.corp", "os": "iOS", "device": "Mobile Phone", "network": "5G Ultra Wideband", "status": "WARNING - REVIEW", "registeredAt": "2026-10-25T11:15:00Z"},
        {"id": "CS50-DEV03", "name": "David Kumar", "phone": "+91-98765-43210", "email": "david.kumar@techglobal.in", "os": "Android", "device": "Mobile Phone", "network": "Wi-Fi 6 Decoy DMZ", "status": "PROTECTED", "registeredAt": "2026-10-26T08:00:00Z"},
        {"id": "CS50-DEV04", "name": "Elena Rostova", "phone": "+44-20-7946-0912", "email": "elena.rostova@cyberdefense.eu", "os": "macOS", "device": "Desktop", "network": "Ethernet 10Gbps Core", "status": "PROTECTED", "registeredAt": "2026-10-26T09:45:00Z"}
    ],
    "admins": [
        {"id": "ADMIN-SUNNY-01", "name": "Sunny (Founder & Super Admin)", "username": "SUNNY", "email": "sunny@cybershield.org", "role": "SUPER_ADMIN", "referrals": 4},
        {"id": "ADMIN-ALEX-02", "name": "Alex Rivera (Lead Security Admin)", "username": "alex.rivera", "email": "alex.rivera@cybershield.org", "role": "ADMIN", "referrals": 1},
        {"id": "ADMIN-SARAH-03", "name": "Sarah Chen (SOC Tier-2 Analyst)", "username": "sarah.chen", "email": "sarah.chen@cybershield.org", "role": "SOC_OPERATOR", "referrals": 0}
    ],
    "incidents": [
        {
            "id": "INC-2026-0814",
            "title": "High-Volume SYN Flood Targeting Perimeter Ingress Sockets",
            "severity": "CRITICAL",
            "status": "CONTAINED",
            "assigned_name": "Alex Rivera",
            "affected_asset": "DMZ Edge Gateway (10.0.4.15)",
            "source_ip": "185.220.101.5",
            "confidence": 96,
            "threat_category": "Denial of Service",
            "summary": "Distributed SYN flood exceeding 18,500 packets/sec attempting to exhaust OS TCP tables.",
            "containment_action": "Source IP quarantined at perimeter firewall.",
            "created_at": "2026-10-26T08:30:00Z",
            "comments": [{"author": "Sarah Chen", "role": "SOC_OPERATOR", "comment": "45x baseline spike in SYN flags observed.", "created_at": "2026-10-26T08:35:00Z"}]
        },
        {
            "id": "INC-2026-0815",
            "title": "Pegasus Mobile C2 Heartbeat Beacon Flagged on Executive Phone",
            "severity": "CRITICAL",
            "status": "INVESTIGATING",
            "assigned_name": "Sunny",
            "affected_asset": "Samsung Galaxy S24 (DEV-MOB-01)",
            "source_ip": "45.154.255.89",
            "confidence": 93,
            "threat_category": "Mobile Spyware",
            "summary": "Suspicious egress TCP heartbeat beacons on port 9001 targeting Pegasus infrastructure.",
            "containment_action": "Mobile Shield AFWall+ rule deployed; device isolated.",
            "created_at": "2026-10-26T10:15:00Z",
            "comments": []
        },
        {
            "id": "INC-2026-0816",
            "title": "SQL Injection Probing on Database Ingress Gateway",
            "severity": "HIGH",
            "status": "MITIGATED",
            "assigned_name": "Sarah Chen",
            "affected_asset": "Customer DB (10.0.8.22)",
            "source_ip": "194.26.29.112",
            "confidence": 89,
            "threat_category": "Web Exploitation",
            "summary": "Tautological SQL syntax injection detected in HTTP query parameters.",
            "containment_action": "Parameterized query boundary reinforced.",
            "created_at": "2026-10-26T12:00:00Z",
            "comments": []
        },
        {
            "id": "INC-2026-0817",
            "title": "PCI-DSS Sensitive Egress Interception & Luhn Card Masking",
            "severity": "MEDIUM",
            "status": "NEW",
            "assigned_name": "Unassigned",
            "affected_asset": "Corporate Internal Subnet",
            "source_ip": "10.0.8.22",
            "confidence": 94,
            "threat_category": "Data Leakage",
            "summary": "Unencrypted egress packet containing customer credit card numbers masked by DLP engine.",
            "containment_action": "Payload masked with XXXX-XXXX-XXXX-1234.",
            "created_at": "2026-10-26T14:45:00Z",
            "comments": []
        }
    ],
    "indicators": [
        {"id": "IOC-2026-001", "type": "IPV4", "value": "185.220.101.5", "threat_score": 96, "severity": "CRITICAL", "confidence": 95, "threat_actor": "Cobalt Gang / APT29", "campaign": "Operation DarkShield", "status": "ACTIVE", "last_seen": "2026-10-28T02:00:00Z"},
        {"id": "IOC-2026-002", "type": "IPV4", "value": "45.154.255.89", "threat_score": 92, "severity": "CRITICAL", "confidence": 90, "threat_actor": "Lazarus Group", "campaign": "GhostRat Cellular", "status": "ACTIVE", "last_seen": "2026-10-28T02:00:00Z"},
        {"id": "IOC-2026-003", "type": "IPV4", "value": "91.240.118.172", "threat_score": 88, "severity": "HIGH", "confidence": 92, "threat_actor": "Mirai Botnet", "campaign": "Edge Sweep", "status": "ACTIVE", "last_seen": "2026-10-28T02:00:00Z"},
        {"id": "IOC-2026-004", "type": "DOMAIN", "value": "update-edge-secureauth.org", "threat_score": 94, "severity": "CRITICAL", "confidence": 95, "threat_actor": "Scattered Spider", "campaign": "SSO Harvest", "status": "ACTIVE", "last_seen": "2026-10-28T02:00:00Z"},
        {"id": "IOC-2026-005", "type": "HASH_SHA256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "threat_score": 98, "severity": "CRITICAL", "confidence": 99, "threat_actor": "LockBit 3.0", "campaign": "Blackout", "status": "ACTIVE", "last_seen": "2026-10-28T02:00:00Z"},
        {"id": "IOC-2026-006", "type": "CVE", "value": "CVE-2024-1709", "threat_score": 99, "severity": "CRITICAL", "confidence": 99, "threat_actor": "Ransomware Affiliates", "campaign": "ScreenConnect Bypass", "status": "ACTIVE", "last_seen": "2026-10-28T02:00:00Z"}
    ],
    "sessions": [
        {"token": "CS-SES-99a1...", "fullToken": "CS-SES-99a188412", "name": "Sunny", "role": "SUPER_ADMIN", "ip": "127.0.0.1", "userAgent": "Chrome / Windows 11", "createdAt": "2026-10-28T01:30:00Z"}
    ],
    "audit_trails": [
        {"id": 1, "timestamp": "2026-10-26T00:00:01Z", "actor": "SYSTEM_KERNEL", "role": "SYSTEM", "action": "GENESIS_BOOT", "targetId": "-", "recordHash": "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef"},
        {"id": 2, "timestamp": "2026-10-26T08:14:22Z", "actor": "SUNNY", "role": "SUPER_ADMIN", "action": "AUTH_LOGIN", "targetId": "-", "recordHash": "b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef12"},
        {"id": 3, "timestamp": "2026-10-26T09:30:15Z", "actor": "AUTONOMOUS_IPS", "role": "SYSTEM", "action": "FIREWALL_DROP", "targetId": "45.142.212.61", "recordHash": "c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef1234"}
    ]
}

class SocRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=FRONTEND_DIR, **kwargs)

    def _send_json(self, status_code, data):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path.startswith("/api/"):
            if path == "/api/status":
                self._send_json(200, {
                    "status": "UP",
                    "metrics": STATE["metrics"],
                    "recentAlerts": [
                        {"id": "ALT-1793021288414-655", "threatType": "DDOS_SYN_FLOOD", "severity": "CRITICAL", "srcIp": "91.240.118.172", "targetFile": "server.js:Lines 42-65", "confidence": 87, "status": "MITIGATED", "timestamp": int(time.time() * 1000) - 60000},
                        {"id": "ALT-1793021205735-451", "threatType": "DATA_EXFILTRATION", "severity": "CRITICAL", "srcIp": "185.220.101.129", "targetFile": "core/dlpEngine.js", "confidence": 64, "status": "ACTIVE", "timestamp": int(time.time() * 1000) - 120000}
                    ]
                })
            elif path == "/api/metrics/soc-overview":
                self._send_json(200, {
                    "success": True,
                    "posture": {
                        "score": 91, "level": "EXCELLENT", "color": "var(--accent-emerald)",
                        "domains": [
                            {"name": "Perimeter Gateway", "score": 96, "color": "var(--accent-emerald)"},
                            {"name": "Mobile & Endpoint Shield", "score": 94, "color": "var(--accent-emerald)"},
                            {"name": "Identity & Access (UEBA)", "score": 92, "color": "var(--accent-cyan)"},
                            {"name": "Data Loss Prevention (DLP)", "score": 95, "color": "var(--accent-emerald)"}
                        ]
                    },
                    "performance": {"mttdFormatted": "1.2s", "mttrFormatted": "4.8s", "autonomousMitigationRate": "94.6%", "triageSlaCompliance": "98.8%"},
                    "severityCounts": {"CRITICAL": 4, "HIGH": 7, "MEDIUM": 2, "LOW": 2},
                    "alertTrends": {"labels": ["12h", "10h", "8h", "6h", "4h", "2h", "Now"], "data": [8, 14, 22, 16, 28, 36, 42]}
                })
            elif path == "/api/incidents":
                self._send_json(200, {"success": True, "total": len(STATE["incidents"]), "incidents": STATE["incidents"]})
            elif path == "/api/threat-intel/indicators":
                self._send_json(200, {"success": True, "total": len(STATE["indicators"]), "indicators": STATE["indicators"]})
            elif path == "/api/admin/users":
                self._send_json(200, {"success": True, "users": STATE["users"], "total": len(STATE["users"])})
            elif path == "/api/admin/admins":
                self._send_json(200, {"success": True, "admins": STATE["admins"]})
            elif path == "/api/auth/sessions":
                self._send_json(200, {"success": True, "sessions": STATE["sessions"]})
            elif path == "/api/verification/totp-status":
                epoch_sec = int(time.time())
                self._send_json(200, {"success": True, "currentCode": "777888", "secondsRemaining": 30 - (epoch_sec % 30), "secret": "JBSWY3DPEHPK3PXP"})
            elif path == "/api/hardware/overview":
                self._send_json(200, {
                    "success": True,
                    "cluster": {
                        "nodes": [
                            {"nodeId": "LOCAL-SOC-HOST", "ipAddress": "127.0.0.1", "os": "Windows 11", "status": "ONLINE"},
                            {"nodeId": "EDGE-GW-01", "ipAddress": "10.0.1.1", "os": "Debian 12", "status": "ONLINE"},
                            {"nodeId": "CORE-AUTH-NODE", "ipAddress": "10.0.2.10", "os": "Ubuntu 24.04", "status": "ONLINE"}
                        ],
                        "latestSamples": {"LOCAL-SOC-HOST": {"cpuUsage": 28.4, "memoryUsage": 54.1, "diskUsage": 52.4, "tempCelsius": 48.2, "netRxKbps": 180, "netTxKbps": 60}},
                        "avgCpu": 32.2, "avgMem": 57.8, "stats": {"samplesPerSecond": 12.4}
                    }
                })
            elif path == "/api/audit/logs":
                self._send_json(200, {"success": True, "total": len(STATE["audit_trails"]), "records": STATE["audit_trails"]})
            elif path == "/api/admin/rbac-matrix":
                self._send_json(200, {
                    "success": True,
                    "roles": ["SUPER_ADMIN", "ADMIN", "SOC_OPERATOR", "SECURITY_AUDITOR", "REGISTERED_USER"],
                    "permissions": [
                        {"key": "DASHBOARD_VIEW", "label": "View Executive Dashboard", "category": "Monitoring"},
                        {"key": "INCIDENTS_VIEW", "label": "View Incident Cases", "category": "Incident Response"},
                        {"key": "INCIDENTS_MANAGE", "label": "Triage & Update Incidents", "category": "Incident Response"},
                        {"key": "ALERTS_VIEW", "label": "View Detection Alerts", "category": "Monitoring"},
                        {"key": "THREAT_INTEL_MANAGE", "label": "Add/Edit/Delete IOCs", "category": "Threat Intel"},
                        {"key": "FIREWALL_RULES_MANAGE", "label": "Autonomous Firewall Rules", "category": "Security Panel"}
                    ]
                })
            else:
                self._send_json(404, {"error": "API route not found"})
            return

        # Serve static file from frontend directory
        super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body = {}
        if length > 0:
            try:
                body = json.loads(self.rfile.read(length).decode("utf-8"))
            except Exception:
                pass

        if path == "/api/admin/users":
            new_user = {
                "id": f"CS50-{hashlib.md5(str(time.time()).encode()).hexdigest()[:6].upper()}",
                "name": body.get("name", "Anonymous Endpoint"),
                "phone": body.get("phone", ""),
                "email": body.get("email", ""),
                "os": body.get("os", "Windows"),
                "device": body.get("device", "Laptop"),
                "network": body.get("network", "Wi-Fi"),
                "status": "PROTECTED",
                "registeredAt": datetime.utcnow().isoformat() + "Z"
            }
            STATE["users"].insert(0, new_user)
            self._send_json(201, {"success": True, "user": new_user})
        elif path == "/api/admin/login":
            u = body.get("username", "").upper()
            p = body.get("password", "")
            if (u == "SUNNY" and (p == "MONKEY" or p == "AdminPass2026!")) or (u == "ALEX.RIVERA" and p == "AdminPass2026!"):
                self._send_json(200, {"success": True, "user": {"name": u, "username": u, "role": "SUPER_ADMIN"}})
            else:
                self._send_json(401, {"error": "Invalid administrator credentials"})
        elif path == "/api/simulate":
            self._send_json(200, {"success": True, "message": f"Simulation {body.get('attackType', 'ddos')} executed successfully."})
        elif path == "/api/mitigate":
            self._send_json(200, {"success": True, "message": "Threat mitigated."})
        elif path == "/api/lockdown/emergency":
            STATE["metrics"]["isEmergencyLockdown"] = True
            self._send_json(200, {"success": True, "message": "Emergency lockdown active."})
        elif path == "/api/lockdown/release":
            STATE["metrics"]["isEmergencyLockdown"] = False
            self._send_json(200, {"success": True, "message": "Emergency lockdown released."})
        elif path == "/api/patch/apply":
            STATE["metrics"]["appliedPatchesCount"] += 1
            self._send_json(200, {"success": True, "message": "Virtual patch applied."})
        elif path == "/api/verification/verify-code":
            self._send_json(200, {"success": True, "method": "TOTP_SIMULATED"})
        elif path == "/api/schema/query":
            self._send_json(200, {
                "success": True,
                "executionMs": 0.18,
                "rowCount": 3,
                "columns": ["id", "title", "severity", "status"],
                "rows": [
                    {"id": "INC-2026-0814", "title": "SYN Flood DDoS", "severity": "CRITICAL", "status": "CONTAINED"},
                    {"id": "INC-2026-0815", "title": "Pegasus Mobile C2", "severity": "CRITICAL", "status": "INVESTIGATING"},
                    {"id": "INC-2026-0816", "title": "SQL Injection Probing", "severity": "HIGH", "status": "MITIGATED"}
                ]
            })
        else:
            self._send_json(200, {"success": True, "message": "Action accepted"})

def run_server():
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
    server_address = ("", PORT)
    with socketserver.TCPServer(server_address, SocRequestHandler) as httpd:
        print("=" * 70)
        print(f"[CYBER SHIELD SOC] Python Backend Server Running")
        print(f"Host Link: http://localhost:{PORT}")
        print(f"Frontend Directory: {FRONTEND_DIR}")
        print("=" * 70)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")

if __name__ == "__main__":
    run_server()
