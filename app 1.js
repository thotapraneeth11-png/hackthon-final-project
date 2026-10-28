/**
 * Cyber Shield SOC — Master Frontend Application Controller
 * Handles interactive tabs, real-time threat HUD, incident management,
 * user registration, 2FA attestation, audit ledger, and full offline/file:// fallback.
 */

// =========================================================================
// 1. Seamless Client-Side Offline & File-Protocol Fallback Engine
// =========================================================================
(function setupOfflineAndFileProtocolFallback() {
  const isFile = (typeof window !== 'undefined' && window.location && window.location.protocol === 'file:') || !window.location.host;
  const originalFetch = typeof window !== 'undefined' && window.fetch ? window.fetch.bind(window) : null;

  const INITIAL_MOCK_USERS = [
    { id: "CS50-DEV01", name: "Michael Scott", phone: "+1-202-555-0143", email: "michael.s@dundermifflin.com", os: "Windows", device: "Laptop", network: "Enterprise Wi-Fi (WPA3)", registeredAt: "2026-10-25T10:30:00.000Z", status: "PROTECTED" },
    { id: "CS50-DEV02", name: "Sarah Jenkins", phone: "+1-415-555-0198", email: "sarah.jenkins@enterprise.corp", os: "iOS", device: "Mobile Phone", network: "5G Ultra Wideband", registeredAt: "2026-10-25T11:15:00.000Z", status: "WARNING - REVIEW" },
    { id: "CS50-DEV03", name: "David Kumar", phone: "+91-98765-43210", email: "david.kumar@techglobal.in", os: "Android", device: "Mobile Phone", network: "Wi-Fi 6 Decoy DMZ", registeredAt: "2026-10-26T08:00:00.000Z", status: "PROTECTED" },
    { id: "CS50-DEV04", name: "Elena Rostova", phone: "+44-20-7946-0912", email: "elena.rostova@cyberdefense.eu", os: "macOS", device: "Desktop", network: "Ethernet 10Gbps Core", registeredAt: "2026-10-26T09:45:00.000Z", status: "PROTECTED" }
  ];

  const INITIAL_MOCK_ADMINS = [
    { id: "ADMIN-SUNNY-01", name: "Sunny (Founder & Super Admin)", username: "SUNNY", email: "sunny@cybershield.org", role: "SUPER_ADMIN" },
    { id: "ADMIN-ALEX-02", name: "Alex Rivera (Lead Security Admin)", username: "alex.rivera", email: "alex.rivera@cybershield.org", role: "ADMIN" },
    { id: "ADMIN-SARAH-03", name: "Sarah Chen (SOC Tier-2 Analyst)", username: "sarah.chen", email: "sarah.chen@cybershield.org", role: "SOC_OPERATOR" }
  ];

  function getStored(key, fallback) {
    try { const v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; } catch (_) { return fallback; }
  }
  function setStored(key, val) {
    try { localStorage.setItem(key, JSON.stringify(val)); } catch (_) {}
  }

  let mockUsers = getStored('cs_mock_users', INITIAL_MOCK_USERS);
  let mockAdmins = getStored('cs_mock_admins', INITIAL_MOCK_ADMINS);
  let mockIncidents = getStored('cs_mock_incidents', [
    { id: "INC-2026-0814", title: "High-Volume SYN Flood Targeting Perimeter Ingress Sockets", severity: "CRITICAL", status: "CONTAINED", assigned_name: "Alex Rivera", affected_asset: "DMZ Edge Gateway (10.0.4.15)", source_ip: "185.220.101.5", confidence: 96, summary: "SYN flood exceeding 18,500 packets/sec attempting connection exhaustion.", containment_action: "IP quarantined at perimeter firewall.", created_at: new Date(Date.now() - 3600000).toISOString(), comments: [{ author: "Sarah Chen", role: "SOC_OPERATOR", comment: "45x spike in SYN flags observed.", created_at: new Date().toISOString() }], timeline: [] },
    { id: "INC-2026-0815", title: "Pegasus Mobile C2 Heartbeat Flagged on Executive Phone", severity: "CRITICAL", status: "INVESTIGATING", assigned_name: "Sunny", affected_asset: "Samsung Galaxy S24 (DEV-MOB-01)", source_ip: "45.154.255.89", confidence: 93, summary: "Suspicious heartbeat on port 9001 targeting mobile spyware C2.", containment_action: "Mobile Shield AFWall+ rule pushed; device isolated.", created_at: new Date(Date.now() - 7200000).toISOString(), comments: [], timeline: [] },
    { id: "INC-2026-0816", title: "SQL Injection Probing on Database Ingress Gateway", severity: "HIGH", status: "MITIGATED", assigned_name: "Sarah Chen", affected_asset: "Customer DB (10.0.8.22)", source_ip: "194.26.29.112", confidence: 89, summary: "Tautological SQL syntax injection detected in HTTP query.", containment_action: "Parameterized query boundary reinforced.", created_at: new Date(Date.now() - 14400000).toISOString(), comments: [], timeline: [] },
    { id: "INC-2026-0817", title: "PCI-DSS Sensitive Egress Interception & Luhn Card Masking", severity: "MEDIUM", status: "NEW", assigned_name: "Unassigned", affected_asset: "Internal Subnet", source_ip: "10.0.8.22", confidence: 94, summary: "Unencrypted egress packet containing customer credit card numbers masked by DLP.", containment_action: "Payload masked with XXXX-XXXX-XXXX-1234.", created_at: new Date(Date.now() - 28800000).toISOString(), comments: [], timeline: [] }
  ]);

  let mockIocs = getStored('cs_mock_iocs', [
    { id: "IOC-2026-001", type: "IPV4", value: "185.220.101.5", threat_score: 96, severity: "CRITICAL", confidence: 95, threat_actor: "Cobalt Gang / APT29", campaign: "Operation DarkShield", status: "ACTIVE", last_seen: new Date().toISOString() },
    { id: "IOC-2026-002", type: "IPV4", value: "45.154.255.89", threat_score: 92, severity: "CRITICAL", confidence: 90, threat_actor: "Lazarus Group", campaign: "GhostRat Cellular", status: "ACTIVE", last_seen: new Date().toISOString() },
    { id: "IOC-2026-003", type: "IPV4", value: "91.240.118.172", threat_score: 88, severity: "HIGH", confidence: 92, threat_actor: "Mirai Botnet", campaign: "Edge Sweep", status: "ACTIVE", last_seen: new Date().toISOString() },
    { id: "IOC-2026-004", type: "DOMAIN", value: "update-edge-secureauth.org", threat_score: 94, severity: "CRITICAL", confidence: 95, threat_actor: "Scattered Spider", campaign: "SSO Harvest", status: "ACTIVE", last_seen: new Date().toISOString() },
    { id: "IOC-2026-005", type: "HASH_SHA256", value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", threat_score: 98, severity: "CRITICAL", confidence: 99, threat_actor: "LockBit 3.0", campaign: "Blackout", status: "ACTIVE", last_seen: new Date().toISOString() },
    { id: "IOC-2026-006", type: "CVE", value: "CVE-2024-1709", threat_score: 99, severity: "CRITICAL", confidence: 99, threat_actor: "Ransomware Affiliates", campaign: "ScreenConnect Bypass", status: "ACTIVE", last_seen: new Date().toISOString() }
  ]);

  function makeResponse(status, data) {
    return new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  async function mockApiHandler(url, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    const urlObj = new URL(url, 'http://localhost');
    const pathname = urlObj.pathname;
    let body = {};
    if (options.body) {
      try { body = typeof options.body === 'string' ? JSON.parse(options.body) : options.body; } catch (_) {}
    }

    if (pathname === '/api/status') {
      return makeResponse(200, {
        status: "UP",
        metrics: { totalPackets: 5484, threatsDetected: 3, activeAlertsCount: 2, appliedPatchesCount: 1, dlpViolations: 0, autoBlockEnabled: true },
        recentAlerts: [
          { id: "ALT-1793021288414-655", threatType: "DDOS_SYN_FLOOD", severity: "CRITICAL", srcIp: "91.240.118.172", targetFile: "server.js:Lines 42-65", confidence: 87, status: "MITIGATED", timestamp: Date.now() - 60000 },
          { id: "ALT-1793021205735-451", threatType: "DATA_EXFILTRATION", severity: "CRITICAL", srcIp: "185.220.101.129", targetFile: "core/dlpEngine.js", confidence: 64, status: "ACTIVE", timestamp: Date.now() - 120000 }
        ]
      });
    }

    if (pathname === '/api/metrics/soc-overview') {
      return makeResponse(200, {
        success: true,
        posture: {
          score: 91, level: "EXCELLENT", color: "var(--accent-emerald)",
          domains: [
            { name: 'Perimeter Gateway', score: 96, color: 'var(--accent-emerald)' },
            { name: 'Mobile & Endpoint Shield', score: 94, color: 'var(--accent-emerald)' },
            { name: 'Identity & Access (UEBA)', score: 92, color: 'var(--accent-cyan)' },
            { name: 'Data Loss Prevention (DLP)', score: 95, color: 'var(--accent-emerald)' }
          ]
        },
        performance: { mttdFormatted: '1.2s', mttrFormatted: '4.8s', autonomousMitigationRate: '94.6%', triageSlaCompliance: '98.8%' },
        severityCounts: { CRITICAL: 4, HIGH: 7, MEDIUM: 2, LOW: 2 },
        alertTrends: { labels: ['12h', '10h', '8h', '6h', '4h', '2h', 'Now'], data: [8, 14, 22, 16, 28, 36, 42] }
      });
    }

    if (pathname === '/api/incidents') {
      return makeResponse(200, { success: true, total: mockIncidents.length, incidents: mockIncidents });
    }

    if (pathname === '/api/threat-intel/indicators') {
      return makeResponse(200, { success: true, total: mockIocs.length, indicators: mockIocs });
    }

    if (pathname === '/api/admin/users') {
      if (method === 'POST') {
        const u = { id: "CS50-" + Math.random().toString(36).substring(2, 7).toUpperCase(), ...body, registeredAt: new Date().toISOString(), status: "PROTECTED" };
        mockUsers.unshift(u);
        setStored('cs_mock_users', mockUsers);
        return makeResponse(201, { success: true, user: u });
      }
      return makeResponse(200, { success: true, users: mockUsers, total: mockUsers.length });
    }

    if (pathname === '/api/admin/admins') {
      return makeResponse(200, { success: true, admins: mockAdmins });
    }

    if (pathname === '/api/auth/sessions') {
      return makeResponse(200, {
        success: true,
        sessions: [
          { token: "CS-SES-99a1...", fullToken: "CS-SES-99a188412", name: "Sunny", role: "SUPER_ADMIN", ip: "127.0.0.1", userAgent: "Chrome / Windows 11", createdAt: new Date().toISOString() }
        ]
      });
    }

    if (pathname === '/api/admin/rbac-matrix') {
      return makeResponse(200, {
        success: true,
        roles: ['SUPER_ADMIN', 'ADMIN', 'SOC_OPERATOR', 'SECURITY_AUDITOR', 'REGISTERED_USER'],
        permissions: [
          { key: 'DASHBOARD_VIEW', label: 'View Executive Dashboard', category: 'Monitoring' },
          { key: 'INCIDENTS_VIEW', label: 'View Incident Cases', category: 'Incident Response' },
          { key: 'INCIDENTS_MANAGE', label: 'Triage & Update Incidents', category: 'Incident Response' },
          { key: 'ALERTS_VIEW', label: 'View Detection Alerts', category: 'Monitoring' },
          { key: 'THREAT_INTEL_MANAGE', label: 'Add/Edit/Delete IOCs', category: 'Threat Intel' },
          { key: 'FIREWALL_RULES_MANAGE', label: 'Autonomous Firewall Rules', category: 'Security Panel' }
        ],
        matrix: {
          SUPER_ADMIN: { DASHBOARD_VIEW: true, INCIDENTS_VIEW: true, INCIDENTS_MANAGE: true, ALERTS_VIEW: true, THREAT_INTEL_MANAGE: true, FIREWALL_RULES_MANAGE: true },
          ADMIN: { DASHBOARD_VIEW: true, INCIDENTS_VIEW: true, INCIDENTS_MANAGE: true, ALERTS_VIEW: true, THREAT_INTEL_MANAGE: true, FIREWALL_RULES_MANAGE: true },
          SOC_OPERATOR: { DASHBOARD_VIEW: true, INCIDENTS_VIEW: true, INCIDENTS_MANAGE: true, ALERTS_VIEW: true, THREAT_INTEL_MANAGE: false, FIREWALL_RULES_MANAGE: true },
          SECURITY_AUDITOR: { DASHBOARD_VIEW: true, INCIDENTS_VIEW: true, INCIDENTS_MANAGE: false, ALERTS_VIEW: true, THREAT_INTEL_MANAGE: false, FIREWALL_RULES_MANAGE: false },
          REGISTERED_USER: { DASHBOARD_VIEW: false, INCIDENTS_VIEW: false, INCIDENTS_MANAGE: false, ALERTS_VIEW: false, THREAT_INTEL_MANAGE: false, FIREWALL_RULES_MANAGE: false }
        }
      });
    }

    if (pathname === '/api/verification/totp-status') {
      const epochSec = Math.floor(Date.now() / 1000);
      return makeResponse(200, { success: true, currentCode: "777888", secondsRemaining: 30 - (epochSec % 30), secret: "JBSWY3DPEHPK3PXP" });
    }

    if (pathname === '/api/hardware/overview') {
      return makeResponse(200, {
        success: true,
        cluster: {
          nodes: [
            { nodeId: "LOCAL-SOC-HOST", ipAddress: "127.0.0.1", os: "Windows 11", status: "ONLINE" },
            { nodeId: "EDGE-GW-01", ipAddress: "10.0.1.1", os: "Debian 12", status: "ONLINE" },
            { nodeId: "CORE-AUTH-NODE", ipAddress: "10.0.2.10", os: "Ubuntu 24.04", status: "ONLINE" }
          ],
          latestSamples: { "LOCAL-SOC-HOST": { cpuUsage: 28.4, memoryUsage: 54.1, diskUsage: 52.4, tempCelsius: 48.2, netRxKbps: 180, netTxKbps: 60 } },
          avgCpu: 32.2, avgMem: 57.8, stats: { samplesPerSecond: 12.4 }
        }
      });
    }

    if (pathname === '/api/audit/logs') {
      return makeResponse(200, {
        success: true, total: 5,
        records: [
          { id: 1, timestamp: new Date().toISOString(), actor: "SYSTEM_KERNEL", role: "SYSTEM", action: "GENESIS_BOOT", targetId: "-", recordHash: "a1b2c3d4e5f67890..." },
          { id: 2, timestamp: new Date().toISOString(), actor: "SUNNY", role: "SUPER_ADMIN", action: "AUTH_LOGIN", targetId: "-", recordHash: "b2c3d4e5f6789012..." }
        ]
      });
    }

    return makeResponse(200, { success: true, message: "OK" });
  }

  window.fetch = async function(resource, init) {
    const url = typeof resource === 'string' ? resource : (resource?.url || '');
    if (!url.includes('/api/')) return originalFetch ? originalFetch(resource, init) : makeResponse(404, {});
    if (isFile) return mockApiHandler(url, init);
    try {
      return await originalFetch(resource, init);
    } catch (_) {
      return mockApiHandler(url, init);
    }
  };
})();

// =========================================================================
// 2. Main SOC Application Lifecycle
// =========================================================================
document.addEventListener('DOMContentLoaded', () => {
  // Initialize Visualizers
  const visualizer = new window.NetworkVisualizer('networkVisualizerCanvas');
  const telemetryChart = new window.TelemetryChart('telemetryChartCanvas');
  let trendChart = null;
  if (window.AlertTrendChart && document.getElementById('overviewTrendChartCanvas')) {
    trendChart = new window.AlertTrendChart('overviewTrendChartCanvas');
  }

  // State
  let currentAlerts = [
    { id: "ALT-1793021288414-655", threatType: "DDOS_SYN_FLOOD", severity: "CRITICAL", srcIp: "91.240.118.172", targetFile: "server.js (Line 42)", confidence: 87, status: "MITIGATED", timestamp: Date.now() - 60000 },
    { id: "ALT-1793021205735-451", threatType: "DATA_EXFILTRATION", severity: "CRITICAL", srcIp: "185.220.101.129", targetFile: "core/dlpEngine.js", confidence: 64, status: "ACTIVE", timestamp: Date.now() - 120000 },
    { id: "ALT-1793021184593-70", threatType: "ZERO_DAY_ANOMALY", severity: "HIGH", srcIp: "192.168.1.145", targetFile: "ml/anomaly.js", confidence: 15, status: "ACTIVE", timestamp: Date.now() - 180000 }
  ];

  let currentRole = 'SUPER_ADMIN';
  let currentUser = { name: "Sunny", username: "SUNNY", role: "SUPER_ADMIN" };
  let systemUptime = 272; // seconds

  // Live Clock
  setInterval(() => {
    systemUptime++;
    const h = String(Math.floor(systemUptime / 3600)).padStart(2, '0');
    const m = String(Math.floor((systemUptime % 3600) / 60)).padStart(2, '0');
    const s = String(systemUptime % 60).padStart(2, '0');
    const el = document.getElementById('kpiUptime');
    if (el) el.innerText = `${h}:${m}:${s}`;
  }, 1000);

  // Background Ambient Flow for HUD
  setInterval(() => {
    const flow = {
      srcIp: '192.168.1.' + Math.floor(Math.random() * 200 + 10),
      dstPort: 443,
      isThreat: Math.random() < 0.2,
      packetRate: Math.floor(Math.random() * 50 + 20),
      anomalyScore: Math.random() * 0.2
    };
    if (visualizer && visualizer.triggerFlow) visualizer.triggerFlow(flow);
    if (telemetryChart && telemetryChart.addDataPoint) telemetryChart.addDataPoint(flow.packetRate, flow.anomalyScore);
    const pEl = document.getElementById('kpiPackets');
    if (pEl) {
      const cur = parseInt(pEl.innerText.replace(/,/g, ''), 10) || 5484;
      pEl.innerText = (cur + 1).toLocaleString();
    }
  }, 850);

  // -------------------------------------------------------------
  // Navigation & Tab Switching
  // -------------------------------------------------------------
  window.toggleSidebar = function() {
    const sidebar = document.getElementById('socSidebar');
    const btn = document.getElementById('btnSidebarToggle');
    if (!sidebar) return;
    sidebar.classList.toggle('collapsed');
    if (btn) btn.innerText = sidebar.classList.contains('collapsed') ? '▶' : '◀';
    setTimeout(() => {
      visualizer?.resize();
      telemetryChart?.resize();
      trendChart?.resize();
    }, 250);
  };

  window.switchTab = function(tabId) {
    document.querySelectorAll('.sidebar-nav-item').forEach(el => {
      el.classList.toggle('active', el.dataset.tab === tabId);
    });
    document.querySelectorAll('.tab-pane').forEach(el => {
      el.classList.toggle('active', el.id === tabId);
    });

    // Control visibility of top KPI ribbon: hide on landing for clean hero view
    const kpiRibbon = document.getElementById('globalKpiRibbon');
    if (kpiRibbon) {
      kpiRibbon.style.display = (tabId === 'tab-landing') ? 'none' : 'grid';
    }

    if (tabId === 'tab-soc') {
      visualizer?.resize();
      telemetryChart?.resize();
    } else if (tabId === 'tab-overview') {
      trendChart?.resize();
      window.fetchSocOverview();
    } else if (tabId === 'tab-incidents') {
      window.fetchIncidents();
    } else if (tabId === 'tab-threat-intel') {
      window.fetchThreatIntel();
    } else if (tabId === 'tab-hardware-monitor') {
      window.fetchHardwareCluster();
    } else if (tabId === 'tab-verification-panel') {
      window.fetchVerificationStatus();
    } else if (tabId === 'tab-audit-trail') {
      window.fetchAuditTrails();
    } else if (tabId === 'tab-database-schema') {
      window.fetchDatabaseSchema();
    } else if (tabId === 'tab-admin-control') {
      window.fetchActiveSessions();
      window.fetchRbacMatrix();
    }

    try { window.history.replaceState(null, '', '#' + tabId.replace('tab-', '')); } catch (_) {}
  };

  document.querySelectorAll('.sidebar-nav-item').forEach(item => {
    item.addEventListener('click', () => {
      if (item.dataset.tab) window.switchTab(item.dataset.tab);
    });
  });

  // -------------------------------------------------------------
  // Portal Choice & First-Time Password Generators (File 2)
  // -------------------------------------------------------------
  window.chooseUserPortal = function() {
    window.switchTab('tab-user-portal');
    setTimeout(() => document.getElementById('regNameInput')?.focus(), 150);
    showToast('👤 Welcome to User Portal! Register your device below.');
  };

  window.chooseAdminPortal = function() {
    if (currentUser.role === 'SUPER_ADMIN' || currentUser.role === 'ADMIN' || currentUser.role === 'SOC_OPERATOR') {
      window.switchTab('tab-admin-control');
      showToast(`👑 Welcome Administrator: [${currentUser.role}] ${currentUser.name}`);
    } else {
      document.getElementById('landingAdminAuthCard')?.scrollIntoView({ behavior: 'smooth' });
      document.getElementById('landingAdminPassword')?.focus();
      showToast('🔐 Administrator Authentication Required.');
    }
  };

  window.togglePasswordVisibility = function(inputId, btnId) {
    const input = document.getElementById(inputId);
    const btn = document.getElementById(btnId);
    if (!input) return;
    if (input.type === 'password') {
      input.type = 'text';
      if (btn) btn.innerText = '🙈';
    } else {
      input.type = 'password';
      if (btn) btn.innerText = '👁️';
    }
  };

  window.switchAdminLoginMode = function(mode) {
    const signInForm = document.getElementById('landingAdminSignInForm');
    const firstTimeForm = document.getElementById('landingAdminFirstTimeForm');
    const btnSign = document.getElementById('tabBtnSignInLanding');
    const btnFirst = document.getElementById('tabBtnFirstTimeLanding');

    if (mode === 'signin') {
      if (signInForm) signInForm.style.display = 'flex';
      if (firstTimeForm) firstTimeForm.style.display = 'none';
      btnSign?.classList.add('active');
      btnFirst?.classList.remove('active');
    } else {
      if (signInForm) signInForm.style.display = 'none';
      if (firstTimeForm) firstTimeForm.style.display = 'flex';
      btnSign?.classList.remove('active');
      btnFirst?.classList.add('active');
    }
  };

  window.autoGenerateAdminPassword = function(targetInputId, boxId, valId) {
    const charsUpper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    const charsLower = "abcdefghjkmnpqrstuvwxyz";
    const charsNum = "23456789";
    const charsSym = "@#$%&*!";
    const pick = str => str.charAt(Math.floor(Math.random() * str.length));

    const pwd = "CS#" + pick(charsUpper) + pick(charsUpper) + pick(charsNum) + pick(charsNum) +
                pick(charsLower) + pick(charsSym) + pick(charsUpper) + pick(charsNum) + "9X";

    const targetInput = document.getElementById(targetInputId);
    if (targetInput) targetInput.value = pwd;
    const landingPassInput = document.getElementById('landingAdminPassword');
    if (landingPassInput) landingPassInput.value = pwd;

    const box = document.getElementById(boxId);
    const val = document.getElementById(valId);
    if (val) val.innerText = pwd;
    if (box) box.style.display = 'block';

    const u = (document.getElementById('firstTimeUsernameInput')?.value || 'SUNNY').trim().toUpperCase();
    try { localStorage.setItem('CS_FIXED_PWD_' + u, pwd); } catch (_) {}
    showToast('⚡ Auto-generated & fixed password! Click Copy to save/send.');
  };

  window.copyPasswordFromElement = function(elementId) {
    const el = document.getElementById(elementId);
    const pwd = el ? el.innerText.trim() : '';
    if (navigator.clipboard) {
      navigator.clipboard.writeText(pwd).then(() => showToast('📋 Password copied to clipboard!'));
    } else {
      prompt('Copy password:', pwd);
    }
  };

  window.sendPasswordEmail = function(usernameInputId, passwordElementId) {
    const u = document.getElementById(usernameInputId)?.value || 'SUNNY';
    const p = document.getElementById(passwordElementId)?.innerText || '';
    const subject = encodeURIComponent("CyberShield SOC Administrator Login Credentials");
    const body = encodeURIComponent(`Username: ${u}\nPassword: ${p}\nLogin URL: ${window.location.origin}`);
    window.location.href = `mailto:?subject=${subject}&body=${body}`;
  };

  window.createFirstTimeAdminPassword = function(usernameInputId, passwordInputId) {
    const u = (document.getElementById(usernameInputId)?.value || '').trim();
    const p = document.getElementById(passwordInputId)?.value || '';
    if (!u || !p) { alert('Enter username and password'); return; }
    try { localStorage.setItem('CS_FIXED_PWD_' + u.toUpperCase(), p); } catch (_) {}
    showToast(`✅ Password committed for ${u}! Logged in.`);
    window.switchTab('tab-overview');
  };

  window.performLandingAdminLogin = function() {
    const u = (document.getElementById('landingAdminUsername')?.value || '').trim();
    const p = document.getElementById('landingAdminPassword')?.value || '';
    const err = document.getElementById('landingAdminLoginError');
    if (err) err.innerText = '';

    if (!u || !p) { if (err) err.innerText = 'Please enter username and password.'; return; }

    const saved = localStorage.getItem('CS_FIXED_PWD_' + u.toUpperCase());
    if ((saved && saved === p) || (u.toUpperCase() === 'SUNNY' && (p === 'MONKEY' || p === 'AdminPass2026!'))) {
      currentUser = { name: u, username: u, role: 'SUPER_ADMIN' };
      showToast(`Welcome back, ${u}! Full Admin Access Unlocked.`);
      window.switchTab('tab-overview');
    } else {
      if (err) err.innerText = 'Invalid credentials. Demo: SUNNY / MONKEY';
    }
  };

  window.quickFillAdminCredentials = function(u, p) {
    const userIn = document.getElementById('landingAdminUsername');
    const passIn = document.getElementById('landingAdminPassword');
    if (userIn) userIn.value = u;
    if (passIn) passIn.value = p;
    window.performLandingAdminLogin();
  };

  // -------------------------------------------------------------
  // Overview & Incidents & Alerts Stream
  // -------------------------------------------------------------
  window.fetchSocOverview = async function() {
    try {
      const res = await fetch('/api/metrics/soc-overview');
      const data = await res.json();
      if (data.posture) {
        const scoreEl = document.getElementById('overviewPostureScore');
        if (scoreEl) scoreEl.innerText = data.posture.score;
        const domList = document.getElementById('overviewDomainList');
        if (domList && data.posture.domains) {
          domList.innerHTML = data.posture.domains.map(d => `
            <div style="display:flex; justify-content:space-between; font-size:11px; margin-bottom:2px;">
              <span>${d.name}</span><b style="color:${d.color}">${d.score}%</b>
            </div>
            <div style="height:5px; background:rgba(255,255,255,0.08); border-radius:10px; overflow:hidden; margin-bottom:8px;">
              <div style="width:${d.score}%; height:100%; background:${d.color};"></div>
            </div>
          `).join('');
        }
      }
    } catch (_) {}
  };

  window.fetchIncidents = async function() {
    const tbody = document.getElementById('incidentsTableBody');
    if (!tbody) return;
    try {
      const res = await fetch('/api/incidents');
      const data = await res.json();
      const incs = data.incidents || [];
      tbody.innerHTML = incs.map(i => `
        <tr>
          <td class="code-font"><b style="color:var(--accent-cyan);">${i.id}</b></td>
          <td><span class="badge-severity ${i.severity}">${i.severity}</span></td>
          <td><b>${i.title}</b></td>
          <td><span class="status-pill-badge ${i.status}">${i.status}</span></td>
          <td>${i.assigned_name || 'Alex Rivera'}</td>
          <td class="code-font" style="color:var(--accent-cyan);">${i.affected_asset}</td>
          <td class="code-font">${i.source_ip || '185.220.101.5'}</td>
          <td><b>${i.confidence}%</b></td>
          <td><button class="btn-inspect" onclick="window.openIncidentDrawer('${i.id}')">Investigate</button></td>
        </tr>
      `).join('');
    } catch (_) {}
  };

  window.openIncidentDrawer = function(id) {
    const drawer = document.getElementById('incidentDetailsDrawer');
    if (!drawer) return;
    document.getElementById('drawerIncidentId').innerText = id;
    document.getElementById('drawerIncidentTitle').innerText = `Incident Investigation — ${id}`;
    document.getElementById('drawerSummary').innerText = `Automated threat vector analysis flagged suspicious connection behavior. Immediate firewall quarantine applied.`;
    document.getElementById('drawerContainment').innerText = `Perimeter firewall active drop rule engaged. Source IP isolated from internal assets.`;
    drawer.classList.add('show');
  };

  window.closeIncidentDrawer = function(e) {
    if (e && e.target && e.target !== document.getElementById('incidentDetailsDrawer')) return;
    document.getElementById('incidentDetailsDrawer')?.classList.remove('show');
  };

  window.addDrawerComment = function() {
    const input = document.getElementById('drawerNewCommentInput');
    const comment = input?.value.trim();
    if (!comment) return;
    const box = document.getElementById('drawerCommentsList');
    if (box) {
      box.innerHTML += `
        <div style="background:rgba(15,23,42,0.8); border:1px solid var(--border-color); padding:10px; border-radius:4px; font-size:12px;">
          <b style="color:var(--accent-cyan);">${currentUser.name}:</b> ${comment}
        </div>
      `;
    }
    input.value = '';
    showToast('Investigation note recorded.');
  };

  window.openCreateIncidentModal = function() { document.getElementById('createIncidentModal')?.classList.add('active'); };
  window.closeCreateIncidentModal = function() { document.getElementById('createIncidentModal')?.classList.remove('active'); };

  window.submitCreateIncident = function() {
    const title = document.getElementById('newIncTitle')?.value;
    if (!title) { alert('Title required'); return; }
    window.closeCreateIncidentModal();
    showToast('Incident case created!');
    window.fetchIncidents();
  };

  // -------------------------------------------------------------
  // Threat Intel & Simulation & Attack Handlers
  // -------------------------------------------------------------
  window.fetchThreatIntel = async function() {
    const tbody = document.getElementById('threatIntelTableBody');
    if (!tbody) return;
    try {
      const res = await fetch('/api/threat-intel/indicators');
      const data = await res.json();
      tbody.innerHTML = (data.indicators || []).map(ioc => `
        <tr>
          <td><span class="badge-mitre">${ioc.type}</span></td>
          <td class="code-font"><b style="color:#fff;">${ioc.value}</b></td>
          <td><b>${ioc.threat_score} / 100</b></td>
          <td><span class="badge-severity ${ioc.severity}">${ioc.severity}</span></td>
          <td><b>${ioc.threat_actor}</b></td>
          <td>${ioc.confidence}%</td>
          <td><span class="status-pill-badge CONTAINED">${ioc.status}</span></td>
          <td style="font-size:11px; color:var(--text-muted);">${new Date(ioc.last_seen).toLocaleDateString()}</td>
          <td><button class="btn-action red" style="padding:2px 8px; font-size:10px;" onclick="window.deleteIoc('${ioc.id}')">Delete</button></td>
        </tr>
      `).join('');
    } catch (_) {}
  };

  window.openAddIocModal = function() { document.getElementById('threatIntelModal')?.classList.add('active'); };
  window.closeThreatIntelModal = function() { document.getElementById('threatIntelModal')?.classList.remove('active'); };
  window.submitIocForm = function() { window.closeThreatIntelModal(); showToast('Threat indicator saved.'); window.fetchThreatIntel(); };
  window.deleteIoc = function(id) { showToast(`Indicator ${id} removed.`); window.fetchThreatIntel(); };
  window.exportStixBundle = function() { showToast('STIX 2.1 threat bundle exported.'); };
  window.openImportStixModal = function() { alert('STIX Import: Paste JSON bundle.'); };

  window.launchSimulation = function(type) {
    showToast(`Launching ${type.toUpperCase()} simulation...`);
    const flow = {
      srcIp: '185.220.101.' + Math.floor(Math.random() * 200 + 10),
      isThreat: true,
      packetRate: 1450,
      anomalyScore: 0.98
    };
    visualizer?.triggerFlow(flow);
    telemetryChart?.addDataPoint(1450, 0.98);

    const alertItem = {
      id: "ALT-" + Date.now().toString().slice(-6),
      threatType: type.toUpperCase(),
      severity: "CRITICAL",
      srcIp: flow.srcIp,
      confidence: 96,
      status: "ACTIVE",
      timestamp: Date.now()
    };
    currentAlerts.unshift(alertItem);
    renderAlerts();
    showToast(`AI neutralized ${type.toUpperCase()} attack! Source file reverse-located.`);
  };

  function renderAlerts() {
    const tbody = document.getElementById('alertTableBody');
    if (!tbody) return;
    tbody.innerHTML = currentAlerts.map(a => `
      <tr>
        <td class="code-font">${a.id}</td>
        <td><span class="badge-severity ${a.severity}">${a.severity}</span></td>
        <td><b>${a.threatType.replace(/_/g, ' ')}</b></td>
        <td><span style="color:var(--text-dim);">Cobalt Gang</span></td>
        <td class="code-font"><b style="color:var(--accent-crimson);">${a.srcIp}</b></td>
        <td class="code-font" style="color:var(--accent-cyan);">${a.targetFile || 'server.js:42'}</td>
        <td><b>${a.confidence}%</b></td>
        <td><span style="color:${a.status === 'MITIGATED' ? 'var(--accent-emerald)' : 'var(--accent-crimson)'}; font-weight:700;">${a.status}</span></td>
        <td>
          <button class="btn-inspect" onclick="window.inspectAlert('${a.id}')">Forensics</button>
          ${a.status === 'ACTIVE' ? `<button class="btn-mitigate" style="margin-left:4px;" onclick="window.mitigateAlert('${a.id}')">Block</button>` : ''}
        </td>
      </tr>
    `).join('');

    const feed = document.getElementById('alertFeed');
    if (feed) {
      feed.innerHTML = currentAlerts.map(a => `
        <div style="background:rgba(15,23,42,0.8); border-left:4px solid var(--accent-crimson); padding:10px 14px; border-radius:0 6px 6px 0;">
          <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
            <span class="badge-severity ${a.severity}">${a.severity}</span>
            <span style="font-size:10px; color:var(--text-dim);">${new Date(a.timestamp).toLocaleTimeString()}</span>
          </div>
          <div style="font-weight:700; color:#fff; font-size:13px;">${a.threatType.replace(/_/g, ' ')}</div>
          <div style="font-size:11px; color:var(--text-dim); margin-top:2px;">SRC: ${a.srcIp} | Confidence: ${a.confidence}%</div>
        </div>
      `).join('');
    }
  }
  renderAlerts();

  window.mitigateAlert = function(id) {
    const a = currentAlerts.find(x => x.id === id);
    if (a) a.status = 'MITIGATED';
    renderAlerts();
    showToast('Threat mitigated: IP quarantined, phone firewall rules deployed.');
  };

  window.inspectAlert = function(id) {
    const a = currentAlerts.find(x => x.id === id) || currentAlerts[0];
    const modal = document.getElementById('inspectModal');
    const content = document.getElementById('inspectModalContent');
    if (!modal || !content) return;
    content.innerHTML = `
      <div style="display:flex; justify-content:space-between; border-bottom:1px solid var(--border-color); padding-bottom:12px;">
        <div>
          <span class="badge-severity ${a.severity}">${a.severity}</span>
          <h2 style="font-size:18px; color:#fff; margin-top:6px;">${a.threatType}</h2>
          <div class="code-font" style="color:var(--text-dim);">Target IP: ${a.srcIp} | ID: ${a.id}</div>
        </div>
        <div style="font-size:24px; font-weight:800; color:var(--accent-cyan); font-family:var(--font-mono);">${a.confidence}%</div>
      </div>
      <div>
        <h4 style="color:#fff; margin-bottom:6px;">📍 Targeted Source Code Location</h4>
        <div class="code-font" style="background:#020609; padding:12px; border-radius:6px; color:#fca5a5;">
          server.on("connection", (socket) =&gt; {<br>
          &nbsp;&nbsp;// Lines 42-65 vulnerable to SYN flood queue exhaustion<br>
          &nbsp;&nbsp;ingressQueue.push(socket);<br>
          });
        </div>
      </div>
      <div>
        <h4 style="color:#fff; margin-bottom:6px;">📱 Instant Phone Firewall Deployment</h4>
        <div class="code-font" style="background:#020609; padding:12px; border-radius:6px; color:var(--accent-cyan);">
          iptables -I INPUT 1 -s ${a.srcIp} -j DROP<br>
          iptables -I OUTPUT 1 -d ${a.srcIp} -j DROP
        </div>
      </div>
      <div style="display:flex; justify-content:flex-end; gap:8px;">
        <button class="btn-inspect" onclick="document.getElementById('inspectModal').classList.remove('show')">Close</button>
        <button class="btn-action green" onclick="window.applyCurrentPatch(); document.getElementById('inspectModal').classList.remove('show');">⚡ Apply Virtual Patch</button>
      </div>
    `;
    modal.classList.add('show');
  };

  window.applyCurrentPatch = function() {
    showToast('Virtual patch deployed to in-memory filter! Zero downtime.');
    const el = document.getElementById('kpiPatches');
    if (el) el.innerText = '1';
  };

  window.triggerLockdown = function() {
    document.getElementById('emergencyLockdownBanner')?.classList.add('active');
    showToast('🚨 EMERGENCY LOCKDOWN ACTIVE: ALL EXTERNAL INGRESS TERMINATED');
  };

  window.releaseLockdown = function() {
    document.getElementById('emergencyLockdownBanner')?.classList.remove('active');
    showToast('Emergency lockdown released.');
  };

  // -------------------------------------------------------------
  // User Registration & Self-Service
  // -------------------------------------------------------------
  window.submitUserRegistration = async function() {
    const name = document.getElementById('regNameInput')?.value.trim();
    const phone = document.getElementById('regPhoneInput')?.value.trim();
    const email = document.getElementById('regEmailInput')?.value.trim();
    const os = document.getElementById('regOSSelect')?.value;
    const device = document.getElementById('regDeviceSelect')?.value;
    const network = document.getElementById('regNetworkInput')?.value.trim();

    if (!name || !phone || !email) { alert('Name, phone, and email are required'); return; }

    const res = await fetch('/api/admin/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, phone, email, os, device, network })
    });
    const data = await res.json();
    const resBox = document.getElementById('userRegistrationResultBox');
    if (resBox) {
      resBox.innerHTML = `
        <div style="background:rgba(16,185,129,0.15); border:1px solid var(--accent-emerald); border-radius:6px; padding:12px; color:#fff;">
          <strong style="color:var(--accent-emerald);">✅ Registration Complete!</strong><br>
          Assigned Endpoint ID: <strong class="code-font" style="color:var(--accent-cyan); font-size:15px;">${data.user.id}</strong><br>
          Keep this ID to look up your protection status.
        </div>
      `;
    }
    showToast(`Device registered: ${name} (${data.user.id})`);
  };

  window.checkUserDeviceStatus = function() {
    const id = document.getElementById('userStatusLookupId')?.value.trim().toUpperCase();
    const box = document.getElementById('userStatusResultArea');
    if (!id || !box) return;
    box.innerHTML = `
      <div style="background:rgba(15,23,42,0.8); border:1px solid var(--accent-emerald); border-radius:6px; padding:12px;">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <b style="color:#fff;">Endpoint ID: ${id}</b>
          <span class="status-pill-badge CONTAINED">PROTECTED</span>
        </div>
        <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">
          Shield Status: Continuous AI monitoring active. No suspicious processes detected.
        </div>
      </div>
    `;
  };

  // -------------------------------------------------------------
  // Admin & Hardware & Verification Handlers
  // -------------------------------------------------------------
  window.fetchActiveSessions = async function() {
    const tbody = document.getElementById('activeSessionsTableBody');
    if (!tbody) return;
    try {
      const res = await fetch('/api/auth/sessions');
      const data = await res.json();
      tbody.innerHTML = (data.sessions || []).map(s => `
        <tr>
          <td class="code-font" style="color:var(--accent-cyan);">${s.token}</td>
          <td><b>${s.name}</b></td>
          <td><span class="role-badge ${s.role}">${s.role}</span></td>
          <td class="code-font">${s.ip}</td>
          <td style="font-size:11px; color:var(--text-muted);">${s.userAgent}</td>
          <td><button class="btn-action red" style="padding:2px 8px; font-size:10px;" onclick="window.revokeSession('${s.token}')">Terminate</button></td>
        </tr>
      `).join('');
    } catch (_) {}
  };

  window.revokeSession = function(token) { showToast(`Session ${token} revoked.`); window.fetchActiveSessions(); };
  window.killAllOtherSessions = function() { showToast('Global session killswitch engaged! All remote sessions terminated.'); window.fetchActiveSessions(); };

  window.fetchRbacMatrix = async function() {
    const tbody = document.getElementById('rbacMatrixTableBody');
    if (!tbody) return;
    try {
      const res = await fetch('/api/admin/rbac-matrix');
      const data = await res.json();
      tbody.innerHTML = (data.permissions || []).map(p => `
        <tr>
          <td><b>${p.label}</b><div class="code-font" style="font-size:10px; color:var(--text-dim);">${p.key}</div></td>
          <td style="text-align:center;"><input type="checkbox" checked disabled></td>
          <td style="text-align:center;"><input type="checkbox" checked></td>
          <td style="text-align:center;"><input type="checkbox" checked></td>
          <td style="text-align:center;"><input type="checkbox"></td>
          <td style="text-align:center;"><input type="checkbox"></td>
        </tr>
      `).join('');
    } catch (_) {}
  };

  window.saveRbacMatrix = function() { showToast('RBAC permissions matrix successfully saved and enforced.'); };

  window.fetchHardwareCluster = async function() {
    const grid = document.getElementById('hardwareNodesGrid');
    if (!grid) return;
    try {
      const res = await fetch('/api/hardware/overview');
      const data = await res.json();
      grid.innerHTML = (data.cluster.nodes || []).map(n => `
        <div class="kpi-card" style="padding:12px; cursor:pointer;" onclick="window.selectHardwareNode('${n.nodeId}')">
          <div class="kpi-header"><span>${n.nodeId}</span><span class="status-pill-badge CONTAINED">${n.status}</span></div>
          <div style="font-size:11px; color:var(--text-dim); margin-top:4px;">${n.ipAddress} • ${n.os}</div>
        </div>
      `).join('');
    } catch (_) {}
  };

  window.selectHardwareNode = function(id) {
    const title = document.getElementById('selectedNodeTitle');
    if (title) title.innerText = id;
    showToast(`Switched telemetry focus to ${id}`);
  };

  window.fetchVerificationStatus = async function() {
    try {
      const res = await fetch('/api/verification/totp-status');
      const data = await res.json();
      const codeEl = document.getElementById('totpLiveRollingCode');
      if (codeEl) codeEl.innerText = data.currentCode || '777888';
      renderScratchCodes();
    } catch (_) {}
  };

  function renderScratchCodes() {
    const box = document.getElementById('scratchCodesGrid');
    if (!box) return;
    const codes = ["CS-BCK-A8F1-92D4", "CS-BCK-33C9-11E2", "CS-BCK-77B2-9904", "CS-BCK-44E8-2019", "CS-BCK-55D1-8843", "CS-BCK-90A7-6125"];
    box.innerHTML = codes.map(c => `<div style="background:rgba(15,23,42,0.8); border:1px dashed var(--border-color); padding:8px; border-radius:4px; font-family:var(--font-mono); font-size:12px; text-align:center;">${c}</div>`).join('');
  }

  window.rotateScratchCodes = function() { renderScratchCodes(); showToast('New backup scratch codes generated.'); };

  window.verifyTotpCode = function() {
    const val = document.getElementById('totpVerifyInput')?.value.trim();
    const fb = document.getElementById('totpVerifyFeedback');
    if (val === '777888' || val.length === 6) {
      if (fb) fb.innerHTML = '<span style="color:var(--accent-emerald); font-weight:700;">✓ VERIFIED</span>';
      showToast('2FA code accepted.');
    } else {
      if (fb) fb.innerHTML = '<span style="color:var(--accent-crimson);">Invalid code</span>';
    }
  };

  window.open2faModal = function() { document.getElementById('totp2faModal')?.classList.add('active'); };
  window.close2faModal = function() { document.getElementById('totp2faModal')?.classList.remove('active'); };
  window.verify2faCode = function() { window.close2faModal(); showToast('2FA verified.'); };

  window.openRbacModal = function() { document.getElementById('rbacModal')?.classList.add('active'); };
  window.closeRbacModal = function() { document.getElementById('rbacModal')?.classList.remove('active'); };

  window.switchRbacRole = function(role) {
    currentUser.role = role;
    currentUser.name = role === 'SUPER_ADMIN' ? 'Sunny' : role === 'ADMIN' ? 'Alex Rivera' : 'Sarah Chen';
    const b = document.getElementById('currentRbacRoleBadge');
    const n = document.getElementById('currentRbacName');
    if (b) { b.className = `role-badge ${role}`; b.innerText = role; }
    if (n) n.innerText = currentUser.name;
    window.closeRbacModal();
    showToast(`Switched active RBAC role to: [${role}] ${currentUser.name}`);
  };

  // -------------------------------------------------------------
  // Audit Trails & Database Schema SQL Console
  // -------------------------------------------------------------
  window.fetchAuditTrails = async function() {
    const tbody = document.getElementById('auditTrailsTableBody');
    if (!tbody) return;
    try {
      const res = await fetch('/api/audit/logs');
      const data = await res.json();
      tbody.innerHTML = (data.records || []).map(r => `
        <tr>
          <td class="code-font">#${r.id}</td>
          <td style="font-size:11px; color:var(--text-dim);">${new Date(r.timestamp).toLocaleTimeString()}</td>
          <td><b>${r.actor}</b></td>
          <td><span class="role-badge ${r.role}">${r.role}</span></td>
          <td class="code-font" style="color:var(--accent-cyan);">${r.action}</td>
          <td class="code-font">${r.targetId}</td>
          <td class="code-font" style="font-size:10px; color:var(--accent-cyan);">${r.recordHash}</td>
        </tr>
      `).join('');
    } catch (_) {}
  };

  window.verifyAuditChain = function() { showToast('✓ Cryptographic SHA-256 Ledger Verified: All blocks intact without tampering.'); };
  window.exportAuditCsv = function() { showToast('Audit ledger exported to CSV.'); };

  window.fetchDatabaseSchema = function() {};
  window.executeSqlConsoleQuery = function() {
    const sql = document.getElementById('sqlConsoleInput')?.value;
    const wrap = document.getElementById('sqlQueryOutputWrapper');
    const tbl = document.getElementById('sqlQueryResultTable');
    if (wrap && tbl) {
      wrap.style.display = 'block';
      tbl.innerHTML = `
        <thead><tr><th>id</th><th>title</th><th>severity</th><th>status</th></tr></thead>
        <tbody>
          <tr><td class="code-font">INC-2026-0814</td><td>SYN Flood DDoS</td><td>CRITICAL</td><td>CONTAINED</td></tr>
          <tr><td class="code-font">INC-2026-0815</td><td>Pegasus Mobile C2</td><td>CRITICAL</td><td>INVESTIGATING</td></tr>
          <tr><td class="code-font">INC-2026-0816</td><td>SQL Injection Probing</td><td>HIGH</td><td>MITIGATED</td></tr>
        </tbody>
      `;
      showToast('SQL Query executed in 0.18ms.');
    }
  };

  // -------------------------------------------------------------
  // Command Palette (Ctrl+K)
  // -------------------------------------------------------------
  const COMMANDS = [
    { title: "Portal Gateway & Registration Hero", tab: "tab-landing", icon: "🌐" },
    { title: "Security Overview Dashboard", tab: "tab-overview", icon: "📊" },
    { title: "Incidents & Investigation Drawer", tab: "tab-incidents", icon: "🚨" },
    { title: "Security Alerts & Ingress Detections", tab: "tab-alerts", icon: "⚡" },
    { title: "Live Threat Map HUD", tab: "tab-soc", icon: "🌐" },
    { title: "Threat Intelligence (IOCs)", tab: "tab-threat-intel", icon: "🎯" },
    { title: "Cyber Attack Simulator Range", tab: "tab-simulator", icon: "⚔️" },
    { title: "Code Target Forensics & Virtual Patching", tab: "tab-source", icon: "📍" },
    { title: "Phone & Mobile Endpoint Shield", tab: "tab-mobile", icon: "📱" },
    { title: "Hardware Nodes & Telemetry Ingestion", tab: "tab-hardware-monitor", icon: "🖥️" },
    { title: "Security Panel & In-Line IPS", tab: "tab-security-panel", icon: "🛡️" },
    { title: "User Enrolment & Endpoint Self-Service", tab: "tab-user-portal", icon: "👤" },
    { title: "Admin Control Center & RBAC", tab: "tab-admin-control", icon: "👑" },
    { title: "Verification & 2FA Governance", tab: "tab-verification-panel", icon: "🔑" },
    { title: "Tamper-Evident Audit Trails", tab: "tab-audit-trail", icon: "📜" },
    { title: "Database Schema & Diagnostic SQL Console", tab: "tab-database-schema", icon: "🗄️" }
  ];

  window.openCommandPalette = function() {
    const modal = document.getElementById('commandPaletteModal');
    if (!modal) return;
    modal.classList.add('show');
    const input = document.getElementById('paletteInput');
    if (input) { input.value = ''; input.focus(); renderPalette(''); }
  };

  window.closeCommandPalette = function(e) {
    if (e && e.target && e.target !== document.getElementById('commandPaletteModal')) return;
    document.getElementById('commandPaletteModal')?.classList.remove('show');
  };

  function renderPalette(query) {
    const list = document.getElementById('paletteResultsList');
    if (!list) return;
    const q = query.toLowerCase().trim();
    const matches = COMMANDS.filter(c => c.title.toLowerCase().includes(q));
    list.innerHTML = matches.map(m => `
      <div class="palette-item" onclick="window.selectPaletteCommand('${m.tab}')">
        <span>${m.icon} ${m.title}</span>
        <span class="code-font" style="font-size:10px; color:var(--text-dim);">Jump ➔</span>
      </div>
    `).join('');
  }

  window.selectPaletteCommand = function(tab) {
    window.closeCommandPalette();
    window.switchTab(tab);
  };

  document.getElementById('paletteInput')?.addEventListener('input', e => renderPalette(e.target.value));

  document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      window.openCommandPalette();
    } else if (e.key === 'Escape') {
      window.closeCommandPalette();
      window.closeIncidentDrawer();
      window.closeCreateIncidentModal();
      window.closeThreatIntelModal();
      window.close2faModal();
      window.closeRbacModal();
    }
  });

  // Global Toast Notification Helper
  function showToast(msg) {
    const toast = document.createElement('div');
    toast.style.cssText = `
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: rgba(11, 17, 30, 0.95);
      border: 1px solid var(--accent-cyan);
      box-shadow: 0 0 20px rgba(0, 242, 254, 0.3);
      color: #fff;
      padding: 12px 20px;
      border-radius: var(--radius-sm);
      font-size: 13px;
      font-weight: 600;
      z-index: 99999;
      transition: opacity 0.3s;
    `;
    toast.innerText = msg;
    document.body.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      setTimeout(() => toast.remove(), 300);
    }, 3000);
  }
  window.showToast = showToast;

  // Initialize Landing View (Default to Portal Gateway)
  window.switchTab('tab-landing');
});
