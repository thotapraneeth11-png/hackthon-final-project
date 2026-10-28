package com.cybershield.soc.controller;

import com.cybershield.soc.model.*;
import com.cybershield.soc.service.SocService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.*;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class SocApiController {

    @Autowired
    private SocService socService;

    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getStatus() {
        Map<String, Object> resp = new HashMap<>();
        resp.put("status", "UP");
        resp.put("metrics", socService.getMetrics());

        List<Map<String, Object>> recentAlerts = new ArrayList<>();
        Map<String, Object> a1 = new HashMap<>();
        a1.put("id", "ALT-1793021288414-655");
        a1.put("threatType", "DDOS_SYN_FLOOD");
        a1.put("severity", "CRITICAL");
        a1.put("srcIp", "91.240.118.172");
        a1.put("confidence", 87);
        a1.put("status", "MITIGATED");
        a1.put("timestamp", Instant.now().toEpochMilli() - 60000);
        recentAlerts.add(a1);

        resp.put("recentAlerts", recentAlerts);
        return ResponseEntity.ok(resp);
    }

    @GetMapping("/metrics/soc-overview")
    public ResponseEntity<Map<String, Object>> getSocOverview() {
        Map<String, Object> resp = new HashMap<>();
        resp.put("success", true);

        Map<String, Object> posture = new HashMap<>();
        posture.put("score", 91);
        posture.put("level", "EXCELLENT");
        posture.put("color", "var(--accent-emerald)");

        List<Map<String, Object>> domains = new ArrayList<>();
        Map<String, Object> d1 = new HashMap<>(); d1.put("name", "Perimeter Gateway"); d1.put("score", 96); d1.put("color", "var(--accent-emerald)"); domains.add(d1);
        Map<String, Object> d2 = new HashMap<>(); d2.put("name", "Mobile & Endpoint Shield"); d2.put("score", 94); d2.put("color", "var(--accent-emerald)"); domains.add(d2);
        Map<String, Object> d3 = new HashMap<>(); d3.put("name", "Identity & Access (UEBA)"); d3.put("score", 92); d3.put("color", "var(--accent-cyan)"); domains.add(d3);
        Map<String, Object> d4 = new HashMap<>(); d4.put("name", "Data Loss Prevention (DLP)"); d4.put("score", 95); d4.put("color", "var(--accent-emerald)"); domains.add(d4);
        posture.put("domains", domains);
        resp.put("posture", posture);

        Map<String, Object> perf = new HashMap<>();
        perf.put("mttdFormatted", "1.2s");
        perf.put("mttrFormatted", "4.8s");
        perf.put("autonomousMitigationRate", "94.6%");
        perf.put("triageSlaCompliance", "98.8%");
        resp.put("performance", perf);

        Map<String, Integer> sev = new HashMap<>();
        sev.put("CRITICAL", 4); sev.put("HIGH", 7); sev.put("MEDIUM", 2); sev.put("LOW", 2);
        resp.put("severityCounts", sev);

        Map<String, Object> trends = new HashMap<>();
        trends.put("labels", Arrays.asList("12h", "10h", "8h", "6h", "4h", "2h", "Now"));
        trends.put("data", Arrays.asList(8, 14, 22, 16, 28, 36, 42));
        resp.put("alertTrends", trends);

        return ResponseEntity.ok(resp);
    }

    @GetMapping("/incidents")
    public ResponseEntity<Map<String, Object>> getIncidents() {
        Map<String, Object> resp = new HashMap<>();
        resp.put("success", true);
        resp.put("total", socService.getIncidents().size());
        resp.put("incidents", socService.getIncidents());
        return ResponseEntity.ok(resp);
    }

    @GetMapping("/threat-intel/indicators")
    public ResponseEntity<Map<String, Object>> getIndicators() {
        Map<String, Object> resp = new HashMap<>();
        resp.put("success", true);
        resp.put("total", socService.getIndicators().size());
        resp.put("indicators", socService.getIndicators());
        return ResponseEntity.ok(resp);
    }

    @GetMapping("/admin/users")
    public ResponseEntity<Map<String, Object>> getUsers() {
        Map<String, Object> resp = new HashMap<>();
        resp.put("success", true);
        resp.put("users", socService.getUsers());
        resp.put("total", socService.getUsers().size());
        return ResponseEntity.ok(resp);
    }

    @PostMapping("/admin/users")
    public ResponseEntity<Map<String, Object>> registerUser(@RequestBody UserEndpoint user) {
        UserEndpoint created = socService.registerUser(user);
        Map<String, Object> resp = new HashMap<>();
        resp.put("success", true);
        resp.put("user", created);
        return ResponseEntity.status(HttpStatus.CREATED).body(resp);
    }

    @GetMapping("/admin/admins")
    public ResponseEntity<Map<String, Object>> getAdmins() {
        Map<String, Object> resp = new HashMap<>();
        resp.put("success", true);
        resp.put("admins", socService.getAdmins());
        return ResponseEntity.ok(resp);
    }

    @PostMapping("/admin/login")
    public ResponseEntity<Map<String, Object>> adminLogin(@RequestBody Map<String, String> credentials) {
        String u = credentials.getOrDefault("username", "").toUpperCase();
        String p = credentials.getOrDefault("password", "");

        if (("SUNNY".equals(u) && ("MONKEY".equals(p) || "AdminPass2026!".equals(p))) ||
            ("ALEX.RIVERA".equals(u) && "AdminPass2026!".equals(p))) {
            Map<String, Object> resp = new HashMap<>();
            resp.put("success", true);
            Map<String, String> adminUser = new HashMap<>();
            adminUser.put("name", u);
            adminUser.put("username", u);
            adminUser.put("role", "SUPER_ADMIN");
            resp.put("user", adminUser);
            return ResponseEntity.ok(resp);
        }

        Map<String, Object> err = new HashMap<>();
        err.put("error", "Invalid administrator credentials");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(err);
    }

    @GetMapping("/auth/sessions")
    public ResponseEntity<Map<String, Object>> getSessions() {
        Map<String, Object> resp = new HashMap<>();
        resp.put("success", true);
        List<Map<String, Object>> sess = new ArrayList<>();
        Map<String, Object> s1 = new HashMap<>();
        s1.put("token", "CS-SES-99a1...");
        s1.put("name", "Sunny");
        s1.put("role", "SUPER_ADMIN");
        s1.put("ip", "127.0.0.1");
        s1.put("userAgent", "Chrome / Windows 11");
        sess.add(s1);
        resp.put("sessions", sess);
        return ResponseEntity.ok(resp);
    }

    @GetMapping("/verification/totp-status")
    public ResponseEntity<Map<String, Object>> getTotpStatus() {
        Map<String, Object> resp = new HashMap<>();
        resp.put("success", true);
        resp.put("currentCode", "777888");
        long sec = 30 - (Instant.now().getEpochSecond() % 30);
        resp.put("secondsRemaining", sec);
        resp.put("secret", "JBSWY3DPEHPK3PXP");
        return ResponseEntity.ok(resp);
    }

    @GetMapping("/hardware/overview")
    public ResponseEntity<Map<String, Object>> getHardwareOverview() {
        Map<String, Object> resp = new HashMap<>();
        resp.put("success", true);
        Map<String, Object> cluster = new HashMap<>();
        cluster.put("nodes", socService.getHardwareNodes());
        cluster.put("avgCpu", 32.2);
        cluster.put("avgMem", 57.8);
        resp.put("cluster", cluster);
        return ResponseEntity.ok(resp);
    }

    @GetMapping("/audit/logs")
    public ResponseEntity<Map<String, Object>> getAuditLogs() {
        Map<String, Object> resp = new HashMap<>();
        resp.put("success", true);
        resp.put("total", socService.getAuditTrails().size());
        resp.put("records", socService.getAuditTrails());
        return ResponseEntity.ok(resp);
    }

    @PostMapping("/simulate")
    public ResponseEntity<Map<String, Object>> simulateAttack(@RequestBody Map<String, Object> payload) {
        Map<String, Object> resp = new HashMap<>();
        resp.put("success", true);
        resp.put("message", "Attack simulation vector executed.");
        return ResponseEntity.ok(resp);
    }

    @PostMapping("/lockdown/emergency")
    public ResponseEntity<Map<String, Object>> emergencyLockdown() {
        socService.applyEmergencyLockdown(true);
        Map<String, Object> resp = new HashMap<>();
        resp.put("success", true);
        resp.put("message", "Lockdown active");
        return ResponseEntity.ok(resp);
    }

    @PostMapping("/lockdown/release")
    public ResponseEntity<Map<String, Object>> releaseLockdown() {
        socService.applyEmergencyLockdown(false);
        Map<String, Object> resp = new HashMap<>();
        resp.put("success", true);
        resp.put("message", "Lockdown released");
        return ResponseEntity.ok(resp);
    }

    @PostMapping("/patch/apply")
    public ResponseEntity<Map<String, Object>> applyPatch() {
        Map<String, Object> resp = new HashMap<>();
        resp.put("success", true);
        resp.put("message", "Virtual patch applied");
        return ResponseEntity.ok(resp);
    }
}
