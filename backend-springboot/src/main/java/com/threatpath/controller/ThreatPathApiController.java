package com.threatpath.controller;

import com.threatpath.dto.AuthorizedScanRequest;
import com.threatpath.dto.InvestigationStartRequest;
import com.threatpath.entity.AssetEntity;
import com.threatpath.entity.AuditEventEntity;
import com.threatpath.repository.AuditEventRepository;
import com.threatpath.service.ThreatPathOrchestrationService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1")
@CrossOrigin(origins = "*")
public class ThreatPathApiController {

    private final ThreatPathOrchestrationService orchestrationService;
    private final AuditEventRepository auditEventRepository;

    public ThreatPathApiController(
            ThreatPathOrchestrationService orchestrationService,
            AuditEventRepository auditEventRepository) {
        this.orchestrationService = orchestrationService;
        this.auditEventRepository = auditEventRepository;
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        return ResponseEntity.ok(Map.of(
                "service", "ThreatPath AI Spring Boot Backend",
                "status", "UP",
                "timestamp", Instant.now().toString()
        ));
    }

    @GetMapping("/assets")
    public ResponseEntity<List<AssetEntity>> listAssets() {
        return ResponseEntity.ok(orchestrationService.listAuthorizedAssets());
    }

    @PostMapping("/scans/nmap")
    public ResponseEntity<Map<String, Object>> runNmapScan(
            @Valid @RequestBody AuthorizedScanRequest req,
            Authentication auth) {
        String user = auth != null ? auth.getName() : "student_analyst";
        return ResponseEntity.ok(orchestrationService.triggerAuthorizedNmapScan(req, user));
    }

    @PostMapping("/investigations/run")
    public ResponseEntity<Map<String, Object>> runInvestigation(
            @Valid @RequestBody InvestigationStartRequest req,
            Authentication auth) {
        String user = auth != null ? auth.getName() : "student_analyst";
        return ResponseEntity.ok(orchestrationService.triggerAiInvestigation(req.getObjective(), user));
    }

    @GetMapping("/audit-logs")
    public ResponseEntity<List<AuditEventEntity>> listAuditLogs() {
        return ResponseEntity.ok(auditEventRepository.findTop50ByOrderByCreatedAtDesc());
    }
}
