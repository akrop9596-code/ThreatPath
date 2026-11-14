package com.threatpath.service;

import com.threatpath.dto.AuthorizedScanRequest;
import com.threatpath.entity.AssetEntity;
import com.threatpath.entity.AuditEventEntity;
import com.threatpath.repository.AssetRepository;
import com.threatpath.repository.AuditEventRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

@Service
public class ThreatPathOrchestrationService {

    private static final Pattern SAFE_TARGET_PATTERN = Pattern.compile(
            "^(127\.0\.0\.1(/32)?|10\.10\.20\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(/24|/32)?|192\.168\.56\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(/24|/32)?)$"
    );

    private final AssetRepository assetRepository;
    private final AuditEventRepository auditEventRepository;
    private final RestTemplate restTemplate;

    @Value("${threatpath.agent.base-url:http://127.0.0.1:8000}")
    private String pythonAgentBaseUrl;

    @Value("${threatpath.agent.internal-api-key:tp_internal_agent_key_2026}")
    private String internalApiKey;

    public ThreatPathOrchestrationService(
            AssetRepository assetRepository,
            AuditEventRepository auditEventRepository,
            RestTemplate restTemplate) {
        this.assetRepository = assetRepository;
        this.auditEventRepository = auditEventRepository;
        this.restTemplate = restTemplate;
    }

    private static String escapeJsonValue(String input) {
        if (input == null) return "";
        return input.replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\n", " ")
                    .replace("\r", " ");
    }

    public List<AssetEntity> listAuthorizedAssets() {
        return assetRepository.findAll();
    }

    public Map<String, Object> triggerAiInvestigation(String objective, String username) {
        auditEventRepository.save(new AuditEventEntity(
                "AI_INVESTIGATION_STARTED",
                username,
                "agent/investigate",
                "ALLOWED",
                "{\"objective\": \"" + escapeJsonValue(objective) + "\"}"
        ));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Internal-Agent-Key", internalApiKey);

        Map<String, Object> payload = new HashMap<>();
        payload.put("objective", objective);
        payload.put("user_id", username);

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(payload, headers);
        @SuppressWarnings("unchecked")
        Map<String, Object> response = restTemplate.postForObject(
                pythonAgentBaseUrl + "/api/v1/agent/investigate",
                request,
                Map.class
        );
        return response;
    }

    public Map<String, Object> triggerAuthorizedNmapScan(AuthorizedScanRequest req, String username) {
        if (!Boolean.TRUE.equals(req.getHumanApprovedForActiveScan())) {
            throw new IllegalArgumentException("Active scan execution requires explicit human approval flag.");
        }
        String target = req.getTarget() != null ? req.getTarget().trim() : "";
        if (!SAFE_TARGET_PATTERN.matcher(target).matches()) {
            auditEventRepository.save(new AuditEventEntity(
                    "NMAP_SCAN_BLOCKED",
                    username,
                    escapeJsonValue(target),
                    "DENIED_UNAUTHORIZED_TARGET",
                    "{\"reason\": \"Target failed strict IPv4/CIDR allowlist validation\"}"
            ));
            throw new SecurityException("Target " + target + " is not in the authorized lab allowlist.");
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Internal-Agent-Key", internalApiKey);

        Map<String, Object> body = new HashMap<>();
        body.put("tool_name", "run_authorized_nmap_scan");
        body.put("parameters", Map.of("target", target, "profile", req.getProfile()));

        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(body, headers);
        @SuppressWarnings("unchecked")
        Map<String, Object> res = restTemplate.postForObject(
                pythonAgentBaseUrl + "/api/v1/agent/tools/execute",
                entity,
                Map.class
        );

        auditEventRepository.save(new AuditEventEntity(
                "NMAP_SCAN_EXECUTED",
                username,
                target,
                "ALLOWED",
                "{\"profile\": \"" + escapeJsonValue(req.getProfile()) + "\"}"
        ));
        return res;
    }
}
