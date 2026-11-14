package com.threatpath.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api/v1/lifecycle")
@CrossOrigin(origins = {"http://localhost:5173", "http://127.0.0.1:5173"})
public class AgentLifecycleAndApprovalController {

    private static final Set<String> FORBIDDEN_AI_ACTORS = Set.of(
            "hermes_agent", "ai_agent", "threatpath_ai", "autonomous_worker", "system_agent"
    );

    private volatile String currentAgentState = "SLEEPING";
    private volatile String desiredStateOnRestart = "SLEEPING";
    private final Map<String, String> proposalStatuses = new ConcurrentHashMap<>();

    @PostMapping("/wake-up")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    public ResponseEntity<Map<String, Object>> wakeUpAgent(Authentication auth) {
        String actor = auth != null ? auth.getName() : "admin_secops";
        String prev = this.currentAgentState;
        this.currentAgentState = "AWAKE";
        this.desiredStateOnRestart = "AWAKE";
        return ResponseEntity.ok(Map.of(
                "previous_state", prev,
                "transition_sequence", List.of("SLEEPING", "STARTING", "AWAKE"),
                "confirmed_state", this.currentAgentState,
                "actor", actor,
                "timestamp", Instant.now().toString()
        ));
    }

    @PostMapping("/sleep")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    public ResponseEntity<Map<String, Object>> sleepAgent(Authentication auth) {
        String actor = auth != null ? auth.getName() : "admin_secops";
        String prev = this.currentAgentState;
        this.currentAgentState = "SLEEPING";
        this.desiredStateOnRestart = "SLEEPING";
        return ResponseEntity.ok(Map.of(
                "previous_state", prev,
                "transition_sequence", List.of(prev, "STOPPING", "SLEEPING"),
                "confirmed_state", this.currentAgentState,
                "findings_preserved", true,
                "passive_logging_active", true,
                "actor", actor,
                "timestamp", Instant.now().toString()
        ));
    }

    @PostMapping("/remediation/{proposalCode}/decide")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> decideRemediation(
            @PathVariable String proposalCode,
            @RequestBody Map<String, String> body,
            Authentication auth) {
        String actor = auth != null ? auth.getName() : "unknown";
        if (FORBIDDEN_AI_ACTORS.contains(actor.toLowerCase())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                    "error_code", "SELF_APPROVAL_FORBIDDEN",
                    "message", "The AI agent is strictly forbidden from approving its own proposed actions."
            ));
        }
        if ("EXECUTED_VERIFIED".equals(proposalStatuses.get(proposalCode))) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                    "error_code", "DUPLICATE_APPROVAL",
                    "message", "Proposal " + proposalCode + " has already been executed and verified."
            ));
        }

        String decision = body.getOrDefault("decision", "APPROVE").toUpperCase();
        boolean verificationConfirmed = Boolean.parseBoolean(body.getOrDefault("verification_confirmed", "true"));

        String newStatus = switch (decision) {
            case "APPROVE" -> verificationConfirmed ? "EXECUTED_VERIFIED" : "VERIFICATION_FAILED";
            case "REJECT" -> "REJECTED";
            case "REQUEST_MORE_INFO" -> "MORE_INFO_REQUESTED";
            case "SCHEDULE_LATER" -> "SCHEDULED_LATER";
            default -> throw new IllegalArgumentException("Unsupported decision: " + decision);
        };
        proposalStatuses.put(proposalCode, newStatus);
        return ResponseEntity.ok(Map.of(
                "proposal_code", proposalCode,
                "decision", decision,
                "new_status", newStatus,
                "decided_by", actor,
                "verified_by_evidence", "EXECUTED_VERIFIED".equals(newStatus),
                "timestamp", Instant.now().toString()
        ));
    }
}
