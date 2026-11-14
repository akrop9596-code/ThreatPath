package com.threatpath.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "audit_events")
public class AuditEventEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "event_type", nullable = false, length = 64)
    private String eventType;

    @Column(name = "actor_username", nullable = false, length = 64)
    private String actorUsername;

    @Column(name = "target_resource", nullable = false, length = 128)
    private String targetResource;

    @Column(name = "action_decision", nullable = false, length = 64)
    private String actionDecision;

    @Column(name = "details_json", nullable = false, columnDefinition = "JSON")
    private String detailsJson;

    @Column(name = "client_ip", nullable = false, length = 45)
    private String clientIp = "127.0.0.1";

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    public AuditEventEntity() {}

    public AuditEventEntity(String eventType, String actorUsername, String targetResource, String actionDecision, String detailsJson) {
        this.eventType = eventType;
        this.actorUsername = actorUsername;
        this.targetResource = targetResource;
        this.actionDecision = actionDecision;
        this.detailsJson = detailsJson;
    }

    public Long getId() { return id; }
    public String getEventType() { return eventType; }
    public String getActorUsername() { return actorUsername; }
    public String getTargetResource() { return targetResource; }
    public String getActionDecision() { return actionDecision; }
    public String getDetailsJson() { return detailsJson; }
    public String getClientIp() { return clientIp; }
    public Instant getCreatedAt() { return createdAt; }
}
