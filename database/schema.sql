-- ============================================================================
-- THREATPATH AI - COMPLETE MYSQL 8.0 SCHEMA (13 CORE TABLES)
-- Autonomous Cybersecurity Tool Orchestration & Attack Path Analysis Platform
-- ============================================================================

CREATE DATABASE IF NOT EXISTS threatpath_db
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE threatpath_db;

-- 1. USERS AND PERMISSIONS
CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    email VARCHAR(128) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('ADMIN', 'ANALYST', 'READ_ONLY') NOT NULL DEFAULT 'ANALYST',
    can_execute_active_scans BOOLEAN NOT NULL DEFAULT FALSE,
    can_approve_disruptive_ops BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP NULL,
    INDEX idx_users_role (role)
) ENGINE=InnoDB;

-- 2. ASSETS (Authorized Lab Hosts & Network Endpoints)
CREATE TABLE IF NOT EXISTS assets (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    asset_code VARCHAR(32) NOT NULL UNIQUE,
    hostname VARCHAR(128) NOT NULL,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    subnet_cidr VARCHAR(45) NOT NULL,
    mac_address VARCHAR(32) NULL,
    os_name VARCHAR(128) NULL,
    asset_type ENUM('WEB_SERVER', 'APP_SERVER', 'DATABASE', 'DOMAIN_CONTROLLER', 'WORKSTATION', 'GATEWAY', 'IOT_SENSOR') NOT NULL,
    network_zone ENUM('DMZ', 'INTERNAL_APP', 'RESTRICTED_DB', 'MGMT_LAB') NOT NULL,
    criticality_level ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL DEFAULT 'MEDIUM',
    criticality_weight DECIMAL(4,2) NOT NULL DEFAULT 5.00,
    is_authorized_target BOOLEAN NOT NULL DEFAULT TRUE,
    owner_department VARCHAR(64) DEFAULT 'SecOps Lab',
    last_seen_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_assets_ip (ip_address),
    INDEX idx_assets_zone_crit (network_zone, criticality_level)
) ENGINE=InnoDB;

-- 3. SCANS (Nmap & OpenVAS Background Scan Jobs)
CREATE TABLE IF NOT EXISTS scans (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    scan_uuid VARCHAR(64) NOT NULL UNIQUE,
    scan_type ENUM('NMAP_DISCOVERY', 'NMAP_SERVICE_VERSION', 'OPENVAS_IMPORT', 'ZEEK_INGEST', 'SURICATA_INGEST') NOT NULL,
    scan_profile VARCHAR(64) NOT NULL,
    target_spec VARCHAR(128) NOT NULL,
    initiated_by_user_id BIGINT NULL,
    investigation_id BIGINT NULL,
    status ENUM('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'BLOCKED_UNAUTHORIZED') NOT NULL DEFAULT 'PENDING',
    execution_mode ENUM('LIVE_BINARY', 'VERIFIED_FIXTURE') NOT NULL DEFAULT 'LIVE_BINARY',
    command_executed VARCHAR(512) NULL,
    raw_output_hash VARCHAR(64) NULL,
    summary_json JSON NULL,
    error_message TEXT NULL,
    started_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_scans_user FOREIGN KEY (initiated_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_scans_status (status),
    INDEX idx_scans_target (target_spec)
) ENGINE=InnoDB;

-- 4. SERVICES (Discovered Open Ports & Fingerprinted Daemons)
CREATE TABLE IF NOT EXISTS services (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    asset_id BIGINT NOT NULL,
    scan_id BIGINT NULL,
    port INT NOT NULL,
    protocol ENUM('tcp', 'udp') NOT NULL DEFAULT 'tcp',
    state ENUM('open', 'filtered', 'closed') NOT NULL DEFAULT 'open',
    service_name VARCHAR(64) NOT NULL,
    product VARCHAR(128) NULL,
    version VARCHAR(64) NULL,
    cpe_uri VARCHAR(255) NULL,
    banner_grab TEXT NULL,
    is_exposed_externally BOOLEAN NOT NULL DEFAULT FALSE,
    first_discovered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_verified_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_services_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    CONSTRAINT fk_services_scan FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL,
    UNIQUE KEY uq_asset_port_proto (asset_id, port, protocol),
    INDEX idx_services_cpe (cpe_uri)
) ENGINE=InnoDB;

-- 5. VULNERABILITY FINDINGS (NVD/CVE + OpenVAS Correlated Findings)
CREATE TABLE IF NOT EXISTS vulnerability_findings (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    finding_code VARCHAR(48) NOT NULL UNIQUE,
    asset_id BIGINT NOT NULL,
    service_id BIGINT NULL,
    cve_id VARCHAR(32) NOT NULL,
    title VARCHAR(255) NOT NULL,
    source_tool ENUM('NMAP_CPE_MATCH', 'OPENVAS_SCAN', 'CORRELATED_INTEL') NOT NULL,
    cvss_v3_score DECIMAL(3,1) NOT NULL,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    exploitability_status ENUM('UNPROVEN', 'POC_AVAILABLE', 'ACTIVE_EXPLOITATION_OBSERVED') NOT NULL DEFAULT 'UNPROVEN',
    evidence_text TEXT NOT NULL,
    confidence_score DECIMAL(3,2) NOT NULL DEFAULT 0.85,
    status ENUM('OPEN', 'IN_REMEDIATION', 'MITIGATED', 'FALSE_POSITIVE') NOT NULL DEFAULT 'OPEN',
    remediation_summary TEXT NOT NULL,
    discovered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_vuln_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    CONSTRAINT fk_vuln_service FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE SET NULL,
    INDEX idx_vuln_cve (cve_id),
    INDEX idx_vuln_severity (severity, status)
) ENGINE=InnoDB;

-- 6. PACKET-ANALYSIS JOBS (Wireshark / TShark Offline PCAP Inspections)
CREATE TABLE IF NOT EXISTS packet_analysis_jobs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    job_uuid VARCHAR(64) NOT NULL UNIQUE,
    pcap_filename VARCHAR(255) NOT NULL,
    pcap_sha256 VARCHAR(64) NOT NULL,
    total_packets INT NOT NULL DEFAULT 0,
    total_bytes BIGINT NOT NULL DEFAULT 0,
    capture_duration_sec DECIMAL(10,2) NOT NULL DEFAULT 0.00,
    protocol_hierarchy_json JSON NOT NULL,
    endpoints_summary_json JSON NOT NULL,
    dns_queries_json JSON NULL,
    http_metadata_json JSON NULL,
    tls_handshakes_json JSON NULL,
    anomalies_detected_json JSON NOT NULL,
    execution_mode ENUM('TSHARK_BINARY', 'PYTHON_PCAP_PARSER') NOT NULL,
    analyzed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_pcap_sha256 (pcap_sha256)
) ENGINE=InnoDB;

-- 7. SECURITY ALERTS (Suricata IDS, Zeek Anomaly & TShark Heuristic Alerts)
CREATE TABLE IF NOT EXISTS security_alerts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    alert_uuid VARCHAR(64) NOT NULL UNIQUE,
    source_sensor ENUM('SURICATA_IDS', 'ZEEK_NSM', 'TSHARK_RULE') NOT NULL,
    signature_id VARCHAR(64) NOT NULL,
    signature_name VARCHAR(255) NOT NULL,
    category VARCHAR(128) NOT NULL,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    src_port INT NULL,
    dest_ip VARCHAR(45) NOT NULL,
    dest_port INT NULL,
    protocol VARCHAR(16) NOT NULL,
    asset_id BIGINT NULL,
    observation_type ENUM('OBSERVED_TRAFFIC_FACT', 'INFERRED_SUSPICIOUS_BEHAVIOR') NOT NULL,
    encrypted_payload_note VARCHAR(255) NOT NULL DEFAULT 'Plaintext header inspected; TLS payload remains opaque',
    raw_evidence_json JSON NOT NULL,
    is_acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    observed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_alerts_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL,
    INDEX idx_alerts_ips (src_ip, dest_ip),
    INDEX idx_alerts_severity (severity)
) ENGINE=InnoDB;

-- 8. ATTACK-PATH NODES (Graph Entities for Multi-Hop Traversal)
CREATE TABLE IF NOT EXISTS attack_path_nodes (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    node_key VARCHAR(64) NOT NULL UNIQUE,
    asset_id BIGINT NULL,
    node_type ENUM('EXTERNAL_ENTRY', 'HOST_ASSET', 'NETWORK_SERVICE', 'CROWN_JEWEL_ASSET') NOT NULL,
    display_label VARCHAR(128) NOT NULL,
    network_zone VARCHAR(32) NOT NULL,
    is_compromised_start BOOLEAN NOT NULL DEFAULT FALSE,
    is_critical_target BOOLEAN NOT NULL DEFAULT FALSE,
    metadata_json JSON NULL,
    CONSTRAINT fk_ap_node_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 9. ATTACK-PATH EDGES (Verified Connectivity vs Hypothesized Pivot Paths)
CREATE TABLE IF NOT EXISTS attack_path_edges (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    edge_key VARCHAR(64) NOT NULL UNIQUE,
    source_node_id BIGINT NOT NULL,
    target_node_id BIGINT NOT NULL,
    relationship_type ENUM('VERIFIED_TRAFFIC_FLOW', 'OPEN_SERVICE_REACHABILITY', 'HYPOTHESIZED_LATERAL_PIVOT') NOT NULL,
    is_confirmed_exploitable BOOLEAN NOT NULL DEFAULT FALSE,
    linked_cve_id VARCHAR(32) NULL,
    supporting_evidence TEXT NOT NULL,
    assumptions_text TEXT NOT NULL,
    edge_confidence DECIMAL(3,2) NOT NULL DEFAULT 0.75,
    traversal_cost DECIMAL(4,2) NOT NULL DEFAULT 1.00,
    CONSTRAINT fk_edge_src FOREIGN KEY (source_node_id) REFERENCES attack_path_nodes(id) ON DELETE CASCADE,
    CONSTRAINT fk_edge_dst FOREIGN KEY (target_node_id) REFERENCES attack_path_nodes(id) ON DELETE CASCADE,
    INDEX idx_edge_src_dst (source_node_id, target_node_id)
) ENGINE=InnoDB;

-- 10. RISK ASSESSMENTS (Explainable Deterministic Risk Scores)
CREATE TABLE IF NOT EXISTS risk_assessments (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    assessment_code VARCHAR(48) NOT NULL UNIQUE,
    asset_id BIGINT NOT NULL,
    vulnerability_id BIGINT NULL,
    composite_risk_score DECIMAL(5,2) NOT NULL,
    severity_label ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    cvss_component DECIMAL(5,2) NOT NULL,
    exploitability_component DECIMAL(5,2) NOT NULL,
    criticality_component DECIMAL(5,2) NOT NULL,
    exposure_reachability_component DECIMAL(5,2) NOT NULL,
    confidence_multiplier DECIMAL(3,2) NOT NULL,
    related_attack_path_summary TEXT NULL,
    scoring_formula_explanation TEXT NOT NULL,
    priority_rank INT NOT NULL DEFAULT 99,
    calculated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_risk_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    CONSTRAINT fk_risk_vuln FOREIGN KEY (vulnerability_id) REFERENCES vulnerability_findings(id) ON DELETE SET NULL,
    INDEX idx_risk_score_rank (composite_risk_score DESC, priority_rank ASC)
) ENGINE=InnoDB;

-- 11. AI INVESTIGATIONS (Bounded Observe-Plan-Act-Evaluate Runs)
CREATE TABLE IF NOT EXISTS ai_investigations (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    investigation_uuid VARCHAR(64) NOT NULL UNIQUE,
    objective_prompt TEXT NOT NULL,
    initiated_by_user_id BIGINT NULL,
    planner_mode ENUM('OLLAMA_LOCAL_LLM', 'DETERMINISTIC_RULE_ENGINE') NOT NULL,
    llm_model_name VARCHAR(64) NOT NULL DEFAULT 'deterministic-secops-v1',
    status ENUM('RUNNING', 'AWAITING_HUMAN_APPROVAL', 'COMPLETED', 'STOPPED_SAFETY_LIMIT', 'FAILED') NOT NULL,
    iterations_completed INT NOT NULL DEFAULT 0,
    max_iterations INT NOT NULL DEFAULT 8,
    reasoning_trace_json JSON NOT NULL,
    consolidated_report_markdown LONGTEXT NULL,
    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    CONSTRAINT fk_inv_user FOREIGN KEY (initiated_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_inv_status (status)
) ENGINE=InnoDB;

-- 12. TOOL EXECUTIONS (Step-by-Step Agent Adapter Audit Trail)
CREATE TABLE IF NOT EXISTS tool_executions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    investigation_id BIGINT NOT NULL,
    step_number INT NOT NULL,
    tool_name VARCHAR(64) NOT NULL,
    validated_input_json JSON NOT NULL,
    permission_check_passed BOOLEAN NOT NULL DEFAULT TRUE,
    execution_status ENUM('SUCCESS', 'ERROR', 'TIMEOUT', 'BLOCKED_ALLOWLIST') NOT NULL,
    duration_ms INT NOT NULL DEFAULT 0,
    structured_output_json JSON NOT NULL,
    evidence_summary TEXT NOT NULL,
    executed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_toolexec_inv FOREIGN KEY (investigation_id) REFERENCES ai_investigations(id) ON DELETE CASCADE,
    INDEX idx_toolexec_inv_step (investigation_id, step_number)
) ENGINE=InnoDB;

-- 13. REMEDIATION RECORDS & AUDIT EVENTS
CREATE TABLE IF NOT EXISTS remediation_records (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    remediation_code VARCHAR(48) NOT NULL UNIQUE,
    asset_id BIGINT NOT NULL,
    vulnerability_id BIGINT NULL,
    priority_rank INT NOT NULL,
    recommended_action TEXT NOT NULL,
    verification_command VARCHAR(255) NULL,
    risk_reduction_estimate DECIMAL(5,2) NOT NULL,
    assigned_to VARCHAR(64) NOT NULL DEFAULT 'SecOps Student Team',
    status ENUM('PENDING', 'IN_PROGRESS', 'VERIFIED_FIXED', 'ACCEPTED_RISK') NOT NULL DEFAULT 'PENDING',
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_rem_asset FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    CONSTRAINT fk_rem_vuln FOREIGN KEY (vulnerability_id) REFERENCES vulnerability_findings(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL,
    actor_username VARCHAR(64) NOT NULL,
    target_resource VARCHAR(128) NOT NULL,
    action_decision ENUM('ALLOWED', 'DENIED_UNAUTHORIZED_TARGET', 'DENIED_RBAC', 'PROMPT_INJECTION_REDACTED') NOT NULL,
    details_json JSON NOT NULL,
    client_ip VARCHAR(45) NOT NULL DEFAULT '127.0.0.1',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_decision (action_decision, created_at)
) ENGINE=InnoDB;


-- ============================================================================
-- PHASE 2, 3, 9 & 10 EXTENDED NORMALIZED TABLES (21-TABLE ENTERPRISE SCHEMA)
-- ============================================================================

-- 14. ROLES AND PERMISSIONS
CREATE TABLE IF NOT EXISTS roles_permissions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    role_name ENUM('ADMIN', 'ANALYST', 'READ_ONLY') NOT NULL,
    permission_key VARCHAR(64) NOT NULL,
    description VARCHAR(255) NOT NULL,
    UNIQUE KEY uq_role_perm (role_name, permission_key)
) ENGINE=InnoDB;

-- 15. TOOL INTEGRATIONS (Configured Adapter Health & Degraded Status)
CREATE TABLE IF NOT EXISTS tool_integrations (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    tool_name VARCHAR(64) NOT NULL UNIQUE,
    adapter_class VARCHAR(128) NOT NULL,
    defensive_purpose VARCHAR(255) NOT NULL,
    permission_required VARCHAR(64) NOT NULL,
    binary_installed BOOLEAN NOT NULL DEFAULT FALSE,
    operational_state ENUM('READY', 'DEGRADED_FIXTURE_FALLBACK', 'DISABLED', 'ERROR') NOT NULL DEFAULT 'READY',
    degraded_reason VARCHAR(255) NULL,
    timeout_seconds INT NOT NULL DEFAULT 60,
    last_health_check_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 16. AGENT CONFIGURATION (Desired State & Safety Limits Across Restarts)
CREATE TABLE IF NOT EXISTS agent_configuration (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(64) NOT NULL UNIQUE,
    desired_power_state ENUM('SLEEPING', 'AWAKE') NOT NULL DEFAULT 'SLEEPING',
    current_confirmed_state ENUM('SLEEPING', 'STARTING', 'AWAKE', 'INVESTIGATING', 'STOPPING', 'DEGRADED') NOT NULL DEFAULT 'SLEEPING',
    planner_mode ENUM('OLLAMA_LOCAL_LLM', 'DETERMINISTIC_FALLBACK') NOT NULL DEFAULT 'DETERMINISTIC_FALLBACK',
    max_iterations INT NOT NULL DEFAULT 8,
    scheduled_monitoring_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    updated_by VARCHAR(64) NOT NULL DEFAULT 'admin_secops',
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 17. AGENT LIFECYCLE EVENTS (Wake Up / Sleep Audit Trail)
CREATE TABLE IF NOT EXISTS agent_lifecycle_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    previous_state VARCHAR(32) NOT NULL,
    new_state VARCHAR(32) NOT NULL,
    transition_action ENUM('WAKE_UP', 'SLEEP', 'START_INVESTIGATION', 'COMPLETE_INVESTIGATION', 'SAFE_SHUTDOWN') NOT NULL,
    triggered_by VARCHAR(64) NOT NULL,
    active_tools_count INT NOT NULL DEFAULT 0,
    degraded_tools_json JSON NULL,
    notes VARCHAR(255) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_lifecycle_created (created_at)
) ENGINE=InnoDB;

-- 18. INVESTIGATION STEPS (8-Stage Observe->Plan->Validate->Act->Evaluate->Correlate->Prioritize->Report)
CREATE TABLE IF NOT EXISTS investigation_steps (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    investigation_id BIGINT NOT NULL,
    step_index INT NOT NULL,
    workflow_stage ENUM('OBSERVE', 'PLAN', 'VALIDATE', 'ACT', 'EVALUATE', 'CORRELATE', 'PRIORITIZE', 'REPORT') NOT NULL,
    tool_selected VARCHAR(64) NULL,
    validation_passed BOOLEAN NOT NULL DEFAULT TRUE,
    summary_text TEXT NOT NULL,
    evidence_json JSON NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_inv_steps_inv FOREIGN KEY (investigation_id) REFERENCES ai_investigations(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 19. REMEDIATION PROPOSALS (Human-in-the-Loop Approval Queue)
CREATE TABLE IF NOT EXISTS remediation_proposals (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    proposal_code VARCHAR(48) NOT NULL UNIQUE,
    finding_code VARCHAR(48) NOT NULL,
    asset_code VARCHAR(32) NOT NULL,
    proposed_change TEXT NOT NULL,
    reason_for_change TEXT NOT NULL,
    expected_security_benefit TEXT NOT NULL,
    potential_impact_downtime VARCHAR(255) NOT NULL,
    preconditions_dependencies TEXT NOT NULL,
    rollback_procedure TEXT NOT NULL,
    verification_plan TEXT NOT NULL,
    approval_status ENUM('PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'MORE_INFO_REQUESTED', 'SCHEDULED_LATER', 'EXECUTED_VERIFIED') NOT NULL DEFAULT 'PENDING_APPROVAL',
    scheduled_for TIMESTAMP NULL,
    action_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 20. APPROVAL RECORDS, EXECUTION RESULTS & VERIFICATION RESULTS
CREATE TABLE IF NOT EXISTS approval_records (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    proposal_code VARCHAR(48) NOT NULL,
    decision ENUM('APPROVE', 'REJECT', 'REQUEST_MORE_INFO', 'SCHEDULE_LATER') NOT NULL,
    decided_by_user VARCHAR(64) NOT NULL,
    decision_notes TEXT NULL,
    approved_action_hash VARCHAR(64) NOT NULL,
    decided_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS remediation_execution_results (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    proposal_code VARCHAR(48) NOT NULL,
    execution_status ENUM('SUCCESS', 'PARTIAL', 'FAILED', 'ROLLED_BACK') NOT NULL,
    execution_log TEXT NOT NULL,
    executed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS verification_results (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    proposal_code VARCHAR(48) NOT NULL,
    verification_tool VARCHAR(64) NOT NULL,
    evidence_confirmed_fixed BOOLEAN NOT NULL DEFAULT FALSE,
    verification_evidence TEXT NOT NULL,
    verified_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 21. NOTIFICATIONS & GENERATED REPORTS (With Deduplication Key)
CREATE TABLE IF NOT EXISTS notifications (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    notif_uuid VARCHAR(64) NOT NULL UNIQUE,
    dedup_key VARCHAR(128) NOT NULL UNIQUE,
    category ENUM('CRITICAL_FINDING', 'EXPOSURE_CHANGE', 'DANGEROUS_ATTACK_PATH', 'SUSPICIOUS_TRAFFIC', 'TOOL_DEGRADED', 'APPROVAL_REQUEST', 'REMEDIATION_RESULT') NOT NULL,
    severity ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO') NOT NULL,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    linked_finding_code VARCHAR(48) NULL,
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_notif_unread (is_read, severity)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS generated_reports (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    report_uuid VARCHAR(64) NOT NULL UNIQUE,
    investigation_uuid VARCHAR(64) NULL,
    report_type ENUM('INVESTIGATION_REPORT', 'RISK_SUMMARY', 'ASSET_INVENTORY', 'ATTACK_PATH_EXPLANATION', 'REMEDIATION_HISTORY') NOT NULL,
    title VARCHAR(255) NOT NULL,
    content_markdown LONGTEXT NOT NULL,
    generated_by VARCHAR(64) NOT NULL DEFAULT 'ThreatPath AI Engine',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
