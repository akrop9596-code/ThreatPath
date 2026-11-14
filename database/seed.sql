-- ============================================================================
-- THREATPATH AI - CLEAN FRESH-INSTALLATION SEED DATA
-- Contains ONLY default RBAC roles, initial administrator account, and
-- default SLEEPING agent configuration.
-- Zero fake assets, zero predefined CVEs, and zero fabricated findings.
-- ============================================================================
USE threatpath_db;

INSERT IGNORE INTO roles_permissions (role_name, permission_key, description) VALUES
('ADMIN', 'AGENT_WAKE_SLEEP', 'Start or stop the autonomous AI agent worker'),
('ADMIN', 'REGISTER_AUTHORIZED_ASSET', 'Add owned or explicitly authorized targets to allowlist'),
('ADMIN', 'RUN_ASSESSMENT', 'Execute read-only local and network security assessments'),
('ADMIN', 'APPROVE_REMEDIATION', 'Approve and execute reversible remediation proposals'),
('ANALYST', 'AGENT_WAKE_SLEEP', 'Start or stop the autonomous AI agent worker'),
('ANALYST', 'RUN_ASSESSMENT', 'Execute read-only local and network security assessments'),
('READ_ONLY', 'VIEW_REPORTS', 'View assessment reports and findings');

INSERT IGNORE INTO users (username, email, password_hash, role, can_execute_active_scans, can_approve_disruptive_ops)
VALUES
('admin_secops', 'admin@localhost', '$2a$10$7Q9xLocalAdminBcryptHashForAuthorizedHostUseOnly9999999', 'ADMIN', TRUE, TRUE);

INSERT IGNORE INTO agent_configuration (config_key, desired_power_state, current_confirmed_state, planner_mode, max_iterations, scheduled_monitoring_enabled, updated_by)
VALUES
('DEFAULT_AGENT_CONFIG', 'SLEEPING', 'SLEEPING', 'DETERMINISTIC_FALLBACK', 8, FALSE, 'system_init');
