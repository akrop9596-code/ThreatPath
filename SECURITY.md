# ThreatPath AI — Security Policy & Defensive Architecture

## 1. Core Security Guarantees
1. **Zero Arbitrary Shell Execution**: All tool executions pass through `ApprovedToolRegistry` with `shell=False` and strict argument validation.
2. **Enforced Network Scan Allowlists**: Public IP addresses (`8.8.8.8`, `1.1.1.1`, etc.) and unapproved subnets are blocked deterministically by `validate_authorized_target()` before any tool or LLM step can run.
3. **No Autonomous System Modification or Self-Approval**: The AI agent (`hermes_agent`, `ai_agent`) is cryptographically and programmatically blocked from approving its own remediation proposals (`AI_AGENT_IDENTITIES` check).
4. **Mandatory Post-Fix Verification**: Remediation proposals are never marked `EXECUTED_VERIFIED` ("Fixed & Verified") unless the post-execution verification check succeeds.
5. **Untrusted Telemetry Prompt-Injection Defense**: Packet payloads, banners, and source-code comments are sanitized via `sanitize_untrusted_telemetry()` before reaching the agent planner.
6. **Multi-User Isolation**: All records in `ThreatPathDatabaseStore` are scoped by `(owner_user_id, installation_id)` with `ON DELETE CASCADE`.
