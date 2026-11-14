# ThreatPath AI — Installation & Multi-User Setup Guide

## 1. Supported Operating Systems & Hardware Profiles
- **Linux**: Debian 12+, Ubuntu 22.04 / 24.04 LTS (x86_64 / ARM64)
- **Windows**: Windows 10 / 11 (WSL2 recommended for full POSIX `/proc/net` & ELF inspection)
- **Hardware Profiles**:
  - **Profile 1 — Core Lightweight (< 4 GB RAM)**: Local OS inspection, Python AST/SAST, binary static inspection (`file`, `readelf`), offline PCAP parser, and deterministic Hermes MCP fallback.
  - **Profile 2 — Network Security Add-ons (4–8 GB RAM)**: Adds optional `nmap`, `tshark`, `suricata`, and `zeek` CLI binaries.
  - **Profile 3 — Advanced Analyst Add-ons (8–16+ GB RAM)**: Adds optional local Ollama LLM (`nousresearch/hermes-3-llama-3.1-8b`), `clamscan`, `semgrep`, `gitleaks`, and `ghidraRun`.

## 2. Clean Installation Steps
```bash
# 1. Verify host environment & installed tools
python3 scripts/check_env.py

# 2. Copy and restrict configuration file permissions (owner-only 0600)
cp .env.example .env
chmod 0600 .env

# 3. Run the automated verification suite (45+ unit, integration & security tests)
python3 ai-agent-service/tests/test_threatpath.py

# 4. Start the Python AI Agent Service
python3 -m ai_agent_service.app.main
```

## 3. Uninstallation & Data Cleanup
To remove a user account and cascade-delete all associated scans, findings, approvals, and logs without affecting other users on the machine, invoke `ThreatPathDatabaseStore.delete_user_account(user_id)` or remove the local SQLite database file (`threatpath_local.db`).
