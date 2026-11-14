# ThreatPath AI — Configuration & Environment Variables Reference

All runtime settings are controlled via `.env` (must be `chmod 0600`) and `ai-agent-service/hermes-threatpath-config.yaml`.

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `SERVER_PORT` | `8080` | Spring Boot REST API port |
| `PYTHON_AGENT_URL` | `http://127.0.0.1:8000` | Python AI Agent microservice endpoint |
| `PYTHON_AGENT_API_KEY` | *(Required in prod)* | Shared internal header key (`X-Internal-Agent-Key`) |
| `ALLOWED_SCAN_CIDRS` | `127.0.0.1/32,10.10.20.0/24,192.168.56.0/24` | Strictly enforced CIDR allowlist for active network scans |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | Optional local Ollama server for Hermes-3 inference |
| `HERMES_EXTERNAL_API_URL` | *(Empty — 100% local)* | Optional external LLM API URL (disclosed in UI when set) |
| `DEFAULT_POLL_INTERVAL_SEC` | `30` | Periodic `/proc/net` socket & interface polling interval |
