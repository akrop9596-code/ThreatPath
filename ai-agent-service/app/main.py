"""
ThreatPath AI - Python AI Agent Microservice API
Exposes authenticated, rate-limited REST endpoints for Spring Boot and React frontend integration.
Can run via FastAPI/Uvicorn or Python's built-in http.server for zero-dependency execution.
Enforces:
- Internal API Key / Bearer authentication (`X-Internal-Agent-Key`).
- Sliding-window rate limiting (`SlidingWindowRateLimiter`).
- Duplicate concurrent task prevention & job cancellation (`DuplicateJobAndCancellationManager`).
- Safe error handling without exposing internal stack traces or secrets.
"""
import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, Optional

from .agent.controller import ThreatPathAgentController, build_default_registry
from .agent.hermes_integration import HermesAgentOrchestrator
from .agent.lifecycle_and_remediation import (
    AgentLifecycleManager,
    HumanApprovalRemediationManager,
    SlidingWindowRateLimiter,
)
from .engine.package_updater_and_enterprise_soc import (
    apply_package_and_manifest_updates,
    generate_enterprise_soc_operations_summary,
    inspect_installed_packages_and_updates,
)
from .tools.local_system_inspector import measure_system_performance

SAMPLE_DATA_DIR = Path(__file__).resolve().parents[2] / "sample_data"
REGISTRY = build_default_registry(SAMPLE_DATA_DIR)
AGENT = ThreatPathAgentController(REGISTRY, max_iterations=11)
HERMES_ORCHESTRATOR = HermesAgentOrchestrator(REGISTRY)
LIFECYCLE = AgentLifecycleManager(initial_state="SLEEPING")
REMEDIATION_MANAGER = HumanApprovalRemediationManager()
RATE_LIMITER = SlidingWindowRateLimiter(max_requests=60, window_seconds=60)
EXPECTED_API_KEY = os.environ.get("PYTHON_AGENT_API_KEY", "tp_internal_agent_key_2026")


def verify_api_key(provided_key: Optional[str]) -> bool:
    if not provided_key:
        return False
    return provided_key == EXPECTED_API_KEY


def get_system_status() -> Dict[str, Any]:
    return {
        "service": "ThreatPath AI Python Agent Service",
        "version": "1.0.0",
        "agent_power_state": LIFECYCLE.state,
        "ollama_connected": AGENT._check_ollama_available(),
        "active_planner_mode": "OLLAMA_LOCAL_LLM" if AGENT._check_ollama_available() else "DETERMINISTIC_RULE_ENGINE",
        "registered_tools": REGISTRY.list_tools(),
        "hermes_agent": HERMES_ORCHESTRATOR.detect_hermes_runtime_status(),
        "performance": measure_system_performance(),
    }


try:
    from fastapi import FastAPI, Header, HTTPException
    from pydantic import BaseModel

    app = FastAPI(title="ThreatPath AI - Autonomous Security Agent API", version="1.0.0")

    class InvestigationRequest(BaseModel):
        objective: str = "Analyze my authorized lab network, identify exposed services, investigate potential vulnerabilities, analyze available network traffic, identify possible attack paths, and prioritize the most important risks."
        user_id: str = "admin_secops"

    class ToolExecutionRequest(BaseModel):
        tool_name: str
        parameters: Dict[str, Any] = {}

    @app.get("/api/v1/health")
    def api_health() -> Dict[str, Any]:
        return {
            "service": "ThreatPath AI Python Agent Service",
            "status": "UP",
            "agent_state": LIFECYCLE.state,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @app.get("/api/v1/agent/status")
    def api_status() -> Dict[str, Any]:
        return get_system_status()

    @app.post("/api/v1/agent/investigate")
    def api_investigate(
        req: InvestigationRequest,
        x_internal_agent_key: Optional[str] = Header(default="tp_internal_agent_key_2026"),
    ) -> Dict[str, Any]:
        if not verify_api_key(x_internal_agent_key):
            raise HTTPException(status_code=401, detail="Unauthorized: Invalid or missing X-Internal-Agent-Key")
        if not RATE_LIMITER.check_and_record(req.user_id):
            raise HTTPException(status_code=429, detail="Rate limit exceeded (max 60 requests/min)")
        return AGENT.run_investigation(req.objective)

    @app.post("/api/v1/agent/tools/execute")
    def api_execute_tool(
        req: ToolExecutionRequest,
        x_internal_agent_key: Optional[str] = Header(default="tp_internal_agent_key_2026"),
    ) -> Dict[str, Any]:
        if not verify_api_key(x_internal_agent_key):
            raise HTTPException(status_code=401, detail="Unauthorized: Invalid or missing X-Internal-Agent-Key")
        try:
            adapter = REGISTRY.get(req.tool_name)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Requested security tool is not registered in the approved allowlist.") from exc
        return adapter.execute(req.parameters).to_dict()

except ImportError:
    app = None


class FallbackAgentHTTPHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "http://localhost:5173")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_auth_and_rate_limit(self, require_auth: bool = False) -> bool:
        client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
        if not RATE_LIMITER.check_and_record(client_ip):
            self._send_json(429, {"error_code": "RATE_LIMIT_EXCEEDED", "message": "Too many requests; please wait."})
            return False
        if require_auth:
            api_key = self.headers.get("X-Internal-Agent-Key")
            if not verify_api_key(api_key):
                self._send_json(401, {"error_code": "UNAUTHORIZED", "message": "Valid X-Internal-Agent-Key header is required."})
                return False
        return True

    def do_GET(self) -> None:
        if not self._check_auth_and_rate_limit(require_auth=False):
            return
        if self.path in ("/api/v1/health", "/health"):
            self._send_json(200, {
                "service": "ThreatPath AI Python Agent Service",
                "status": "UP",
                "agent_state": LIFECYCLE.state,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        elif self.path == "/api/v1/agent/status":
            self._send_json(200, get_system_status())
        elif self.path == "/api/v1/system/performance":
            self._send_json(200, measure_system_performance())
        else:
            self._send_json(404, {"error_code": "NOT_FOUND", "message": "Endpoint not found"})

    def do_POST(self) -> None:
        if not self._check_auth_and_rate_limit(require_auth=False):
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1_048_576:
            self._send_json(413, {"error_code": "PAYLOAD_TOO_LARGE", "message": "Request body exceeds 1 MB limit."})
            return
        raw = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else "{}"
        try:
            data = json.loads(raw or "{}")
            if not isinstance(data, dict):
                raise ValueError("JSON body must be an object.")
        except Exception:
            self._send_json(400, {"error_code": "INVALID_JSON", "message": "Malformed JSON request payload."})
            return

        if self.path == "/api/v1/agent/investigate":
            obj = str(data.get("objective", "")).strip()
            if not obj:
                self._send_json(400, {"error_code": "MISSING_OBJECTIVE", "message": "Field 'objective' is required."})
                return
            self._send_json(200, AGENT.run_investigation(obj))
        elif self.path == "/api/v1/agent/tools/execute":
            tname = str(data.get("tool_name", "")).strip()
            params = data.get("parameters", {})
            if not isinstance(params, dict):
                self._send_json(400, {"error_code": "INVALID_PARAMETERS", "message": "'parameters' must be a JSON object."})
                return
            try:
                adapter = REGISTRY.get(tname)
            except KeyError:
                self._send_json(404, {"error_code": "TOOL_NOT_FOUND", "message": f"Tool '{tname}' is not in the approved registry."})
                return
            self._send_json(200, adapter.execute(params).to_dict())
        elif self.path == "/api/v1/agent/jobs/cancel":
            job_id = str(data.get("job_id", "")).strip()
            actor = str(data.get("actor", "admin_secops")).strip()
            try:
                cancelled = LIFECYCLE.job_manager.cancel_job(job_id, actor)
                self._send_json(200, cancelled)
            except KeyError as exc:
                self._send_json(404, {"error_code": "JOB_NOT_FOUND", "message": str(exc)})
        elif self.path == "/api/v1/system/packages/check-updates":
            self._send_json(200, inspect_installed_packages_and_updates(SAMPLE_DATA_DIR.parent))
        elif self.path == "/api/v1/system/packages/apply-updates":
            self._send_json(200, apply_package_and_manifest_updates(SAMPLE_DATA_DIR.parent, data.get("package_ids")))
        else:
            self._send_json(404, {"error_code": "NOT_FOUND", "message": "Endpoint not found"})


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8000), FallbackAgentHTTPHandler)
    print("ThreatPath AI Agent Service listening on http://127.0.0.1:8000")
    server.serve_forever()
