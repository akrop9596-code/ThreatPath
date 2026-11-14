"""
ThreatPath AI - Extensible Plugin-Style Security Tool Adapter Architecture
Every tool provides:
- Tool name & description
- Validated input schema
- Execution handler with timeout & resource limits
- Structured output schema
- Error handling & evidence metadata
- Permission requirements & audit logging
"""
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class EvidenceMetadata:
    source_tool: str
    execution_mode: str  # "LIVE_BINARY" or "VERIFIED_FIXTURE"
    confidence: float
    raw_artifact_ref: str
    assumptions: List[str] = field(default_factory=list)
    prompt_injection_redacted: bool = False


@dataclass
class ToolExecutionResult:
    tool_name: str
    status: str  # "SUCCESS", "ERROR", "TIMEOUT", "BLOCKED_ALLOWLIST"
    duration_ms: int
    permission_required: str
    validated_input: Dict[str, Any]
    structured_output: Dict[str, Any]
    evidence_metadata: EvidenceMetadata
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BaseSecurityToolAdapter(ABC):
    """Plugin interface for all defensive cybersecurity tools in ThreatPath AI."""

    name: str = "base_tool"
    description: str = "Abstract security tool adapter"
    permission_required: str = "READ_ONLY"
    timeout_seconds: int = 60
    requires_human_approval: bool = False

    @abstractmethod
    def input_schema(self) -> Dict[str, Any]:
        """Returns JSON Schema describing accepted parameters."""

    @abstractmethod
    def validate_inputs(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Validates and normalizes tool input parameters; raises ValueError/PermissionError on failure."""

    @abstractmethod
    def _execute_impl(self, validated_params: Dict[str, Any]) -> Tuple[Dict[str, Any], EvidenceMetadata]:
        """Performs the actual controlled tool execution and returns structured output + evidence metadata."""

    def execute(self, params: Dict[str, Any], audit_log: Optional[List[Dict[str, Any]]] = None) -> ToolExecutionResult:
        start = time.time()
        try:
            validated = self.validate_inputs(params or {})
        except PermissionError as exc:
            duration = int((time.time() - start) * 1000)
            res = ToolExecutionResult(
                tool_name=self.name,
                status="BLOCKED_ALLOWLIST",
                duration_ms=duration,
                permission_required=self.permission_required,
                validated_input=params or {},
                structured_output={},
                evidence_metadata=EvidenceMetadata(
                    source_tool=self.name,
                    execution_mode="BLOCKED",
                    confidence=1.0,
                    raw_artifact_ref="allowlist_guardrail",
                ),
                error_message=str(exc),
            )
            if audit_log is not None:
                audit_log.append({
                    "event_type": "TOOL_EXECUTION_BLOCKED",
                    "tool_name": self.name,
                    "decision": "DENIED_UNAUTHORIZED_TARGET",
                    "details": str(exc),
                })
            return res
        except Exception as exc:
            duration = int((time.time() - start) * 1000)
            return ToolExecutionResult(
                tool_name=self.name,
                status="ERROR",
                duration_ms=duration,
                permission_required=self.permission_required,
                validated_input=params or {},
                structured_output={},
                evidence_metadata=EvidenceMetadata(
                    source_tool=self.name,
                    execution_mode="VALIDATION_ERROR",
                    confidence=0.0,
                    raw_artifact_ref="schema_validator",
                ),
                error_message=f"Input validation failed: {exc}",
            )

        try:
            output, metadata = self._execute_impl(validated)
            duration = int((time.time() - start) * 1000)
            res = ToolExecutionResult(
                tool_name=self.name,
                status="SUCCESS",
                duration_ms=duration,
                permission_required=self.permission_required,
                validated_input=validated,
                structured_output=output,
                evidence_metadata=metadata,
            )
            if audit_log is not None:
                audit_log.append({
                    "event_type": "TOOL_EXECUTION_COMPLETED",
                    "tool_name": self.name,
                    "decision": "ALLOWED",
                    "execution_mode": metadata.execution_mode,
                    "duration_ms": duration,
                })
            return res
        except TimeoutError as exc:
            duration = int((time.time() - start) * 1000)
            return ToolExecutionResult(
                tool_name=self.name,
                status="TIMEOUT",
                duration_ms=duration,
                permission_required=self.permission_required,
                validated_input=validated,
                structured_output={},
                evidence_metadata=EvidenceMetadata(
                    source_tool=self.name,
                    execution_mode="TIMEOUT",
                    confidence=0.0,
                    raw_artifact_ref="timeout_guardrail",
                ),
                error_message=str(exc),
            )
        except Exception as exc:
            duration = int((time.time() - start) * 1000)
            return ToolExecutionResult(
                tool_name=self.name,
                status="ERROR",
                duration_ms=duration,
                permission_required=self.permission_required,
                validated_input=validated,
                structured_output={},
                evidence_metadata=EvidenceMetadata(
                    source_tool=self.name,
                    execution_mode="RUNTIME_ERROR",
                    confidence=0.0,
                    raw_artifact_ref="exception_handler",
                ),
                error_message=str(exc),
            )


class ApprovedToolRegistry:
    """Central registry of approved security tools exposed to the AI agent."""

    def __init__(self) -> None:
        self._tools: Dict[str, BaseSecurityToolAdapter] = {}

    def register(self, adapter: BaseSecurityToolAdapter) -> None:
        self._tools[adapter.name] = adapter

    def get(self, name: str) -> BaseSecurityToolAdapter:
        if name not in self._tools:
            raise KeyError(f"Tool '{name}' is not in the approved tool registry.")
        return self._tools[name]

    def list_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": t.name,
                "description": t.description,
                "permission_required": t.permission_required,
                "timeout_seconds": t.timeout_seconds,
                "requires_human_approval": t.requires_human_approval,
                "input_schema": t.input_schema(),
            }
            for t in self._tools.values()
        ]
