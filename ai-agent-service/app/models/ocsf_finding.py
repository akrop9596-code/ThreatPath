"""
ThreatPath AI - Normalized Security Finding Engine (OCSF-Compatible Schema)
All integrated System, Network, Code, Reverse-Engineering, and Threat-Intel tools
normalize their outputs into this 19-field internal schema.
Supports deterministic severity/priority ranking and lossless multi-tool deduplication.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class NormalizedSecurityFinding:
    finding_id: str
    source_tool: str
    finding_category: str  # SYSTEM_SECURITY | NETWORK_SECURITY | CODE_SECURITY | REVERSE_ENGINEERING | THREAT_INTEL
    affected_asset: str
    title: str
    description: str
    severity: str  # Critical | High | Medium | Low | Informational
    confidence: str  # High | Medium | Low
    evidence: List[str] = field(default_factory=list)
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    source_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    detection_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    cve_ids: List[str] = field(default_factory=list)
    attack_techniques: List[str] = field(default_factory=list)
    recommended_remediation: str = ""
    approval_status: str = "PENDING_REVIEW"
    remediation_status: str = "OPEN"
    verification_status: str = "UNVERIFIED"
    raw_tool_references: List[str] = field(default_factory=list)

    def dedup_fingerprint(self) -> str:
        """Deterministic deduplication key combining asset, category, file/line, and primary title/CVE."""
        cve_part = ",".join(sorted(self.cve_ids)) if self.cve_ids else self.title[:48].lower()
        loc_part = f"{self.file_path or ''}:{self.line_number or 0}"
        return f"{self.finding_category}|{self.affected_asset}|{loc_part}|{cve_part}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class NormalizedFindingEngine:
    """
    Deduplicates findings across multiple tools without losing evidence or source attribution.
    Uses deterministic rules for severity ranking—Hermes Agent explains findings but never invents verdicts.
    """

    SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}

    def __init__(self) -> None:
        self._by_fingerprint: Dict[str, NormalizedSecurityFinding] = {}

    def ingest(self, finding: NormalizedSecurityFinding) -> NormalizedSecurityFinding:
        fp = finding.dedup_fingerprint()
        if fp not in self._by_fingerprint:
            if finding.source_tool not in finding.raw_tool_references:
                finding.raw_tool_references.append(finding.source_tool)
            self._by_fingerprint[fp] = finding
            return finding

        # Merge evidence and tool attribution without losing any source
        existing = self._by_fingerprint[fp]
        if finding.source_tool not in existing.source_tool.split(" + "):
            existing.source_tool = f"{existing.source_tool} + {finding.source_tool}"
        for ev in finding.evidence:
            if ev not in existing.evidence:
                existing.evidence.append(ev)
        for cve in finding.cve_ids:
            if cve not in existing.cve_ids:
                existing.cve_ids.append(cve)
        for tech in finding.attack_techniques:
            if tech not in existing.attack_techniques:
                existing.attack_techniques.append(tech)
        for ref in finding.raw_tool_references + [finding.source_tool]:
            if ref not in existing.raw_tool_references:
                existing.raw_tool_references.append(ref)

        # Keep the highest deterministic severity if corroborated by multiple tools
        if self.SEVERITY_ORDER.get(finding.severity, 0) > self.SEVERITY_ORDER.get(existing.severity, 0):
            existing.severity = finding.severity

        return existing

    def list_prioritized(self) -> List[Dict[str, Any]]:
        items = list(self._by_fingerprint.values())
        items.sort(
            key=lambda f: (self.SEVERITY_ORDER.get(f.severity, 0), len(f.evidence)),
            reverse=True,
        )
        return [i.to_dict() for i in items]
