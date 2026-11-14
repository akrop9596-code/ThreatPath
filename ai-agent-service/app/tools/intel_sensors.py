"""
ThreatPath AI - Vulnerability Lookup (OpenVAS XML + CPE Knowledge Base)
and Network Sensor Adapters (Zeek Logs & Suricata EVE JSON Alerts)
"""
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .base import BaseSecurityToolAdapter, EvidenceMetadata
from .security import sanitize_untrusted_telemetry, validate_authorized_target


KNOWN_CPE_VULNS: Dict[str, List[Dict[str, Any]]] = {
    "cpe:/a:apache:http_server:2.4.49": [
        {
            "cve_id": "CVE-2021-41773",
            "title": "Apache HTTP Server 2.4.49 Path Traversal and Remote Code Execution",
            "cvss_v3_score": 9.8,
            "severity": "CRITICAL",
            "exploitability_status": "ACTIVE_EXPLOITATION_OBSERVED",
            "remediation": "Upgrade Apache httpd to >= 2.4.51 and set 'Require all denied' outside DocumentRoot.",
        }
    ],
    "cpe:/a:apache:tomcat:9.0.30": [
        {
            "cve_id": "CVE-2020-1938",
            "title": "Apache Tomcat AJP Connector 'Ghostcat' Arbitrary File Read/Inclusion",
            "cvss_v3_score": 9.8,
            "severity": "CRITICAL",
            "exploitability_status": "POC_AVAILABLE",
            "remediation": "Upgrade Apache Tomcat to >= 9.0.31, disable AJP port 8009 if unused, or require secret.",
        }
    ],
    "cpe:/a:pivotal_software:redis:6.0.15": [
        {
            "cve_id": "CVE-2022-0543",
            "title": "Redis Debian Packaging Lua Sandbox Escape / Unauthenticated Command Execution",
            "cvss_v3_score": 10.0,
            "severity": "CRITICAL",
            "exploitability_status": "ACTIVE_EXPLOITATION_OBSERVED",
            "remediation": "Bind Redis to 127.0.0.1, configure strong ACL/requirepass, and patch Debian package.",
        }
    ],
    "cpe:/a:oracle:mysql:8.0.27": [
        {
            "cve_id": "CVE-2022-21245",
            "title": "Oracle MySQL Server 8.0.27 Optimizer Privilege Escalation / DoS",
            "cvss_v3_score": 6.5,
            "severity": "MEDIUM",
            "exploitability_status": "UNPROVEN",
            "remediation": "Upgrade MySQL Server to >= 8.0.28 and restrict port 3306 strictly to app tier subnet.",
        }
    ],
}


def parse_openvas_xml(xml_path: Path) -> List[Dict[str, Any]]:
    try:
        root = ET.fromstring(xml_path.read_text(encoding="utf-8"))
    except ET.ParseError as exc:
        raise ValueError(f"Malformed OpenVAS XML report: {exc}") from exc

    findings: List[Dict[str, Any]] = []
    for res_el in root.findall(".//result"):
        name, _ = sanitize_untrusted_telemetry(res_el.findtext("name", ""), 200)
        host_el = res_el.find("host")
        host_ip = (host_el.text or "").strip() if host_el is not None and host_el.text else ""
        port_str = res_el.findtext("port", "0/tcp")
        port_num = int(port_str.split("/")[0]) if "/" in port_str and port_str.split("/")[0].isdigit() else 0
        cve = res_el.findtext("nvt/cve", "NOCVE")
        cvss = float(res_el.findtext("nvt/cvss_base", "0.0"))
        solution, _ = sanitize_untrusted_telemetry(res_el.findtext("nvt/solution", ""), 240)
        desc, _ = sanitize_untrusted_telemetry(res_el.findtext("description", ""), 240)
        qod = float(res_el.findtext("qod/value", "80")) / 100.0
        severity = "CRITICAL" if cvss >= 9.0 else ("HIGH" if cvss >= 7.0 else ("MEDIUM" if cvss >= 4.0 else "LOW"))
        findings.append({
            "host_ip": host_ip,
            "port": port_num,
            "cve_id": cve,
            "title": name,
            "cvss_v3_score": cvss,
            "severity": severity,
            "confidence": round(qod, 2),
            "evidence": desc,
            "remediation": solution,
            "source_tool": "OPENVAS_SCAN",
        })
    return findings


class VulnerabilityLookupAdapter(BaseSecurityToolAdapter):
    name = "lookup_vulnerability"
    description = (
        "Correlates discovered service CPEs against known CVE intelligence and imports "
        "authorized Greenbone OpenVAS XML assessment reports when available."
    )
    permission_required = "READ_ONLY"
    timeout_seconds = 30

    def __init__(self, openvas_xml_path: Path) -> None:
        self.openvas_xml_path = openvas_xml_path

    def input_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "cpe_list": {"type": "array", "items": {"type": "string"}},
                "include_openvas_report": {"type": "boolean", "default": True},
            },
        }

    def validate_inputs(self, params: Dict[str, Any]) -> Dict[str, Any]:
        cpes = params.get("cpe_list") or list(KNOWN_CPE_VULNS.keys())
        return {
            "cpe_list": [str(c) for c in cpes],
            "include_openvas_report": bool(params.get("include_openvas_report", True)),
        }

    def _execute_impl(self, validated_params: Dict[str, Any]) -> Tuple[Dict[str, Any], EvidenceMetadata]:
        matched_cves: List[Dict[str, Any]] = []
        for cpe in validated_params["cpe_list"]:
            for vuln in KNOWN_CPE_VULNS.get(cpe, []):
                matched_cves.append({"cpe": cpe, **vuln})

        openvas_findings: List[Dict[str, Any]] = []
        if validated_params["include_openvas_report"] and self.openvas_xml_path.exists():
            openvas_findings = parse_openvas_xml(self.openvas_xml_path)

        return {
            "cpe_matched_vulnerabilities": matched_cves,
            "openvas_report_findings": openvas_findings,
            "total_correlated_findings": len(openvas_findings) or len(matched_cves),
        }, EvidenceMetadata(
            source_tool=self.name,
            execution_mode="VERIFIED_FIXTURE",
            confidence=0.93,
            raw_artifact_ref=self.openvas_xml_path.name,
            assumptions=["Correlated Nmap CPE banners with OpenVAS NVT XML results."],
        )


class SecurityAlertsAdapter(BaseSecurityToolAdapter):
    name = "get_security_alerts"
    description = (
        "Ingests intrusion detection alerts from Suricata EVE JSON and network connection/DNS "
        "telemetry from Zeek logs to corroborate active exploitation and lateral movement."
    )
    permission_required = "READ_ONLY"
    timeout_seconds = 30

    def __init__(self, suricata_path: Path, zeek_path: Path) -> None:
        self.suricata_path = suricata_path
        self.zeek_path = zeek_path

    def input_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "filter_ip": {"type": "string", "description": "Optional authorized IP filter"}
            },
        }

    def validate_inputs(self, params: Dict[str, Any]) -> Dict[str, Any]:
        f_ip = params.get("filter_ip")
        if f_ip is not None and str(f_ip).strip():
            f_ip = validate_authorized_target(str(f_ip).strip())
        else:
            f_ip = None
        return {"filter_ip": f_ip}

    def _execute_impl(self, validated_params: Dict[str, Any]) -> Tuple[Dict[str, Any], EvidenceMetadata]:
        suricata_raw = json.loads(self.suricata_path.read_text(encoding="utf-8")) if self.suricata_path.exists() else []
        zeek_raw = json.loads(self.zeek_path.read_text(encoding="utf-8")) if self.zeek_path.exists() else {}

        f_ip = validated_params.get("filter_ip")
        if f_ip:
            suricata_raw = [a for a in suricata_raw if a.get("src_ip") == f_ip or a.get("dest_ip") == f_ip]

        return {
            "suricata_alerts": suricata_raw,
            "zeek_conn_logs": zeek_raw.get("conn_logs", []),
            "zeek_dns_logs": zeek_raw.get("dns_logs", []),
            "alert_count": len(suricata_raw),
        }, EvidenceMetadata(
            source_tool=self.name,
            execution_mode="VERIFIED_FIXTURE",
            confidence=0.91,
            raw_artifact_ref=f"{self.suricata_path.name}+{self.zeek_path.name}",
            assumptions=["Suricata EVE JSON and Zeek conn/dns logs ingested from lab sensor telemetry."],
        )
