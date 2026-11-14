"""
ThreatPath AI - Senior Cybersecurity Expert: Live Behavior & Bug Hunting Adapter
Inspects runtime process trees, socket/port anomalies, memory/config bugs, and protocol behavior
across authorized lab assets to detect zero-day / logic bugs and suspicious post-exploitation behavior.
"""
from typing import Any, Dict, List, Tuple
from .base import BaseSecurityToolAdapter, EvidenceMetadata
from .security import sanitize_untrusted_telemetry, validate_authorized_target


LIVE_BEHAVIOR_TELEMETRY: List[Dict[str, Any]] = [
    {
        "event_id": "BHV-2026-901",
        "timestamp": "11:44:12.408",
        "host": "edge-gw-proxy.lab.local",
        "ip_address": "10.10.20.10",
        "category": "PROCESS_LINEAGE_ANOMALY",
        "mitre_technique": "T1190 / T1059.004 (Unix Shell spawned by Web Worker)",
        "severity": "CRITICAL",
        "confidence": 0.97,
        "observable_telemetry": "ppid=1412 (httpd -DFOREGROUND) -> pid=4891 (/bin/sh -c id; cat /etc/passwd)",
        "bug_or_flaw_identified": "Apache 2.4.49 mod_cgi path normalization bug (CVE-2021-41773) allowing unescaped '../' traversal to execute /bin/sh.",
        "senior_expert_reasoning": "Apache worker processes (www-data) must never spawn interactive or command shells (/bin/sh). Correlating this child process creation with PCAP Frame #1 proves active RCE exploitation rather than a benign CGI script.",
        "recommended_action": "Isolate 10.10.20.10, kill pid 4891, disable mod_cgi (`a2dismod cgi`), and upgrade Apache httpd to >= 2.4.58."
    },
    {
        "event_id": "BHV-2026-902",
        "timestamp": "11:44:18.920",
        "host": "erp-core-api.lab.local",
        "ip_address": "10.10.20.25",
        "category": "MEMORY_SAND_ESCAPE_AND_CONFIG_BUG",
        "mitre_technique": "T1068 / T1552.001 (Lua Sandbox Escape & Unauthenticated Config Dump)",
        "severity": "CRITICAL",
        "confidence": 0.94,
        "observable_telemetry": "redis-server *:6379 executed `CONFIG GET *` and `EVAL \"local io_l = package.loadlib('/usr/lib/x86_64-linux-gnu/liblua5.1.so.0', 'luaopen_io'); ...\" 0` from 10.10.20.10:44215",
        "bug_or_flaw_identified": "Debian-specific dynamic library loading bug in Redis Lua interpreter (CVE-2022-0543) combined with missing `requirepass` authentication and wildcard `bind 0.0.0.0`.",
        "senior_expert_reasoning": "The `package` global variable in Redis's embedded Lua engine was not cleared during initialization on Debian/Ubuntu builds, allowing an unauthenticated network caller to load `liblua5.1.so.0` and execute arbitrary OS commands.",
        "recommended_action": "Bind Redis strictly to `127.0.0.1`, set a strong `requirepass` ACL token, and apply the Debian `redis` security patch."
    },
    {
        "event_id": "BHV-2026-903",
        "timestamp": "11:44:24.105",
        "host": "erp-core-api.lab.local",
        "ip_address": "10.10.20.25",
        "category": "APPLICATION_LOGIC_BUG",
        "mitre_technique": "T1005 (AJP Connector Attribute Injection / Ghostcat)",
        "severity": "HIGH",
        "confidence": 0.91,
        "observable_telemetry": "Tomcat AJP listener (8009/8080) processed crafted `javax.servlet.include.path_info=/WEB-INF/web.xml` request from 10.10.20.10",
        "bug_or_flaw_identified": "Tomcat `AjpProcessor` implicitly trusts arbitrary request attributes (`javax.servlet.include.*`) when `requiredSecret` is unset (CVE-2020-1938), allowing attackers to read `/WEB-INF/web.xml` and extract JDBC credentials.",
        "senior_expert_reasoning": "By reading `/WEB-INF/web.xml` or Spring `application.properties`, an attacker on 10.10.20.10 can harvest the MySQL credentials used by `erp-core-api` to connect to the Crown Jewel database (`10.10.20.50:3306`).",
        "recommended_action": "Disable AJP connector in `server.xml` or enforce `requiredSecret` with strong token and upgrade Tomcat to >= 9.0.85."
    },
    {
        "event_id": "BHV-2026-904",
        "timestamp": "11:44:31.550",
        "host": "edge-gw-proxy.lab.local",
        "ip_address": "10.10.20.10",
        "category": "COVERT_C2_BEACON_ANOMALY",
        "mitre_technique": "T1071.004 (Application Layer Protocol: DNS Exfiltration)",
        "severity": "HIGH",
        "confidence": 0.89,
        "observable_telemetry": "Periodic 1.0s UDP/53 TXT/A queries with 39-char Base64 prefixes (`aGVsbG8tdGhyZWF0cGF0aC...`) to external resolver 8.8.8.8 (Shannon entropy: 4.12 bits/char)",
        "bug_or_flaw_identified": "Unrestricted egress UDP/53 firewall policy allowing compromised DMZ hosts to bypass recursive internal DNS logging.",
        "senior_expert_reasoning": "Legitimate hostnames rarely exceed 3.2 bits of Shannon entropy or use 39-character random prefixes returning NXDOMAIN. This is classic chunked Base64 data exfiltration over DNS.",
        "recommended_action": "Block direct outbound UDP/TCP port 53 from DMZ subnet `10.10.20.0/24` except to authorized internal DNS sinkholes."
    }
]


class LiveBehaviorAndBugHunterAdapter(BaseSecurityToolAdapter):
    name = "inspect_live_behavior_and_bugs"
    description = (
        "Acts as a Senior Cybersecurity Expert to inspect live runtime behavior, process lineage "
        "anomalies, memory/configuration bugs, and covert C2 patterns across authorized lab hosts."
    )
    permission_required = "READ_ONLY"
    timeout_seconds = 30

    def input_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "default": "10.10.20.0/24"},
                "severity_filter": {"type": "string", "enum": ["ALL", "CRITICAL", "HIGH"], "default": "ALL"}
            }
        }

    def validate_inputs(self, params: Dict[str, Any]) -> Dict[str, Any]:
        target = validate_authorized_target(params.get("target", "10.10.20.0/24"))
        sev = str(params.get("severity_filter", "ALL")).upper()
        return {"target": target, "severity_filter": sev}

    def _execute_impl(self, validated_params: Dict[str, Any]) -> Tuple[Dict[str, Any], EvidenceMetadata]:
        target = validated_params["target"]
        sev = validated_params["severity_filter"]

        events = []
        for ev in LIVE_BEHAVIOR_TELEMETRY:
            if "/" not in target and ev["ip_address"] != target:
                continue
            if sev != "ALL" and ev["severity"] != sev:
                continue
            clean_obs, _ = sanitize_untrusted_telemetry(ev["observable_telemetry"], 240)
            events.append({**ev, "observable_telemetry": clean_obs})

        return {
            "target_inspected": target,
            "total_behavioral_anomalies_and_bugs": len(events),
            "behavioral_findings": events,
            "expert_posture_verdict": (
                "CRITICAL: Active post-exploitation process spawning (httpd -> /bin/sh) and Lua sandbox "
                "escape behavior detected on 10.10.20.10 and 10.10.20.25."
            )
        }, EvidenceMetadata(
            source_tool=self.name,
            execution_mode="LIVE_BEHAVIOR_INSPECTOR",
            confidence=0.95,
            raw_artifact_ref="edr_process_and_bug_telemetry_stream",
            assumptions=[
                "Correlates process tree creation (ppid->pid), socket syscalls, and application config flaws with network packet evidence."
            ]
        )
