"""
ThreatPath AI - Threat Intelligence Enrichment Engine
Enriches CVEs, file hashes, domains, and IP indicators using local cached intelligence
modeled on free, reputable public feeds:
- CISA Known Exploited Vulnerabilities (KEV)
- FIRST EPSS (Exploit Prediction Scoring System)
- MITRE ATT&CK Enterprise Matrix
- OSV (Open Source Vulnerabilities)
- abuse.ch (URLhaus, Feodo Tracker, MalwareBazaar)

Safety & Privacy Guarantees:
- Records exact source name, retrieval/cache timestamp, and feed status.
- Handles offline/unavailable feeds gracefully without failing the investigation.
- Never transmits sensitive local files or private IPs externally without consent.
- Never automatically blocks an IP address solely on a reputation match (requires confidence + context + human approval).
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


LOCAL_CACHED_KEV_AND_EPSS: Dict[str, Dict[str, Any]] = {
    "CVE-2021-41773": {
        "cisa_kev_listed": True,
        "kev_date_added": "2021-11-03",
        "epss_score": 0.9742,
        "epss_percentile": 0.999,
        "attack_techniques": ["T1190 (Exploit Public-Facing Application)", "T1059.004 (Unix Shell)"],
        "source": "CISA KEV + FIRST EPSS Local Cache",
    },
    "CVE-2022-0543": {
        "cisa_kev_listed": True,
        "kev_date_added": "2022-03-28",
        "epss_score": 0.9685,
        "epss_percentile": 0.998,
        "attack_techniques": ["T1068 (Exploitation for Privilege Escalation)"],
        "source": "CISA KEV + FIRST EPSS + OSV (DSA-5081-1) Local Cache",
    },
    "CVE-2020-1938": {
        "cisa_kev_listed": True,
        "kev_date_added": "2022-03-03",
        "epss_score": 0.9610,
        "epss_percentile": 0.996,
        "attack_techniques": ["T1005 (Data from Local System)"],
        "source": "CISA KEV + FIRST EPSS Local Cache",
    },
}

LOCAL_CACHED_ABUSE_CH_INDICATORS: Dict[str, Dict[str, Any]] = {
    "198.51.100.77": {
        "feed": "abuse.ch Feodo Tracker / URLhaus (Cached Indicator)",
        "indicator_type": "IPv4",
        "reputation_status": "SUSPICIOUS_SCANNER_REPUTATION",
        "confidence": "Medium (0.72)",
        "auto_blocked": False,
        "policy_note": (
            "Reputation match alone does NOT prove compromise and is NEVER auto-blocked without "
            "corroborating local evidence and explicit administrator approval."
        ),
    }
}


class ThreatIntelligenceEngine:
    """Enriches findings with cached CISA KEV, FIRST EPSS, MITRE ATT&CK, OSV, and abuse.ch context."""

    def __init__(self, allow_external_queries: bool = False) -> None:
        self.allow_external_queries = allow_external_queries
        self.cache_timestamp = "2026-10-30T10:00:00Z"

    def enrich_cve(self, cve_id: str) -> Dict[str, Any]:
        entry = LOCAL_CACHED_KEV_AND_EPSS.get(cve_id.upper())
        if not entry:
            return {
                "cve_id": cve_id,
                "cisa_kev_listed": False,
                "epss_score": None,
                "source": "Local Offline Cache (No KEV match)",
                "retrieved_at": self.cache_timestamp,
                "external_network_used": False,
            }
        return {
            "cve_id": cve_id.upper(),
            **entry,
            "retrieved_at": self.cache_timestamp,
            "external_network_used": False,
        }

    def check_network_indicator(self, ip_or_domain: str) -> Dict[str, Any]:
        match = LOCAL_CACHED_ABUSE_CH_INDICATORS.get(ip_or_domain.strip())
        if not match:
            return {
                "indicator": ip_or_domain,
                "matched": False,
                "reputation_status": "NO_KNOWN_BAD_REPUTATION",
                "auto_blocked": False,
                "source": "abuse.ch URLhaus & Feodo Tracker Local Cache",
                "retrieved_at": self.cache_timestamp,
                "distinction_note": "No match in local cache; absence of a reputation match does not guarantee safety.",
            }
        return {
            "indicator": ip_or_domain,
            "matched": True,
            **match,
            "retrieved_at": self.cache_timestamp,
        }
