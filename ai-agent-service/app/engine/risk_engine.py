"""
ThreatPath AI - Phase 7: Explainable Deterministic Risk Prioritization Engine
Calculates reproducible numerical risk scores (0.00 - 100.00) without LLM hallucination
or double-counting correlated factors.

Documented Formula:
  Base_Score (0..100) =
      (CVSS_v3 * 3.5)                       [Max 35.0 pts: Inherent vulnerability severity]
    + (Exploitability_Weight * 25.0)        [Max 25.0 pts: Unproven=0.25, PoC=0.65, Active=1.00]
    + (Asset_Criticality_Weight * 2.5)      [Max 25.0 pts: Asset criticality 1..10 scaled to 25]
    + (Exposure_Reachability_Weight * 15.0) [Max 15.0 pts: Isolated=0.30, Internal_Pivot=0.75, DMZ_Exposed=1.00]

  Final_Risk_Score = round(Base_Score * Confidence_Multiplier, 2)
  Thresholds:
    CRITICAL : >= 80.0
    HIGH     : 60.0 - 79.99
    MEDIUM   : 35.0 - 59.99
    LOW      : < 35.0
"""
from typing import Any, Dict, List

EXPLOITABILITY_WEIGHTS = {
    "UNPROVEN": 0.25,
    "POC_AVAILABLE": 0.65,
    "ACTIVE_EXPLOITATION_OBSERVED": 1.00,
}

EXPOSURE_WEIGHTS = {
    "ISOLATED": 0.30,
    "INTERNAL_PIVOT_REACHABLE": 0.75,
    "DMZ_INTERNET_EXPOSED": 1.00,
}


def calculate_finding_risk(
    finding_code: str,
    asset_code: str,
    hostname: str,
    ip_address: str,
    cve_id: str,
    title: str,
    cvss_v3: float,
    exploitability_status: str,
    asset_criticality_1_to_10: float,
    exposure_state: str,
    confidence: float,
    supporting_evidence: List[str],
    related_attack_paths: List[str],
    remediation_fix: str,
) -> Dict[str, Any]:
    cvss_clamped = max(0.0, min(10.0, float(cvss_v3)))
    crit_clamped = max(1.0, min(10.0, float(asset_criticality_1_to_10)))
    conf_clamped = max(0.1, min(1.0, float(confidence)))

    exp_factor = EXPLOITABILITY_WEIGHTS.get(exploitability_status, 0.25)
    reach_factor = EXPOSURE_WEIGHTS.get(exposure_state, 0.50)

    cvss_pts = round(cvss_clamped * 3.5, 2)
    exploit_pts = round(exp_factor * 25.0, 2)
    crit_pts = round(crit_clamped * 2.5, 2)
    reach_pts = round(reach_factor * 15.0, 2)

    raw_base = cvss_pts + exploit_pts + crit_pts + reach_pts
    final_score = round(raw_base * conf_clamped, 2)

    if final_score >= 80.0:
        severity = "CRITICAL"
    elif final_score >= 60.0:
        severity = "HIGH"
    elif final_score >= 35.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    formula_breakdown = (
        f"Score {final_score}/100 = ("
        f"CVSS[{cvss_clamped}*3.5={cvss_pts}] + "
        f"Exploit[{exploitability_status}={exploit_pts}] + "
        f"Criticality[{crit_clamped}*2.5={crit_pts}] + "
        f"Reachability[{exposure_state}={reach_pts}]"
        f") * Confidence[{conf_clamped}]"
    )

    why_first = (
        f"{cve_id} on {hostname} ({ip_address}) scores {final_score}/100 ({severity}) because "
        f"it combines a CVSS {cvss_clamped} flaw with {exploitability_status.replace('_', ' ').lower()} "
        f"and {exposure_state.replace('_', ' ').lower()} posture on a criticality-{crit_clamped}/10 asset."
    )

    return {
        "finding_code": finding_code,
        "asset_code": asset_code,
        "hostname": hostname,
        "ip_address": ip_address,
        "cve_id": cve_id,
        "title": title,
        "risk_score": final_score,
        "severity": severity,
        "components": {
            "cvss_points": cvss_pts,
            "exploitability_points": exploit_pts,
            "criticality_points": crit_pts,
            "reachability_points": reach_pts,
            "confidence_multiplier": conf_clamped,
        },
        "formula_explanation": formula_breakdown,
        "supporting_evidence": supporting_evidence,
        "related_attack_paths": related_attack_paths,
        "confidence": conf_clamped,
        "recommended_fix": remediation_fix,
        "why_address_first": why_first,
    }


def prioritize_all_findings(findings_inputs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    scored = [calculate_finding_risk(**item) for item in findings_inputs]
    scored.sort(key=lambda x: x["risk_score"], reverse=True)
    for idx, item in enumerate(scored, start=1):
        item["priority_rank"] = idx
    return scored
