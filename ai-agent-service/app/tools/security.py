"""
ThreatPath AI - Security Guardrails, Target Allowlist Validation & Prompt-Injection Defense
Never allows arbitrary shell execution, unauthorized IP targets, or untrusted packet strings
to hijack the LLM prompt context.
"""
import ipaddress
import re
from typing import List, Tuple

DEFAULT_ALLOWED_CIDRS = [
    "127.0.0.1/32",
    "10.10.20.0/24",
    "192.168.56.0/24",
]

SAFE_NMAP_PROFILES = {
    "quick_safe": ["-sV", "-T3", "--top-ports", "100"],
    "version_conservative": ["-sV", "-T2", "--version-light", "--top-ports", "50"],
    "ping_discovery": ["-sn", "-PE", "-T3"],
}

PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.IGNORECASE),
    re.compile(r"system\s*prompt", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+", re.IGNORECASE),
    re.compile(r"(drop\s+database|rm\s+-rf|curl\s+http|wget\s+http|;\s*sh\b)", re.IGNORECASE),
]

SECRET_REDACTION_PATTERNS = [
    (re.compile(r"(Authorization:\s*Bearer\s+)[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(password|passwd|secret|api_key)\s*[:=]\s*\S+", re.IGNORECASE), r"\1=[REDACTED_SECRET]"),
]


class TargetAuthorizationError(PermissionError):
    """Raised when a requested scan target is outside the authorized lab allowlist."""


class ToolInputValidationError(ValueError):
    """Raised when tool parameters violate strict schema or safety rules."""


def validate_authorized_target(target: str, allowed_cidrs: List[str] = None) -> str:
    """
    Validates that `target` is a valid IPv4 address or CIDR block strictly inside
    the explicitly authorized lab subnets. Rejects shell metacharacters or external IPs.
    """
    if not target or not isinstance(target, str):
        raise ToolInputValidationError("Target specification must be a non-empty string.")

    cleaned = target.strip()
    forbidden_chars = [";", "&", "|", "`", "$", "(", ")", "<", ">", " ", "\n", "\r"]
    if any(ch in cleaned for ch in forbidden_chars):
        raise ToolInputValidationError(f"Forbidden shell or control characters in target: {cleaned!r}")

    cidrs = allowed_cidrs or DEFAULT_ALLOWED_CIDRS
    allowed_nets = [ipaddress.ip_network(c, strict=False) for c in cidrs]

    try:
        if "/" in cleaned:
            req_net = ipaddress.ip_network(cleaned, strict=False)
            if not any(req_net.subnet_of(net) for net in allowed_nets):
                raise TargetAuthorizationError(
                    f"Target subnet {cleaned} is NOT in authorized allowlist {cidrs}."
                )
        else:
            req_ip = ipaddress.ip_address(cleaned)
            if not any(req_ip in net for net in allowed_nets):
                raise TargetAuthorizationError(
                    f"Target IP {cleaned} is NOT in authorized allowlist {cidrs}."
                )
    except ValueError as exc:
        raise ToolInputValidationError(f"Invalid IP or CIDR target '{cleaned}': {exc}") from exc

    return cleaned


def sanitize_untrusted_telemetry(raw_text: str, max_length: int = 240) -> Tuple[str, bool]:
    """
    Sanitizes untrusted strings extracted from PCAP payloads (HTTP headers, DNS queries,
    service banners) to neutralize indirect prompt injection and redact credentials.
    Returns (sanitized_string, injection_detected_flag).
    """
    if not raw_text:
        return "", False

    text = str(raw_text)
    injection_detected = False

    for pattern in PROMPT_INJECTION_PATTERNS:
        if pattern.search(text):
            injection_detected = True
            text = pattern.sub("[PROMPT_INJECTION_ATTEMPT_REDACTED]", text)

    for pattern, replacement in SECRET_REDACTION_PATTERNS:
        text = pattern.sub(replacement, text)

    text = "".join(ch if 32 <= ord(ch) <= 126 else " " for ch in text)
    if len(text) > max_length:
        text = text[:max_length] + "...[TRUNCATED]"

    return text.strip(), injection_detected
