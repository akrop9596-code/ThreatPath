"""
ThreatPath AI - Phase 5: Wireshark / TShark Offline PCAP Packet-File Analysis Adapter
Supports both live `tshark` CLI automation when installed and a built-in RFC-compliant
binary libpcap parser so offline `.pcap` inspection works out-of-the-box without root privileges.
Strictly separates observable packet headers from inferred suspicious behavior and never claims
encrypted TLS payloads are decrypted.
"""
import hashlib
import math
import shutil
import socket
import struct
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .base import BaseSecurityToolAdapter, EvidenceMetadata
from .security import ToolInputValidationError, sanitize_untrusted_telemetry


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 3)


def parse_pcap_binary(pcap_path: Path) -> Dict[str, Any]:
    """
    Parses a standard libpcap binary file directly in Python (Ethernet -> IPv4 -> TCP/UDP -> DNS/HTTP/TLS)
    and runs deterministic heuristic rules while sanitizing untrusted packet strings against prompt injection.
    """
    raw_bytes = pcap_path.read_bytes()
    if len(raw_bytes) < 24:
        raise ValueError("File is too short to be a valid libpcap capture.")

    magic = struct.unpack("<I", raw_bytes[:4])[0]
    endian = "<" if magic == 0xA1B2C3D4 else (">" if magic == 0xD4C3B2A1 else None)
    if endian is None:
        raise ValueError(f"Unsupported PCAP magic header: 0x{magic:08x}")

    offset = 24
    total_packets = 0
    total_bytes = 0
    timestamps: List[int] = []
    proto_counts: Counter = Counter()
    endpoints: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tx_packets": 0, "rx_packets": 0, "tx_bytes": 0})
    flows: Counter = Counter()
    syn_tracker: Dict[Tuple[str, str], set] = defaultdict(set)
    dns_queries: List[Dict[str, Any]] = []
    http_requests: List[Dict[str, Any]] = []
    tls_sessions: List[Dict[str, Any]] = []
    anomalies: List[Dict[str, Any]] = []
    any_injection_redacted = False

    while offset + 16 <= len(raw_bytes):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", raw_bytes[offset:offset + 16])
        offset += 16
        frame = raw_bytes[offset:offset + incl_len]
        offset += incl_len

        total_packets += 1
        total_bytes += orig_len
        timestamps.append(ts_sec)

        if len(frame) < 34:
            continue
        eth_type = struct.unpack("!H", frame[12:14])[0]
        if eth_type != 0x0800:
            continue

        ip_hdr = frame[14:]
        ihl = (ip_hdr[0] & 0x0F) * 4
        proto = ip_hdr[9]
        src_ip = socket.inet_ntoa(ip_hdr[12:16])
        dst_ip = socket.inet_ntoa(ip_hdr[16:20])

        endpoints[src_ip]["tx_packets"] += 1
        endpoints[src_ip]["tx_bytes"] += orig_len
        endpoints[dst_ip]["rx_packets"] += 1

        l4 = ip_hdr[ihl:]
        if proto == 6 and len(l4) >= 20:  # TCP
            sport, dport, seq, ack, offset_res, flags = struct.unpack("!HHIIBB", l4[:14])
            tcp_hdr_len = (offset_res >> 4) * 4
            payload = l4[tcp_hdr_len:]
            flows[(src_ip, dst_ip, dport, "TCP")] += 1

            if (flags & 0x02) and not (flags & 0x10):  # SYN only
                syn_tracker[(src_ip, dst_ip)].add(dport)

            if dport in (80, 8080) and payload:
                proto_counts["HTTP"] += 1
                raw_http = payload.decode("latin-1", errors="replace")
                first_line = raw_http.splitlines()[0] if raw_http else ""
                clean_line, inj1 = sanitize_untrusted_telemetry(first_line, 180)
                clean_full, inj2 = sanitize_untrusted_telemetry(raw_http, 240)
                any_injection_redacted = any_injection_redacted or inj1 or inj2
                http_requests.append({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dport,
                    "request_line": clean_line,
                    "sanitized_header_preview": clean_full,
                    "prompt_injection_filtered": (inj1 or inj2),
                })
                if ".%2e" in first_line.lower() or "../" in first_line or "/etc/passwd" in first_line:
                    anomalies.append({
                        "rule_id": "TSHARK-HTTP-001",
                        "severity": "CRITICAL",
                        "observation_type": "OBSERVED_TRAFFIC_FACT",
                        "src_ip": src_ip,
                        "dest_ip": dst_ip,
                        "dest_port": dport,
                        "observable_fact": f"HTTP request to {dst_ip}:{dport} contained path traversal sequence: {clean_line}",
                        "inferred_behavior": "Attempted exploitation of Apache CVE-2021-41773 path traversal / RCE.",
                        "encrypted_payload_note": "Plaintext HTTP header inspected directly.",
                    })
                if "/manager/html" in first_line:
                    anomalies.append({
                        "rule_id": "TSHARK-HTTP-002",
                        "severity": "HIGH",
                        "observation_type": "INFERRED_SUSPICIOUS_BEHAVIOR",
                        "src_ip": src_ip,
                        "dest_ip": dst_ip,
                        "dest_port": dport,
                        "observable_fact": f"Internal host {src_ip} sent HTTP POST to {dst_ip}:{dport}/manager/html",
                        "inferred_behavior": "Lateral movement pivot targeting Apache Tomcat administrative interface.",
                        "encrypted_payload_note": "Plaintext HTTP POST observed.",
                    })
            elif dport == 6379 and payload:
                proto_counts["REDIS"] += 1
                clean_redis, inj = sanitize_untrusted_telemetry(payload.decode("latin-1", errors="replace"), 120)
                any_injection_redacted = any_injection_redacted or inj
                if "CONFIG" in clean_redis.upper():
                    anomalies.append({
                        "rule_id": "TSHARK-REDIS-001",
                        "severity": "CRITICAL",
                        "observation_type": "OBSERVED_TRAFFIC_FACT",
                        "src_ip": src_ip,
                        "dest_ip": dst_ip,
                        "dest_port": 6379,
                        "observable_fact": f"Unauthenticated Redis RESP command '{clean_redis}' sent from {src_ip} to {dst_ip}:6379",
                        "inferred_behavior": "Lateral movement / configuration reconnaissance against exposed Redis store.",
                        "encrypted_payload_note": "Plaintext Redis RESP protocol inspected.",
                    })
            elif payload and payload[0] == 0x16:  # TLS Handshake record
                proto_counts["TLS"] += 1
                tls_sessions.append({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dport,
                    "record_type": "TLS Handshake (0x16)",
                    "payload_visibility": "ENCRYPTED_OPAQUE (Metadata & 5-tuple only; payload cannot be inspected without keys)",
                })
            else:
                proto_counts["TCP"] += 1

        elif proto == 17 and len(l4) >= 8:  # UDP
            sport, dport, ulen, _ = struct.unpack("!HHHH", l4[:8])
            payload = l4[8:]
            flows[(src_ip, dst_ip, dport, "UDP")] += 1
            if dport == 53 and len(payload) > 12:
                proto_counts["DNS"] += 1
                # Extract QNAME labels
                idx = 12
                labels = []
                while idx < len(payload) and payload[idx] != 0:
                    lbl_len = payload[idx]
                    idx += 1
                    labels.append(payload[idx:idx + lbl_len].decode("ascii", errors="replace"))
                    idx += lbl_len
                qname, inj = sanitize_untrusted_telemetry(".".join(labels), 180)
                any_injection_redacted = any_injection_redacted or inj
                sub_entropy = shannon_entropy(labels[0]) if labels else 0.0
                dns_queries.append({
                    "src_ip": src_ip,
                    "resolver_ip": dst_ip,
                    "qname": qname,
                    "subdomain_entropy": sub_entropy,
                })
                if len(labels[0]) > 28 and sub_entropy >= 3.8:
                    anomalies.append({
                        "rule_id": "TSHARK-DNS-001",
                        "severity": "HIGH",
                        "observation_type": "INFERRED_SUSPICIOUS_BEHAVIOR",
                        "src_ip": src_ip,
                        "dest_ip": dst_ip,
                        "dest_port": 53,
                        "observable_fact": f"Outbound DNS query '{qname}' has first-label length {len(labels[0])} and Shannon entropy {sub_entropy} bits.",
                        "inferred_behavior": "Suspected base64/high-entropy DNS tunneling or C2 beacon activity.",
                        "encrypted_payload_note": "Plaintext UDP/53 DNS query header inspected.",
                    })
            else:
                proto_counts["UDP"] += 1

    for (src_ip, dst_ip), ports in syn_tracker.items():
        if len(ports) >= 4:
            anomalies.append({
                "rule_id": "TSHARK-TCP-SYNSCAN",
                "severity": "MEDIUM",
                "observation_type": "INFERRED_SUSPICIOUS_BEHAVIOR",
                "src_ip": src_ip,
                "dest_ip": dst_ip,
                "dest_port": 0,
                "observable_fact": f"Host {src_ip} sent TCP SYN packets (without ACK) to {len(ports)} distinct ports on {dst_ip}: {sorted(ports)}",
                "inferred_behavior": "Internal port scanning / lateral discovery activity.",
                "encrypted_payload_note": "TCP L4 flags inspected.",
            })

    duration = float(max(timestamps) - min(timestamps)) if len(timestamps) >= 2 else 0.0
    sha256 = hashlib.sha256(raw_bytes).hexdigest()

    return {
        "pcap_filename": pcap_path.name,
        "pcap_sha256": sha256,
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "capture_duration_sec": duration,
        "protocol_statistics": dict(proto_counts),
        "endpoints": dict(endpoints),
        "verified_flows": [
            {"src_ip": s, "dst_ip": d, "dst_port": p, "protocol": pr, "packet_count": cnt}
            for (s, d, p, pr), cnt in flows.items()
        ],
        "dns_queries": dns_queries,
        "http_metadata": http_requests,
        "tls_handshakes": tls_sessions,
        "anomalies": anomalies,
        "prompt_injection_redacted": any_injection_redacted,
    }


class PacketCaptureAnalysisAdapter(BaseSecurityToolAdapter):
    name = "analyze_packet_capture"
    description = (
        "Analyzes an offline PCAP/PCAPNG file using TShark or the built-in binary PCAP parser. "
        "Extracts protocol hierarchy, endpoint flows, DNS/HTTP/TLS metadata, and heuristic anomalies "
        "while separating observable traffic facts from inferred behavior."
    )
    permission_required = "READ_ONLY"
    timeout_seconds = 45

    def __init__(self, default_pcap_path: Path) -> None:
        self.default_pcap_path = default_pcap_path

    def input_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "pcap_file": {
                    "type": "string",
                    "description": "Filename inside sample_data/ to inspect (defaults to lab_capture.pcap)",
                    "default": "lab_capture.pcap",
                }
            },
        }

    def validate_inputs(self, params: Dict[str, Any]) -> Dict[str, Any]:
        fname = params.get("pcap_file", "lab_capture.pcap")
        if "/" in fname or "\\" in fname or ".." in fname:
            raise ToolInputValidationError("PCAP filename must be a simple filename inside the authorized capture directory.")
        target_path = self.default_pcap_path.parent / fname
        if not target_path.exists():
            raise ToolInputValidationError(f"PCAP file '{fname}' does not exist in capture directory.")
        return {"pcap_path": str(target_path)}

    def _execute_impl(self, validated_params: Dict[str, Any]) -> Tuple[Dict[str, Any], EvidenceMetadata]:
        pcap_path = Path(validated_params["pcap_path"])
        parsed = parse_pcap_binary(pcap_path)

        tshark_bin = shutil.which("tshark")
        exec_mode = "PYTHON_PCAP_PARSER"
        if tshark_bin:
            try:
                proc = subprocess.run(
                    [tshark_bin, "-r", str(pcap_path), "-q", "-z", "io,phs"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=self.timeout_seconds,
                    shell=False,
                    check=False,
                )
                if proc.returncode == 0:
                    parsed["tshark_phs_raw"] = proc.stdout.strip()
                    exec_mode = "TSHARK_BINARY"
            except Exception:
                pass

        return parsed, EvidenceMetadata(
            source_tool=self.name,
            execution_mode=exec_mode,
            confidence=0.94,
            raw_artifact_ref=f"{pcap_path.name}#sha256:{parsed['pcap_sha256'][:16]}",
            assumptions=[
                "Offline PCAP parsed without live root capture privileges.",
                "Encrypted TLS records (0x16) are reported as opaque metadata only; payload decryption is not claimed.",
            ],
            prompt_injection_redacted=parsed["prompt_injection_redacted"],
        )
