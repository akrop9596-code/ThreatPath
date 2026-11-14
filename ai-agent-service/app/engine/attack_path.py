"""
ThreatPath AI - Phase 8: Graph-Based Attack Path Engine
Builds a directed security graph separating:
- VERIFIED_TRAFFIC_FLOW (observed in PCAP / Zeek / Suricata)
- OPEN_SERVICE_REACHABILITY (observed via Nmap service discovery)
- HYPOTHESIZED_LATERAL_PIVOT (inferred potential hop, explicitly labeled as unconfirmed)
Never presents mere network connectivity as a confirmed exploit unless active evidence exists.
"""
from collections import deque
from typing import Any, Dict, List


class AttackPathGraphEngine:
    def __init__(self) -> None:
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []
        self.adj: Dict[str, List[Dict[str, Any]]] = {}

    def add_node(
        self,
        node_key: str,
        label: str,
        ip_address: str,
        node_type: str,
        network_zone: str,
        criticality_weight: float,
        is_entry: bool = False,
        is_crown_jewel: bool = False,
        open_ports: List[int] = None,
        cves: List[str] = None,
    ) -> None:
        self.nodes[node_key] = {
            "node_key": node_key,
            "label": label,
            "ip_address": ip_address,
            "node_type": node_type,
            "network_zone": network_zone,
            "criticality_weight": criticality_weight,
            "is_entry": is_entry,
            "is_crown_jewel": is_crown_jewel,
            "open_ports": open_ports or [],
            "cves": cves or [],
        }
        self.adj.setdefault(node_key, [])

    def add_edge(
        self,
        edge_key: str,
        source_key: str,
        target_key: str,
        relationship_type: str,
        is_confirmed_exploitable: bool,
        linked_cve: str,
        supporting_evidence: str,
        assumptions: str,
        confidence: float,
    ) -> None:
        edge = {
            "edge_key": edge_key,
            "source": source_key,
            "target": target_key,
            "relationship_type": relationship_type,
            "is_confirmed_exploitable": is_confirmed_exploitable,
            "linked_cve": linked_cve,
            "supporting_evidence": supporting_evidence,
            "assumptions": assumptions,
            "confidence": round(confidence, 2),
        }
        self.edges.append(edge)
        self.adj.setdefault(source_key, []).append(edge)

    def discover_paths_to_critical_assets(self, max_depth: int = 5) -> List[Dict[str, Any]]:
        """
        Uses Breadth-First Graph Traversal to enumerate all acyclic attack paths from
        entry nodes to critical destination assets, computing joint path confidence
        and distinguishing verified exploit chains from hypothesized connectivity paths.
        """
        entry_keys = [k for k, n in self.nodes.items() if n.get("is_entry")]
        critical_keys = {k for k, n in self.nodes.items() if n.get("is_crown_jewel")}

        discovered_paths: List[Dict[str, Any]] = []
        queue = deque([(start, [start], []) for start in entry_keys])

        while queue:
            curr, node_chain, edge_chain = queue.popleft()
            if len(edge_chain) > max_depth:
                continue

            if curr in critical_keys and len(edge_chain) >= 1:
                path_conf = 1.0
                for e in edge_chain:
                    path_conf *= e["confidence"]
                path_conf = round(path_conf, 2)

                all_confirmed = all(e["is_confirmed_exploitable"] for e in edge_chain)
                has_hypothesized = any(e["relationship_type"] == "HYPOTHESIZED_LATERAL_PIVOT" for e in edge_chain)

                path_classification = (
                    "EVIDENCE_BACKED_ACTIVE_ATTACK_PATH"
                    if all_confirmed
                    else (
                        "HYPOTHESIZED_MULTI_HOP_EXPOSURE_PATH"
                        if has_hypothesized
                        else "VERIFIED_CONNECTIVITY_POTENTIAL_PIVOT_PATH"
                    )
                )

                start_node = self.nodes[node_chain[0]]
                dest_node = self.nodes[node_chain[-1]]
                intermediates = [self.nodes[k]["label"] for k in node_chain[1:-1]]
                cves = [e["linked_cve"] for e in edge_chain if e.get("linked_cve")]

                discovered_paths.append({
                    "path_id": f"PATH-{len(discovered_paths) + 1:02d}",
                    "classification": path_classification,
                    "starting_asset": f"{start_node['label']} ({start_node['ip_address']})",
                    "intermediate_systems": intermediates,
                    "destination_asset": f"{dest_node['label']} ({dest_node['ip_address']})",
                    "node_sequence": node_chain,
                    "relevant_vulnerabilities": cves,
                    "supporting_evidence": [e["supporting_evidence"] for e in edge_chain],
                    "assumptions": [e["assumptions"] for e in edge_chain],
                    "path_confidence": path_conf,
                    "potential_impact": (
                        f"Compromise of {dest_node['label']} ({dest_node['network_zone']}, "
                        f"Criticality {dest_node['criticality_weight']}/10) risking unauthorized financial ledger access."
                    ),
                    "recommended_mitigation": (
                        "1) Patch Apache 2.4.49 (CVE-2021-41773) on DMZ proxy; "
                        "2) Bind Redis 6379 to localhost & patch Tomcat AJP (CVE-2020-1938) on ERP API server; "
                        "3) Enforce strict firewall micro-segmentation blocking DMZ-to-DB direct SYN probes."
                    ),
                })

            for edge in self.adj.get(curr, []):
                nxt = edge["target"]
                if nxt not in node_chain:
                    queue.append((nxt, node_chain + [nxt], edge_chain + [edge]))

        discovered_paths.sort(key=lambda p: p["path_confidence"], reverse=True)
        return discovered_paths


def build_lab_attack_graph() -> Dict[str, Any]:
    engine = AttackPathGraphEngine()
    engine.add_node(
        "EXT-ATTACKER", "External Threat Actor", "198.51.100.77",
        "EXTERNAL_ENTRY", "INTERNET", 1.0, is_entry=True
    )
    engine.add_node(
        "AST-DMZ-01", "edge-gw-proxy.lab.local", "10.10.20.10",
        "HOST_ASSET", "DMZ", 7.5, open_ports=[22, 80, 443], cves=["CVE-2021-41773"]
    )
    engine.add_node(
        "AST-APP-02", "erp-core-api.lab.local", "10.10.20.25",
        "HOST_ASSET", "INTERNAL_APP", 8.5, open_ports=[22, 6379, 8080], cves=["CVE-2020-1938", "CVE-2022-0543"]
    )
    engine.add_node(
        "AST-DB-03", "fin-ledger-db.lab.local", "10.10.20.50",
        "CROWN_JEWEL_ASSET", "RESTRICTED_DB", 10.0, is_crown_jewel=True, open_ports=[3306, 5432], cves=["CVE-2022-21245"]
    )
    engine.add_node(
        "AST-WK-04", "dev-bastion-01.lab.local", "10.10.20.105",
        "HOST_ASSET", "MGMT_LAB", 5.5, open_ports=[22], cves=[]
    )

    # Edge 1: External -> DMZ (Confirmed by PCAP HTTP path traversal + Suricata SID 2034039 + OpenVAS CVE-2021-41773)
    engine.add_edge(
        "EDGE-01", "EXT-ATTACKER", "AST-DMZ-01",
        relationship_type="VERIFIED_TRAFFIC_FLOW",
        is_confirmed_exploitable=True,
        linked_cve="CVE-2021-41773",
        supporting_evidence="PCAP packet #1 & Suricata SID 2034039 show HTTP GET /cgi-bin/.%2e/.../etc/passwd against Apache 2.4.49 on 10.10.20.10:80.",
        assumptions="mod_cgi is enabled on Apache 2.4.49 as reported by OpenVAS NVT 1.3.6.1.4.1.25623.1.0.146846.",
        confidence=0.95,
    )
    # Edge 2: DMZ -> Internal App Server via Redis 6379 / Tomcat 8080
    engine.add_edge(
        "EDGE-02", "AST-DMZ-01", "AST-APP-02",
        relationship_type="VERIFIED_TRAFFIC_FLOW",
        is_confirmed_exploitable=True,
        linked_cve="CVE-2022-0543",
        supporting_evidence="PCAP packets #2-#3, Zeek UID C7g8h9, and Suricata SID 2029811 confirm 10.10.20.10 issuing unauthenticated Redis CONFIG GET and Tomcat /manager/html POST to 10.10.20.25.",
        assumptions="Attacker leverages foothold on edge-gw-proxy to pivot into unauthenticated Redis 6.0.15 on erp-core-api.",
        confidence=0.92,
    )
    # Edge 3: Internal App Server -> Restricted Database (Verified connectivity + MySQL CVE-2022-21245)
    engine.add_edge(
        "EDGE-03", "AST-APP-02", "AST-DB-03",
        relationship_type="OPEN_SERVICE_REACHABILITY",
        is_confirmed_exploitable=False,
        linked_cve="CVE-2022-21245",
        supporting_evidence="PCAP packet #4 and Zeek UID C9j0k1 verify active TLS MySQL session from 10.10.20.25 to 10.10.20.50:3306; Nmap confirms port 3306 MySQL 8.0.27 open.",
        assumptions="Connectivity is verified, but exploitation of MySQL 8.0.27 requires valid application DB credentials extracted from erp-core-api memory/config (not yet confirmed as compromised).",
        confidence=0.84,
    )
    # Edge 4: DMZ -> Restricted Database Direct SYN Scan (Hypothesized direct pivot)
    engine.add_edge(
        "EDGE-04", "AST-DMZ-01", "AST-DB-03",
        relationship_type="HYPOTHESIZED_LATERAL_PIVOT",
        is_confirmed_exploitable=False,
        linked_cve="CVE-2022-21245",
        supporting_evidence="PCAP packets #8-#12 show TCP SYN scan from 10.10.20.10 to 10.10.20.50 ports 22, 80, 443, 3306, 5432 without SYN-ACK completion in capture.",
        assumptions="Hypothesized direct path if internal firewall rules are misconfigured; currently only reconnaissance SYN packets observed.",
        confidence=0.45,
    )

    paths = engine.discover_paths_to_critical_assets()
    return {
        "nodes": list(engine.nodes.values()),
        "edges": engine.edges,
        "attack_paths": paths,
    }
