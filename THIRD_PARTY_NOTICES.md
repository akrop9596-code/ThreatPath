# ThreatPath AI — Third-Party Software & Rule-Set Licensing Notices

This file documents the licenses, source repositories, rule-set/signature licensing distinctions, and commercial/redistribution conditions for all libraries and optional external security tools integrated with **ThreatPath AI**.

> **Architectural & Licensing Policy**: ThreatPath AI invokes external CLI security tools (`nmap`, `tshark`, `clamscan`, `suricata`, `zeek`, `semgrep`, `gitleaks`, `osv-scanner`, `ghidra`, `capa`, `floss`) strictly as separate operating-system processes when installed by the user. No third-party copyleft source code or proprietary rule sets are embedded into the ThreatPath AI source tree.

---

## 1. Core Application Dependencies

| Component | Version | License | Source Repository | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **NousResearch Hermes Agent** | `main` (2026) | **MIT License** | `https://github.com/NousResearch/hermes-agent` | AI orchestration & MCP protocol bridge |
| **Spring Boot** | `3.2.5` | **Apache-2.0** | `https://github.com/spring-projects/spring-boot` | Java REST API & RBAC backend |
| **FastAPI & Pydantic** | `0.110.0` / `2.6+` | **MIT License** | `https://github.com/fastapi/fastapi` | Python AI Agent & MCP microservice |
| **React & Recharts** | `18.3.1` / `2.13.3` | **MIT License** | `https://github.com/facebook/react` | Frontend dashboard |
| **Lucide Icons** | `0.468.0` | **ISC License** | `https://github.com/lucide-icons/lucide` | UI iconography |

---

## 2. Optional System, Network, Code & Reverse-Engineering Tool Integrations

| Tool | Code License | Rule-Set / Signature / Feed License | Source URL & Redistribution Conditions |
| :--- | :--- | :--- | :--- |
| **ClamAV (`clamscan`)** | **GPL-2.0** | ClamAV Virus Database (Cisco Talos TOS) | `https://github.com/Cisco-Talos/clamav` — Invoked as external CLI process; signature downloads require adhering to Cisco Talos rate-limit policies. |
| **YARA (`yara`)** | **BSD-3-Clause** | Rule licenses vary by repository (e.g., Yara-Rules GPL-2.0 / CC-BY-NC) | `https://github.com/VirusTotal/yara` — Engine is BSD-3-Clause; commercial deployments must audit individual `.yar` rule licenses. |
| **osquery (`osqueryi`)** | **Apache-2.0 / GPL-2.0** | Apache-2.0 query packs | `https://github.com/osquery/osquery` |
| **Nmap (`nmap`)** | **NPSL (Nmap Public Source License)** | NPSL NSE scripts | `https://nmap.org/npsl/` — Free for local end-user installation; commercial redistribution inside proprietary installers requires an Nmap OEM license. |
| **Wireshark / TShark** | **GPL-2.0+** | GPL-2.0+ dissectors | `https://gitlab.com/wireshark/wireshark` — Invoked via external CLI or replaced by ThreatPath's clean-room RFC libpcap parser. |
| **Suricata (`suricata`)** | **GPL-2.0** | Emerging Threats Open (BSD/MIT) vs ET Pro (Commercial) | `https://github.com/OISF/suricata` |
| **Zeek (`zeek`)** | **BSD-3-Clause** | BSD-3-Clause scripts | `https://github.com/zeek/zeek` |
| **Semgrep (`semgrep`)** | **LGPL-2.1** (CLI engine) | **Semgrep Registry Rules**: many community rules use **Semgrep Rules License v1.0** (restricts competing commercial SAST offerings) | `https://github.com/semgrep/semgrep` — ThreatPath AI includes its own clean-room MIT Python AST/regex rules and only invokes `semgrep` when explicitly installed by the user. |
| **Gitleaks (`gitleaks`)** | **MIT License** | MIT default `gitleaks.toml` rules | `https://github.com/gitleaks/gitleaks` |
| **OSV-Scanner** | **Apache-2.0** | CC-BY-4.0 OSV advisories | `https://github.com/google/osv-scanner` |
| **Ghidra** | **Apache-2.0** | Apache-2.0 processor specs | `https://github.com/NationalSecurityAgency/ghidra` |
| **capa & FLOSS** | **Apache-2.0** | `capa-rules` (Apache-2.0) | `https://github.com/mandiant/capa` & `https://github.com/mandiant/flare-floss` |

---

## 3. Threat Intelligence Feeds & Attribution

- **CISA Known Exploited Vulnerabilities (KEV)**: Public Domain (U.S. CISA — `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`).
- **FIRST EPSS**: Creative Commons Attribution (FIRST.org — `https://www.first.org/epss/`).
- **MITRE ATT&CK®**: Apache-2.0 / MITRE Copyright Notice (`https://attack.mitre.org/`).
- **abuse.ch (URLhaus, Feodo Tracker, MalwareBazaar)**: CC0 1.0 Universal Public Domain Dedication (`https://abuse.ch/`).
