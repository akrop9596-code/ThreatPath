"""
ThreatPath AI - Hardware-Aware Installation Profiles & SBOM Generator
Implements Section 11 & 12:
1. Installation Profiles:
   - Core Installation (Hermes MCP, Basic System/Socket Inspection, AST/SAST Code Checks, Local DB/UI)
   - Network Security Add-ons (Suricata, Zeek, TShark, Nmap)
   - Advanced Security Add-ons (OpenVAS, Ghidra, capa, FLOSS, CAPE)
2. Checks available RAM, CPU, and disk space before recommending or enabling resource-heavy modules.
3. Generates a CycloneDX 1.5 Software Bill of Materials (SBOM) for the ThreatPath AI platform.
"""
import os
import platform
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


INSTALLATION_PROFILES = {
    "core": {
        "profile_id": "core",
        "name": "Core Installation (Default — Low Resource)",
        "min_ram_gb": 4.0,
        "min_disk_gb": 2.0,
        "included_modules": [
            "NousResearch Hermes Agent MCP Bridge",
            "Local OS, Process (`ps`), Socket (`/proc/net`), and File Permission Inspector",
            "Built-in RFC Binary PCAP & Nmap XML Parsers",
            "Python AST & SAST Code Security Scanner",
            "Static ELF/PE Binary Header & Symbol Inspector (`file`, `readelf`, `strings`)",
            "React Dashboard, Spring Boot API & Local Storage",
        ],
        "auto_downloads_large_models": False,
    },
    "network_addons": {
        "profile_id": "network_addons",
        "name": "Network Security Add-ons",
        "min_ram_gb": 8.0,
        "min_disk_gb": 10.0,
        "included_modules": [
            "Nmap CLI (`nmap` — MIT/NPSL)",
            "Wireshark / TShark CLI (`tshark` — GPL-2.0+)",
            "Suricata IDS (`suricata` — GPL-2.0)",
            "Zeek Network Security Monitor (`zeek` — BSD-3-Clause)",
        ],
        "auto_downloads_large_models": False,
    },
    "advanced_addons": {
        "profile_id": "advanced_addons",
        "name": "Advanced Security & Reverse Engineering Add-ons",
        "min_ram_gb": 16.0,
        "min_disk_gb": 35.0,
        "included_modules": [
            "Greenbone OpenVAS (`gvm` — GPL-2.0+)",
            "NSA Ghidra Reverse Engineering Suite (`ghidra` — Apache-2.0)",
            "Mandiant capa (`capa` — Apache-2.0) & FLARE FLOSS (`floss` — Apache-2.0)",
            "Local Ollama 8B LLM (`nousresearch/hermes-3-llama-3.1-8b` — Llama 3.1 Community License)",
        ],
        "auto_downloads_large_models": False,
    },
}


def evaluate_hardware_and_profiles() -> Dict[str, Any]:
    ram_gb = 8.0
    if platform.system() == "Linux" and Path("/proc/meminfo").exists():
        try:
            for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
                if line.startswith("MemTotal:"):
                    ram_gb = round(int(line.split()[1]) / (1024 * 1024), 2)
                    break
        except Exception:
            pass

    disk_usage = shutil.disk_usage("/")
    free_disk_gb = round(disk_usage.free / (1024 ** 3), 2)
    cpu_cores = os.cpu_count() or 2

    profile_compatibility = {}
    for pid, pinfo in INSTALLATION_PROFILES.items():
        ram_ok = ram_gb >= pinfo["min_ram_gb"]
        disk_ok = free_disk_gb >= pinfo["min_disk_gb"]
        profile_compatibility[pid] = {
            **pinfo,
            "hardware_supported": ram_ok and disk_ok,
            "compatibility_note": (
                f"Supported on this host ({ram_gb} GB RAM, {free_disk_gb} GB free disk)."
                if (ram_ok and disk_ok)
                else f"Not recommended for automatic enabling: requires >= {pinfo['min_ram_gb']} GB RAM (detected {ram_gb} GB)."
            ),
        }

    return {
        "detected_ram_gb": ram_gb,
        "detected_free_disk_gb": free_disk_gb,
        "detected_cpu_cores": cpu_cores,
        "profiles": profile_compatibility,
    }


def generate_project_sbom() -> Dict[str, Any]:
    """Generates a CycloneDX 1.5 JSON Software Bill of Materials (SBOM) with license provenance."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "type": "application",
                "name": "threatpath-ai",
                "version": "2.0.0",
                "licenses": [{"license": {"id": "MIT"}}],
            },
        },
        "components": [
            {"type": "application", "name": "NousResearch/hermes-agent", "version": "main", "licenses": [{"license": {"id": "MIT"}}], "externalReferences": [{"type": "vcs", "url": "https://github.com/NousResearch/hermes-agent"}]},
            {"type": "framework", "name": "spring-boot", "version": "3.2.5", "licenses": [{"license": {"id": "Apache-2.0"}}]},
            {"type": "library", "name": "fastapi", "version": "0.110.0", "licenses": [{"license": {"id": "MIT"}}]},
            {"type": "library", "name": "react", "version": "18.3.1", "licenses": [{"license": {"id": "MIT"}}]},
            {"type": "library", "name": "lucide-react", "version": "0.468.0", "licenses": [{"license": {"id": "ISC"}}]},
            {"type": "library", "name": "recharts", "version": "2.13.3", "licenses": [{"license": {"id": "MIT"}}]},
        ],
    }
