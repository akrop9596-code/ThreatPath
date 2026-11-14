#!/usr/bin/env python3
"""
ThreatPath AI - Phase 1 Hardware & Environment Readiness Checker
"""
import json
import os
import platform
import shutil
import subprocess
import sys

def get_ram_gb() -> float:
    try:
        if platform.system() == "Linux":
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        return round(int(line.split()[1]) / (1024 * 1024), 2)
    except Exception:
        pass
    return 8.0

def check_binary(name: str, flag: str = "--version"):
    path = shutil.which(name)
    if not path:
        return {"installed": False, "path": None, "version": None}
    try:
        out = subprocess.check_output([name, flag], stderr=subprocess.STDOUT, text=True, timeout=5)
        return {"installed": True, "path": path, "version": out.strip().splitlines()[0]}
    except Exception as e:
        return {"installed": True, "path": path, "version": str(e)}

def main():
    ram = get_ram_gb()
    tools = {
        "python3": check_binary("python3"),
        "java": check_binary("java", "-version"),
        "mvn": check_binary("mvn"),
        "node": check_binary("node", "-v"),
        "npm": check_binary("npm", "-v"),
        "mysql": check_binary("mysql"),
        "git": check_binary("git"),
        "nmap": check_binary("nmap"),
        "tshark": check_binary("tshark"),
        "wireshark": check_binary("wireshark"),
        "ollama": check_binary("ollama"),
        "zeek": check_binary("zeek"),
        "suricata": check_binary("suricata", "-V"),
    }
    mode = "Hybrid Ollama (llama3.2:3b) + Deterministic Fallback" if ram >= 12 else "Deterministic Rule-Based Agent Controller (Primary) + Optional Ollama (qwen2.5:1.5b)"
    print(json.dumps({"os": platform.platform(), "ram_gb": ram, "recommended_ai_mode": mode, "tools": tools}, indent=2))

if __name__ == "__main__":
    main()
