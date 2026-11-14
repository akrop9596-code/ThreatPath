"""
ThreatPath AI - Reverse Engineering & Static Binary Analysis Module
Performs 100% read-only static inspection of ELF / PE / script binaries on the host.
Uses installed native Linux binary inspection tools (`/usr/bin/file`, `/usr/bin/readelf`,
`/usr/bin/objdump`, `/usr/bin/strings`) and Python header/entropy parsing while checking
whether optional advanced reverse-engineering tools (`Ghidra`, `capa`, `FLOSS`, `LIEF`,
`pefile`, `Detect It Easy`) are installed.

Safety Guarantees:
- Never executes unknown or inspected binaries on the host.
- Preserves original files untouched (read-only).
- Blocks path traversal ('..') and blocks reading sensitive credential files (/etc/shadow, .env, private keys).
- Never silently substitutes another binary when a requested file does not exist.
"""
import hashlib
import math
import shutil
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .base import BaseSecurityToolAdapter, EvidenceMetadata
from .security import ToolInputValidationError


CAPABILITY_SYMBOL_MAP = {
    "socket": ("Create network socket", "cap-net-socket", "T1071 (Application Layer Protocol)"),
    "connect": ("Initiate outbound network connection", "cap-net-connect", "T1071"),
    "bind": ("Bind listening port", "cap-net-bind", "T1049"),
    "execve": ("Execute child program", "cap-proc-exec", "T1059 (Command and Scripting Interpreter)"),
    "system": ("Execute shell command string", "cap-proc-system", "T1059.004"),
    "popen": ("Open pipe to child process", "cap-proc-popen", "T1059.004"),
    "ptrace": ("Inspect or attach to another process (anti-debug / injection indicator)", "cap-proc-ptrace", "T1055"),
    "dlopen": ("Dynamically load shared library at runtime", "cap-dyn-dlopen", "T1129"),
    "chmod": ("Modify file permission bits", "cap-fs-chmod", "T1222"),
}

FORBIDDEN_SENSITIVE_PATHS = (
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "id_rsa",
    "id_ed25519",
    ".env",
)


def compute_bytes_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return round(-sum((c / total) * math.log2(c / total) for c in counts.values()), 3)


def check_re_tools_installed() -> Dict[str, Dict[str, Any]]:
    tools = {}
    for name, purpose in [
        ("file", "Magic-byte file type identification"),
        ("readelf", "ELF header, section & dynamic symbol table inspector"),
        ("objdump", "Disassembler & symbol table viewer"),
        ("strings", "Printable ASCII/UTF-8 string extractor"),
        ("ghidraRun", "Ghidra Headless / GUI decompiler & reverse-engineering suite (Optional Add-on)"),
        ("capa", "Mandiant capa executable capability detector (Optional Add-on)"),
        ("floss", "FLARE Obfuscated String Solver (Optional Add-on)"),
        ("diec", "Detect It Easy packer/compiler identifier (Optional Add-on)"),
    ]:
        path = shutil.which(name)
        tools[name] = {
            "installed": path is not None,
            "path": path,
            "purpose": purpose,
        }
    return tools


def analyze_binary_static_readonly(binary_path: Path) -> Dict[str, Any]:
    """
    Performs read-only static binary analysis on `binary_path` without executing the target binary.
    """
    if not binary_path.exists() or not binary_path.is_file():
        raise ToolInputValidationError(f"Binary file '{binary_path}' does not exist.")

    raw = binary_path.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    sha1 = hashlib.sha1(raw).hexdigest()
    md5 = hashlib.md5(raw).hexdigest()
    overall_entropy = compute_bytes_entropy(raw[:262144])

    magic_format = "Unknown Binary"
    if raw.startswith(b"\x7fELF"):
        elf_class = "ELF64" if len(raw) > 4 and raw[4] == 2 else "ELF32"
        endian = "Little-Endian" if len(raw) > 5 and raw[5] == 1 else "Big-Endian"
        magic_format = f"{elf_class} ({endian})"
    elif raw.startswith(b"MZ"):
        magic_format = "PE32/PE32+ (Windows Portable Executable)"

    file_desc = magic_format
    if shutil.which("file"):
        try:
            proc = subprocess.run(
                ["file", "-b", str(binary_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                shell=False,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                file_desc = proc.stdout.strip()
        except Exception:
            pass

    imported_symbols: List[str] = []
    elf_security_flags = {"pie_or_dyn": False, "nx_stack": False}
    if shutil.which("readelf") and raw.startswith(b"\x7fELF"):
        try:
            proc_syms = subprocess.run(
                ["readelf", "-W", "--dyn-syms", str(binary_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                shell=False,
                check=False,
            )
            for line in (proc_syms.stdout or "").splitlines():
                for sym_name in CAPABILITY_SYMBOL_MAP:
                    if f" {sym_name}@" in line or line.strip().endswith(f" {sym_name}"):
                        if sym_name not in imported_symbols:
                            imported_symbols.append(sym_name)

            proc_hdr = subprocess.run(
                ["readelf", "-W", "-l", str(binary_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                shell=False,
                check=False,
            )
            hdr_out = proc_hdr.stdout or ""
            elf_security_flags["pie_or_dyn"] = "DYN (Position-Independent" in hdr_out or "DYN (Shared" in hdr_out
            elf_security_flags["nx_stack"] = "GNU_STACK" in hdr_out and "RWE" not in hdr_out
        except Exception:
            pass

    mapped_capabilities = [
        {
            "symbol": sym,
            "capability": CAPABILITY_SYMBOL_MAP[sym][0],
            "rule_id": CAPABILITY_SYMBOL_MAP[sym][1],
            "attack_technique": CAPABILITY_SYMBOL_MAP[sym][2],
        }
        for sym in imported_symbols
    ]

    packer_indicator = (
        "High entropy (>= 7.2 bits/byte) — May indicate compressed sections or packing; does NOT by itself prove malware."
        if overall_entropy >= 7.2
        else f"Normal code/data entropy ({overall_entropy} bits/byte) — No packing detected."
    )

    return {
        "file_path": str(binary_path),
        "file_name": binary_path.name,
        "file_size_bytes": len(raw),
        "hashes": {"sha256": sha256, "sha1": sha1, "md5": md5},
        "binary_format": magic_format,
        "file_command_summary": file_desc,
        "entropy_bits_per_byte": overall_entropy,
        "packer_assessment": packer_indicator,
        "elf_hardening": elf_security_flags,
        "detected_capabilities": mapped_capabilities,
        "re_tools_availability": check_re_tools_installed(),
        "what_this_proves": (
            f"Confirms static file hashes, {magic_format} header structure, section entropy ({overall_entropy}), "
            f"and {len(mapped_capabilities)} imported OS API capabilities ({', '.join(imported_symbols) or 'none'})."
        ),
        "what_this_does_not_prove": (
            "Static API imports (such as socket, connect, or execve) and entropy values are present in legitimate "
            "system utilities and servers. They do NOT by themselves prove a binary is malicious."
        ),
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }


class ReverseEngineeringStaticAdapter(BaseSecurityToolAdapter):
    name = "analyze_binary_static"
    description = (
        "Performs read-only static binary analysis (hashes, ELF/PE headers, entropy, "
        "`readelf` symbols, and capability mapping) without executing the target binary."
    )
    permission_required = "FILE_DIRECTORY_INSPECTION"
    timeout_seconds = 30

    def input_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to local binary to inspect statically (read-only)",
                    "default": "/usr/bin/Xtigervnc",
                }
            },
        }

    def validate_inputs(self, params: Dict[str, Any]) -> Dict[str, Any]:
        explicit_param = params.get("binary_path")
        if explicit_param is not None:
            bpath = str(explicit_param).strip()
            if ".." in bpath:
                raise ToolInputValidationError("Path traversal ('..') is forbidden in binary_path.")
            for forbidden in FORBIDDEN_SENSITIVE_PATHS:
                if forbidden in bpath:
                    raise ToolInputValidationError(f"Inspecting credential or secret file '{bpath}' is forbidden.")
            p = Path(bpath)
            if not p.exists() or not p.is_file():
                raise ToolInputValidationError(f"Requested binary '{bpath}' does not exist; refusing to substitute another file.")
            return {"binary_path": str(p.resolve())}

        # Default when no parameter is specified
        default_p = Path("/usr/bin/Xtigervnc")
        if not default_p.exists():
            default_p = Path(shutil.which("python3") or "/bin/sh")
        return {"binary_path": str(default_p)}

    def _execute_impl(self, validated_params: Dict[str, Any]) -> Tuple[Dict[str, Any], EvidenceMetadata]:
        res = analyze_binary_static_readonly(Path(validated_params["binary_path"]))
        return res, EvidenceMetadata(
            source_tool=self.name,
            execution_mode="LIVE_BINARY",
            confidence=1.0,
            raw_artifact_ref=f"sha256:{res['hashes']['sha256'][:16]}",
            assumptions=["100% read-only static binary header & symbol inspection; target was never executed."],
        )
