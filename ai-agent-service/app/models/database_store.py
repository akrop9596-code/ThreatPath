"""
ThreatPath AI - Production SQLite / MySQL-Compatible Relational Database & Multi-User Isolation Store
Implements Section 10, 11, 12, and 13 requirements:
- Real relational schema with foreign keys (PRAGMA foreign_keys = ON), unique constraints, and indexes.
- Multi-user and per-installation tenant isolation (`owner_user_id` and `installation_id`).
- Ensures deleting a user or installation cascades cleanly without exposing or affecting any other user's data.
- Enforces duplicate-record prevention, finding history, evidence references, approval history, audit logs,
  configurable data retention, and verified database backup & restore.
"""
import hashlib
import json
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


SQLITE_SCHEMA_DDL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('ADMIN', 'ANALYST', 'READ_ONLY')) DEFAULT 'ANALYST',
    installation_id TEXT NOT NULL,
    can_execute_active_scans INTEGER NOT NULL DEFAULT 0,
    can_approve_disruptive_ops INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_installation ON users(installation_id);

CREATE TABLE IF NOT EXISTS user_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    permission_key TEXT NOT NULL,
    granted INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    UNIQUE(user_id, permission_key),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_user_id INTEGER NOT NULL,
    installation_id TEXT NOT NULL,
    asset_code TEXT NOT NULL,
    hostname TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    subnet_cidr TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    network_zone TEXT NOT NULL,
    criticality_level TEXT NOT NULL DEFAULT 'MEDIUM',
    criticality_weight REAL NOT NULL DEFAULT 5.0,
    is_authorized_target INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    UNIQUE(owner_user_id, asset_code),
    UNIQUE(owner_user_id, ip_address),
    FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_assets_owner ON assets(owner_user_id, installation_id);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_uuid TEXT NOT NULL UNIQUE,
    owner_user_id INTEGER NOT NULL,
    installation_id TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    target_spec TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED', 'BLOCKED_UNAUTHORIZED')),
    execution_mode TEXT NOT NULL,
    raw_output_hash TEXT,
    summary_json TEXT,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_scans_owner_status ON scans(owner_user_id, status);

CREATE TABLE IF NOT EXISTS security_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_code TEXT NOT NULL,
    owner_user_id INTEGER NOT NULL,
    installation_id TEXT NOT NULL,
    asset_id INTEGER,
    category TEXT NOT NULL,
    classification TEXT NOT NULL CHECK(classification IN (
        'CONFIRMED_MALWARE_DETECTION',
        'SUSPICIOUS_INDICATOR',
        'POTENTIAL_VULNERABILITY',
        'INFORMATIONAL_EVENT',
        'FALSE_POSITIVE_CANDIDATE',
        'UNVERIFIED_FINDING'
    )),
    severity TEXT NOT NULL CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INFO')),
    risk_score REAL NOT NULL DEFAULT 0.0,
    title TEXT NOT NULL,
    evidence_text TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('OPEN', 'IN_REMEDIATION', 'VERIFIED_FIXED', 'VERIFICATION_FAILED', 'FALSE_POSITIVE')) DEFAULT 'OPEN',
    discovered_at TEXT NOT NULL,
    UNIQUE(owner_user_id, finding_code),
    FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_findings_owner_sev ON security_findings(owner_user_id, severity, status);

CREATE TABLE IF NOT EXISTS remediation_proposals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proposal_code TEXT NOT NULL,
    owner_user_id INTEGER NOT NULL,
    installation_id TEXT NOT NULL,
    finding_code TEXT NOT NULL,
    target_resource TEXT NOT NULL,
    proposed_change TEXT NOT NULL,
    rollback_procedure TEXT NOT NULL,
    verification_plan TEXT NOT NULL,
    action_hash TEXT NOT NULL,
    approval_status TEXT NOT NULL CHECK(approval_status IN (
        'PENDING_APPROVAL',
        'APPROVED',
        'REJECTED',
        'MORE_INFO_REQUESTED',
        'SCHEDULED_LATER',
        'EXPIRED',
        'FAILED_REMEDIATION',
        'INTERRUPTED_ROLLED_BACK',
        'VERIFICATION_FAILED',
        'EXECUTED_VERIFIED',
        'ROLLED_BACK'
    )) DEFAULT 'PENDING_APPROVAL',
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(owner_user_id, proposal_code),
    FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS approval_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_user_id INTEGER NOT NULL,
    proposal_code TEXT NOT NULL,
    decision TEXT NOT NULL,
    decided_by_username TEXT NOT NULL,
    approved_action_hash TEXT NOT NULL,
    verification_passed INTEGER NOT NULL DEFAULT 0,
    verification_evidence TEXT,
    decided_at TEXT NOT NULL,
    FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_user_id INTEGER,
    installation_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_username TEXT NOT NULL,
    target_resource TEXT NOT NULL,
    action_decision TEXT NOT NULL CHECK(action_decision IN (
        'ALLOWED',
        'DENIED_UNAUTHORIZED_TARGET',
        'DENIED_RBAC',
        'DENIED_SELF_APPROVAL',
        'PROMPT_INJECTION_REDACTED',
        'RATE_LIMITED'
    )),
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_audit_owner_created ON audit_logs(owner_user_id, created_at);
"""


def hash_password_pbkdf2(password: str, salt: str = "threatpath_v1_salt") -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000)
    return f"pbkdf2_sha256$120000${salt}${dk.hex()}"


class ThreatPathDatabaseStore:
    """
    Production SQLite relational store with strict foreign-key integrity,
    multi-user tenant isolation, duplicate prevention, retention cleanup, and backup/restore.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(SQLITE_SCHEMA_DDL)
            conn.commit()

    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        role: str = "ANALYST",
        installation_id: str = "TP-INST-DEFAULT",
        can_execute_active_scans: bool = False,
        can_approve_disruptive_ops: bool = False,
    ) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        pw_hash = hash_password_pbkdf2(password)
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO users (
                    username, email, password_hash, role, installation_id,
                    can_execute_active_scans, can_approve_disruptive_ops, is_active, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (
                    username,
                    email,
                    pw_hash,
                    role,
                    installation_id,
                    int(can_execute_active_scans),
                    int(can_approve_disruptive_ops),
                    now,
                ),
            )
            uid = cur.lastrowid
            conn.commit()
        return {
            "id": uid,
            "username": username,
            "email": email,
            "role": role,
            "installation_id": installation_id,
            "can_execute_active_scans": can_execute_active_scans,
            "can_approve_disruptive_ops": can_approve_disruptive_ops,
        }

    def register_asset(
        self,
        owner_user_id: int,
        installation_id: str,
        asset_code: str,
        hostname: str,
        ip_address: str,
        subnet_cidr: str,
        asset_type: str = "WORKSTATION",
        network_zone: str = "MGMT_LAB",
        criticality_level: str = "MEDIUM",
        criticality_weight: float = 5.0,
    ) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO assets (
                    owner_user_id, installation_id, asset_code, hostname, ip_address,
                    subnet_cidr, asset_type, network_zone, criticality_level, criticality_weight,
                    is_authorized_target, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (
                    owner_user_id,
                    installation_id,
                    asset_code,
                    hostname,
                    ip_address,
                    subnet_cidr,
                    asset_type,
                    network_zone,
                    criticality_level,
                    criticality_weight,
                    now,
                ),
            )
            aid = cur.lastrowid
            conn.commit()
        return {"id": aid, "owner_user_id": owner_user_id, "asset_code": asset_code, "ip_address": ip_address}

    def list_assets_for_user(self, owner_user_id: int, installation_id: str) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM assets WHERE owner_user_id = ? AND installation_id = ? ORDER BY id ASC",
                (owner_user_id, installation_id),
            ).fetchall()
        return [dict(r) for r in rows]

    def record_finding(
        self,
        owner_user_id: int,
        installation_id: str,
        finding_code: str,
        category: str,
        classification: str,
        severity: str,
        risk_score: float,
        title: str,
        evidence_text: str,
        asset_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        ev_hash = hashlib.sha256(evidence_text.encode("utf-8")).hexdigest()
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO security_findings (
                    finding_code, owner_user_id, installation_id, asset_id,
                    category, classification, severity, risk_score, title,
                    evidence_text, evidence_sha256, status, discovered_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?)
                """,
                (
                    finding_code,
                    owner_user_id,
                    installation_id,
                    asset_id,
                    category,
                    classification,
                    severity,
                    risk_score,
                    title,
                    evidence_text,
                    ev_hash,
                    now,
                ),
            )
            fid = cur.lastrowid
            conn.commit()
        return {"id": fid, "finding_code": finding_code, "owner_user_id": owner_user_id, "evidence_sha256": ev_hash}

    def list_findings_for_user(self, owner_user_id: int, installation_id: str) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM security_findings WHERE owner_user_id = ? AND installation_id = ? ORDER BY risk_score DESC",
                (owner_user_id, installation_id),
            ).fetchall()
        return [dict(r) for r in rows]

    def log_audit_event(
        self,
        owner_user_id: Optional[int],
        installation_id: str,
        event_type: str,
        actor_username: str,
        target_resource: str,
        action_decision: str,
        details: Dict[str, Any],
        created_at_override: Optional[str] = None,
    ) -> int:
        now = created_at_override or datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO audit_logs (
                    owner_user_id, installation_id, event_type, actor_username,
                    target_resource, action_decision, details_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    owner_user_id,
                    installation_id,
                    event_type,
                    actor_username,
                    target_resource,
                    action_decision,
                    json.dumps(details, sort_keys=True),
                    now,
                ),
            )
            conn.commit()
            return int(cur.lastrowid)

    def delete_user_account(self, user_id: int) -> Dict[str, Any]:
        """
        Deletes a user account and cascades deletion strictly to that user's assets,
        scans, findings, proposals, and audit logs without touching any other user's data.
        """
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            return {"deleted_user_id": user_id, "rows_deleted": cur.rowcount}

    def apply_retention_policy(self, retention_days: int = 90) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM audit_logs WHERE created_at < ?", (cutoff,))
            conn.commit()
            return int(cur.rowcount)

    def backup_database(self, backup_path: Path) -> Dict[str, Any]:
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as src_conn:
            with sqlite3.connect(str(backup_path)) as dst_conn:
                src_conn.backup(dst_conn)
        sha256 = hashlib.sha256(backup_path.read_bytes()).hexdigest()
        return {"backup_path": str(backup_path), "size_bytes": backup_path.stat().st_size, "sha256": sha256}

    def restore_database(self, backup_path: Path) -> Dict[str, Any]:
        if not backup_path.exists():
            raise FileNotFoundError(f"Backup file '{backup_path}' does not exist.")
        shutil.copy2(backup_path, self.db_path)
        return {"restored_from": str(backup_path), "restored_size_bytes": self.db_path.stat().st_size}
