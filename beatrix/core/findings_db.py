"""
BEATRIX Findings Database

SQLite-backed persistent storage for hunt findings.
Every hunt auto-saves so findings can be queried, compared, and exported later.

"You didn't think it was gonna be that easy, did you?"

Usage:
    db = FindingsDB()
    hunt_id = db.save_hunt(target, preset, findings, duration, modules_run)
    findings = db.get_findings(hunt_id=1, severity="high")
    hunts = db.list_hunts()
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from beatrix.core.types import Finding

# Default database location
DEFAULT_DB_PATH = Path.home() / ".beatrix" / "findings.db"


class FindingsDB:
    """
    Persistent SQLite store for Beatrix hunt results.

    Stores hunts and their findings with full detail so they can be
    queried, filtered, compared, and exported at any time.
    """

    SCHEMA_VERSION = 2

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self) -> None:
        """Create tables if they don't exist."""
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS hunts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                preset TEXT NOT NULL DEFAULT 'standard',
                started_at TEXT NOT NULL,
                duration_secs REAL NOT NULL DEFAULT 0,
                modules_run TEXT NOT NULL DEFAULT '[]',
                total_findings INTEGER NOT NULL DEFAULT 0,
                ai_enabled INTEGER NOT NULL DEFAULT 0,
                notes TEXT
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hunt_id INTEGER NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,

                -- Classification
                title TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'info',
                confidence TEXT NOT NULL DEFAULT 'tentative',

                -- OWASP/MITRE
                owasp_category TEXT,
                mitre_technique TEXT,
                mitre_tactic TEXT,
                cwe_id TEXT,

                -- Technical
                url TEXT NOT NULL DEFAULT '',
                parameter TEXT,
                injection_point TEXT,
                payload TEXT,

                -- Evidence
                request TEXT,
                response TEXT,
                evidence TEXT,

                -- Description
                description TEXT NOT NULL DEFAULT '',
                impact TEXT,
                remediation TEXT,

                -- References (JSON array)
                refs TEXT DEFAULT '[]',

                -- PoC
                reproduction_steps TEXT DEFAULT '[]',
                poc_curl TEXT,
                poc_python TEXT,

                -- Metadata
                scanner_module TEXT NOT NULL DEFAULT '',
                found_at TEXT NOT NULL,
                validated INTEGER NOT NULL DEFAULT 0,
                reported INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_findings_hunt ON findings(hunt_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_module ON findings(scanner_module);
            CREATE INDEX IF NOT EXISTS idx_findings_url ON findings(url);
            CREATE INDEX IF NOT EXISTS idx_hunts_target ON hunts(target);
        """)
        # Additive migration (schema v2): provenance column for the evidence
        # contract. Guarded so existing databases gain the column and old rows
        # read back NULL — never a breaking change.
        _cols = {row[1] for row in self.conn.execute("PRAGMA table_info(findings)").fetchall()}
        if "provenance" not in _cols:
            self.conn.execute("ALTER TABLE findings ADD COLUMN provenance TEXT")
        self.conn.commit()

    # ── Save ──────────────────────────────────────────────────────────────

    def save_hunt(
        self,
        target: str,
        preset: str,
        findings: List[Finding],
        duration: float,
        modules_run: List[str],
        ai_enabled: bool = False,
        started_at: Optional[datetime] = None,
    ) -> int:
        """
        Save a complete hunt with all findings. Returns hunt_id.
        """
        now = started_at or datetime.now()

        cursor = self.conn.execute(
            """INSERT INTO hunts (target, preset, started_at, duration_secs,
               modules_run, total_findings, ai_enabled)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                target,
                preset,
                now.isoformat(),
                duration,
                json.dumps(modules_run),
                len(findings),
                int(ai_enabled),
            ),
        )
        hunt_id = cursor.lastrowid

        for f in findings:
            self._insert_finding(hunt_id, f)

        self.conn.commit()
        return hunt_id

    def _insert_finding(self, hunt_id: int, f: Finding) -> int:
        """Insert a single finding linked to a hunt."""
        # Serialize complex fields
        evidence_str = f.evidence
        if isinstance(evidence_str, dict):
            evidence_str = json.dumps(evidence_str)
        elif evidence_str is None:
            evidence_str = ""

        prov_str = f.provenance
        if isinstance(prov_str, dict):
            prov_str = json.dumps(prov_str)

        refs = json.dumps(f.references) if f.references else "[]"
        steps = json.dumps(f.reproduction_steps) if f.reproduction_steps else "[]"

        cwe = str(f.cwe_id) if f.cwe_id else None
        mitre_tactic = f.mitre_tactic.value if f.mitre_tactic else None

        cursor = self.conn.execute(
            """INSERT INTO findings (
                hunt_id, title, severity, confidence,
                owasp_category, mitre_technique, mitre_tactic, cwe_id,
                url, parameter, injection_point, payload,
                request, response, evidence,
                description, impact, remediation,
                refs, reproduction_steps, poc_curl, poc_python,
                scanner_module, found_at, validated, reported, provenance
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                hunt_id,
                f.title,
                f.severity.value,
                f.confidence.value,
                f.owasp_category,
                f.mitre_technique,
                mitre_tactic,
                cwe,
                f.url,
                f.parameter,
                f.injection_point.value if f.injection_point else None,
                f.payload,
                f.request,
                f.response,
                evidence_str,
                f.description,
                f.impact,
                f.remediation,
                refs,
                steps,
                f.poc_curl,
                f.poc_python,
                f.scanner_module,
                f.found_at.isoformat(),
                int(f.validated),
                int(f.reported),
                prov_str,
            ),
        )
        return cursor.lastrowid

    # ── Query ─────────────────────────────────────────────────────────────

    def list_hunts(
        self,
        target: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """List recent hunts, optionally filtered by target."""
        query = "SELECT * FROM hunts"
        params: list = []

        if target:
            query += " WHERE target LIKE ?"
            params.append(f"%{target}%")

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        rows = self.conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_hunt(self, hunt_id: int) -> Optional[Dict[str, Any]]:
        """Get a single hunt by ID."""
        row = self.conn.execute(
            "SELECT * FROM hunts WHERE id = ?", (hunt_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_findings(
        self,
        hunt_id: Optional[int] = None,
        severity: Optional[str] = None,
        module: Optional[str] = None,
        target: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Query findings with flexible filters.

        Args:
            hunt_id: Filter to specific hunt
            severity: Filter by severity (critical, high, medium, low, info)
            module: Filter by scanner module name
            target: Filter by target (substring match on URL)
            search: Full-text search across title/description/evidence
            limit: Max results
        """
        query = """
            SELECT f.*, h.target as hunt_target, h.preset, h.started_at as hunt_started
            FROM findings f
            JOIN hunts h ON f.hunt_id = h.id
            WHERE 1=1
        """
        params: list = []

        if hunt_id is not None:
            query += " AND f.hunt_id = ?"
            params.append(hunt_id)

        if severity:
            query += " AND f.severity = ?"
            params.append(severity.lower())

        if module:
            query += " AND f.scanner_module = ?"
            params.append(module)

        if target:
            query += " AND (h.target LIKE ? OR f.url LIKE ?)"
            params.append(f"%{target}%")
            params.append(f"%{target}%")

        if search:
            query += " AND (f.title LIKE ? OR f.description LIKE ? OR f.evidence LIKE ?)"
            params.append(f"%{search}%")
            params.append(f"%{search}%")
            params.append(f"%{search}%")

        query += " ORDER BY CASE f.severity "
        query += " WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2"
        query += " WHEN 'low' THEN 3 WHEN 'info' THEN 4 END, f.id DESC"
        query += " LIMIT ?"
        params.append(limit)

        rows = self.conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_finding_detail(self, finding_id: int) -> Optional[Dict[str, Any]]:
        """Get full detail for a single finding."""
        row = self.conn.execute(
            """SELECT f.*, h.target as hunt_target, h.preset, h.started_at as hunt_started
               FROM findings f JOIN hunts h ON f.hunt_id = h.id
               WHERE f.id = ?""",
            (finding_id,),
        ).fetchone()
        return dict(row) if row else None

    def get_hunt_summary(self, hunt_id: int) -> Dict[str, Any]:
        """Get aggregated stats for a hunt."""
        hunt = self.get_hunt(hunt_id)
        if not hunt:
            return {}

        rows = self.conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM findings WHERE hunt_id = ? GROUP BY severity",
            (hunt_id,),
        ).fetchall()
        by_severity = {r["severity"]: r["cnt"] for r in rows}

        rows = self.conn.execute(
            "SELECT scanner_module, COUNT(*) as cnt FROM findings WHERE hunt_id = ? GROUP BY scanner_module",
            (hunt_id,),
        ).fetchall()
        by_module = {r["scanner_module"]: r["cnt"] for r in rows}

        return {
            **hunt,
            "by_severity": by_severity,
            "by_module": by_module,
        }

    # ── Export ────────────────────────────────────────────────────────────

    def export_findings_json(
        self,
        hunt_id: Optional[int] = None,
        **filters,
    ) -> str:
        """Export findings as JSON string."""
        findings = self.get_findings(hunt_id=hunt_id, **filters)

        # Parse JSON fields back to native types
        for f in findings:
            try:
                f["refs"] = json.loads(f.get("refs", "[]") or "[]")
            except (json.JSONDecodeError, TypeError):
                f["refs"] = []
            try:
                f["reproduction_steps"] = json.loads(
                    f.get("reproduction_steps", "[]") or "[]"
                )
            except (json.JSONDecodeError, TypeError):
                f["reproduction_steps"] = []
            try:
                f["provenance"] = json.loads(f["provenance"]) if f.get("provenance") else None
            except (json.JSONDecodeError, TypeError):
                f["provenance"] = None

        return json.dumps(findings, indent=2, default=str)

    def delete_hunt(self, hunt_id: int) -> bool:
        """Delete a hunt and all its findings."""
        cursor = self.conn.execute("DELETE FROM hunts WHERE id = ?", (hunt_id,))
        self.conn.commit()
        return cursor.rowcount > 0

    def close(self):
        """Close the database connection."""
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
