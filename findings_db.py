"""
FINDINGS DATABASE — audit history with run-over-run diffs.

=============================================================
  WHAT WE PERSIST AND WHY
=============================================================

We store the DETERMINISTIC artifacts of each audit — the raw tool
invocations and their JSON results — NOT the LLM-synthesized prose
report. Two reasons:

  1. The tool outputs are structured and stable across runs. You can
     diff them mechanically.
  2. The LLM report is non-deterministic; two runs can phrase the same
     finding three different ways. Storing it for diffs is a trap.

So the schema is tiny and honest:

  audits            one row per invocation of run_audit(...)
  tool_invocations  one row per call the agent made to one of our tools

Everything else (finding severity, prioritization, remediation) is
derived at query time from the raw tool JSON. No denormalization.

=============================================================
  HOW DIFFS WORK
=============================================================

For each tool called in BOTH runs, we hash the canonicalized JSON
result. Identical hash = unchanged. Different hash = something
changed — the CLI shows a structural summary (added/removed keys,
list length deltas).

This lets you answer questions like:
  "Did the most recent audit find anything new vs last week?"
  "Is my risk profile drifting?"

without any LLM in the loop for the comparison step.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def collect_severities(result_json: str) -> list[str]:
    """Walk a tool result JSON and collect every severity-like value.

    Tools use several shapes (model_files[].risk, behavioral_risks[].severity,
    risk_level, etc.) so we walk the structure and pluck any string value
    equal to one of our known severity names. Heuristic but honest.
    """
    try:
        obj = json.loads(result_json)
    except (json.JSONDecodeError, TypeError):
        return []

    found: list[str] = []

    def walk(node):
        if isinstance(node, dict):
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
        elif isinstance(node, str) and node in SEVERITY_ORDER:
            found.append(node)

    walk(obj)
    return found


SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    project_path TEXT    NOT NULL,
    project_hash TEXT,
    timestamp    TEXT    NOT NULL,
    backend      TEXT    NOT NULL,
    model        TEXT
);

CREATE TABLE IF NOT EXISTS tool_invocations (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id       INTEGER NOT NULL,
    tool_name      TEXT    NOT NULL,
    arguments_json TEXT    NOT NULL,
    result_json    TEXT    NOT NULL,
    result_hash    TEXT    NOT NULL,
    timestamp      TEXT    NOT NULL,
    FOREIGN KEY (audit_id) REFERENCES audits(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_audit_project    ON audits(project_path, timestamp);
CREATE INDEX IF NOT EXISTS idx_invocation_audit ON tool_invocations(audit_id);
"""


class FindingsDB:
    """Thin wrapper over SQLite. Zero deps outside stdlib."""

    def __init__(self, db_path: str | Path):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ---------------------------------------------------------------
    # Writers
    # ---------------------------------------------------------------

    def start_audit(self, project_path: str, backend: str, model: str | None = None) -> int:
        """Record a new audit run. Returns the audit_id."""
        cur = self.conn.execute(
            "INSERT INTO audits (project_path, project_hash, timestamp, backend, model) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                str(Path(project_path).resolve()),
                _git_head(project_path),
                _iso_now(),
                backend,
                model,
            ),
        )
        self.conn.commit()
        return cur.lastrowid

    def log_tool_invocation(
        self,
        audit_id: int,
        tool_name: str,
        arguments: dict,
        result: str,
    ) -> None:
        """Store one tool call + its result.

        `result` is the raw string returned by the tool runner. We try to
        canonicalize (sorted keys) before hashing so unchanged semantic
        content produces unchanged hashes regardless of key order.
        """
        self.conn.execute(
            "INSERT INTO tool_invocations "
            "(audit_id, tool_name, arguments_json, result_json, result_hash, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                audit_id,
                tool_name,
                json.dumps(arguments, sort_keys=True),
                result,
                _canonical_hash(result),
                _iso_now(),
            ),
        )
        self.conn.commit()

    # ---------------------------------------------------------------
    # Readers
    # ---------------------------------------------------------------

    def list_audits(self, project_path: str | None = None, limit: int = 20) -> list[dict]:
        if project_path:
            rows = self.conn.execute(
                "SELECT * FROM audits WHERE project_path = ? "
                "ORDER BY timestamp DESC LIMIT ?",
                (str(Path(project_path).resolve()), limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM audits ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_audit(self, audit_id: int) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM audits WHERE id = ?", (audit_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_invocations(self, audit_id: int) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM tool_invocations WHERE audit_id = ? ORDER BY id",
            (audit_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def severity_counts(self, audit_id: int) -> dict[str, int]:
        """Count every severity mention across all tool invocations for an audit."""
        counts = {k: 0 for k in SEVERITY_ORDER}
        for inv in self.get_invocations(audit_id):
            for sev in collect_severities(inv["result_json"]):
                counts[sev] += 1
        return counts

    # ---------------------------------------------------------------
    # Diff
    # ---------------------------------------------------------------

    def diff_audits(self, old_id: int, new_id: int) -> dict:
        """Compare two audits tool-by-tool.

        Returns a dict shaped like:
            {
              "old": {audit metadata},
              "new": {audit metadata},
              "tools": {
                "scan_inventory": {
                  "status": "changed" | "unchanged" | "added" | "removed",
                  "summary": "...",   # only for changed/added/removed
                },
                ...
              }
            }
        """
        old = self.get_audit(old_id)
        new = self.get_audit(new_id)
        if not old or not new:
            raise ValueError(f"Audit not found: old={old_id}, new={new_id}")

        old_by_tool = _latest_per_tool(self.get_invocations(old_id))
        new_by_tool = _latest_per_tool(self.get_invocations(new_id))

        tool_names = set(old_by_tool) | set(new_by_tool)
        tools = {}
        for name in sorted(tool_names):
            o, n = old_by_tool.get(name), new_by_tool.get(name)
            if o and not n:
                tools[name] = {"status": "removed", "summary": "tool not called in new audit"}
            elif n and not o:
                tools[name] = {"status": "added", "summary": "tool newly called in this audit"}
            elif o["result_hash"] == n["result_hash"]:
                tools[name] = {"status": "unchanged"}
            else:
                tools[name] = {
                    "status": "changed",
                    "summary": _summarize_json_diff(o["result_json"], n["result_json"]),
                }

        return {"old": old, "new": new, "tools": tools}


# ===================================================================
#  Helpers
# ===================================================================

def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_hash(raw: str) -> str:
    """Hash a JSON string with sorted keys so formatting doesn't trip diffs."""
    try:
        obj = json.loads(raw)
        canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    except json.JSONDecodeError:
        canonical = raw  # non-JSON: hash as-is
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _git_head(project_path: str) -> str | None:
    """Return the git HEAD commit sha, or None if the project isn't a git repo."""
    try:
        out = subprocess.run(
            ["git", "-C", str(project_path), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=2,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _latest_per_tool(invocations: list[dict]) -> dict[str, dict]:
    """If a tool was called multiple times in one audit, keep the latest call.

    The agent may call the same tool with different arguments (e.g.,
    verify_integrity on two different files). For a diff view we want one
    canonical output per tool — the last one is a reasonable proxy.
    """
    by_tool: dict[str, dict] = {}
    for inv in invocations:
        by_tool[inv["tool_name"]] = inv
    return by_tool


def _summarize_json_diff(old_raw: str, new_raw: str) -> str:
    """One-line human summary of what changed between two JSON blobs."""
    try:
        o = json.loads(old_raw)
        n = json.loads(new_raw)
    except json.JSONDecodeError:
        return f"non-JSON output changed (old={len(old_raw)}B, new={len(new_raw)}B)"

    if not isinstance(o, dict) or not isinstance(n, dict):
        return "output shape differs"

    added = sorted(set(n) - set(o))
    removed = sorted(set(o) - set(n))
    changed_keys = [k for k in set(o) & set(n) if json.dumps(o[k], sort_keys=True) != json.dumps(n[k], sort_keys=True)]

    parts: list[str] = []
    if added:
        parts.append(f"+keys: {added}")
    if removed:
        parts.append(f"-keys: {removed}")
    if changed_keys:
        parts.append(f"~keys: {sorted(changed_keys)}")

    # For list-valued keys, also note length delta — usually the signal
    # people care about ("2 new findings").
    for k in changed_keys:
        if isinstance(o.get(k), list) and isinstance(n.get(k), list):
            delta = len(n[k]) - len(o[k])
            if delta != 0:
                sign = "+" if delta > 0 else ""
                parts.append(f"{k}: {sign}{delta} items")

    return "; ".join(parts) or "content changed"
