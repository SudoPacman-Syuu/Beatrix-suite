"""
BEATRIX Evidence-Provenance Contract

Every claim a scanner makes carries its epistemic status and the evidence behind
it. Ported from the discipline of reverse-engineering tooling (REA): a finding is
not just "here is a bug" but "here is what we OBSERVED, what we DERIVED from it,
what we INFERRED heuristically, and — critically — what we could NOT determine."

Rule: an UNKNOWN is never silently treated as clean/absent. A scanner that could
not reach a target, parse a response, or recover a source says so, and the report
readiness gate refuses to call such a finding report-ready.

Adoption is incremental and additive:

    from beatrix.core.provenance import Provenance

    finding = self.create_finding(..., provenance=Provenance.observation(
        method="sourcemap.sourcesContent",
        source=map_url, locator="sourcesContent[3]", literal=path,
    ).to_dict())

Nothing else in a scanner needs to change; findings without provenance behave
exactly as they did before.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class ClaimType(Enum):
    """Epistemic status of a claim — how we know what we say we know."""

    OBSERVATION = "observation"   # Directly present in bytes we fetched / saw on the wire
    DERIVATION = "derivation"     # Deterministically computed from observations (decode/parse/join)
    INFERENCE = "inference"       # Heuristic / probabilistic (regex "looks-like", entropy, naming)
    UNKNOWN = "unknown"           # Could NOT be determined — never equals clean/absent

    @property
    def label(self) -> str:
        return self.value.upper()


def mask_literal(value: str, keep: int = 4) -> str:
    """Mask the middle of a sensitive literal, keeping a short prefix/suffix.

    ``"sk_live_abcdefghijklmnop"`` -> ``"sk_l…mnop"``. Short values are fully
    masked so a secret can never be reconstructed from its provenance record.
    """
    if value is None:
        return ""
    v = str(value)
    if len(v) <= keep * 2:
        return "…" * min(len(v), 3) if v else ""
    return f"{v[:keep]}…{v[-keep:]}"


@dataclass
class Evidence:
    """One concrete piece of support for a claim."""

    source: str = ""              # URL or logical origin ("https://x/main.js.map", "webpack://app/src/api.js")
    locator: str = ""             # Where within the source ("sourcesContent[3]", "Route path=", "line 42")
    literal: str = ""             # Exact substring matched (already masked for secrets)
    line: Optional[int] = None
    col: Optional[int] = None
    byte_start: Optional[int] = None
    byte_end: Optional[int] = None
    retrieved_at: Optional[str] = None   # ISO timestamp (best-effort)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "source": self.source,
            "locator": self.locator,
            "literal": self.literal,
        }
        for k in ("line", "col", "byte_start", "byte_end", "retrieved_at"):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Evidence":
        return cls(
            source=d.get("source", ""),
            locator=d.get("locator", ""),
            literal=d.get("literal", ""),
            line=d.get("line"),
            col=d.get("col"),
            byte_start=d.get("byte_start"),
            byte_end=d.get("byte_end"),
            retrieved_at=d.get("retrieved_at"),
        )


def _now_iso() -> Optional[str]:
    # Best-effort timestamp; never let clock access break a finding.
    try:
        return datetime.now().isoformat(timespec="seconds")
    except Exception:
        return None


@dataclass
class Provenance:
    """The epistemic record attached to a finding (or a sub-claim of one)."""

    claim: ClaimType = ClaimType.INFERENCE
    method: str = ""                                   # "sourcemap.sourcesContent", "regex:stripe_key", "router:react-router"
    evidence: List[Evidence] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    confidence_basis: str = ""                         # short "why this ClaimType"
    unknowns: List[str] = field(default_factory=list)  # named facts we could not determine

    # ── Serialization ──────────────────────────────────────────────────────
    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim": self.claim.value,
            "method": self.method,
            "evidence": [e.to_dict() for e in self.evidence],
            "limitations": list(self.limitations),
            "confidence_basis": self.confidence_basis,
            "unknowns": list(self.unknowns),
        }

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> Optional["Provenance"]:
        if not d:
            return None
        try:
            claim = ClaimType(d.get("claim", "inference"))
        except ValueError:
            claim = ClaimType.INFERENCE
        return cls(
            claim=claim,
            method=d.get("method", ""),
            evidence=[Evidence.from_dict(e) for e in d.get("evidence", []) if isinstance(e, dict)],
            limitations=list(d.get("limitations", [])),
            confidence_basis=d.get("confidence_basis", ""),
            unknowns=list(d.get("unknowns", [])),
        )

    # ── Introspection ────────────────────────────────────────────────────────
    def relies_on_unknown(self) -> bool:
        """True when the core claim is UNKNOWN or named unknowns remain."""
        return self.claim == ClaimType.UNKNOWN or bool(self.unknowns)

    def has_direct_evidence(self) -> bool:
        """True when the claim is backed by observation/derivation (not pure heuristic)."""
        return self.claim in (ClaimType.OBSERVATION, ClaimType.DERIVATION) and bool(self.evidence)

    # ── Constructor helpers ───────────────────────────────────────────────────
    @classmethod
    def _single(
        cls,
        claim: ClaimType,
        method: str,
        *,
        source: str = "",
        locator: str = "",
        literal: str = "",
        line: Optional[int] = None,
        byte_start: Optional[int] = None,
        byte_end: Optional[int] = None,
        limitations: Optional[List[str]] = None,
        confidence_basis: str = "",
        unknowns: Optional[List[str]] = None,
    ) -> "Provenance":
        ev: List[Evidence] = []
        if source or locator or literal or line is not None:
            ev.append(Evidence(
                source=source, locator=locator, literal=literal, line=line,
                byte_start=byte_start, byte_end=byte_end, retrieved_at=_now_iso(),
            ))
        return cls(
            claim=claim, method=method, evidence=ev,
            limitations=list(limitations or []),
            confidence_basis=confidence_basis,
            unknowns=list(unknowns or []),
        )

    @classmethod
    def observation(cls, method: str, **kw) -> "Provenance":
        return cls._single(ClaimType.OBSERVATION, method, **kw)

    @classmethod
    def derivation(cls, method: str, **kw) -> "Provenance":
        return cls._single(ClaimType.DERIVATION, method, **kw)

    @classmethod
    def inference(cls, method: str, **kw) -> "Provenance":
        return cls._single(ClaimType.INFERENCE, method, **kw)

    @classmethod
    def unknown(cls, what: str, *, method: str = "", limitations: Optional[List[str]] = None) -> "Provenance":
        """Record that a fact could not be determined. ``what`` names the undetermined fact."""
        return cls(
            claim=ClaimType.UNKNOWN,
            method=method,
            unknowns=[what],
            limitations=list(limitations or []),
            confidence_basis="not determinable with the evidence available",
        )

    def with_evidence(self, **kw) -> "Provenance":
        """Append another Evidence row and return self (chainable)."""
        self.evidence.append(Evidence(retrieved_at=_now_iso(), **kw))
        return self


def attach(finding: Any, prov: Any) -> Any:
    """Attach provenance (a ``Provenance`` or an already-serialized dict) to a Finding."""
    finding.provenance = prov.to_dict() if isinstance(prov, Provenance) else prov
    return finding


def readiness(prov: Optional[Dict[str, Any]]) -> "tuple[bool, List[str]]":
    """Gate helper: is a provenance-carrying finding fit to report?

    Returns ``(ready, reasons)``. The "unknowns never silently clean" rule:
      * a core claim of UNKNOWN is never report-ready;
      * an absence/negative claim with no direct (observation/derivation)
        evidence surfaces its unknowns as blocking reasons.
    Findings without provenance return ``(True, [])`` — fully backward compatible.
    """
    p = Provenance.from_dict(prov)
    if p is None:
        return True, []
    reasons: List[str] = []
    if p.claim == ClaimType.UNKNOWN:
        reasons.append("core claim is UNKNOWN — cannot be reported as fact")
    if p.unknowns and not p.has_direct_evidence():
        reasons.extend(f"undetermined: {u}" for u in p.unknowns)
    return (len(reasons) == 0), reasons
