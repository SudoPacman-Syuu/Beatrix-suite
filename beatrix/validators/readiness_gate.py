"""
BEATRIX Report Readiness Gate

The final checkpoint before any report gets submitted.
Implements Rule #7 (Three-Cycle) and Rule #8 (Assume Hostile Triage).

A finding that passes ImpactValidator still needs to pass HERE
before it touches HackerOne.

This gate asks: "Would a hostile triager close this?"
If the answer is anything but "absolutely not" — it's not ready.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import List

from beatrix.core.types import Finding, Severity


@dataclass
class ReadinessCheck:
    """Result of a single readiness check"""
    name: str
    passed: bool
    reason: str
    required: bool = True  # If True, failure blocks submission


@dataclass
class ReadinessVerdict:
    """Final verdict on report readiness"""
    finding: Finding
    ready: bool
    checks: List[ReadinessCheck] = field(default_factory=list)
    score: int = 0        # 0-100 readiness score
    reason: str = ""
    validated_at: datetime = field(default_factory=datetime.now)

    @property
    def failed_required(self) -> List[ReadinessCheck]:
        return [c for c in self.checks if not c.passed and c.required]

    @property
    def failed_optional(self) -> List[ReadinessCheck]:
        return [c for c in self.checks if not c.passed and not c.required]

    def summary(self) -> str:
        lines = [f"{'✅ READY' if self.ready else '❌ NOT READY'} (score: {self.score}/100)"]
        lines.append(f"  {self.reason}")
        if self.failed_required:
            lines.append("  BLOCKERS:")
            for c in self.failed_required:
                lines.append(f"    ❌ {c.name}: {c.reason}")
        if self.failed_optional:
            lines.append("  WARNINGS:")
            for c in self.failed_optional:
                lines.append(f"    ⚠️  {c.name}: {c.reason}")
        return "\n".join(lines)


class ReportReadinessGate:
    """
    Final gate before submission. Implements Rules #7 and #8.

    Usage:
        gate = ReportReadinessGate()
        verdict = gate.check(finding)
        if not verdict.ready:
            # DO NOT SUBMIT
            print(verdict.summary())
    """

    def check(self, finding: Finding) -> ReadinessVerdict:
        """Run all readiness checks."""
        checks: List[ReadinessCheck] = []

        checks.append(self._check_title_quality(finding))
        checks.append(self._check_description_quality(finding))
        checks.append(self._check_impact_statement(finding))
        checks.append(self._check_poc_exists(finding))
        checks.append(self._check_evidence_concrete(finding))
        checks.append(self._check_provenance_unknowns(finding))
        checks.append(self._check_no_theoretical_language(finding))
        checks.append(self._check_severity_justified(finding))
        checks.append(self._check_remediation(finding))
        checks.append(self._check_references(finding))

        # Score calculation
        total = len(checks)
        passed = sum(1 for c in checks if c.passed)
        score = int((passed / total) * 100) if total > 0 else 0

        # Must pass ALL required checks
        failed_required = [c for c in checks if not c.passed and c.required]
        ready = len(failed_required) == 0 and score >= 70

        if ready:
            reason = "Report passes all required checks. Ready for Three-Cycle validation."
        elif failed_required:
            reason = f"{len(failed_required)} required check(s) failed. Fix before submitting."
        else:
            reason = f"Score too low ({score}/100). Improve report quality."

        return ReadinessVerdict(
            finding=finding,
            ready=ready,
            checks=checks,
            score=score,
            reason=reason,
        )

    # ====================================================================
    # CHECKS
    # ====================================================================

    def _check_provenance_unknowns(self, finding: Finding) -> ReadinessCheck:
        """Rule: an UNKNOWN is never silently treated as clean/absent.

        If the finding carries an evidence-provenance record (see
        beatrix.core.provenance) whose core claim is UNKNOWN — or whose
        unresolved unknowns lack direct observation/derivation evidence — it
        is not report-ready until resolved. Findings with no provenance pass
        unchanged (fully backward compatible)."""
        from beatrix.core.provenance import readiness
        ok, reasons = readiness(getattr(finding, "provenance", None))
        if ok:
            return ReadinessCheck(
                name="provenance_unknowns",
                passed=True,
                reason="No undetermined claims (or no provenance record).",
            )
        return ReadinessCheck(
            name="provenance_unknowns",
            passed=False,
            reason="Undetermined claim(s): " + "; ".join(reasons),
            required=True,
        )

    def _check_title_quality(self, finding: Finding) -> ReadinessCheck:
        """Title must be specific and professional."""
        title = finding.title.strip()

        if not title:
            return ReadinessCheck(
                name="title_quality",
                passed=False,
                reason="No title.",
                required=True,
            )

        if len(title) < 15:
            return ReadinessCheck(
                name="title_quality",
                passed=False,
                reason="Title too short. Be specific about vuln type + endpoint.",
                required=True,
            )

        if len(title) > 200:
            return ReadinessCheck(
                name="title_quality",
                passed=False,
                reason="Title too long. Keep it concise.",
                required=False,
            )

        # Should contain vulnerability type
        vuln_keywords = [
            "xss", "sqli", "sql injection", "idor", "ssrf", "cors",
            "rce", "lfi", "rfi", "csrf", "open redirect", "auth bypass",
            "privilege escalation", "information disclosure", "injection",
            "broken access", "misconfiguration", "takeover", "leak",
            "exposure", "overflow", "deserialization", "xxe",
        ]
        has_vuln_type = any(kw in title.lower() for kw in vuln_keywords)

        if not has_vuln_type:
            return ReadinessCheck(
                name="title_quality",
                passed=False,
                reason="Title doesn't clearly state the vulnerability type. "
                       "Example: 'IDOR on /api/users/{id} allows reading other users' data'",
                required=False,
            )

        return ReadinessCheck(
            name="title_quality",
            passed=True,
            reason="Title is clear and specific.",
        )

    def _check_description_quality(self, finding: Finding) -> ReadinessCheck:
        """Description must explain the vulnerability clearly."""
        desc = finding.description.strip()

        if not desc:
            return ReadinessCheck(
                name="description_quality",
                passed=False,
                reason="No description.",
                required=True,
            )

        if len(desc) < 50:
            return ReadinessCheck(
                name="description_quality",
                passed=False,
                reason="Description too brief. Explain what, where, and how.",
                required=True,
            )

        return ReadinessCheck(
            name="description_quality",
            passed=True,
            reason="Description is present and substantive.",
        )

    def _check_impact_statement(self, finding: Finding) -> ReadinessCheck:
        """
        Impact must be CONCRETE, not theoretical.

        BAD:  "An attacker could potentially access user data."
        GOOD: "An attacker can read any user's email and phone number by
               changing the user_id parameter. Demonstrated with user ID 12345."
        """
        impact = finding.impact.strip() if finding.impact else ""

        if not impact:
            return ReadinessCheck(
                name="impact_statement",
                passed=False,
                reason="No impact statement. Must explain exactly what "
                       "an attacker gains from this vulnerability.",
                required=True,
            )

        if len(impact) < 30:
            return ReadinessCheck(
                name="impact_statement",
                passed=False,
                reason="Impact statement too vague. Be specific about "
                       "what data/action is compromised.",
                required=True,
            )

        return ReadinessCheck(
            name="impact_statement",
            passed=True,
            reason="Impact statement present.",
        )

    def _check_poc_exists(self, finding: Finding) -> ReadinessCheck:
        """
        Rule #6: Could a triager paste this into a terminal and see it?
        """
        has_curl = bool(finding.poc_curl)
        has_python = bool(finding.poc_python)
        has_steps = len(finding.reproduction_steps) >= 2

        if has_curl or has_python:
            return ReadinessCheck(
                name="poc_exists",
                passed=True,
                reason="PoC command available.",
            )

        if has_steps:
            return ReadinessCheck(
                name="poc_exists",
                passed=True,
                reason="Reproduction steps documented.",
            )

        return ReadinessCheck(
            name="poc_exists",
            passed=False,
            reason="No PoC curl command, Python script, or reproduction steps. "
                   "Triager MUST be able to reproduce independently.",
            required=True,
        )

    def _check_evidence_concrete(self, finding: Finding) -> ReadinessCheck:
        """Evidence must show actual data, not just status codes."""
        evidence = str(finding.evidence or "")
        response = str(finding.response or "")
        combined = f"{evidence} {response}"

        if not combined.strip():
            return ReadinessCheck(
                name="evidence_concrete",
                passed=False,
                reason="No evidence or response data. Show the actual "
                       "vulnerable response.",
                required=True,
            )

        # Check for actual data vs just status codes
        just_status = bool(re.match(r'^\s*(HTTP/\S+\s+)?\d{3}\s*$', combined.strip()))
        if just_status:
            return ReadinessCheck(
                name="evidence_concrete",
                passed=False,
                reason="Evidence is just a status code. Show the response "
                       "body containing sensitive data or the exploit result.",
                required=True,
            )

        return ReadinessCheck(
            name="evidence_concrete",
            passed=True,
            reason="Concrete evidence present.",
        )

    def _check_no_theoretical_language(self, finding: Finding) -> ReadinessCheck:
        """
        Rule #8: No hand-waving.

        Flag reports that use weasel words instead of concrete proof.
        """
        all_text = " ".join([
            finding.title or "",
            finding.description or "",
            finding.impact or "",
        ]).lower()

        theoretical_phrases = [
            "could potentially",
            "might allow",
            "may lead to",
            "could be used to",
            "theoretically",
            "in theory",
            "if an attacker were to",
            "it is possible that",
            "this could allow",
            "potential impact",
            "potentially sensitive",
        ]

        found = [p for p in theoretical_phrases if p in all_text]

        if found:
            return ReadinessCheck(
                name="no_theoretical",
                passed=False,
                reason=f"Theoretical language detected: '{found[0]}'. "
                       "Replace with concrete statements. "
                       "'An attacker CAN do X' not 'could potentially do X'.",
                required=False,  # Warning, not blocker
            )

        return ReadinessCheck(
            name="no_theoretical",
            passed=True,
            reason="Language is concrete and assertive.",
        )

    def _check_severity_justified(self, finding: Finding) -> ReadinessCheck:
        """
        Severity must match the actual demonstrated impact.
        Over-rating gets reports closed faster than under-rating.
        """
        sev = finding.severity

        # Critical/High findings need strong evidence
        if sev in (Severity.CRITICAL, Severity.HIGH):
            has_data_proof = bool(finding.evidence) and bool(finding.poc_curl or finding.poc_python)
            if not has_data_proof:
                return ReadinessCheck(
                    name="severity_justified",
                    passed=False,
                    reason=f"{sev.value.upper()} severity requires both evidence "
                           "of data access AND a working PoC. Consider lowering "
                           "severity or adding stronger proof.",
                    required=True,
                )

        return ReadinessCheck(
            name="severity_justified",
            passed=True,
            reason="Severity is justified by evidence level.",
        )

    def _check_remediation(self, finding: Finding) -> ReadinessCheck:
        """Remediation advice shows professionalism."""
        rem = finding.remediation.strip() if finding.remediation else ""

        if not rem:
            return ReadinessCheck(
                name="remediation",
                passed=False,
                reason="No remediation advice. Always suggest a fix.",
                required=False,
            )

        if len(rem) < 20:
            return ReadinessCheck(
                name="remediation",
                passed=False,
                reason="Remediation too brief. Be specific about the fix.",
                required=False,
            )

        return ReadinessCheck(
            name="remediation",
            passed=True,
            reason="Remediation advice present.",
        )

    def _check_references(self, finding: Finding) -> ReadinessCheck:
        """References add credibility."""
        if finding.references and len(finding.references) > 0:
            return ReadinessCheck(
                name="references",
                passed=True,
                reason="References included.",
            )

        return ReadinessCheck(
            name="references",
            passed=False,
            reason="No references. Add OWASP, CWE, or relevant links.",
            required=False,
        )
