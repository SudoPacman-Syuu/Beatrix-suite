"""
BEATRIX Report Generator

Auto-generates bug bounty reports from findings.
Outputs Markdown reports ready for bug bounty platform submission.
Enriches findings with Bugcrowd VRT classification and CVSS 3.1 scores.
"""

import json  # noqa: F401
import os
from dataclasses import asdict  # noqa: F401
from datetime import datetime
from pathlib import Path
from typing import List, Optional  # noqa: F401


def _fix_sudo_file(filepath: Path) -> None:
    """Chown a file back to the real user when running under sudo."""
    sudo_uid = os.environ.get("SUDO_UID")
    if not sudo_uid:
        return
    try:
        os.chown(filepath, int(sudo_uid), int(os.environ.get("SUDO_GID", sudo_uid)))
    except OSError:
        pass

from beatrix.core.types import Finding, Severity

# VRT classification for Bugcrowd-style priority rating + CVSS scoring
try:
    from beatrix.utils.vrt_classifier import VRTClassifier, classify_finding
    HAS_VRT = True
except ImportError:
    HAS_VRT = False

# Attack chain reporting (correlation engine → HTML/JSON chain reports)
try:
    from beatrix.reporters.chain_reporting import (  # noqa: F401
        AttackChainReportGenerator,
        enrich_report_with_chains,
        generate_attack_chain_section_html,
    )
    HAS_CHAIN_REPORTING = True
except ImportError:
    HAS_CHAIN_REPORTING = False

# PoC chain engine (transforms vuln chains into exploit code)
try:
    from beatrix.core.poc_chain_engine import PoCChainEngine, generate_poc_chains  # noqa: F401
    HAS_POC_ENGINE = True
except ImportError:
    HAS_POC_ENGINE = False


class ReportGenerator:
    """
    Generates professional bug bounty reports from findings.
    """

    SEVERITY_CVSS = {
        Severity.CRITICAL: "9.0-10.0",
        Severity.HIGH: "7.0-8.9",
        Severity.MEDIUM: "4.0-6.9",
        Severity.LOW: "0.1-3.9",
        Severity.INFO: "0.0",
    }

    def __init__(self, output_dir: Path = Path("./reports")):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        finding: Finding,
        program: str = "Unknown",
        researcher: str = "Security Researcher",
    ) -> Path:
        """Generate a Markdown report for a single finding"""

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_title = "".join(c if c.isalnum() else "_" for c in finding.title[:50])
        filename = f"{timestamp}_{safe_title}.md"
        filepath = self.output_dir / filename

        report = self._format_report(finding, program, researcher)
        filepath.write_text(report)
        _fix_sudo_file(filepath)

        return filepath

    def generate_batch_report(
        self,
        findings: List[Finding],
        target: str,
        program: str = "Unknown",
    ) -> Path:
        """Generate a combined report for multiple findings"""

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = "".join(c if c.isalnum() else "_" for c in target[:30])
        filename = f"{timestamp}_{safe_target}_scan_report.md"
        filepath = self.output_dir / filename

        report = self._format_batch_report(findings, target, program)
        filepath.write_text(report)
        _fix_sudo_file(filepath)

        return filepath

    def _format_report(
        self,
        finding: Finding,
        program: str,
        researcher: str,
    ) -> str:
        """Format a single finding as a full report"""

        return f"""# {finding.title}

## Summary
{finding.description}

## Severity
**{finding.severity.value.upper()}** (CVSS {self.SEVERITY_CVSS.get(finding.severity, "N/A")})

## Affected Endpoint
```
{finding.url}
```

## Technical Details

### Evidence
```
{finding.evidence or "See request/response below"}
```

### Request
```http
{finding.request or "N/A"}
```

### Response
```http
{finding.response or "N/A"}
```

## Impact
{finding.impact or self._generate_impact(finding)}

## Proof of Concept
{self._generate_poc(finding)}

## Remediation
{finding.remediation or "Implement proper security controls."}

## References
{self._format_references(finding.references)}

## Classification
- **OWASP**: {finding.owasp_category or "N/A"}
- **MITRE ATT&CK**: {finding.mitre_technique or "N/A"}
- **CWE**: {finding.cwe_id or "N/A"}
{self._format_vrt_section(finding)}
{self._format_provenance_section(finding)}
---
**Program**: {program}
**Discovered**: {finding.found_at.strftime("%Y-%m-%d %H:%M:%S")}
**Scanner**: BEATRIX v1.0.0 ({finding.scanner_module})
**Researcher**: {researcher}
"""

    def _format_batch_report(
        self,
        findings: List[Finding],
        target: str,
        program: str,
    ) -> str:
        """Format multiple findings as a scan report"""

        # Group by severity
        by_severity = {}
        for f in findings:
            sev = f.severity.value
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(f)

        # Summary stats
        summary = f"""# Security Scan Report: {target}

## Executive Summary
- **Target**: {target}
- **Scan Date**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- **Total Findings**: {len(findings)}
- **Critical**: {len(by_severity.get('critical', []))}
- **High**: {len(by_severity.get('high', []))}
- **Medium**: {len(by_severity.get('medium', []))}
- **Low**: {len(by_severity.get('low', []))}
- **Info**: {len(by_severity.get('info', []))}

---

"""

        # Add each finding
        for i, finding in enumerate(findings, 1):
            # Enrich with VRT classification if available
            vrt_section = ""
            if HAS_VRT:
                vrt = VRTClassifier.classify(
                    finding.title,
                    str(finding.evidence or ""),
                    finding.severity.value,
                )
                if vrt:
                    cvss_score = vrt.cvss.calculate_base_score()
                    vrt_section = f"""
**Bugcrowd VRT**: {vrt.get_priority_label()} — {vrt.get_full_classification()}
**CVSS 3.1**: {cvss_score} ({vrt.cvss.get_severity_rating()}) `{vrt.cvss.get_vector_string()}`"""

            summary += f"""
## Finding #{i}: {finding.title}

**Severity**: {finding.severity.icon} {finding.severity.value.upper()}
**URL**: `{finding.url}`
**Confidence**: {finding.confidence.value}{vrt_section}

### Description
{finding.description}

### Evidence
```
{finding.evidence or "N/A"}
```

### Remediation
{finding.remediation or "See vendor documentation."}

---
"""

        summary += f"""
## Methodology
Automated scan performed using BEATRIX autonomous security scanner.

**Program**: {program}
**Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""

        return summary

    def _generate_impact(self, finding: Finding) -> str:
        """Generate impact description based on finding type"""

        title_lower = finding.title.lower()

        if "cors" in title_lower:
            return """An attacker can host a malicious webpage that makes authenticated cross-origin
requests to this endpoint. If a victim visits the attacker's page while logged in,
the attacker can read sensitive data from the response."""

        if "sql" in title_lower or "injection" in title_lower:
            return """An attacker could extract, modify, or delete data from the database.
In severe cases, this could lead to full database compromise or remote code execution."""

        if "xss" in title_lower:
            return """An attacker can execute arbitrary JavaScript in the context of the victim's
browser session. This can be used to steal session tokens, perform actions on
behalf of the user, or redirect to malicious sites."""

        return "This vulnerability could be exploited by an attacker to compromise the security of the application or its users."

    def _format_vrt_section(self, finding: Finding) -> str:
        """Generate Bugcrowd VRT classification section for a finding."""
        if not HAS_VRT:
            return ""
        vrt = VRTClassifier.classify(
            finding.title,
            str(finding.evidence or ""),
            finding.severity.value,
        )
        if not vrt:
            return ""
        cvss_score = vrt.cvss.calculate_base_score()
        return (
            f"\n## Bugcrowd VRT Classification\n"
            f"- **Priority**: {vrt.get_priority_label()}\n"
            f"- **Category**: {vrt.get_full_classification()}\n"
            f"- **CVSS 3.1**: {cvss_score} ({vrt.cvss.get_severity_rating()})\n"
            f"- **Vector**: `{vrt.cvss.get_vector_string()}`\n"
            f"\n### Impact Assessment\n{VRTClassifier.get_impact_statement(vrt)}\n"
        )

    def _format_provenance_section(self, finding: Finding) -> str:
        """Render the evidence-provenance record (beatrix.core.provenance).

        Surfaces what was observed/derived/inferred and — critically — any
        unresolved UNKNOWNs, which are never presented as absent/clean."""
        prov = getattr(finding, "provenance", None)
        if not prov:
            return ""
        try:
            from beatrix.core.provenance import Provenance
            p = Provenance.from_dict(prov)
        except Exception:
            return ""
        if p is None:
            return ""
        lines = ["\n## Evidence Provenance",
                 f"- **Claim**: {p.claim.label}",
                 f"- **Method**: {p.method or 'N/A'}"]
        if p.confidence_basis:
            lines.append(f"- **Basis**: {p.confidence_basis}")
        if p.evidence:
            lines.append("\n### Evidence")
            for e in p.evidence:
                loc = []
                if e.line is not None:
                    loc.append(f"line {e.line}")
                if e.byte_start is not None:
                    loc.append(f"bytes {e.byte_start}-{e.byte_end}")
                suffix = f" ({', '.join(loc)})" if loc else ""
                lit = f" — `{e.literal}`" if e.literal else ""
                where = e.source + (f" [{e.locator}]" if e.locator else "")
                lines.append(f"- {where}{lit}{suffix}")
        if p.limitations:
            lines.append("\n### Limitations")
            lines.extend(f"- {lim}" for lim in p.limitations)
        if p.claim.value == "unknown" or p.unknowns:
            lines.append("\n### Unknowns (unresolved — not treated as absent/clean)")
            if p.unknowns:
                lines.extend(f"- {u}" for u in p.unknowns)
            else:
                lines.append("- core claim could not be determined")
        return "\n".join(lines) + "\n"

    def _generate_poc(self, finding: Finding) -> str:
        """Generate proof of concept code"""

        title_lower = finding.title.lower()

        if "cors" in title_lower:
            return f"""```html
<html>
<body>
<h1>CORS PoC</h1>
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', '{finding.url}', true);
xhr.withCredentials = true;
xhr.onload = function() {{
    console.log('Response:', xhr.responseText);
    document.body.innerHTML += '<pre>' + xhr.responseText + '</pre>';
}};
xhr.send();
</script>
</body>
</html>
```"""

        if finding.poc_curl:
            return f"```bash\n{finding.poc_curl}\n```"

        return "```\nManual verification required.\n```"

    def _format_references(self, refs: List[str]) -> str:
        """Format references as markdown list"""
        if not refs:
            return "- N/A"
        return "\n".join(f"- {ref}" for ref in refs)

    def export_json(self, findings: List[Finding], filepath: Path, target: str = None) -> None:
        """Export findings as JSON for further processing.

        Produces a standardised ``{"findings": [...], "metadata": {...}}``
        envelope compatible with ``beatrix validate``.
        """
        from datetime import datetime

        finding_list = []
        for f in findings:
            d = {
                "title": f.title,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "url": f.url,
                "description": f.description,
                "evidence": f.evidence,
                "provenance": f.provenance,
                "request": f.request,
                "response": f.response,
                "remediation": f.remediation,
                "scanner_module": f.scanner_module,
                "found_at": f.found_at.isoformat(),
            }
            finding_list.append(d)

        report = {
            "findings": finding_list,
            "metadata": {
                "tool": "beatrix",
                "version": "1.0.0",
                "target": target,
                "total_findings": len(finding_list),
                "generated_at": datetime.now(tz=__import__('datetime').timezone.utc).isoformat(),
            },
        }

        filepath.write_text(json.dumps(report, indent=2, default=str))
        _fix_sudo_file(filepath)
