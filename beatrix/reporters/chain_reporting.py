"""
Beatrix Attack Chain Report Generation

Generates comprehensive reports with:
- Vulnerability chain visualizations
- Kill Chain progression mapping
- MITRE ATT&CK Navigator layers
- Risk amplification analysis
- Prioritized remediation guidance

Based on industry reporting standards:
- PTES Reporting Guidelines
- OWASP Testing Guide Reporting
- NIST SP 800-115 Reporting
- PCI DSS Penetration Testing Reporting

Author: Beatrix Framework
Version: 2.0
"""

import html
import json
from datetime import datetime
from typing import Dict

try:
    from beatrix.core.correlation_engine import (
        KILL_CHAIN_MITRE_MAPPING,  # noqa: F401
        VULNERABILITY_CHAIN_PATTERNS,  # noqa: F401
        AttackChain,  # noqa: F401
        CorrelatedEvent,  # noqa: F401
        CyberKillChainPhase,  # noqa: F401
        EventCorrelationEngine,  # noqa: F401
        VulnerabilityChainPattern,  # noqa: F401
        correlate_scan_results,  # noqa: F401
        get_kill_chain_summary,  # noqa: F401
    )
except ImportError as _import_err:
    raise ImportError(
        "beatrix.core.correlation_engine is required for chain reporting. "
        "Ensure Beatrix is properly installed."
    ) from _import_err


# =============================================================================
# ATTACK CHAIN REPORT GENERATOR
# =============================================================================

class AttackChainReportGenerator:
    """
    Generate rich reports for attack chain analysis.

    Report sections:
    1. Executive Summary
    2. Kill Chain Analysis
    3. Attack Chain Details
    4. MITRE ATT&CK Coverage
    5. Vulnerability Correlation
    6. Remediation Roadmap
    """

    def __init__(self, engine: EventCorrelationEngine):
        self.engine = engine

    def generate_executive_summary(self) -> Dict:
        """Generate executive summary of attack surface and chains"""
        summary = self.engine.get_attack_surface_summary()

        # Calculate overall risk level
        chains = self.engine.chains
        critical_chains = sum(1 for c in chains if c.combined_severity == 'critical')
        high_chains = sum(1 for c in chains if c.combined_severity == 'high')

        if critical_chains > 0:
            overall_risk = "CRITICAL"
        elif high_chains > 0:
            overall_risk = "HIGH"
        elif summary['chains_detected'] > 0:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"

        # Kill chain coverage analysis
        phases_covered = len([p for p, c in summary['kill_chain_coverage'].items() if c > 0])
        kc_coverage_pct = (phases_covered / 7) * 100

        return {
            **summary,
            'overall_risk': overall_risk,
            'critical_chains': critical_chains,
            'high_chains': high_chains,
            'kill_chain_coverage_percent': kc_coverage_pct,
            'assessment_date': datetime.now().isoformat(),
        }

    def generate_html_report(self) -> str:
        """Generate complete HTML report with attack chain visualization"""
        summary = self.generate_executive_summary()

        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Beatrix Attack Chain Analysis Report</title>
    <style>
        {self._get_report_styles()}
    </style>
</head>
<body>
    <div class="report-container">
        {self._generate_header()}
        {self._generate_executive_summary_section(summary)}
        {self._generate_kill_chain_section()}
        {self._generate_attack_chains_section()}
        {self._generate_mitre_section()}
        {self._generate_remediation_section(summary)}
        {self._generate_footer()}
    </div>
    <script>
        {self._get_report_scripts()}
    </script>
</body>
</html>
"""
        return html_content

    def _get_report_styles(self) -> str:
        """Return CSS styles for the report"""
        return """
        /* ═══════════════════════════════════════════════════════════════
           ATTACK CHAIN REPORT - PROFESSIONAL DARK THEME
           ═══════════════════════════════════════════════════════════════ */

        :root {
            --bg-primary: #0a0a0a;
            --bg-surface: #121212;
            --bg-elevated: #1a1a1a;
            --bg-card: #1e1e1e;

            --text-primary: #e0e0e0;
            --text-secondary: #a0a0a0;
            --text-muted: #666;

            --accent-primary: #00c853;
            --accent-blue: #2196f3;
            --accent-orange: #ff9800;

            --critical: #c62828;
            --high: #d84315;
            --medium: #f9a825;
            --low: #388e3c;
            --info: #1565c0;

            --border: #333;
            --shadow: rgba(0,0,0,0.5);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }

        .report-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }

        /* Header */
        .report-header {
            text-align: center;
            padding: 3rem 0;
            border-bottom: 1px solid var(--border);
            margin-bottom: 2rem;
        }

        .report-header h1 {
            font-size: 2.5rem;
            color: var(--accent-primary);
            margin-bottom: 0.5rem;
        }

        .report-header .subtitle {
            color: var(--text-secondary);
            font-size: 1.1rem;
        }

        /* Sections */
        .section {
            background: var(--bg-surface);
            border-radius: 8px;
            padding: 2rem;
            margin-bottom: 2rem;
            border: 1px solid var(--border);
        }

        .section h2 {
            color: var(--accent-primary);
            margin-bottom: 1.5rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--accent-primary);
        }

        .section h3 {
            color: var(--text-primary);
            margin: 1.5rem 0 1rem;
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: var(--bg-card);
            padding: 1.5rem;
            border-radius: 8px;
            text-align: center;
            border: 1px solid var(--border);
        }

        .stat-card .value {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }

        .stat-card .label {
            color: var(--text-secondary);
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 1px;
        }

        .stat-card.critical .value { color: var(--critical); }
        .stat-card.high .value { color: var(--high); }
        .stat-card.medium .value { color: var(--medium); }
        .stat-card.low .value { color: var(--low); }
        .stat-card.info .value { color: var(--info); }
        .stat-card.accent .value { color: var(--accent-primary); }

        /* Risk Badge */
        .risk-badge {
            display: inline-block;
            padding: 0.5rem 1.5rem;
            border-radius: 20px;
            font-weight: bold;
            font-size: 1.2rem;
            text-transform: uppercase;
        }

        .risk-badge.critical { background: var(--critical); color: white; }
        .risk-badge.high { background: var(--high); color: white; }
        .risk-badge.medium { background: var(--medium); color: black; }
        .risk-badge.low { background: var(--low); color: white; }

        /* Kill Chain Visualization */
        .kill-chain {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            padding: 2rem 0;
            overflow-x: auto;
        }

        .kc-phase {
            flex: 1;
            min-width: 150px;
            text-align: center;
            padding: 1rem;
            position: relative;
        }

        .kc-phase:not(:last-child)::after {
            content: '→';
            position: absolute;
            right: -10px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--accent-primary);
            font-size: 1.5rem;
        }

        .kc-phase .phase-icon {
            width: 60px;
            height: 60px;
            border-radius: 50%;
            background: var(--bg-card);
            border: 3px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 1rem;
            font-size: 1.5rem;
        }

        .kc-phase.active .phase-icon {
            border-color: var(--accent-primary);
            background: rgba(0, 200, 83, 0.1);
        }

        .kc-phase .phase-name {
            font-weight: bold;
            font-size: 0.85rem;
            margin-bottom: 0.5rem;
        }

        .kc-phase .phase-count {
            font-size: 1.5rem;
            color: var(--accent-primary);
            font-weight: bold;
        }

        .kc-phase .phase-count.zero {
            color: var(--text-muted);
        }

        /* Attack Chain Cards */
        .chain-card {
            background: var(--bg-card);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            border-left: 4px solid var(--border);
        }

        .chain-card.critical { border-left-color: var(--critical); }
        .chain-card.high { border-left-color: var(--high); }
        .chain-card.medium { border-left-color: var(--medium); }
        .chain-card.low { border-left-color: var(--low); }

        .chain-card h4 {
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .chain-card .severity {
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.75rem;
            text-transform: uppercase;
        }

        .chain-card .severity.critical { background: var(--critical); }
        .chain-card .severity.high { background: var(--high); }
        .chain-card .severity.medium { background: var(--medium); color: black; }
        .chain-card .severity.low { background: var(--low); }

        .chain-card .description {
            color: var(--text-secondary);
            margin-bottom: 1rem;
        }

        .chain-card .chain-flow {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            flex-wrap: wrap;
            padding: 1rem;
            background: var(--bg-elevated);
            border-radius: 4px;
        }

        .chain-step {
            padding: 0.5rem 1rem;
            background: var(--bg-surface);
            border-radius: 4px;
            font-size: 0.85rem;
        }

        .chain-arrow {
            color: var(--accent-primary);
            font-weight: bold;
        }

        /* MITRE Heatmap */
        .mitre-heatmap {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
            gap: 0.5rem;
        }

        .mitre-cell {
            padding: 0.75rem;
            background: var(--bg-card);
            border-radius: 4px;
            text-align: center;
            font-size: 0.75rem;
            border: 1px solid var(--border);
        }

        .mitre-cell .technique-id {
            font-weight: bold;
            color: var(--text-primary);
        }

        .mitre-cell .count {
            color: var(--accent-primary);
            font-size: 1.2rem;
            font-weight: bold;
        }

        /* Remediation */
        .remediation-item {
            padding: 1rem;
            background: var(--bg-card);
            border-radius: 8px;
            margin-bottom: 1rem;
            border-left: 4px solid;
        }

        .remediation-item.critical { border-left-color: var(--critical); }
        .remediation-item.high { border-left-color: var(--high); }
        .remediation-item.medium { border-left-color: var(--medium); }

        .remediation-item h4 {
            margin-bottom: 0.5rem;
        }

        .remediation-item .rationale {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }

        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }

        th {
            background: var(--bg-elevated);
            color: var(--accent-primary);
            font-weight: 500;
        }

        tr:hover {
            background: var(--bg-elevated);
        }

        /* Footer */
        .report-footer {
            text-align: center;
            padding: 2rem;
            color: var(--text-muted);
            border-top: 1px solid var(--border);
            margin-top: 2rem;
        }

        /* Utility */
        .badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            margin: 0 0.25rem;
        }

        .badge.technique { background: var(--accent-blue); }
        .badge.phase { background: var(--accent-orange); color: black; }
        """

    def _generate_header(self) -> str:
        """Generate report header"""
        return f"""
        <header class="report-header">
            <h1>⚡ Attack Chain Analysis Report</h1>
            <p class="subtitle">
                Generated by Beatrix Correlation Engine |
                {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </p>
        </header>
        """

    def _generate_executive_summary_section(self, summary: Dict) -> str:
        """Generate executive summary section"""
        risk_class = summary['overall_risk'].lower()

        return f"""
        <section class="section">
            <h2>📊 Executive Summary</h2>

            <div style="text-align: center; margin-bottom: 2rem;">
                <p style="margin-bottom: 1rem; color: var(--text-secondary);">Overall Risk Assessment</p>
                <span class="risk-badge {risk_class}">{summary['overall_risk']}</span>
            </div>

            <div class="stats-grid">
                <div class="stat-card accent">
                    <div class="value">{summary['total_events']}</div>
                    <div class="label">Total Findings</div>
                </div>
                <div class="stat-card critical">
                    <div class="value">{summary['chains_detected']}</div>
                    <div class="label">Attack Chains</div>
                </div>
                <div class="stat-card high">
                    <div class="value">{summary['critical_chains']}</div>
                    <div class="label">Critical Chains</div>
                </div>
                <div class="stat-card medium">
                    <div class="value">{summary['high_chains']}</div>
                    <div class="label">High Chains</div>
                </div>
                <div class="stat-card info">
                    <div class="value">{summary['kill_chain_coverage_percent']:.0f}%</div>
                    <div class="label">Kill Chain Coverage</div>
                </div>
                <div class="stat-card low">
                    <div class="value">{summary['risk_amplifications']}</div>
                    <div class="label">Risk Amplifications</div>
                </div>
            </div>

            <h3>Severity Distribution</h3>
            <div class="stats-grid">
                <div class="stat-card critical">
                    <div class="value">{summary['severity_distribution'].get('critical', 0)}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="stat-card high">
                    <div class="value">{summary['severity_distribution'].get('high', 0)}</div>
                    <div class="label">High</div>
                </div>
                <div class="stat-card medium">
                    <div class="value">{summary['severity_distribution'].get('medium', 0)}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="stat-card low">
                    <div class="value">{summary['severity_distribution'].get('low', 0)}</div>
                    <div class="label">Low</div>
                </div>
                <div class="stat-card info">
                    <div class="value">{summary['severity_distribution'].get('info', 0)}</div>
                    <div class="label">Info</div>
                </div>
            </div>
        </section>
        """

    def _generate_kill_chain_section(self) -> str:
        """Generate kill chain visualization section"""
        kc_data = self.engine.correlate_by_kill_chain()

        phases_html = []
        phase_icons = {
            CyberKillChainPhase.RECONNAISSANCE: "🔍",
            CyberKillChainPhase.WEAPONIZATION: "⚔️",
            CyberKillChainPhase.DELIVERY: "📨",
            CyberKillChainPhase.EXPLOITATION: "💥",
            CyberKillChainPhase.INSTALLATION: "📥",
            CyberKillChainPhase.COMMAND_CONTROL: "📡",
            CyberKillChainPhase.ACTIONS_ON_OBJECTIVES: "🎯",
        }

        for phase in CyberKillChainPhase:
            events = kc_data.get(phase, [])
            count = len(events)
            active = "active" if count > 0 else ""
            count_class = "" if count > 0 else "zero"

            mapping = KILL_CHAIN_MITRE_MAPPING[phase]

            phases_html.append(f"""
                <div class="kc-phase {active}">
                    <div class="phase-icon">{phase_icons.get(phase, '○')}</div>
                    <div class="phase-name">{phase.name.replace('_', ' ')}</div>
                    <div class="phase-count {count_class}">{count}</div>
                </div>
            """)

        return f"""
        <section class="section">
            <h2>🔗 Cyber Kill Chain Analysis</h2>
            <p style="color: var(--text-secondary); margin-bottom: 1rem;">
                Mapping findings to Lockheed Martin's Cyber Kill Chain framework
            </p>

            <div class="kill-chain">
                {''.join(phases_html)}
            </div>

            <h3>Phase Details</h3>
            {self._generate_phase_details(kc_data)}
        </section>
        """

    def _generate_phase_details(self, kc_data: Dict) -> str:
        """Generate detailed phase information"""
        rows = []

        for phase in CyberKillChainPhase:
            events = kc_data.get(phase, [])
            mapping = KILL_CHAIN_MITRE_MAPPING[phase]

            tactics = ', '.join(t.value for t in mapping.mitre_tactics)

            finding_types = {}
            for e in events:
                t = e.finding_type
                finding_types[t] = finding_types.get(t, 0) + 1

            types_str = ', '.join(f"{html.escape(t)} ({c})" for t, c in finding_types.items()) or "None"

            rows.append(f"""
                <tr>
                    <td><strong>{phase.name.replace('_', ' ')}</strong></td>
                    <td>{len(events)}</td>
                    <td>{tactics}</td>
                    <td style="font-size: 0.85rem;">{types_str[:100]}{'...' if len(types_str) > 100 else ''}</td>
                </tr>
            """)

        return f"""
            <table>
                <thead>
                    <tr>
                        <th>Phase</th>
                        <th>Findings</th>
                        <th>MITRE Tactics</th>
                        <th>Finding Types</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        """

    def _generate_attack_chains_section(self) -> str:
        """Generate attack chains section"""
        chains = sorted(
            self.engine.chains,
            key=lambda c: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(c.combined_severity, 5)
        )

        if not chains:
            return """
            <section class="section">
                <h2>⛓️ Detected Attack Chains</h2>
                <p style="color: var(--text-secondary); text-align: center; padding: 2rem;">
                    No attack chains detected. Individual vulnerabilities may still require attention.
                </p>
            </section>
            """

        chains_html = []
        for chain in chains[:10]:  # Top 10 chains
            events_flow = []
            for event in chain.events:
                events_flow.append(f'<span class="chain-step">{html.escape(event.finding_type)}</span>')

            flow_html = '<span class="chain-arrow"> → </span>'.join(events_flow)

            techniques = ' '.join(
                f'<span class="badge technique">{t}</span>'
                for t in chain.mitre_techniques[:5]
            )

            phases = ' '.join(
                f'<span class="badge phase">{p.name}</span>'
                for p in chain.kill_chain_progression[:3]
            )

            chains_html.append(f"""
                <div class="chain-card {chain.combined_severity}">
                    <h4>
                        {html.escape(chain.name)}
                        <span class="severity {chain.combined_severity}">{chain.combined_severity}</span>
                    </h4>
                    <p class="description">{html.escape(chain.description)}</p>

                    <div class="chain-flow">
                        {flow_html}
                    </div>

                    <div style="margin-top: 1rem;">
                        <strong>Risk Score:</strong> {chain.risk_score:.1f}/10 |
                        <strong>Events:</strong> {len(chain.events)}
                    </div>

                    <div style="margin-top: 0.5rem;">
                        <strong>MITRE:</strong> {techniques}
                    </div>

                    <div style="margin-top: 0.5rem;">
                        <strong>Kill Chain:</strong> {phases}
                    </div>
                </div>
            """)

        return f"""
        <section class="section">
            <h2>⛓️ Detected Attack Chains ({len(chains)} total)</h2>
            <p style="color: var(--text-secondary); margin-bottom: 1.5rem;">
                Vulnerability chains that enable multi-stage attacks
            </p>

            {''.join(chains_html)}

            {f'<p style="color: var(--text-secondary); margin-top: 1rem;">Showing top 10 of {len(chains)} chains</p>' if len(chains) > 10 else ''}
        </section>
        """

    def _generate_mitre_section(self) -> str:
        """Generate MITRE ATT&CK coverage section"""
        technique_dist = dict(sorted(
            self.engine.events_by_technique.items(),
            key=lambda x: -len(x[1])
        )[:20])

        cells_html = []
        for tech_id, events in technique_dist.items():
            cells_html.append(f"""
                <div class="mitre-cell">
                    <div class="technique-id">{tech_id}</div>
                    <div class="count">{len(events)}</div>
                </div>
            """)

        return f"""
        <section class="section">
            <h2>🎯 MITRE ATT&CK Coverage</h2>
            <p style="color: var(--text-secondary); margin-bottom: 1.5rem;">
                Top techniques identified across findings
            </p>

            <div class="mitre-heatmap">
                {' '.join(cells_html)}
            </div>

            <p style="margin-top: 1rem; font-size: 0.85rem; color: var(--text-secondary);">
                💡 Export to <a href="#" onclick="downloadNavigator()" style="color: var(--accent-primary);">MITRE ATT&CK Navigator</a> for visualization
            </p>
        </section>
        """

    def _generate_remediation_section(self, summary: Dict) -> str:
        """Generate remediation recommendations section"""
        recommendations = summary.get('recommended_actions', [])

        if not recommendations:
            return ""

        items_html = []
        for rec in recommendations:
            priority = rec.get('priority', 'medium')
            items_html.append(f"""
                <div class="remediation-item {priority}">
                    <h4>
                        <span style="text-transform: uppercase; font-size: 0.75rem; color: var(--{priority});">
                            [{priority}]
                        </span>
                        {html.escape(rec.get('category', ''))}
                    </h4>
                    <p><strong>Action:</strong> {html.escape(rec.get('action', ''))}</p>
                    <p class="rationale">{html.escape(rec.get('rationale', ''))}</p>
                </div>
            """)

        return f"""
        <section class="section">
            <h2>🛡️ Remediation Roadmap</h2>
            <p style="color: var(--text-secondary); margin-bottom: 1.5rem;">
                Prioritized recommendations based on attack chain analysis
            </p>

            {''.join(items_html)}
        </section>
        """

    def _generate_footer(self) -> str:
        """Generate report footer"""
        return """
        <footer class="report-footer">
            <p>Generated by Beatrix Security Framework v2.1</p>
            <p style="margin-top: 0.5rem; font-size: 0.85rem;">
                Methodology: MITRE ATT&CK | Cyber Kill Chain | PTES | OWASP WSTG
            </p>
        </footer>
        """

    def _get_report_scripts(self) -> str:
        """Return JavaScript for interactive features"""
        navigator_data = json.dumps(self.engine.export_mitre_navigator())

        return f"""
        const navigatorData = {navigator_data};

        function downloadNavigator() {{
            const blob = new Blob([JSON.stringify(navigatorData, null, 2)], {{type: 'application/json'}});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'beatrix_attack_navigator.json';
            a.click();
            URL.revokeObjectURL(url);
        }}
        """

    def generate_json_report(self) -> Dict:
        """Generate JSON report for programmatic consumption"""
        summary = self.generate_executive_summary()

        return {
            "report_type": "attack_chain_analysis",
            "generated_at": datetime.now().isoformat(),
            "framework_version": "2.0",

            "executive_summary": summary,

            "kill_chain_analysis": {
                phase.name: {
                    "count": len(self.engine.events_by_phase.get(phase, [])),
                    "events": [
                        {
                            "id": e.id,
                            "type": e.finding_type,
                            "severity": e.severity,
                            "url": e.url,
                        }
                        for e in self.engine.events_by_phase.get(phase, [])[:10]
                    ]
                }
                for phase in CyberKillChainPhase
            },

            "attack_chains": [
                {
                    "id": chain.id,
                    "name": chain.name,
                    "description": chain.description,
                    "severity": chain.combined_severity,
                    "risk_score": chain.risk_score,
                    "events": [
                        {
                            "id": e.id,
                            "type": e.finding_type,
                            "url": e.url,
                        }
                        for e in chain.events
                    ],
                    "kill_chain_phases": [p.name for p in chain.kill_chain_progression],
                    "mitre_techniques": chain.mitre_techniques,
                    "pattern": chain.pattern.name if chain.pattern else None,
                }
                for chain in self.engine.chains
            ],

            "mitre_navigator_layer": self.engine.export_mitre_navigator(),

            "recommendations": summary.get('recommended_actions', []),
        }


# =============================================================================
# INTEGRATION WITH EXISTING REPORTING
# =============================================================================

def enrich_report_with_chains(report_data: Dict, engine: EventCorrelationEngine) -> Dict:
    """
    Enrich existing report data with attack chain analysis.

    Args:
        report_data: Existing Beatrix report data
        engine: Configured EventCorrelationEngine

    Returns:
        Enriched report data with chain analysis
    """
    chain_generator = AttackChainReportGenerator(engine)

    report_data['attack_chain_analysis'] = {
        'summary': chain_generator.generate_executive_summary(),
        'chains': [
            {
                'name': c.name,
                'severity': c.combined_severity,
                'risk_score': c.risk_score,
                'event_count': len(c.events),
                'narrative': c.attack_narrative,
            }
            for c in engine.chains
        ],
        'kill_chain_coverage': {
            phase.name: len(engine.events_by_phase.get(phase, []))
            for phase in CyberKillChainPhase
        },
    }

    return report_data


def generate_attack_chain_section_html(engine: EventCorrelationEngine) -> str:
    """
    Generate HTML section for attack chains to embed in existing reports.

    Args:
        engine: Configured EventCorrelationEngine

    Returns:
        HTML string for the attack chain section
    """
    generator = AttackChainReportGenerator(engine)
    generator.generate_executive_summary()

    return f"""
    {generator._generate_kill_chain_section()}
    {generator._generate_attack_chains_section()}
    """


# =============================================================================
# EXPORT
# =============================================================================

__all__ = [
    'AttackChainReportGenerator',
    'enrich_report_with_chains',
    'generate_attack_chain_section_html',
]
