"""
BEATRIX Core Types

Data classes and enums used throughout the framework.
Aligned with MITRE ATT&CK, OWASP, and Cyber Kill Chain.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

# =============================================================================
# SEVERITY & CONFIDENCE (OWASP/CVSS aligned)
# =============================================================================

class Severity(Enum):
    """Finding severity levels"""
    CRITICAL = "critical"  # CVSS 9.0-10.0
    HIGH = "high"          # CVSS 7.0-8.9
    MEDIUM = "medium"      # CVSS 4.0-6.9
    LOW = "low"            # CVSS 0.1-3.9
    INFO = "info"          # Informational

    @property
    def color(self) -> str:
        """Rich console color for this severity"""
        return {
            Severity.CRITICAL: "bright_red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }[self]

    @property
    def icon(self) -> str:
        """Icon for this severity"""
        return {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }[self]


class Confidence(Enum):
    """Finding confidence levels"""
    CERTAIN = "certain"      # Confirmed exploitable
    FIRM = "firm"            # High confidence, likely exploitable
    TENTATIVE = "tentative"  # Possible, needs verification
    WEAK = "weak"            # Low confidence, likely false positive

    # Aliases (used by some scanners)
    HIGH = "firm"            # Alias for FIRM
    MEDIUM = "tentative"     # Alias for TENTATIVE
    LOW = "weak"             # Alias for WEAK (distinct from MEDIUM)
    CONFIRMED = "certain"    # Alias for CERTAIN

    @property
    def icon(self) -> str:
        return {
            "certain": "✓✓",
            "firm": "✓",
            "tentative": "?",
            "weak": "~",
        }[self.value]


# =============================================================================
# MITRE ATT&CK TACTICS (Web-focused subset)
# =============================================================================

class MitreTactic(Enum):
    """MITRE ATT&CK Tactics relevant to web application testing"""
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


# =============================================================================
# OWASP TOP 10 (2021)
# =============================================================================

class OwaspCategory(Enum):
    """OWASP Top 10 2021 Categories"""
    A01_BROKEN_ACCESS_CONTROL = "A01:2021"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021"
    A03_INJECTION = "A03:2021"
    A04_INSECURE_DESIGN = "A04:2021"
    A05_SECURITY_MISCONFIGURATION = "A05:2021"
    A06_VULNERABLE_COMPONENTS = "A06:2021"
    A07_AUTH_FAILURES = "A07:2021"
    A08_DATA_INTEGRITY_FAILURES = "A08:2021"
    A09_LOGGING_FAILURES = "A09:2021"
    A10_SSRF = "A10:2021"


# =============================================================================
# INSERTION POINTS (Where to inject payloads)
# =============================================================================

class InsertionPointType(Enum):
    """Types of injection points in HTTP requests"""
    # Primary names (used by scanners)
    URL_PARAM = auto()         # URL query parameter
    BODY_PARAM = auto()        # POST body parameter
    COOKIE = auto()            # Cookie value
    HEADER = auto()            # Header value
    JSON_VALUE = auto()        # JSON body value
    XML_VALUE = auto()         # XML body value
    URL_PATH = auto()          # URL path segment
    URL_PATH_FOLDER = auto()   # Directory in path
    ENTIRE_BODY = auto()       # Full body replacement
    MULTIPART = auto()         # Multipart form field


@dataclass
class InsertionPoint:
    """A specific location where payloads can be injected"""
    name: str                          # Parameter/header name
    value: str                         # Current/original value
    type: InsertionPointType           # Type of insertion point
    original_request: Any = None       # Reference to original request
    position: Tuple[int, int] = (0, 0) # Position range in request

    # Alias for backward compat
    @property
    def original_value(self) -> str:
        return self.value

    def with_payload(self, payload: str) -> str:
        """Return the payload that should replace the original value"""
        return payload


# =============================================================================
# TARGETS
# =============================================================================

class TargetStatus(Enum):
    """Status of a target in the death list"""
    PENDING = "pending"        # Not yet started
    RECON = "recon"            # Reconnaissance phase
    SCANNING = "scanning"      # Active scanning
    EXPLOITING = "exploiting"  # Exploitation attempts
    COMPLETE = "complete"      # Finished
    PAUSED = "paused"          # Manually paused
    ERROR = "error"            # Error occurred


@dataclass
class Target:
    """A target in the death list"""
    id: Optional[int] = None
    domain: str = ""
    scope: List[str] = field(default_factory=list)      # In-scope patterns
    exclude: List[str] = field(default_factory=list)    # Out-of-scope patterns
    status: TargetStatus = TargetStatus.PENDING
    priority: int = 5                                    # 1-10, higher = more important

    # Metadata
    program: Optional[str] = None                        # Bug bounty program name
    platform: Optional[str] = None                       # hackerone, bugcrowd, etc.

    # Progress
    findings_count: int = 0
    last_scan: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.now)

    # Notes
    notes: str = ""


# =============================================================================
# FINDINGS
# =============================================================================

@dataclass
class Finding:
    """A discovered vulnerability"""
    id: Optional[int] = None
    target_id: Optional[int] = None

    # Classification
    title: str = ""
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.TENTATIVE

    # OWASP/MITRE alignment
    owasp_category: Optional[str] = None  # String for flexibility
    mitre_technique: Optional[str] = None  # MITRE technique ID
    mitre_tactic: Optional[MitreTactic] = None
    cwe_id: Any = None  # Can be int or str

    # Technical details
    url: str = ""
    parameter: Optional[str] = None
    injection_point: Optional[InsertionPointType] = None
    payload: Optional[str] = None

    # Evidence
    request: Optional[str] = None
    response: Optional[str] = None
    evidence: Any = None  # Can be str, dict, or any serializable type

    # Description
    description: str = ""
    impact: str = ""
    remediation: str = ""

    # References
    references: List[str] = field(default_factory=list)

    # PoC
    reproduction_steps: List[str] = field(default_factory=list)
    poc_curl: Optional[str] = None
    poc_python: Optional[str] = None

    # Metadata
    scanner_module: str = ""
    found_at: datetime = field(default_factory=datetime.now)
    discovered_at: datetime = field(default_factory=datetime.now)
    validated: bool = False
    reported: bool = False

    # Evidence-provenance record (see beatrix.core.provenance). Optional and
    # additive: findings without it behave exactly as before.
    provenance: Optional[Dict[str, Any]] = None

    def __str__(self) -> str:
        return f"[{self.severity.value.upper()}] {self.title} @ {self.url}"


# =============================================================================
# SCAN RESULTS
# =============================================================================

@dataclass
class ScanResult:
    """Result of a scan operation"""
    target: str
    module: str
    started_at: datetime
    completed_at: Optional[datetime] = None

    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    # Stats
    requests_sent: int = 0
    endpoints_tested: int = 0

    @property
    def duration(self) -> float:
        """Duration in seconds"""
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return 0.0

    @property
    def finding_count(self) -> Dict[Severity, int]:
        """Count findings by severity"""
        counts = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        return counts


# =============================================================================
# HTTP TYPES
# =============================================================================

@dataclass
class HttpRequest:
    """HTTP request representation"""
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: Any = None  # Can be str, bytes, or None
    cookies: Dict[str, str] = field(default_factory=dict)

    @property
    def host(self) -> str:
        """Extract host from URL"""
        from urllib.parse import urlparse
        return urlparse(self.url).netloc


@dataclass
class HttpResponse:
    """HTTP response representation"""
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    time_ms: float = 0.0

    @property
    def content_type(self) -> str:
        """Get content-type header"""
        return self.headers.get("content-type", "").lower()

    @property
    def is_html(self) -> bool:
        return "text/html" in self.content_type

    @property
    def is_json(self) -> bool:
        return "application/json" in self.content_type
