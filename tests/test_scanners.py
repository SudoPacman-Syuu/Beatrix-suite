"""
Scanner Module Test Suite

Unit tests for base scanner, ScanContext, InsertionPointDetector,
and scanner module instantiation. Does NOT make real HTTP calls.
"""

from datetime import datetime
from typing import AsyncIterator

import pytest

from beatrix.core.types import (
    Confidence,
    Finding,
    HttpRequest,
    HttpResponse,
    InsertionPoint,
    InsertionPointType,
    ScanResult,
    Severity,
    Target,
    TargetStatus,
)
from beatrix.scanners import (
    AuthScanner,
    BACScanner,
    CORSScanner,
    EndpointProber,
    ErrorDisclosureScanner,
    HeaderSecurityScanner,
    IDORScanner,
    InjectionScanner,
    JSBundleAnalyzer,
    OAuthRedirectScanner,
    OpenRedirectScanner,
    SSRFScanner,
    SubdomainTakeoverScanner,
)
from beatrix.scanners.base import BaseScanner, ScanContext
from beatrix.scanners.insertion import BodyFormat, InsertionPointDetector, ParsedRequest

# =============================================================================
# SCAN CONTEXT TESTS
# =============================================================================

class TestScanContext:
    """Tests for ScanContext construction and helpers"""

    def test_from_url_simple(self):
        ctx = ScanContext.from_url("https://example.com/api/users")
        assert ctx.url == "https://example.com/api/users"
        assert ctx.base_url == "https://example.com"
        assert ctx.request.method == "GET"
        assert ctx.parameters == {}

    def test_from_url_with_query_params(self):
        ctx = ScanContext.from_url("https://example.com/search?q=test&page=1")
        assert ctx.parameters["q"] == "test"
        assert ctx.parameters["page"] == "1"

    def test_from_url_multiple_values_takes_first(self):
        ctx = ScanContext.from_url("https://example.com/api?id=1&id=2")
        assert ctx.parameters["id"] == "1"

    def test_from_url_no_query(self):
        ctx = ScanContext.from_url("https://example.com/")
        assert ctx.parameters == {}

    def test_context_has_timestamp(self):
        ctx = ScanContext.from_url("https://example.com")
        assert isinstance(ctx.timestamp, datetime)

    def test_context_with_response(self):
        resp = HttpResponse(
            status_code=200,
            headers={"content-type": "application/json"},
            body='{"ok": true}',
        )
        ctx = ScanContext(
            url="https://example.com/api",
            base_url="https://example.com",
            request=HttpRequest(method="GET", url="https://example.com/api"),
            response=resp,
        )
        assert ctx.response.status_code == 200
        assert ctx.response.is_json

    def test_context_with_cookies(self):
        ctx = ScanContext(
            url="https://example.com",
            base_url="https://example.com",
            request=HttpRequest(method="GET", url="https://example.com"),
            cookies={"session": "abc123"},
        )
        assert ctx.cookies["session"] == "abc123"

    def test_context_with_headers(self):
        ctx = ScanContext(
            url="https://example.com",
            base_url="https://example.com",
            request=HttpRequest(method="GET", url="https://example.com"),
            headers={"Authorization": "Bearer token"},
        )
        assert ctx.headers["Authorization"] == "Bearer token"


# =============================================================================
# CORE TYPE TESTS
# =============================================================================

class TestCoreTypes:
    """Tests for core data types"""

    def test_severity_colors(self):
        assert Severity.CRITICAL.color == "bright_red"
        assert Severity.INFO.color == "dim"

    def test_severity_icons(self):
        for s in Severity:
            assert s.icon  # all severity levels have icons

    def test_confidence_icons(self):
        assert Confidence.CERTAIN.icon == "✓✓"
        assert Confidence.FIRM.icon == "✓"
        assert Confidence.TENTATIVE.icon == "?"

    def test_finding_str(self):
        f = Finding(
            title="XSS in Search",
            severity=Severity.HIGH,
            url="https://example.com/search",
        )
        s = str(f)
        assert "HIGH" in s
        assert "XSS in Search" in s
        assert "example.com" in s

    def test_finding_defaults(self):
        f = Finding()
        assert f.severity == Severity.INFO
        assert f.confidence == Confidence.TENTATIVE
        assert f.validated is False
        assert f.reported is False
        assert f.references == []
        assert f.reproduction_steps == []

    def test_http_request_host(self):
        r = HttpRequest(method="GET", url="https://api.example.com/v1/users")
        assert r.host == "api.example.com"

    def test_http_response_content_type(self):
        r = HttpResponse(
            status_code=200,
            headers={"content-type": "text/html; charset=utf-8"},
            body="<html></html>",
        )
        assert r.is_html
        assert not r.is_json

    def test_http_response_json(self):
        r = HttpResponse(
            status_code=200,
            headers={"content-type": "application/json"},
            body='{}',
        )
        assert r.is_json
        assert not r.is_html

    def test_insertion_point(self):
        ip = InsertionPoint(
            name="id",
            value="1",
            type=InsertionPointType.URL_PARAM,
        )
        assert ip.name == "id"
        assert ip.original_value == "1"  # backward compat property
        assert ip.with_payload("' OR 1=1--") == "' OR 1=1--"

    def test_scan_result_duration(self):
        start = datetime(2026, 1, 1, 12, 0, 0)
        end = datetime(2026, 1, 1, 12, 0, 30)
        result = ScanResult(
            target="example.com",
            module="cors",
            started_at=start,
            completed_at=end,
        )
        assert result.duration == 30.0

    def test_scan_result_no_completion(self):
        result = ScanResult(
            target="example.com",
            module="cors",
            started_at=datetime.now(),
        )
        assert result.duration == 0.0

    def test_scan_result_finding_count(self):
        result = ScanResult(
            target="example.com",
            module="headers",
            started_at=datetime.now(),
            findings=[
                Finding(severity=Severity.HIGH),
                Finding(severity=Severity.HIGH),
                Finding(severity=Severity.LOW),
            ],
        )
        counts = result.finding_count
        assert counts[Severity.HIGH] == 2
        assert counts[Severity.LOW] == 1
        assert counts[Severity.CRITICAL] == 0

    def test_target_defaults(self):
        t = Target(domain="example.com")
        assert t.status == TargetStatus.PENDING
        assert t.priority == 5
        assert t.findings_count == 0

    def test_insertion_point_types_complete(self):
        """Verify all expected insertion point types exist"""
        for name in [
            "URL_PARAM", "BODY_PARAM", "COOKIE", "HEADER",
            "JSON_VALUE", "XML_VALUE", "URL_PATH", "ENTIRE_BODY",
        ]:
            assert hasattr(InsertionPointType, name)


# =============================================================================
# BASE SCANNER TESTS
# =============================================================================

class ConcreteScanner(BaseScanner):
    """Concrete implementation for testing abstract BaseScanner"""
    name = "test_scanner"
    description = "Test scanner for unit tests"

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        yield self.create_finding(
            title="Test Finding",
            severity=Severity.MEDIUM,
            confidence=Confidence.FIRM,
            url=context.url,
            description="Test finding for unit tests",
        )


class TestBaseScanner:
    """Tests for BaseScanner abstract class"""

    def test_scanner_metadata(self):
        scanner = ConcreteScanner()
        assert scanner.name == "test_scanner"
        assert scanner.description == "Test scanner for unit tests"

    def test_scanner_config(self):
        scanner = ConcreteScanner(config={"rate_limit": 5, "timeout": 30})
        assert scanner.rate_limit == 5
        assert scanner.timeout == 30

    def test_scanner_default_config(self):
        scanner = ConcreteScanner()
        assert scanner.rate_limit == 10
        assert scanner.timeout == 10

    def test_create_finding(self):
        scanner = ConcreteScanner()
        scanner.owasp_category = "A03:2021"
        scanner.mitre_technique = "T1190"

        finding = scanner.create_finding(
            title="SQL Injection",
            severity=Severity.CRITICAL,
            confidence=Confidence.CERTAIN,
            url="https://example.com/api",
            description="SQL injection in id parameter",
            evidence="Error: You have an error in your SQL syntax",
            remediation="Use parameterized queries",
        )
        assert finding.title == "SQL Injection"
        assert finding.severity == Severity.CRITICAL
        assert finding.confidence == Confidence.CERTAIN
        assert finding.scanner_module == "test_scanner"
        assert finding.owasp_category == "A03:2021"
        assert finding.mitre_technique == "T1190"
        assert isinstance(finding.found_at, datetime)

    @pytest.mark.asyncio
    async def test_scan_yields_findings(self):
        scanner = ConcreteScanner()
        ctx = ScanContext.from_url("https://example.com/api")
        findings = []
        async for f in scanner.scan(ctx):
            findings.append(f)
        assert len(findings) == 1
        assert findings[0].title == "Test Finding"

    @pytest.mark.asyncio
    async def test_passive_scan_empty_by_default(self):
        scanner = ConcreteScanner()
        ctx = ScanContext.from_url("https://example.com")
        findings = []
        async for f in scanner.passive_scan(ctx):
            findings.append(f)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_request_without_context_manager_raises(self):
        scanner = ConcreteScanner()
        with pytest.raises(RuntimeError, match="not initialized"):
            await scanner.request("GET", "https://example.com")


# =============================================================================
# SCANNER MODULE INSTANTIATION TESTS
# =============================================================================

class TestScannerInstantiation:
    """Test that all scanner modules can be instantiated"""

    SCANNERS = [
        CORSScanner,
        InjectionScanner,
        HeaderSecurityScanner,
        OpenRedirectScanner,
        OAuthRedirectScanner,
        IDORScanner,
        BACScanner,
        AuthScanner,
        SSRFScanner,
        SubdomainTakeoverScanner,
        ErrorDisclosureScanner,
        JSBundleAnalyzer,
        EndpointProber,
    ]

    @pytest.mark.parametrize("scanner_cls", SCANNERS)
    def test_instantiate(self, scanner_cls):
        s = scanner_cls()
        assert s.name  # has a name
        assert isinstance(s.name, str)
        assert len(s.name) > 0

    @pytest.mark.parametrize("scanner_cls", SCANNERS)
    def test_has_scan_method(self, scanner_cls):
        s = scanner_cls()
        assert callable(getattr(s, "scan", None))

    @pytest.mark.parametrize("scanner_cls", SCANNERS)
    def test_inherits_base_scanner(self, scanner_cls):
        assert issubclass(scanner_cls, BaseScanner)

    @pytest.mark.parametrize("scanner_cls", SCANNERS)
    def test_has_description(self, scanner_cls):
        s = scanner_cls()
        assert s.description
        assert isinstance(s.description, str)

    # Scanners with custom __init__ that don't accept config kwarg
    CUSTOM_INIT_SCANNERS = {IDORScanner, BACScanner, AuthScanner}

    @pytest.mark.parametrize("scanner_cls", SCANNERS)
    def test_config_override(self, scanner_cls):
        if scanner_cls in self.CUSTOM_INIT_SCANNERS:
            pytest.skip(f"{scanner_cls.__name__} has custom __init__")
        s = scanner_cls(config={"rate_limit": 3, "timeout": 20})
        assert s.rate_limit == 3
        assert s.timeout == 20


# =============================================================================
# CORS SCANNER TESTS
# =============================================================================

class TestCORSScanner:
    """Tests for CORSScanner test origin generation"""

    def test_generate_test_origins(self):
        scanner = CORSScanner()
        origins = scanner._generate_test_origins("https://app.example.com/api")
        assert len(origins) > 0
        # Should include reflected origin test
        names = [o["name"] for o in origins]
        assert "reflected_origin" in names
        assert "null_origin" in names

    def test_generate_test_origins_uses_base_domain(self):
        scanner = CORSScanner()
        origins = scanner._generate_test_origins("https://sub.example.com")
        # Should have prefix bypass using base domain
        origin_values = [o["origin"] for o in origins]
        assert any("example.com" in o for o in origin_values)

    def test_cors_metadata(self):
        scanner = CORSScanner()
        assert scanner.owasp_category == "A01:2021"
        assert scanner.name == "cors"


# =============================================================================
# HEADER SCANNER TESTS
# =============================================================================

class TestHeaderScanner:
    """Tests for HeaderSecurityScanner configuration"""

    def test_required_headers_defined(self):
        scanner = HeaderSecurityScanner()
        assert "strict-transport-security" in scanner.REQUIRED_HEADERS
        assert "x-content-type-options" in scanner.REQUIRED_HEADERS
        assert "x-frame-options" in scanner.REQUIRED_HEADERS
        assert "content-security-policy" in scanner.REQUIRED_HEADERS

    def test_required_headers_have_metadata(self):
        scanner = HeaderSecurityScanner()
        for header, info in scanner.REQUIRED_HEADERS.items():
            assert "severity" in info
            assert "description" in info
            assert "remediation" in info
            assert isinstance(info["severity"], Severity)

    def test_sensitive_headers_list(self):
        scanner = HeaderSecurityScanner()
        assert "server" in scanner.SENSITIVE_HEADERS
        assert "x-powered-by" in scanner.SENSITIVE_HEADERS


# =============================================================================
# INSERTION POINT DETECTOR TESTS
# =============================================================================

class TestInsertionPointDetector:
    """Tests for InsertionPointDetector"""

    def test_detector_instantiation(self):
        detector = InsertionPointDetector()
        assert detector.TESTABLE_HEADERS
        assert len(detector.TESTABLE_HEADERS) > 0

    def test_testable_headers_include_common(self):
        detector = InsertionPointDetector()
        for header in ["user-agent", "referer", "x-forwarded-for", "host", "origin"]:
            assert header in detector.TESTABLE_HEADERS


# =============================================================================
# BODY FORMAT TESTS
# =============================================================================

class TestBodyFormat:
    """Tests for BodyFormat enum"""

    def test_body_formats_exist(self):
        assert BodyFormat.NONE
        assert BodyFormat.FORM_URLENCODED
        assert BodyFormat.JSON
        assert BodyFormat.XML
        assert BodyFormat.MULTIPART
        assert BodyFormat.RAW


class TestParsedRequest:
    """Tests for ParsedRequest dataclass"""

    def test_parsed_request_defaults(self):
        pr = ParsedRequest(
            method="GET",
            url="https://example.com",
            path="/",
            query_string="",
            headers={},
            cookies={},
            body=b"",
            body_format=BodyFormat.NONE,
        )
        assert pr.url_params == {}
        assert pr.body_params == {}
        assert pr.path_segments == []
        assert pr.json_paths == []

    def test_parsed_request_with_json(self):
        pr = ParsedRequest(
            method="POST",
            url="https://example.com/api/login",
            path="/api/login",
            query_string="",
            headers={"content-type": "application/json"},
            cookies={},
            body=b'{"username": "admin", "password": "pass"}',
            body_format=BodyFormat.JSON,
            body_params={"username": "admin", "password": "pass"},
        )
        assert pr.body_format == BodyFormat.JSON
        assert pr.body_params["username"] == "admin"
