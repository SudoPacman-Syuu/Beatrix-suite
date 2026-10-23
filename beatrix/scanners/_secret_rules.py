"""
BEATRIX Shared Secret-Scanning Rules

Single source of truth for the secret/credential regex tables, entropy gate, and
false-positive filters. Extracted so both the GitHub recon scanner and the
client-side SPA recon scanner apply the SAME detection logic and FP suppression
to any text (repo files, recovered JS sources) — no divergent copies.

Public surface:
  * data tables: SECRET_PATTERNS, ENTROPY_REQUIRED_TYPES, MIN_SECRET_ENTROPY, ...
  * filters:     is_placeholder / is_code_pattern / is_ci_test_credential / is_docker_dev_secret
  * convenience: scan_text(content, source) -> list of structured secret hits
"""

import math
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from beatrix.core.types import Severity


# =============================================================================
# DATA TABLES (moved verbatim from github_recon.py — the canonical home)
# =============================================================================

SECRET_PATTERNS: List[Tuple[str, str, Severity]] = [
    # AWS
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID", Severity.CRITICAL),
    (r'(?i)aws[_\-\.]?secret[_\-\.]?access[_\-\.]?key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', "AWS Secret Access Key", Severity.CRITICAL),

    # Google
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key", Severity.HIGH),
    (r'(?i)google[_\-\.]?api[_\-\.]?key\s*[=:]\s*["\']?([A-Za-z0-9\-_]{35,})', "Google API Key", Severity.HIGH),

    # Generic API keys and tokens
    (r'(?i)(?:api[_\-\.]?key|apikey|api_secret|api_token)\s*[=:]\s*["\']?([A-Za-z0-9\-_\.]{16,})["\']?', "API Key/Token", Severity.HIGH),
    (r'(?i)(?:access[_\-\.]?token|auth[_\-\.]?token|bearer)\s*[=:]\s*["\']?([A-Za-z0-9\-_\.]{16,})["\']?', "Access/Auth Token", Severity.HIGH),

    # JWT Secrets
    (r'(?i)(?:jwt[_\-\.]?secret|jwt[_\-\.]?key|token[_\-\.]?secret)\s*[=:]\s*["\']?([^\s"\']{8,})["\']?', "JWT Secret", Severity.HIGH),

    # Database credentials
    (r'(?i)(?:db|database|mysql|postgres|pgsql|mongo|redis)[_\-\.]?(?:pass|password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{4,})["\']?', "Database Password", Severity.HIGH),
    (r'(?i)mongodb(?:\+srv)?://[^\s"\']+:[^\s"\']+@[^\s"\']+', "MongoDB Connection String", Severity.CRITICAL),
    (r'(?i)postgres(?:ql)?://[^\s"\']+:[^\s"\']+@[^\s"\']+', "PostgreSQL Connection String", Severity.CRITICAL),
    (r'(?i)mysql://[^\s"\']+:[^\s"\']+@[^\s"\']+', "MySQL Connection String", Severity.CRITICAL),
    (r'(?i)redis://[^\s"\']*:[^\s"\']+@[^\s"\']+', "Redis Connection String", Severity.HIGH),

    # Private keys
    (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "Private Key", Severity.CRITICAL),
    (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', "PGP Private Key", Severity.CRITICAL),

    # Generic passwords in config
    (r'(?i)"password"\s*:\s*"([^"]{4,})"', "Password in JSON Config", Severity.HIGH),
    (r'(?i)"secret"\s*:\s*"([^"]{4,})"', "Secret in JSON Config", Severity.HIGH),

    # Encryption keys — require the value to look like an actual key (hex/base64), not code
    (r'(?i)(?:aes|encryption|cipher)[_\-\.]?(?:key|secret)\s*[=:]\s*["\']([A-Za-z0-9+/=_\-]{16,})["\']', "Encryption Key", Severity.CRITICAL),

    # Slack/Discord webhooks
    (r'https://hooks\.slack\.com/services/[A-Za-z0-9/]+', "Slack Webhook", Severity.MEDIUM),
    (r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+', "Discord Webhook", Severity.MEDIUM),

    # Stripe
    (r'sk_live_[0-9a-zA-Z]{24,}', "Stripe Secret Key (Live)", Severity.CRITICAL),
    (r'rk_live_[0-9a-zA-Z]{24,}', "Stripe Restricted Key (Live)", Severity.HIGH),

    # Twilio
    (r'SK[0-9a-fA-F]{32}', "Twilio API Key", Severity.HIGH),

    # SendGrid
    (r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}', "SendGrid API Key", Severity.HIGH),

    # Heroku
    (r'(?i)heroku[_\-\.]?api[_\-\.]?key\s*[=:]\s*["\']?([0-9a-f\-]{36})["\']?', "Heroku API Key", Severity.HIGH),

    # GitHub tokens
    (r'gh[pousr]_[A-Za-z0-9_]{36,}', "GitHub Token", Severity.CRITICAL),

    # Generic high-entropy strings in key positions
    (r'(?i)(?:secret|token|key|password|passwd|pwd|apikey|api_key|auth)\s*[=:]\s*["\']([A-Za-z0-9@#$%^&*!]{12,})["\']', "Hardcoded Secret", Severity.MEDIUM),
]

# Patterns whose matched VALUE requires high entropy to be a real secret.
# Structural patterns (AWS key prefix, private key header, connection strings)
# are always valid regardless of entropy.
ENTROPY_REQUIRED_TYPES = {
    "API Key/Token", "Access/Auth Token", "JWT Secret",
    "Database Password", "Password in JSON Config", "Secret in JSON Config",
    "Hardcoded Secret", "Encryption Key", "Heroku API Key",
}

# Minimum Shannon entropy (bits/char) for generic secret values.
# Real secrets (hex, base64, random): 3.5-6.0
# English words: 2.0-3.2
# Repeated chars: <2.0
MIN_SECRET_ENTROPY = 3.2


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not s:
        return 0.0
    length = len(s)
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((count / length) * math.log2(count / length) for count in freq.values())

# Files that commonly contain secrets
INTERESTING_FILES = [
    ".env", ".env.production", ".env.staging", ".env.local", ".env.development",
    "config/production.json", "config/staging.json", "config/default.json",
    "config/database.yml", "config/secrets.yml", "config/credentials.yml",
    "appsettings.json", "appsettings.Production.json",
    "application.properties", "application.yml", "application-prod.yml",
    "docker-compose.yml", "docker-compose.prod.yml",
    "Dockerfile", ".dockerenv",
    "wp-config.php", "settings.py", "local_settings.py",
    "firebase.json", ".firebaserc",
    "serverless.yml", "terraform.tfvars", "terraform.tfstate",
    ".npmrc", ".pypirc", ".gem/credentials",
    "id_rsa", "id_ecdsa", "id_ed25519",
    ".htpasswd", ".pgpass", ".my.cnf", ".netrc",
]

# Generic placeholder values to IGNORE (reduce false positives)
PLACEHOLDER_VALUES = {
    "supersecret", "supersecret!!!!!", "your-secret-here", "changeme",
    "password", "admin", "secret", "test", "example", "placeholder",
    "your-api-key", "your_api_key", "xxx", "TODO", "CHANGEME",
    "replace-me", "insert-here", "your-token", "put-your-key-here",
    "12345678", "abcdefgh", "qwerty", "password123",
    # Common dev/example passwords that pass entropy checks
    "passw0rd", "p@ssw0rd", "p@ssword", "p@ssword1", "password1",
    "devpasswd", "rootpassword", "mysecretpassword", "letmein",
    "some_random_secret_key", "some-random-secret-key",
    "my-secret-key", "my_secret_key", "secretkey", "secret_key",
    "testpassword", "development", "production",
}

# Common CI/test default credentials — always false positives
CI_TEST_CREDENTIALS = {
    "root", "root:root", "postgres", "postgres:postgres",
    "mysql", "mysql:mysql", "redis", "redis:redis",
    "testuser", "testpass", "testpassword", "test123",
    "sa", "localdb", "devpassword", "devuser",
    "db_password", "db_user", "database",
    "passw0rd", "p@ssw0rd", "password1", "admin123",
}

# Docker/container service hostnames — connection strings to these are local dev only
DOCKER_SERVICE_HOSTS = {
    "mysql", "postgres", "postgresql", "redis", "mongo", "mongodb",
    "elasticsearch", "rabbitmq", "memcached", "mariadb", "mssql",
    "db", "database", "cache", "queue", "broker",
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
    "host.docker.internal", "docker.internal",
}

# File paths that indicate example/demo/template context (always FP for secrets)
EXAMPLE_CONFIG_PATHS = {
    "example", "sample", "template", "demo", "quickstart",
    "bundled", "skeleton", "boilerplate", "starter",
    "getting-started", "getting_started", "tutorial",
    "containers/", "docker/", "docker-compose",
}

# File paths that indicate CI/test context (findings here are almost always FP)
CI_TEST_PATHS = {
    ".github/", "github/actions/", ".circleci/", ".travis.yml",
    "Jenkinsfile", ".gitlab-ci", "docker-compose.test",
    "docker-compose.ci", "test/", "tests/", "spec/",
    "fixtures/", "__tests__/", "e2e/",
}

# =============================================================================
# FALSE-POSITIVE FILTERS (standalone; github_recon's instance methods delegate
# conceptually to these — kept pure so any scanner can call them)
# =============================================================================

def is_placeholder(value: str) -> bool:
    """True if a matched value is just a placeholder, not a real secret."""
    v = value.lower().strip().strip('"\'')
    if v in PLACEHOLDER_VALUES:
        return True
    placeholder_patterns = [
        r'^your[_\-]', r'^<.*>$', r'^\$\{', r'^%\(', r'x{4,}', r'^todo',
        r'^change', r'^replace', r'^insert', r'^put[_\-]', r'^enter[_\-]',
        r'^fake', r'^dummy', r'^sample', r'^example',
        r'^test[_\-]?(?:key|token|secret|pass)',
    ]
    for p in placeholder_patterns:
        if re.match(p, v, re.IGNORECASE):
            return True
    return False


def is_code_pattern(value: str) -> bool:
    """True if a matched value looks like code/an identifier rather than a secret."""
    v = value.strip().strip('"\'')
    if '(' in v and ')' in v:
        return True
    if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*\.', v):
        return True
    if v.startswith('$') or v.startswith('os.environ') or v.startswith('process.env'):
        return True
    if v.lower() in ('none', 'true', 'false', 'null', 'undefined', 'nil'):
        return True
    if '{{' in v or '{%' in v:
        return True
    if re.match(r'^k[A-Z][a-zA-Z]{4,}', v):
        return True
    if re.match(r'^[A-Z][A-Z0-9_]{3,}$', v) and '_' in v:
        return True
    if re.match(r'^[a-z][a-z0-9]*(?:_[a-z][a-z0-9]*){2,}$', v):
        return True
    if re.match(r'^[a-z]+(?:[A-Z][a-z0-9]+)+$', v):
        return True
    if re.match(r'^[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+)+$', v):
        return True
    words = re.split(r'[_\-]', v.lower())
    if len(words) >= 2 and all(w.isalpha() and len(w) >= 3 for w in words):
        return True
    if re.match(r'^(?:test|mock|fake|stub|dummy)[_\-]', v, re.I):
        return True
    return False


def is_ci_test_credential(value: str, file_path: str = "") -> bool:
    """True if this is a common CI/test default credential (false positive)."""
    v = value.lower().strip().strip('"\'')
    if v in CI_TEST_CREDENTIALS:
        return True
    fp = file_path.lower()
    if any(ci_path in fp for ci_path in CI_TEST_PATHS):
        return True
    return False


def is_docker_dev_secret(value: str, file_path: str = "") -> bool:
    """True if a connection string/secret points to a Docker/local dev environment."""
    v = value.lower().strip().strip('"\'')
    fp = file_path.lower()
    conn_match = re.match(
        r'(?:mysql|postgres|postgresql|redis|mongo|mongodb|amqp|mssql)'
        r'(?:\+[a-z]+)?://[^@]*@([^:/\s]+)',
        v,
    )
    if conn_match:
        host = conn_match.group(1)
        if host in DOCKER_SERVICE_HOSTS:
            return True
    if any(ctx in fp for ctx in EXAMPLE_CONFIG_PATHS):
        if any(proto in v for proto in ('://', 'conn', 'connection')):
            return True
        if any(dev_val in v for dev_val in (
            'passw0rd', 'password', 'secret', 'test', 'changeme',
            'some_random', 'some-random', 'my_secret', 'my-secret',
        )):
            return True
    if any(kw in v for kw in ('some_random_secret', 'change_me', 'replace_this')):
        return True
    return False


def scan_text(content: str, source: str = "") -> List[Dict[str, Any]]:
    """Scan arbitrary text for secrets, applying the full FP suppression chain.

    Mirrors GitHubRecon._scan_content_for_secrets but is source-agnostic and
    returns plain dicts: {secret_type, value, severity (Severity), line_number}.
    ``source`` is used both as the file-path hint for CI/docker filtering and as
    the evidence origin by the caller.
    """
    out: List[Dict[str, Any]] = []
    lines = content.split('\n')
    for pattern, secret_type, severity in SECRET_PATTERNS:
        for i, line in enumerate(lines, 1):
            for match in re.finditer(pattern, line):
                value = match.group(1) if match.lastindex else match.group(0)
                if is_placeholder(value):
                    continue
                if len(value) < 4:
                    continue
                if is_code_pattern(value):
                    continue
                if secret_type in ENTROPY_REQUIRED_TYPES:
                    if _shannon_entropy(value) < MIN_SECRET_ENTROPY:
                        continue
                stripped = line.strip()
                if stripped.startswith('//') or stripped.startswith('#') or stripped.startswith('*'):
                    looks_like_docs = (
                        any(p in value.lower() for p in
                            ['example', 'test', 'sample', 'todo',
                             'username', 'password', 'hostname', 'changeme'])
                        or _shannon_entropy(value) < MIN_SECRET_ENTROPY
                    )
                    if looks_like_docs:
                        continue
                if is_ci_test_credential(value, source):
                    continue
                if is_docker_dev_secret(value, source):
                    continue
                out.append({
                    "secret_type": secret_type,
                    "value": value,
                    "severity": severity,
                    "line_number": i,
                })
    return out
