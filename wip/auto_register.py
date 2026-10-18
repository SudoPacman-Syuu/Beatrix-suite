#!/usr/bin/env python3
"""
BEATRIX Auto-Registration System
Automatically create accounts on target platforms for authenticated testing
"""

import asyncio
import json
import random
import string
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

try:
    from playwright.async_api import Browser, Page, async_playwright  # noqa: F401
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    print("⚠️  Playwright not installed. Run: pip install playwright && playwright install chromium")


@dataclass
class Credential:
    """Stored credential for a registered account"""
    platform: str
    email: str
    password: str
    username: Optional[str] = None
    registered_at: str = ""
    verified: bool = False
    notes: str = ""
    cookies: Optional[Dict] = None


class CredentialStore:
    """Secure storage for registered credentials"""

    def __init__(self, store_path: Optional[str] = None):
        if store_path is None:
            self.store_path = Path.home() / ".beatrix" / "credentials.json"
        else:
            self.store_path = Path(store_path)
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self._credentials: Dict[str, List[Credential]] = {}
        self._load()

    def _load(self):
        """Load credentials from disk"""
        if self.store_path.exists():
            try:
                with open(self.store_path, 'r') as f:
                    data = json.load(f)
                    for platform, creds in data.items():
                        self._credentials[platform] = [
                            Credential(**c) for c in creds
                        ]
            except Exception as e:
                print(f"⚠️  Error loading credentials: {e}")

    def _save(self):
        """Save credentials to disk"""
        data = {}
        for platform, creds in self._credentials.items():
            data[platform] = [asdict(c) for c in creds]

        with open(self.store_path, 'w') as f:
            json.dump(data, f, indent=2)

    def add(self, cred: Credential):
        """Add a credential"""
        if cred.platform not in self._credentials:
            self._credentials[cred.platform] = []
        self._credentials[cred.platform].append(cred)
        self._save()
        print(f"✅ Stored credential for {cred.platform}: {cred.email}")

    def get(self, platform: str) -> List[Credential]:
        """Get all credentials for a platform"""
        return self._credentials.get(platform, [])

    def get_one(self, platform: str) -> Optional[Credential]:
        """Get first credential for a platform"""
        creds = self.get(platform)
        return creds[0] if creds else None

    def list_all(self) -> Dict[str, int]:
        """List all platforms and credential counts"""
        return {p: len(c) for p, c in self._credentials.items()}


class EmailGenerator:
    """Generate disposable emails for registration"""

    # Use email aliases with + syntax (most providers support this)
    BASE_EMAILS = [
        # Add your own base emails here
        # Format: "base+{tag}@domain.com"
    ]

    @staticmethod
    def generate_random_email(domain: str = "tempmail.beatrix") -> str:
        """Generate a random email address"""
        random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        return f"test_{random_str}@{domain}"

    @staticmethod
    def generate_alias(base_email: str, tag: str) -> str:
        """Generate an email alias using + syntax"""
        local, domain = base_email.split('@')
        return f"{local}+{tag}@{domain}"

    @staticmethod
    def generate_bugbounty_email(platform: str) -> str:
        """Generate a realistic bug bounty testing email"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M")
        random_suffix = ''.join(random.choices(string.ascii_lowercase, k=4))
        return f"security.test.{platform}.{timestamp}.{random_suffix}@protonmail.com"


class PasswordGenerator:
    """Generate secure passwords for registration"""

    @staticmethod
    def generate(length: int = 20) -> str:
        """Generate a secure random password"""
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        # Ensure at least one of each type
        password = [
            random.choice(string.ascii_uppercase),
            random.choice(string.ascii_lowercase),
            random.choice(string.digits),
            random.choice("!@#$%^&*")
        ]
        password += random.choices(chars, k=length-4)
        random.shuffle(password)
        return ''.join(password)


class AutoRegistrar:
    """Automated account registration using browser automation"""

    def __init__(self, headless: bool = True):
        self.headless = headless
        self.store = CredentialStore()
        self.browser: Browser = None
        self._playwright = None

    async def __aenter__(self):
        if not PLAYWRIGHT_AVAILABLE:
            raise RuntimeError("Playwright not available")
        self._playwright = await async_playwright().start()
        self.browser = await self._playwright.chromium.launch(
            headless=self.headless,
            args=['--disable-blink-features=AutomationControlled']
        )
        return self

    async def __aexit__(self, *args):
        if self.browser:
            await self.browser.close()
        if self._playwright:
            await self._playwright.stop()

    async def register_generic(
        self,
        signup_url: str,
        platform: str,
        email_selector: str = "input[type='email'], input[name='email']",
        password_selector: str = "input[type='password'], input[name='password']",
        submit_selector: str = "button[type='submit'], input[type='submit']",
        extra_steps: Optional[List[Dict]] = None
    ) -> Optional[Credential]:
        """Generic registration flow"""

        email = EmailGenerator.generate_bugbounty_email(platform)
        password = PasswordGenerator.generate()

        context = await self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )
        page = await context.new_page()

        try:
            print(f"📝 Attempting registration on {platform}...")
            await page.goto(signup_url, wait_until='networkidle')
            await asyncio.sleep(2)  # Wait for JS to load

            # Fill email
            await page.fill(email_selector, email)
            await asyncio.sleep(0.5)

            # Fill password
            await page.fill(password_selector, password)
            await asyncio.sleep(0.5)

            # Extra steps (like username, confirm password, checkboxes)
            if extra_steps:
                for step in extra_steps:
                    action = step.get('action', 'fill')
                    selector = step.get('selector')
                    value = step.get('value', '')

                    if action == 'fill':
                        await page.fill(selector, value)
                    elif action == 'click':
                        await page.click(selector)
                    elif action == 'check':
                        await page.check(selector)

                    await asyncio.sleep(0.3)

            # Submit
            await page.click(submit_selector)
            await asyncio.sleep(3)

            # Check if registration succeeded (basic check)
            cookies = await context.cookies()

            cred = Credential(
                platform=platform,
                email=email,
                password=password,
                registered_at=datetime.now().isoformat(),
                verified=False,
                cookies={c['name']: c['value'] for c in cookies}
            )

            self.store.add(cred)
            return cred

        except Exception as e:
            print(f"❌ Registration failed for {platform}: {e}")
            return None
        finally:
            await context.close()

    async def register_doordash_dasher(self) -> Optional[Credential]:
        """Register a DoorDash Dasher account"""
        return await self.register_generic(
            signup_url="https://www.doordash.com/dasher/signup/",
            platform="doordash_dasher",
            email_selector="input[name='email']",
            password_selector="input[name='password']",
            submit_selector="button[type='submit']"
        )

    async def register_doordash_consumer(self) -> Optional[Credential]:
        """Register a DoorDash consumer account"""
        return await self.register_generic(
            signup_url="https://www.doordash.com/signup/",
            platform="doordash_consumer",
            email_selector="input[name='email']",
            password_selector="input[name='password']",
            submit_selector="button[type='submit']"
        )


# Platform-specific registration configs
PLATFORM_CONFIGS = {
    'doordash': {
        'consumer': {
            'signup_url': 'https://www.doordash.com/signup/',
            'selectors': {
                'email': 'input[name="email"]',
                'password': 'input[name="password"]',
                'submit': 'button[type="submit"]'
            }
        },
        'dasher': {
            'signup_url': 'https://www.doordash.com/dasher/signup/',
            'selectors': {
                'email': 'input[name="email"]',
                'password': 'input[name="password"]',
                'submit': 'button[type="submit"]'
            }
        }
    },
    'uber': {
        'rider': {
            'signup_url': 'https://auth.uber.com/v2/',
            'requires_phone': True
        }
    },
    'notion': {
        'free': {
            'signup_url': 'https://www.notion.so/signup',
            'selectors': {
                'email': 'input[type="email"]',
                'submit': 'button[type="submit"]'
            },
            'requires_verification': True
        }
    }
}


async def quick_register(platform: str, account_type: Optional[str] = None) -> Optional[Credential]:
    """Quick registration helper"""
    if not PLAYWRIGHT_AVAILABLE:
        print("❌ Playwright not available. Install with: pip install playwright && playwright install chromium")
        return None

    async with AutoRegistrar(headless=False) as registrar:
        if platform == 'doordash':
            if account_type == 'dasher':
                return await registrar.register_doordash_dasher()
            else:
                return await registrar.register_doordash_consumer()
        else:
            print(f"⚠️  Platform '{platform}' not yet implemented")
            return None


def get_stored_credentials(platform: Optional[str] = None) -> Dict:
    """Get stored credentials"""
    store = CredentialStore()
    if platform:
        creds = store.get(platform)
        return {platform: [asdict(c) for c in creds]}
    return {p: [asdict(c) for c in creds] for p, creds in store._credentials.items()}


# CLI interface
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("BEATRIX Auto-Registration System")
        print("-" * 40)
        print("\nUsage:")
        print("  python auto_register.py list              - List stored credentials")
        print("  python auto_register.py register <platform> [type]")
        print("\nSupported platforms:")
        print("  - doordash (consumer, dasher)")
        print("  - notion (free)")
        print("  - uber (requires phone verification)")
        sys.exit(0)

    cmd = sys.argv[1]

    if cmd == 'list':
        store = CredentialStore()
        creds = store.list_all()
        if not creds:
            print("No credentials stored yet.")
        else:
            print("\n📋 Stored Credentials:")
            for platform, count in creds.items():
                print(f"  {platform}: {count} account(s)")
                for c in store.get(platform):
                    print(f"    - {c.email} (verified: {c.verified})")

    elif cmd == 'register':
        if len(sys.argv) < 3:
            print("Usage: python auto_register.py register <platform> [type]")
            sys.exit(1)

        platform = sys.argv[2]
        account_type = sys.argv[3] if len(sys.argv) > 3 else None

        cred = asyncio.run(quick_register(platform, account_type))
        if cred:
            print("\n✅ Registration successful!")
            print(f"   Email: {cred.email}")
            print(f"   Password: {cred.password}")
            print("   Note: Verification may be required")
