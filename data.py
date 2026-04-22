"""
Simulated URL → downloadable files mapping.
Each file entry has:
  name       : display filename
  type       : file extension category
  size       : simulated size string
  safe       : True = hash will match, False = hash mismatch (malicious/tampered)
  icon       : emoji for UI
  description: short label
"""

# Pre-computed SHA-256 hashes for simulation
# "safe" files have a stored expected hash that matches the generated one
# "malicious" files have a stored expected hash that deliberately mismatches

SAFE_HASH   = "a3f5c2d1b8e74f9a0c6d2e1b3f7a8c9d0e2f4b6a8c0d2e4f6a8b0c2d4e6f8a0b2"
TAMPER_HASH = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

URL_FILE_MAP = {
    # ── SAFE SITES ──────────────────────────────────────────────────────────
    "https://google.com": [
        {"name": "google-terms.pdf",      "type": "PDF",  "size": "142 KB", "safe": True,  "icon": "📄", "description": "Terms of Service"},
        {"name": "google-privacy.pdf",    "type": "PDF",  "size": "98 KB",  "safe": True,  "icon": "📄", "description": "Privacy Policy"},
    ],
    "https://github.com": [
        {"name": "github-desktop.zip",    "type": "ZIP",  "size": "78 MB",  "safe": True,  "icon": "📦", "description": "GitHub Desktop Installer"},
        {"name": "git-cheatsheet.pdf",    "type": "PDF",  "size": "512 KB", "safe": True,  "icon": "📄", "description": "Git Command Reference"},
    ],
    "https://microsoft.com": [
        {"name": "vs-code-setup.exe",     "type": "EXE",  "size": "91 MB",  "safe": True,  "icon": "💾", "description": "VS Code Official Installer"},
        {"name": "ms-security-guide.pdf", "type": "PDF",  "size": "2.1 MB", "safe": True,  "icon": "📄", "description": "Security Best Practices"},
    ],
    "https://python.org": [
        {"name": "python-3.12.0.zip",     "type": "ZIP",  "size": "26 MB",  "safe": True,  "icon": "📦", "description": "Python Source Code"},
        {"name": "python-docs.pdf",       "type": "PDF",  "size": "8.4 MB", "safe": True,  "icon": "📄", "description": "Python 3.12 Documentation"},
    ],
    "https://wikipedia.org": [
        {"name": "wikipedia-dump.zip",    "type": "ZIP",  "size": "21 GB",  "safe": True,  "icon": "📦", "description": "Wikipedia Data Dump"},
    ],

    # ── PHISHING / SUSPICIOUS SITES ─────────────────────────────────────────
    "http://secure-login-paytm.xyz": [
        {"name": "paytm-update.exe",      "type": "EXE",  "size": "3.2 MB", "safe": False, "icon": "⚠️", "description": "Fake App Updater"},
        {"name": "verify-account.bat",    "type": "BAT",  "size": "14 KB",  "safe": False, "icon": "💀", "description": "Suspicious Script"},
    ],
    "http://free-money-now.biz": [
        {"name": "claim-prize.exe",       "type": "EXE",  "size": "1.8 MB", "safe": False, "icon": "💀", "description": "Malware Dropper"},
        {"name": "winner-form.pdf",       "type": "PDF",  "size": "220 KB", "safe": False, "icon": "⚠️", "description": "Phishing PDF Form"},
    ],
    "http://paypal-secure-login.tk": [
        {"name": "paypal-security.exe",   "type": "EXE",  "size": "4.5 MB", "safe": False, "icon": "💀", "description": "Credential Stealer"},
        {"name": "account-restore.zip",   "type": "ZIP",  "size": "890 KB", "safe": False, "icon": "⚠️", "description": "Suspicious Archive"},
    ],
    "http://verify-bank-account-alert.com": [
        {"name": "bank-verify-tool.exe",  "type": "EXE",  "size": "2.9 MB", "safe": False, "icon": "💀", "description": "Fake Verification Tool"},
        {"name": "account-form.pdf",      "type": "PDF",  "size": "180 KB", "safe": False, "icon": "⚠️", "description": "Phishing Form"},
    ],
    "http://192.168.1.1": [
        {"name": "router-firmware.bin",   "type": "BIN",  "size": "6.1 MB", "safe": False, "icon": "⚠️", "description": "Unsigned Firmware"},
        {"name": "admin-tool.exe",        "type": "EXE",  "size": "1.2 MB", "safe": False, "icon": "💀", "description": "Suspicious Admin Tool"},
    ],
}

# Default files shown for unknown URLs
DEFAULT_SAFE_FILES = [
    {"name": "readme.txt",   "type": "TXT", "size": "4 KB",  "safe": True,  "icon": "📄", "description": "Site Information"},
    {"name": "terms.pdf",    "type": "PDF", "size": "88 KB", "safe": True,  "icon": "📄", "description": "Terms & Conditions"},
]
DEFAULT_PHISH_FILES = [
    {"name": "setup.exe",    "type": "EXE", "size": "2.4 MB", "safe": False, "icon": "💀", "description": "Unknown Executable"},
    {"name": "update.bat",   "type": "BAT", "size": "8 KB",   "safe": False, "icon": "⚠️", "description": "Suspicious Script"},
]


# ── Simulated redirect chains ────────────────────────────────────────────────
# Each entry is a list of hops. Safe sites have 0-1 hops, phishing sites have
# multiple suspicious hops to simulate real-world redirect abuse.

REDIRECT_MAP = {
    # SAFE — direct or single canonical redirect
    "https://google.com":     [],
    "https://github.com":     [],
    "https://microsoft.com":  [],
    "https://python.org":     [],
    "https://wikipedia.org":  [],

    # PHISHING — multi-hop redirect chains
    "http://free-money-now.biz": [
        {"hop": 1, "url": "http://free-money-now.biz",           "status": 301, "note": "Initial request"},
        {"hop": 2, "url": "http://redirect-hub.xyz/go?id=4821",  "status": 302, "note": "⚠️ Redirected to suspicious domain"},
        {"hop": 3, "url": "http://bit.ly/3xFakeLink",            "status": 301, "note": "⚠️ URL shortener detected"},
        {"hop": 4, "url": "http://claim-prize-now.tk/landing",   "status": 200, "note": "🚨 Final phishing page"},
    ],
    "http://secure-login-paytm.xyz": [
        {"hop": 1, "url": "http://secure-login-paytm.xyz",       "status": 301, "note": "Initial request"},
        {"hop": 2, "url": "http://paytm-verify.ml/auth",         "status": 302, "note": "⚠️ Redirected to lookalike domain"},
        {"hop": 3, "url": "http://login-secure-alert.cf/signin", "status": 200, "note": "🚨 Credential harvesting page"},
    ],
    "http://paypal-secure-login.tk": [
        {"hop": 1, "url": "http://paypal-secure-login.tk",       "status": 301, "note": "Initial request"},
        {"hop": 2, "url": "http://tinyurl.com/pp-verify",        "status": 302, "note": "⚠️ URL shortener used to hide destination"},
        {"hop": 3, "url": "http://paypal.com.fake-secure.ga",    "status": 302, "note": "⚠️ Domain spoofing PayPal"},
        {"hop": 4, "url": "http://steal-creds.pw/paypal/login",  "status": 200, "note": "🚨 Credential stealer endpoint"},
    ],
    "http://verify-bank-account-alert.com": [
        {"hop": 1, "url": "http://verify-bank-account-alert.com","status": 302, "note": "Initial request"},
        {"hop": 2, "url": "http://bank-alert-redirect.xyz/go",   "status": 302, "note": "⚠️ Suspicious redirect"},
        {"hop": 3, "url": "http://secure-bank-verify.tk/form",   "status": 200, "note": "🚨 Fake bank verification form"},
    ],
    "http://192.168.1.1": [
        {"hop": 1, "url": "http://192.168.1.1",                  "status": 301, "note": "⚠️ IP address used instead of domain"},
        {"hop": 2, "url": "http://192.168.1.1/admin/redirect",   "status": 302, "note": "⚠️ Internal redirect on IP host"},
        {"hop": 3, "url": "http://malicious-payload.cf/drop",    "status": 200, "note": "🚨 Malware delivery endpoint"},
    ],
}


def get_redirects(url: str, is_phishing: bool) -> list:
    """Return simulated redirect chain for a URL."""
    url = url.strip().rstrip('/')

    if url in REDIRECT_MAP:
        return REDIRECT_MAP[url]

    from urllib.parse import urlparse
    parsed = urlparse(url if url.startswith('http') else 'https://' + url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    if base in REDIRECT_MAP:
        return REDIRECT_MAP[base]

    # Generic fallback
    if is_phishing:
        return [
            {"hop": 1, "url": url,                              "status": 301, "note": "Initial request"},
            {"hop": 2, "url": "http://suspicious-redirect.xyz", "status": 302, "note": "⚠️ Redirected to unknown domain"},
            {"hop": 3, "url": "http://phish-landing.tk/page",   "status": 200, "note": "🚨 Phishing landing page"},
        ]
    return []  # safe sites have no redirects


def get_files_for_url(url: str, is_phishing: bool) -> list:
    """Return simulated file list for a given URL."""
    url = url.strip().rstrip('/')

    # Try exact match first
    if url in URL_FILE_MAP:
        return URL_FILE_MAP[url]

    # Try stripping path — match on scheme+domain only
    from urllib.parse import urlparse
    parsed = urlparse(url if url.startswith('http') else 'http://' + url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    if base in URL_FILE_MAP:
        return URL_FILE_MAP[base]

    # Fallback based on phishing verdict
    return DEFAULT_PHISH_FILES if is_phishing else DEFAULT_SAFE_FILES


def simulate_file_scan(filename: str, is_safe: bool) -> dict:
    """
    Simulate a file integrity scan without real file I/O.
    Returns hash, status, and message.
    """
    import hashlib, time
    # Deterministic fake hash based on filename
    fake_content = f"{filename}-simulated-content-{int(time.time() // 3600)}"
    generated = hashlib.sha256(fake_content.encode()).hexdigest()

    if is_safe:
        # Safe: expected == generated (integrity passes)
        return {
            "generated_hash": generated,
            "expected_hash":  generated,
            "status":  "verified",
            "message": "File integrity confirmed — SHA-256 hash matches. File is SAFE.",
        }
    else:
        # Malicious: expected hash is deliberately different
        tampered_expected = hashlib.sha256(b"known-good-version").hexdigest()
        return {
            "generated_hash": generated,
            "expected_hash":  tampered_expected,
            "status":  "tampered",
            "message": "File integrity FAILED — hash mismatch detected. File may be MALICIOUS or TAMPERED.",
        }
