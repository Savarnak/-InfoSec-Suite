import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {'.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.click', '.link'}
URL_SHORTENERS = {'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'short.io'}
SUSPICIOUS_KEYWORDS = ['login', 'verify', 'bank', 'update', 'free', 'secure', 'account',
                       'alert', 'confirm', 'password', 'signin', 'ebayisapi', 'webscr',
                       'paypal', 'billing', 'support', 'urgent', 'suspended', 'validate']

def extract_features(url):
    # Normalize: prepend https:// if no scheme present
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    full = url.lower()

    # 1. URL length
    url_length = len(url)

    # 2. Number of dots
    dot_count = url.count('.')

    # 3. Has @ symbol
    has_at = 1 if '@' in url else 0

    # 4. Has hyphen in domain
    has_hyphen = 1 if '-' in domain else 0

    # 5. Is HTTPS
    is_https = 1 if parsed.scheme == 'https' else 0

    # 6. Digit count in URL
    digit_count = sum(c.isdigit() for c in url)

    # 7. Suspicious keyword present
    has_suspicious_keyword = 1 if any(w in full for w in SUSPICIOUS_KEYWORDS) else 0

    # 8. IP address in URL
    has_ip = 1 if re.search(r'\d{1,3}(\.\d{1,3}){3}', domain) else 0

    # 9. Domain length
    domain_length = len(domain)

    # 10. Number of subdomains
    subdomain_count = len(domain.split('.')) - 2 if domain else 0

    # 11. Suspicious TLD
    has_suspicious_tld = 1 if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0

    # 12. URL shortener
    is_shortened = 1 if any(s in domain for s in URL_SHORTENERS) else 0

    # 13. Special character count (?, =, %, &)
    special_char_count = sum(url.count(c) for c in ['?', '=', '%', '&', '#'])

    # 14. Double slash in path
    has_double_slash = 1 if '//' in parsed.path else 0

    # 15. Hyphen count in full URL
    hyphen_count = url.count('-')

    return [
        url_length, dot_count, has_at, has_hyphen, is_https,
        digit_count, has_suspicious_keyword, has_ip, domain_length,
        subdomain_count, has_suspicious_tld, is_shortened,
        special_char_count, has_double_slash, hyphen_count
    ]


def rule_based_score(url):
    """Returns a risk score (0-100) and list of triggered rule explanations."""
    # Normalize: prepend https:// if no scheme present
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    full = url.lower()

    score = 0
    reasons = []

    if len(url) > 75:
        score += 10
        reasons.append("URL is unusually long (>75 chars)")

    if re.search(r'\d{1,3}(\.\d{1,3}){3}', domain):
        score += 20
        reasons.append("Uses IP address instead of a domain name")

    if '@' in url:
        score += 15
        reasons.append("Contains '@' symbol — browser ignores everything before it")

    if parsed.scheme == 'http':
        score += 10
        reasons.append("Not using HTTPS (insecure connection)")
    subdomain_count = len(domain.split('.')) - 2
    if subdomain_count > 2:
        score += 15
        reasons.append(f"Too many subdomains ({subdomain_count}) — common phishing trick")

    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 15
        reasons.append("Uses a suspicious top-level domain (e.g. .xyz, .tk, .ml)")

    if any(s in domain for s in URL_SHORTENERS):
        score += 10
        reasons.append("Uses a URL shortening service — hides real destination")

    for word in SUSPICIOUS_KEYWORDS:
        if word in full:
            score += 8
            reasons.append(f"Contains suspicious keyword: '{word}'")
            break  # only flag once

    special_chars = sum(url.count(c) for c in ['?', '=', '%', '&'])
    if special_chars > 5:
        score += 8
        reasons.append(f"High number of special characters ({special_chars}) in URL")

    if url.count('-') > 3:
        score += 5
        reasons.append("Excessive hyphens in URL")

    if '//' in parsed.path:
        score += 5
        reasons.append("Double slash found in URL path")

    if len(domain) > 30:
        score += 5
        reasons.append("Domain name is very long")

    if not reasons:
        reasons.append("No suspicious patterns detected by rule engine")

    return min(score, 100), reasons
