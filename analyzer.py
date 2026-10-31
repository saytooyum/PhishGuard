"""
analyzer.py — Rule-based URL and email phishing analysis for PhishGuard.

Each check adds points to a risk score (0–100).
The final score maps to a Low / Medium / High label.
"""

import re
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _score_to_label(score: int) -> str:
    """Convert a numeric score to a human-readable risk label."""
    if score >= 60:
        return "High Risk"
    elif score >= 30:
        return "Medium Risk"
    else:
        return "Low Risk"


# ---------------------------------------------------------------------------
# URL analysis
# ---------------------------------------------------------------------------

# Well-known URL shortener domains
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "shorte.st", "cutt.ly",
}

# Words in a URL path / query string that are commonly abused in phishing
SUSPICIOUS_URL_WORDS = [
    "login", "signin", "verify", "update", "secure", "account",
    "banking", "confirm", "password", "credential", "urgent",
    "suspended", "locked", "validate", "recover",
]


def analyze_url(url: str) -> dict:
    """
    Analyse a single URL and return a dict with:
        score   (int  0–100)
        label   (str  Low / Medium / High Risk)
        reasons (list of str)
    """
    url = url.strip()
    if not url:
        return {"score": 0, "label": "Low Risk", "reasons": ["No URL provided."]}

    # Make sure the URL has a scheme so urlparse works correctly
    if not url.startswith(("http://", "https://", "ftp://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        path_query = (parsed.path + "?" + parsed.query).lower()
    except Exception:
        return {"score": 50, "label": "Medium Risk",
                "reasons": ["Could not parse the URL — it may be malformed."]}

    score = 0
    reasons = []

    # 1. No HTTPS
    if parsed.scheme != "https":
        score += 20
        reasons.append("URL does not use HTTPS (unencrypted connection).")

    # 2. IP address used as host instead of a domain name
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    if ip_pattern.match(host):
        score += 35
        reasons.append("Host is a raw IP address instead of a domain name.")

    # 3. Suspicious words in the URL
    found_words = [w for w in SUSPICIOUS_URL_WORDS if w in path_query]
    if found_words:
        score += min(20, len(found_words) * 7)
        reasons.append(f"Suspicious word(s) in URL: {', '.join(found_words)}.")

    # 4. Known URL shortener
    if host in URL_SHORTENERS:
        score += 20
        reasons.append(f"'{host}' is a known URL shortener — the real destination is hidden.")

    # 5. Too many subdomains (more than 3 dot-separated labels is unusual)
    #    Skip this check when the host is already a raw IP address.
    labels = host.split(".")
    if len(labels) > 3 and not ip_pattern.match(host):
        score += 20
        reasons.append(f"Unusually many subdomains ({len(labels) - 2} levels deep).")

    # 6. Very long URL (over 100 characters is a soft signal)
    if len(url) > 100:
        score += 10
        reasons.append("URL is unusually long.")

    score = min(score, 100)

    if not reasons:
        reasons.append("No obvious phishing indicators found.")

    return {"score": score, "label": _score_to_label(score), "reasons": reasons}


# ---------------------------------------------------------------------------
# Email analysis
# ---------------------------------------------------------------------------

URGENT_WORDS = [
    "urgent", "immediately", "act now", "within 24 hours", "your account has been",
    "suspended", "verify now", "confirm your identity", "click here",
    "limited time", "expires", "failure to", "legal action", "account locked",
]

SENSITIVE_REQUESTS = [
    "password", "otp", "one-time", "pin", "social security", "credit card",
    "bank account", "ssn", "date of birth", "mother's maiden",
]

# Very rough pattern to spot URLs embedded in email text
EMBEDDED_URL_PATTERN = re.compile(r"https?://\S+", re.IGNORECASE)

# Suspicious sender patterns: free webmail domains used to impersonate companies
FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "protonmail.com", "mail.com",
}


def analyze_email(email_text: str, sender: str = "") -> dict:
    """
    Analyse email body text (and optionally the sender address) and return:
        score   (int  0–100)
        label   (str  Low / Medium / High Risk)
        reasons (list of str)
    """
    email_text = email_text.strip()
    sender = sender.strip().lower()

    if not email_text:
        return {"score": 0, "label": "Low Risk", "reasons": ["No email text provided."]}

    text_lower = email_text.lower()
    score = 0
    reasons = []

    # 1. Urgent / threatening language
    found_urgent = [w for w in URGENT_WORDS if w in text_lower]
    if found_urgent:
        score += min(25, len(found_urgent) * 8)
        reasons.append(f"Urgent or threatening language detected: {', '.join(found_urgent[:3])}{'…' if len(found_urgent) > 3 else ''}.")

    # 2. Requests for sensitive information
    found_sensitive = [w for w in SENSITIVE_REQUESTS if w in text_lower]
    if found_sensitive:
        score += min(30, len(found_sensitive) * 10)
        reasons.append(f"Sensitive information requested: {', '.join(found_sensitive[:3])}{'…' if len(found_sensitive) > 3 else ''}.")

    # 3. Embedded links in the email body
    links = EMBEDDED_URL_PATTERN.findall(email_text)
    if links:
        score += 10
        reasons.append(f"{len(links)} link(s) embedded in the email body.")

        # Check each embedded link with the URL analyser
        for link in links[:3]:          # limit to first 3 to keep it brief
            url_result = analyze_url(link)
            if url_result["score"] >= 30:
                score += 10
                reasons.append(f"Embedded link looks suspicious: {link[:60]}{'…' if len(link) > 60 else ''}")
                break

    # 4. Suspicious sender address
    if sender:
        if "@" not in sender:
            score += 10
            reasons.append("Sender address does not look like a valid email.")
        else:
            domain = sender.split("@")[-1]
            if domain in FREE_MAIL_DOMAINS:
                score += 15
                reasons.append(f"Sender uses a free webmail service ({domain}) to contact you.")

    # 5. Impersonation signal: claims to be a well-known brand but sender domain doesn't match
    KNOWN_BRANDS = ["paypal", "amazon", "microsoft", "apple", "google", "netflix", "facebook"]
    for brand in KNOWN_BRANDS:
        if brand in text_lower:
            if sender and "@" in sender:
                domain = sender.split("@")[-1]
                if brand not in domain:
                    score += 15
                    reasons.append(
                        f"Email mentions '{brand}' but sender domain is '{domain}' — possible impersonation."
                    )
                    break

    score = min(score, 100)

    if not reasons:
        reasons.append("No obvious phishing indicators found.")

    return {"score": score, "label": _score_to_label(score), "reasons": reasons}
