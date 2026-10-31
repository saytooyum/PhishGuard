"""
app.py — PhishGuard Streamlit interface.

Run with:
    streamlit run app.py
"""

import streamlit as st
from analyzer import analyze_url, analyze_email

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="centered",
)

st.title("🛡️ PhishGuard")
st.caption("A beginner-friendly, rule-based phishing URL and email analyzer.")

st.info(
    "⚠️ **Disclaimer:** PhishGuard uses simple pattern-based rules. "
    "Its results are **indicators**, not a guarantee that something is safe or malicious. "
    "Always use your own judgement and consult a security professional when in doubt.",
    icon="ℹ️",
)

st.divider()


# ---------------------------------------------------------------------------
# Helper: display a result card
# ---------------------------------------------------------------------------

def show_result(result: dict) -> None:
    """Render a score card for a given analysis result dict."""
    score = result["score"]
    label = result["label"]
    reasons = result["reasons"]

    # Colour-code by risk level
    if label == "High Risk":
        color = "🔴"
        st.error(f"{color} **{label}** — Score: {score} / 100")
    elif label == "Medium Risk":
        color = "🟡"
        st.warning(f"{color} **{label}** — Score: {score} / 100")
    else:
        color = "🟢"
        st.success(f"{color} **{label}** — Score: {score} / 100")

    st.progress(score / 100)

    st.markdown("**Findings:**")
    for reason in reasons:
        st.markdown(f"- {reason}")


# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------

tab_url, tab_email = st.tabs(["🔗 URL Analyzer", "📧 Email Analyzer"])


# ── Tab 1: URL Analyzer ──────────────────────────────────────────────────────

with tab_url:
    st.subheader("URL Analyzer")
    st.markdown(
        "Paste a URL below to check it for common phishing indicators such as "
        "missing HTTPS, IP-address hosts, URL shorteners, and suspicious words."
    )

    url_input = st.text_input(
        "Enter a URL",
        placeholder="e.g. http://192.168.1.1/login or https://bit.ly/abc123",
    )

    if st.button("Analyse URL", key="btn_url"):
        if url_input.strip():
            result = analyze_url(url_input)
            st.divider()
            show_result(result)
        else:
            st.warning("Please enter a URL before clicking Analyse.")

    with st.expander("What does this check?"):
        st.markdown(
            """
- **HTTPS** — Legitimate sites almost always use encrypted connections.
- **IP address as host** — Phishing pages often use raw IPs to avoid domain registration trails.
- **Suspicious words** — Words like *login*, *verify*, *password* in the URL path are a red flag.
- **URL shorteners** — These hide the real destination URL.
- **Too many subdomains** — e.g. `paypal.com.evil.com` tries to fool you with a familiar-looking prefix.
- **Long URL** — Attackers sometimes pad URLs to obscure the real domain.
            """
        )


# ── Tab 2: Email Analyzer ────────────────────────────────────────────────────

with tab_email:
    st.subheader("Email Analyzer")
    st.markdown(
        "Paste the email body text below (and optionally the sender address) "
        "to check for urgent language, sensitive data requests, suspicious links, and impersonation."
    )

    sender_input = st.text_input(
        "Sender email address (optional)",
        placeholder="e.g. support@paypal-security.com",
    )

    email_input = st.text_area(
        "Email body text",
        placeholder="Paste the full email text here…",
        height=200,
    )

    if st.button("Analyse Email", key="btn_email"):
        if email_input.strip():
            result = analyze_email(email_input, sender=sender_input)
            st.divider()
            show_result(result)
        else:
            st.warning("Please paste some email text before clicking Analyse.")

    with st.expander("What does this check?"):
        st.markdown(
            """
- **Urgent / threatening language** — Phrases like *"act now"*, *"account suspended"*, *"within 24 hours"*.
- **Sensitive data requests** — Asking for passwords, OTPs, PINs, credit card numbers, or SSNs.
- **Embedded links** — Any URLs in the email body are also checked with the URL analyser.
- **Free webmail sender** — A company using Gmail or Yahoo to contact you is unusual.
- **Brand impersonation** — Mentioning PayPal, Amazon, etc. while the sender domain doesn't match.
            """
        )


# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------

st.divider()
st.caption("PhishGuard · Built with Python and Streamlit · For educational purposes only.")
