"""
test_analyzer.py — Basic unit tests for PhishGuard's analyzer module.

Run with:
    python -m unittest test_analyzer.py
"""

import unittest
from analyzer import analyze_url, analyze_email


class TestAnalyzeURL(unittest.TestCase):

    def test_blank_input_returns_low_risk(self):
        result = analyze_url("")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["label"], "Low Risk")

    def test_http_ip_address_is_high_risk(self):
        # Raw IP + no HTTPS should score high
        result = analyze_url("http://192.168.0.1/login")
        self.assertGreaterEqual(result["score"], 60)
        self.assertEqual(result["label"], "High Risk")

    def test_url_shortener_raises_score(self):
        result = analyze_url("http://bit.ly/abc123")
        self.assertGreaterEqual(result["score"], 30)

    def test_https_clean_url_is_low_risk(self):
        result = analyze_url("https://example.com")
        self.assertEqual(result["label"], "Low Risk")

    def test_suspicious_words_in_path(self):
        result = analyze_url("http://example.com/verify/password/update")
        self.assertGreater(result["score"], 0)
        self.assertTrue(any("suspicious" in r.lower() for r in result["reasons"]))


class TestAnalyzeEmail(unittest.TestCase):

    def test_blank_input_returns_low_risk(self):
        result = analyze_email("")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["label"], "Low Risk")

    def test_urgent_language_raises_score(self):
        text = "Your account has been suspended. Act now to avoid legal action."
        result = analyze_email(text)
        self.assertGreater(result["score"], 0)

    def test_sensitive_request_raises_score(self):
        text = "Please reply with your password and credit card number to verify."
        result = analyze_email(text)
        self.assertGreater(result["score"], 0)
        self.assertTrue(any("sensitive" in r.lower() for r in result["reasons"]))

    def test_free_webmail_sender_raises_score(self):
        text = "Hello, please review your invoice."
        result = analyze_email(text, sender="billing@gmail.com")
        self.assertGreater(result["score"], 0)
        self.assertTrue(any("webmail" in r.lower() for r in result["reasons"]))

    def test_brand_impersonation_raises_score(self):
        # Sender domain must not contain the brand name to trigger the impersonation check
        text = "Your PayPal account needs verification."
        result = analyze_email(text, sender="support@fraudulent-alerts.com")
        self.assertTrue(any("impersonation" in r.lower() for r in result["reasons"]))

    def test_clean_email_is_low_risk(self):
        text = "Hi, just checking in about the meeting tomorrow. See you then."
        result = analyze_email(text, sender="alice@example.com")
        self.assertEqual(result["label"], "Low Risk")


if __name__ == "__main__":
    unittest.main()
