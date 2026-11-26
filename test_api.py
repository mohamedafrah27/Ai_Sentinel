import json
import unittest
from backend.app import app
from backend.rag_engine import get_vector_db


class TestAISentinelRealTimeProtection(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_health_check(self):
        """Verify Flask backend health endpoint."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data.get("status"), "AI Sentinel is running")

    def test_genuine_detection_legitimate_urls(self):
        """
        GENUINE DETECTION TEST:
        Validates real-time analysis on actual, legitimate public domains.
        Expects: Low Risk (0–30), Green status, Clean indicators, RAG Safe Browsing Best Practices.
        """
        legitimate_test_urls = [
            "https://www.google.com",
            "https://en.wikipedia.org/wiki/Phishing",
            "https://docs.python.org/3/library/urllib.parse.html",
        ]

        print("\n===========================================================")
        print(" [GENUINE DETECTION TEST] - Legitimate Public Webpages")
        print("===========================================================")

        for url in legitimate_test_urls:
            with self.subTest(url=url):
                response = self.client.post("/scan", json={"url": url})
                self.assertEqual(response.status_code, 200)
                data = response.get_json()

                # Verify actual model response
                self.assertIsInstance(data["risk_score"], int)
                self.assertLessEqual(data["risk_score"], 30, f"Expected Low Risk for legitimate site: {url}")
                self.assertEqual(data["category"], "Low Risk")
                self.assertEqual(data["safety_status"], "Safe")

                # Verify RAG fields
                self.assertIn("ai_generated_explanation", data)
                self.assertIn("retrieved_security_info", data)
                self.assertIn("safety_recommendation", data)

                print(f"[GENUINE] URL: {url}")
                print(f"          Risk Score: {data['risk_score']}/100 | Category: {data['category']}")
                print(f"          Explanation: {data['ai_generated_explanation'][:110]}...")

    def test_simulated_phishing_url_detection(self):
        """
        SIMULATED PHISHING TEST:
        Validates real-time analysis against synthetic malicious URLs mirroring active phishing tactics.
        Expects: High Risk (61–100), Red status, Detected indicators, User risks, RAG context.
        """
        simulated_phishing_urls = [
            "http://paypal-security-update-account.verify.xyz/signin",
            "http://192.168.10.50/account-verification-alert/login",
            "http://update-wallet-crypto-free.pw/claim",
        ]

        print("\n===========================================================")
        print(" [SIMULATED PHISHING TEST] - Synthetic Deceptive URLs")
        print("===========================================================")

        for url in simulated_phishing_urls:
            with self.subTest(url=url):
                response = self.client.post("/scan", json={"url": url})
                self.assertEqual(response.status_code, 200)
                data = response.get_json()

                self.assertIsInstance(data["risk_score"], int)
                self.assertGreaterEqual(data["risk_score"], 61, f"Expected High Risk for phishing URL: {url}")
                self.assertEqual(data["category"], "High Risk")
                self.assertEqual(data["safety_status"], "Malicious")

                # Verify indicators and RAG intelligence
                indicators = data["detected_indicators"]
                self.assertTrue(len(indicators) >= 2)
                self.assertTrue(len(data["retrieved_security_info"]) > 0)
                self.assertIn("CRITICAL", data["safety_recommendation"])

                print(f"[SIMULATED PHISH] URL: {url}")
                print(f"                 Score: {data['risk_score']}/100 | Category: {data['category']}")
                print(f"                 Detected Indicators: {indicators[:2]}")
                print(f"                 RAG Topic: {data['retrieved_security_info'][0]['topic']}")

    def test_simulated_medium_risk_url(self):
        """
        SIMULATED MEDIUM RISK TEST:
        Validates detection of moderate risk factors (e.g., unencrypted HTTP with sensitive keywords).
        """
        url = "http://secure-login.example.org"
        response = self.client.post("/scan", json={"url": url})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()

        self.assertIn(data["category"], ["Medium Risk", "High Risk"])
        self.assertGreaterEqual(data["risk_score"], 31)

        print("\n===========================================================")
        print(" [SIMULATED CAUTION TEST] - Moderate Risk URL")
        print("===========================================================")
        print(f"[CAUTION] URL: {url}")
        print(f"          Score: {data['risk_score']}/100 | Category: {data['category']}")
        print(f"          Recommendation: {data['safety_recommendation']}")

    def test_deduplication_and_error_handling(self):
        """Verify API input validation and error formats."""
        # Non-JSON
        resp1 = self.client.post("/scan", data="plain text", content_type="text/plain")
        self.assertEqual(resp1.status_code, 400)

        # Missing URL
        resp2 = self.client.post("/scan", json={})
        self.assertEqual(resp2.status_code, 400)

        # Invalid protocol
        resp3 = self.client.post("/scan", json={"url": "ftp://fileserver.local"})
        self.assertEqual(resp3.status_code, 400)


if __name__ == "__main__":
    unittest.main()
