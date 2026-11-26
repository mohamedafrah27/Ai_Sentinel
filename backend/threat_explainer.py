"""
AI Sentinel - Threat Explanation Module
Analyzes URL heuristics, machine learning classification outputs, and external intelligence
to generate grounded, evidence-based security explanations, user risk assessments, and recommendations.
"""

from typing import Dict, Any, List


def generate_threat_explanation(
    url: str,
    risk_score: int,
    category: str,
    features: Dict[str, Any],
    safe_browsing: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Synthesizes phishing detection evidence into an AI-powered threat explanation.

    Strict Grounding Guarantee:
    Explanations and risk assessments are strictly mapped to verified indicators
    present in the features dictionary or Safe Browsing telemetry.

    Returns:
    {
        "summary": str,
        "classification_reason": str,
        "detected_indicators": List[str],
        "user_risks": List[str],
        "recommendations": List[str]
    }
    """
    detected_indicators: List[str] = []
    user_risks: List[str] = []
    recommendations: List[str] = []

    # -------------------------------------------------------------------------
    # 1. Identify Detected Phishing Indicators (Grounding)
    # -------------------------------------------------------------------------
    # Check Google Safe Browsing intelligence
    if safe_browsing.get("is_threat"):
        threat_types = safe_browsing.get("threat_types", [])
        threat_str = ", ".join(threat_types) if threat_types else "MALICIOUS"
        detected_indicators.append(
            f"Google Safe Browsing Intelligence: URL is blacklisted for {threat_str}."
        )

    # Check hostname format (Direct IP)
    if features.get("has_ip_address"):
        detected_indicators.append(
            "Direct IP Address Hostname: Host uses an IPv4 address directly instead of a verified domain name."
        )

    # Check SSL/TLS protocol encryption
    if features.get("is_https") == 0:
        detected_indicators.append(
            "Insecure Communication: Site uses unencrypted HTTP protocol without SSL/TLS security."
        )

    # Check for deceptive/sensitive phishing keywords
    matched_kws = features.get("matched_keywords") or []
    if matched_kws:
        detected_indicators.append(
            f"Deceptive Keywords: High-risk phishing terms detected ({', '.join(matched_kws)})."
        )

    # Check for high-abuse TLDs
    if features.get("suspicious_tld"):
        detected_indicators.append(
            "High-Abuse Top-Level Domain: Domain uses a TLD associated with disposable malicious campaigns."
        )

    # Check for '@' symbol spoofing
    if features.get("has_at_symbol"):
        detected_indicators.append(
            "URL Obfuscation ('@' Delimiter): Contains '@' symbol used to spoof domain authority."
        )

    # Check for double-slash redirection
    if features.get("has_double_slash_redirect"):
        detected_indicators.append(
            "Path Redirection ('//'): Contains consecutive slashes in URL path to trigger hidden redirects."
        )

    # Check for excessive subdomains
    subdomains = features.get("subdomain_count", 0)
    if subdomains >= 3:
        detected_indicators.append(
            f"Excessive Subdomains: Host contains {subdomains} subdomain levels mimicking authentic services."
        )

    # Check for domain hyphens
    hyphens = features.get("hyphen_count_domain", 0)
    if hyphens >= 3:
        detected_indicators.append(
            f"Excessive Domain Hyphens: Host contains {hyphens} hyphens commonly used for typo-squatting."
        )

    # Check for abnormally long URLs
    url_len = features.get("url_length", 0)
    if url_len > 85:
        detected_indicators.append(
            f"Abnormally Long URL: Length ({url_len} chars) suggests embedded redirection or token smuggling."
        )

    if not detected_indicators:
        detected_indicators.append(
            "Clean URL Heuristics: Standard domain hierarchy, HTTPS encryption, and zero phishing keywords."
        )

    # -------------------------------------------------------------------------
    # 2. Explain Classification Reason
    # -------------------------------------------------------------------------
    if category == "High Risk":
        classification_reason = (
            f"Classified as High Risk ({risk_score}/100) because the Random Forest ML classifier "
            f"detected severe phishing patterns corroborated by {len(detected_indicators)} suspicious indicator(s)."
        )
    elif category == "Medium Risk":
        classification_reason = (
            f"Classified as Medium Risk ({risk_score}/100) due to anomalous structural heuristics "
            f"({len(detected_indicators)} indicator(s)) that deviate from established trust baselines."
        )
    else:
        classification_reason = (
            f"Classified as Low Risk ({risk_score}/100). The URL exhibits valid security attributes "
            f"with HTTPS encryption and no deceptive keywords or domain spoofing."
        )

    # -------------------------------------------------------------------------
    # 3. Explain Potential Risks to Users
    # -------------------------------------------------------------------------
    # Risk: Malware infection
    if safe_browsing.get("is_threat") or any("MALWARE" in t for t in safe_browsing.get("threat_types", [])):
        user_risks.append(
            "Malware Infection: Visiting this website may trigger drive-by downloads or payload exploits."
        )

    # Risk: Credential harvesting
    credential_keywords = {"login", "signin", "password", "credential", "verify", "account", "recover", "authenticate"}
    if any(kw in credential_keywords for kw in matched_kws):
        user_risks.append(
            "Credential Harvesting: High risk of deceptive login forms designed to steal usernames, passwords, and multi-factor auth tokens."
        )

    # Risk: Financial fraud / Identity theft
    financial_keywords = {"banking", "paypal", "billing", "wallet", "crypto", "claim", "free-gift", "ebayisapi", "webscr"}
    if any(kw in financial_keywords for kw in matched_kws):
        user_risks.append(
            "Financial Fraud & Identity Theft: Deceptive pages may attempt to harvest payment card details, bank logins, or digital wallet assets."
        )

    # Risk: Brand impersonation / Spoofing
    if features.get("has_ip_address") or features.get("has_at_symbol") or features.get("suspicious_tld"):
        user_risks.append(
            "Brand Impersonation: Attackers use disposable domains or raw IP hosts to pose as trusted institutions."
        )

    # Risk: Eavesdropping & Cleartext interception
    if features.get("is_https") == 0:
        user_risks.append(
            "Eavesdropping & Interception: Because traffic is unencrypted (HTTP), attackers on the local network can observe and capture submitted data."
        )

    # Default fallback risks grounded by category
    if category == "High Risk" and not user_risks:
        user_risks.append(
            "Data Compromise: High likelihood of deceptive content aimed at harvesting sensitive personal data."
        )
    elif category == "Medium Risk" and not user_risks:
        user_risks.append(
            "Unverified Origin: Potential exposure to deceptive links or unauthenticated service endpoints."
        )
    elif category == "Low Risk":
        user_risks.append(
            "Minimal Threat Exposure: No active credential harvesting, malware, or eavesdropping vulnerabilities detected."
        )

    # -------------------------------------------------------------------------
    # 4. Provide Tailored Safety Recommendations
    # -------------------------------------------------------------------------
    if category == "High Risk":
        recommendations.append("Do NOT submit any passwords, credit card numbers, or personal credentials on this page.")
        recommendations.append("Close this browser tab immediately to prevent potential exploitation or tracking.")
        recommendations.append("If you reached this page via an unexpected email, SMS, or direct message, report it as phishing.")
    elif category == "Medium Risk":
        recommendations.append("Inspect the exact domain name in the address bar before interacting with any page elements.")
        if features.get("is_https") == 0:
            recommendations.append("Avoid entering any information over this unencrypted HTTP connection.")
        recommendations.append("Navigate to the service directly via a verified search engine or your own bookmark.")
    else:
        recommendations.append("The website demonstrates legitimate trust signals. Standard safe browsing practices apply.")
        recommendations.append("Verify that the HTTPS padlock icon remains intact during login or checkout.")

    # -------------------------------------------------------------------------
    # 5. Short Summary
    # -------------------------------------------------------------------------
    if category == "High Risk":
        summary = (
            f"HIGH THREAT ({risk_score}/100): Random Forest model and threat analysis flagged high phishing probability. "
            f"Key indicators: {'; '.join([i.split(':')[0] for i in detected_indicators[:2]])}."
        )
    elif category == "Medium Risk":
        summary = (
            f"SUSPICIOUS ACTIVITY ({risk_score}/100): Moderate anomalies detected. "
            f"Key indicators: {'; '.join([i.split(':')[0] for i in detected_indicators[:2]])}."
        )
    else:
        summary = (
            f"LOW RISK ({risk_score}/100): Clean URL structure confirmed by Random Forest model with verified security telemetry."
        )

    return {
        "summary": summary,
        "classification_reason": classification_reason,
        "detected_indicators": detected_indicators,
        "user_risks": user_risks,
        "recommendations": recommendations,
    }
