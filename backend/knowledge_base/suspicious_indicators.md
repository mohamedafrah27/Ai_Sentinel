# Suspicious Website Indicators and Heuristic Signals

## Critical Indicators of Deceptive Websites
Cybersecurity telemetry and AI detection systems evaluate structural and lexical heuristics to compute phishing probability:

### 1. Absence of Valid Domain Hierarchy
- Excessive number of subdomain labels (more than two or three dots in hostname).
- Unusual character repetitions or hyphen abuse (e.g., `login-verify-account-security-update.com`).
- Mismatch between the page title, brand logos, and the root domain registrar.

### 2. Sensitive Keyword Clumping
Phishing URLs concentrate action-oriented, urgent, or high-value keywords within the path or query parameters, including:
`login`, `verify`, `account`, `signin`, `password`, `credential`, `banking`, `security`, `recover`, `wallet`, `crypto`, `billing`, and `authenticate`.

### 3. Connection Anomalies
- Absence of HTTPS on pages demanding authentication or payment information.
- Self-signed, expired, or hostname-mismatched SSL certificates.
- Rapid redirects across multiple unrelated domain boundaries.

### 4. Content and Behavior Red Flags
- Inability to select or copy text (content rendered inside flat images).
- Disabled right-click or inspection handlers.
- Immediate aggressive popups requesting credential validation or 2FA entry.
