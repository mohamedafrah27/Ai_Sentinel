# HTTPS, SSL Certificates, and Encryption Analysis

## The Role of HTTPS in Web Security
HTTPS (Hypertext Transfer Protocol Secure) provides Transport Layer Security (TLS) encryption between the client's browser and the web server. It ensures two foundational security properties:
1. Confidentiality: Encrypts data in transit against eavesdropping on local networks or Wi-Fi hotspots.
2. Integrity: Prevents tampering, injection, or Man-in-the-Middle (MitM) alterations of transmitted web pages.

## Unencrypted HTTP Vulnerabilities
Websites operating over unencrypted HTTP transmit all requests, form inputs, session cookies, and login credentials in plain text. Any network intermediary, malicious Wi-Fi hotspot operator, or ISP router can inspect, log, or alter this sensitive data without notification to the user.

## The Myth of the "Secure" Padlock on Phishing Sites
A common misconception is that the HTTPS padlock icon guarantees a website is legitimate and trustworthy. In reality:
- Free automated Certificate Authorities (e.g., Let's Encrypt, ZeroSSL) issue Domain Validation (DV) certificates verifying only domain ownership, not the legitimacy of the entity or the business.
- Over 80% of modern phishing websites now utilize valid HTTPS certificates to deceive users into a false sense of security.
- Security analysis must examine domain identity, lexical heuristics, and reputation rather than relying solely on certificate presence.
