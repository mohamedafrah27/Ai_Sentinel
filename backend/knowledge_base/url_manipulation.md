# URL Manipulation and Obfuscation Tactics

## How Attackers Manipulate URLs
Phishing operators deliberately manipulate URL syntactical structures to obscure malicious destinations and bypass basic heuristic scanners.

### 1. Direct IP Address Hostnames
Legitimate consumer and corporate web applications almost universally resolve through domain name registries. Phishing sites frequently use raw IPv4 addresses (such as `http://192.168.1.1/login` or public IP ranges) to bypass domain reputation checks, domain blacklist filters, and avoid domain registration records.

### 2. '@' Symbol Obfuscation
The RFC standard allows URI authentication strings formatted as `scheme://user:password@host/`. Phishing actors use the `@` symbol to mislead users: everything before the `@` is treated by browsers as username credentials, while the actual host contacted is after the `@` (e.g., `http://paypal.com@malicious-phishing-host.com/`).

### 3. Double Slash Redirection ('//')
Using consecutive slashes within the path component can cause URL parsers or vulnerable web servers to trigger open redirects, taking the user away from the perceived destination to an unverified third-party attacker domain.

### 4. Excessive Length and Query String Smuggling
Artificially bloating URLs with long padding parameters, encoded tracking tokens, and repetitive subdirectories pushes the suspicious root domain out of view in mobile or truncated browser address bars.
