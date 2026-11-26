# Website Spoofing and Interface Replication

## Overview of Website Spoofing
Website spoofing is the creation of a fraudulent website designed to closely replicate the visual appearance, branding, typography, and structure of a legitimate, trusted website. The primary objective is to mislead visitors into believing they are interacting with the genuine service.

## Techniques Employed in Website Spoofing
1. Cloned Assets: Direct scraping and hotlinking of CSS stylesheets, company logos, favicons, and layout templates from the authentic target.
2. Mirror Login Forms: Form actions redirected to attacker-controlled backend endpoints while mirroring the look and feel of authentic OAuth, Single Sign-On (SSO), or two-factor authentication interfaces.
3. Frame Overlay and Tabnabbing: Leveraging browser tabs or deceptive popups that rewrite content when the user is inactive.
4. Deceptive Error Messages: Presenting false account lockouts or expired session warnings to induce panic and prompt rapid credential re-entry.

## Countermeasures and Detection
Legitimate websites utilize Content Security Policies (CSP), subresource integrity, and domain verification. Users should verify top-level domains, ensure certificates match the brand identity, and utilize password managers that refuse auto-fill on spoofed domains.
