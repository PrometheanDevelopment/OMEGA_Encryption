# Security Policy

# Supported Versions

The following versions of OMEGA Encryption currently receive security updates:

| Version | Supported |
|---------|-----------|
| v1.0    |    NO     |
| v1.5    |    NO     |
| v2.3    |    YES    |
| v2.4    |    YES    |

If you are using an unsupported version, you are strongly encouraged to upgrade to the latest release.

---

# Reporting a Vulnerability

If you discover a security vulnerability, **please DO NOT open a public issue**.

Instead, report it privately via:

**Email:** prometheus12@outlook.com 

When reporting a vulnerability, please include:

- A description of the issue  
- Steps to reproduce  
- Impact assessment (if known)  
- Suggested fixes (optional)  
- Any relevant logs, proof-of-concept code, or screenshots  

We will acknowledge receipt within **72 hours**, and aim to provide:

- An initial assessment within **7 days**  
- A fix or mitigation plan within **30 days**, depending on severity  

If required, we may request additional information.

# Security Expectations for Contributors

To maintain a secure cryptographic codebase, contributors should:

- Avoid introducing new cryptographic primitives or algorithms without prior discussion.  
- Use constant-time operations where applicable.  
- Never log sensitive data such as keys, plaintext, or salts.  
- Ensure randomness comes from cryptographically secure sources (`os.urandom`, `secrets`, or library-provided RNG).  
- Validate all inputs and handle errors securely.  
- Follow safe memory-handling practices (avoid lingering secrets in long-lived variables where possible).  

Pull requests that introduce security-sensitive changes may be subject to enhanced review.

---

## Disclosure Policy

Security vulnerabilities will be disclosed responsibly:

1. A fix is developed and tested.  
2. A new patched release is published.  
3. CVE identifiers may be requested for severe vulnerabilities.  
4. A public security advisory is issued describing the impact and resolution.  

We will credit reporters unless they request anonymity.

---

# Cryptography Disclaimer

OMEGA Encryption implements modern cryptographic techniques (X25519, HKDF, AES-256-GCM, and optional PQ KEMs).  
**No cryptographic library can guarantee perfect security.**

Users should:

- Review the code and assess suitability for their threat model.  
- Keep libraries and dependencies updated.  
- Use strong, high-entropy secrets.  
- Avoid modifying cryptographic components without expertise.  
