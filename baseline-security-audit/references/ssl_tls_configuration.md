# SSL/TLS Configuration Security Analysis

Analyze the production application's SSL/TLS configuration to identify weak protocols, cipher suites, and other TLS-related vulnerabilities:

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A04 Cryptographic Failures, A02 Security Misconfiguration · **ASVS 5.0:** V12 Secure Communication

> **Hosting model:** this check depends on `HOSTING_MODEL` from SKILL.md Step 0b. `web.config` sections apply only when it is `iis`; for `linux` use the middleware or platform equivalents named in this file and do not report missing `web.config` entries; with the `edge` modifier the live `PRODUCTION_URL` response is the ground truth and `UseForwardedHeaders` must be configured.

## Core Security Principle
**Only strong TLS protocols (TLS 1.2 and TLS 1.3) should be enabled with secure cipher suites. Weak or deprecated protocols and ciphers must be disabled to prevent downgrade attacks and cryptographic vulnerabilities.**

## 1. SSL Labs Testing

**Primary Tool**: the SSL Labs Server Test, driven through its API v4 (API v3 was retired on 1 January 2024; the browser form is only the fallback in (c)).

Test `PRODUCTION_URL` and, after asking once, any additional endpoints (API host, admin portal).

**How to Test**:

**(a) SSL Labs API v4** — Enigmatry is registered for the API; send `support@enigmatry.com` in the `email` header of every call.
```bash
curl -s -H "email: support@enigmatry.com" "https://api.ssllabs.com/api/v4/analyze?host=<host>&publish=off&all=done"
# add &startNew=on to the first call for a fresh assessment, then repeat the call without it every 10-30 s until "status" is "READY" (or "ERROR")
```
Read `endpoints[].grade` and `endpoints[].details`: `protocols` (section 2), `suites` (section 3), `cert` / `certChains` (section 4), `hstsPolicy` (section 8), `namedGroups` (X25519MLKEM768 present = post-quantum hybrid key exchange offered, section 12) and the vulnerability fields (`poodle`, `heartbleed`, `freak`, `logjam`, `drownVulnerable`, section 7).

**(b) Local probes** when the API is unavailable (no registration, rate limit, host not reachable from SSL Labs):
```bash
openssl s_client -connect <host>:443 -tls1_1 </dev/null   # must FAIL (handshake failure)
openssl s_client -connect <host>:443 -tls1_3 </dev/null   # must SUCCEED (Protocol: TLSv1.3)
testssl.sh <host>                                          # full protocol, cipher and vulnerability scan
nmap --script ssl-enum-ciphers -p 443 <host>               # protocols and cipher grades
```

**(c) Fallback**: ask the user to run https://www.ssllabs.com/ssltest/ themselves (with "Do not show the results on the boards" checked) and paste the report; rate from the pasted data and state in the report that the result was user-supplied.

Source: https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v4.md

## 2. SSL/TLS Protocol Versions

**REQUIRED - Only secure protocols:**

**✅ GOOD - Enabled protocols:**
```
TLS 1.3 (Recommended)
TLS 1.2 (Minimum required)
```

**❌ BAD - MUST be disabled:**
```
SSL 2.0 (Critical - Broken, deprecated in 2011)
SSL 3.0 (Critical - POODLE attack, deprecated in 2015)
TLS 1.0 (High - Deprecated in 2020, PCI DSS non-compliant)
TLS 1.1 (High - Deprecated in 2020, PCI DSS non-compliant)
```

**HTTP to HTTPS enforcement:** besides App Service `httpsOnly` (section 9), look for `app.UseHttpsRedirection()` with `AddHsts` / `UseHsts` in `Program.cs`, `[RequireHttps]` on legacy MVC controllers, and on `iis` the native `<hsts redirectHttpToHttps="true">` element or a URL Rewrite rule redirecting to `https://{HTTP_HOST}{REQUEST_URI}`. No application-level or platform-level redirect = Medium. HSTS header values are rated in check 14 (security_headers.md).

## 3. Cipher Suite Security

**REQUIRED - Strong cipher suites only**

**✅ GOOD - Recommended cipher suites:**

**TLS 1.3 (Preferred):**
```
TLS_AES_256_GCM_SHA384
TLS_AES_128_GCM_SHA256
TLS_CHACHA20_POLY1305_SHA256
```

**TLS 1.2 (Acceptable):**
```
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
```

**❌ BAD - MUST NOT be enabled:**

**Critical - Known broken ciphers:**
```
NULL ciphers (No encryption)
EXPORT ciphers (40-bit/56-bit keys - FREAK attack)
DES/3DES (64-bit blocks - Sweet32 attack)
RC4 (Stream cipher - multiple attacks)
MD5-based ciphers (Collision attacks)
```

**High - Weak or deprecated:**
```
CBC mode ciphers without AEAD (BEAST, Lucky13 attacks)
RSA key exchange without PFS (No forward secrecy)
Anonymous DH (No authentication)
Cipher suites with key size < 128 bits
```

Server-preferred cipher order is expected; client preference = Medium (section 12).

## 4. Certificate Security

**Check certificate configuration:**

**✅ GOOD:**
```
RSA key size: ≥ 2048 bits (4096 bits recommended)
ECDSA key size: ≥ 256 bits
Signature algorithm: SHA-256 or better
Certificate chain: Complete and valid
Certificate transparency: Enabled
OCSP stapling: Enabled only if the certificate carries an OCSP URL (Let's Encrypt stopped OCSP in August 2025; CRL-only certificates cannot staple and this is not a finding)
Validity period: ≤ 200 days for certificates issued on or after 15 March 2026 (CA/Browser Forum SC-081); ≤ 100 days from 15 March 2027; ≤ 47 days from 15 March 2029
Renewal: automated (ACME client, App Service managed certificate, Key Vault auto-rotation) — manual renewal cannot keep up with these lifetimes and is a High finding
```

**❌ BAD:**
```
RSA key size: < 2048 bits
Signature algorithm: SHA-1 (deprecated since 2017)
Self-signed certificates in production
Expired certificates
Incomplete certificate chain
Missing intermediate certificates
Certificate hostname mismatch
```

**SSL Labs checks:**
- Certificate trust (trusted by major browsers)
- Certificate validity dates
- Certificate revocation (CRL/OCSP)
- Public key strength
- Signature algorithm strength

## 5. TLS Features and Extensions

**REQUIRED security features:**

**✅ MUST be enabled:**
```
Server Name Indication (SNI): Supported
Secure Renegotiation: Supported
Session resumption: Supported (for performance)
```

**✅ SHOULD be enabled:**
```
OCSP Stapling (only where the certificate has an OCSP URL; N/A for CRL-only certificates)
Certificate Transparency (SCTs)
TLS compression: DISABLED (CRIME attack)
Client-initiated renegotiation: DISABLED
TLS 1.3 (SSL Labs caps servers without TLS 1.3 at A- since March 2025; TLS_FALLBACK_SCSV is no longer graded and is irrelevant once TLS 1.0/1.1 are disabled)
```

## 6. Forward Secrecy (Perfect Forward Secrecy - PFS)

**Required (no Forward Secrecy is rated High):**

**✅ REQUIRED:**
- All cipher suites should support Forward Secrecy
- Use ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) or DHE
- Avoid RSA key exchange

SSL Labs "Forward Secrecy": "Yes (with most browsers)" is compliant; "No" or "With some browsers" = High.

## 7. Common Vulnerabilities to Check

**SSL Labs automatically tests for:**

**Critical vulnerabilities** (BEAST on TLS 1.0 is rated High, like TLS 1.0 itself):
```
POODLE (SSL 3.0) - SSLv3 must be disabled
BEAST (TLS 1.0 with CBC) - TLS 1.2+ required
CRIME (TLS compression) - Compression must be disabled
BREACH (HTTP compression) - Monitor HTTP compression usage
Heartbleed (OpenSSL bug) - Keep OpenSSL updated
FREAK (Export ciphers) - Export ciphers must be disabled
Logjam (Weak DH) - Use strong DH parameters (2048+ bits)
DROWN (SSLv2) - SSLv2 must be completely disabled
Sweet32 (3DES) - 3DES must be disabled
```

Any "Yes" in the SSL Labs vulnerability fields is Critical.

## 8. SSL Labs Grading Criteria

**Target Grade: A or A+**

**How SSL Labs grades** (an overall score with caps, not category percentages):
- Overall score 80 or more → A
- A+ → grade A plus HSTS with `max-age` of at least six months and no warnings
- TLS 1.0 or 1.1 enabled → capped at B
- No TLS 1.3 → capped at A-
- HSTS missing or invalid → capped at A-
- RC4, SSL 3.0 or an untrusted certificate → F or T

Source: https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide

## 9. Azure App Service TLS Configuration (Infrastructure Code)

For Azure-hosted applications, HTTPS enforcement and the minimum TLS version are set on the App Service resource in infrastructure-as-code.

Read the project's module in the infrastructure repository (SKILL.md Step 1).

**GOOD:**
```bicep
resource appService 'Microsoft.Web/sites@2022-03-01' = {
  properties: {
    httpsOnly: true
    siteConfig: {
      minTlsVersion: '1.2'   // or '1.3'
      ftpsState: 'Disabled'  // FTP must be disabled
    }
  }
}
```

**RED FLAGS:**
```bicep
// BAD — HTTPS not enforced
properties: {
  httpsOnly: false   // or property absent (defaults to false)
  siteConfig: {
    minTlsVersion: '1.0'  // Too low
  }
}
```

**What to check:**
- `httpsOnly: true` — App Service must redirect HTTP to HTTPS
- `minTlsVersion` — must be `'1.2'` or `'1.3'`; flag `'1.0'` or `'1.1'` as High
- `ftpsState: 'Disabled'` — FTP access must be disabled in production; flag `'AllAllowed'` or `'FtpsOnly'` as Medium
- With the `edge` modifier TLS terminates at Front Door (`Microsoft.Cdn/profiles` custom domain `minimumTlsVersion`) or Application Gateway (`sslPolicy`); the SSL Labs result reflects that edge policy, so check those Bicep properties as well as the App Service `minTlsVersion`

## 10. Code-Level TLS Settings

**Files to examine:** `*.cs`, `appsettings*.json`, `*.bicep`, pipeline variable files.

**Search patterns:**
```regex
SslProtocols\.(Tls|Tls11|Ssl2|Ssl3|None)\b
SecurityProtocolType\.(Tls|Tls11|Ssl3)\b
ServicePointManager\.SecurityProtocol
TrustServerCertificate\s*=\s*(True|true|yes)
Encrypt\s*=\s*(False|false|no)
ServerCertificateCustomValidationCallback
DangerousAcceptAnyServerCertificateValidator
ServerCertificateValidationCallback\s*=
RemoteCertificateValidationCallback
(UseHttpsRedirection|RequireHttps|AddHsts|redirectHttpToHttps)
```

| Finding | Severity |
|---------|----------|
| Certificate validation disabled (`DangerousAcceptAnyServerCertificateValidator`, a callback that returns `true`) in production code | High |
| `TrustServerCertificate=True` or `Encrypt=False` in a production SQL connection string (the development `appsettings.Development.json` value is not a finding) | High |
| `SslProtocols` / `SecurityProtocolType` explicitly enabling TLS 1.0 or 1.1 | High |
| `SslProtocols` pinned to TLS 1.2 only (`SystemDefault`/`None` lets the OS negotiate TLS 1.3) | Low |

## 11. What to Report

**For each production endpoint tested:**

Per endpoint: overall grade and the cap that applies (section 8); protocols (TLS 1.3 / 1.2 present, TLS 1.1 / 1.0 / SSL absent); cipher suites (strong only, or the weak and broken suites by name); certificate issuer, validity dates, key type and size, signature algorithm, chain completeness; the vulnerability fields (POODLE, BEAST, CRIME, Heartbleed, FREAK, Logjam, DROWN, Sweet32); Forward Secrecy and OCSP stapling status. Each gap is a finding rated per section 12.

## 12. Remediation Priorities

**Critical (Fix Immediately):**
- SSL 2.0/3.0 enabled
- Known vulnerabilities (POODLE, DROWN, etc.)
- Broken ciphers (NULL, EXPORT, RC4, DES)
- Certificate expired or untrusted
- Grade F or T (Trust issues)

**High (Fix Soon):**
- TLS 1.0 enabled (PCI DSS non-compliant)
- TLS 1.1 enabled
- Weak ciphers (3DES, CBC-mode)
- No Forward Secrecy
- Certificate key size < 2048 bits
- SHA-1 certificate signature
- No automated certificate renewal (see section 4)
- Code-level: certificate validation disabled, `TrustServerCertificate=True` in production, TLS 1.0/1.1 enabled in code (see section 10)

**Medium (Plan to Fix):**
- Cipher suite ordering (client preference)
- Missing OCSP stapling (only when the certificate has an OCSP URL)
- No TLS 1.3 support (SSL Labs caps the grade at A-)
- Certificate issued after 15 March 2026 with validity > 200 days
- No HTTP to HTTPS redirect at application or platform level (see section 2)

**Low (Best Practice):**
- ECDSA P-256/P-384 certificates (smaller handshakes; RSA key size above 2048 is not a finding either way)
- Certificate Transparency compliance
- Post-quantum hybrid key exchange (X25519MLKEM768) not offered — hygiene; default in current browsers, available on Windows Server 2025
