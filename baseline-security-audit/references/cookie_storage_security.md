# Cookie and Local Storage Security Analysis

Analyze the codebase to identify insecure usage of cookies and local storage that could expose sensitive information:

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A02 Security Misconfiguration, A07 Authentication Failures · **ASVS 5.0:** V7 Session Management, V3 Web Frontend Security

> **Hosting model:** this check depends on `HOSTING_MODEL` from SKILL.md Step 0b. `web.config` sections apply only when it is `iis`; for `linux` use the middleware or platform equivalents named in this file and do not report missing `web.config` entries; with the `edge` modifier the live `PRODUCTION_URL` response is the ground truth and `UseForwardedHeaders` must be configured.

## Core Security Principle
**Storing sensitive information in cookies or local storage should be prevented. Cookies must be properly configured with security flags (Secure, HttpOnly, SameSite). If sensitive data storage cannot be avoided, it must be encrypted. Client-side storage is inherently less secure than server-side storage.**

## 1. Backend Cookie Configuration (ASP.NET Core)

**Check cookie configuration in Startup.cs / Program.cs:**

**Files to examine:**
- `Startup.cs` - Legacy ASP.NET Core configuration
- `Program.cs` - .NET 6+ minimal API configuration
- Cookie authentication configuration
- Session cookie configuration
- Custom cookie middleware

**Authentication cookie configuration:**
```csharp
// Startup.cs or Program.cs
services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.HttpOnly = true;      // MUST be true
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;  // MUST be Always
        options.Cookie.SameSite = SameSiteMode.Lax;     // Lax (the framework default) for auth cookies; Strict breaks the OIDC /signin-oidc POST callback
        options.Cookie.Name = "__Host-YourApp.Auth";  // __Host- prefix: browser enforces Secure, Path=/ and no Domain
        options.ExpireTimeSpan = TimeSpan.FromHours(1);
        options.SlidingExpiration = true;
    });
```

**Session cookie configuration:**
```csharp
services.AddSession(options =>
{
    options.Cookie.HttpOnly = true;          // MUST be true
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;  // MUST be Always
    options.Cookie.SameSite = SameSiteMode.Lax;     // Lax for session cookies that must survive the OIDC redirect
    options.Cookie.Name = "__Host-YourApp.Session";
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.IsEssential = true;
});
```

**Application cookie defaults:**
```csharp
services.Configure<CookiePolicyOptions>(options =>
{
    options.HttpOnly = HttpOnlyPolicy.None;      // Do NOT use Always: it makes the Angular XSRF-TOKEN cookie unreadable and silently disables CSRF protection
    options.Secure = CookieSecurePolicy.Always;  // MUST be Always
    options.MinimumSameSitePolicy = SameSiteMode.Unspecified;  // the default: no global minimum. Lax or Strict here upgrades the SameSite=None that OIDC correlation/nonce cookies require and breaks sign-in; set SameSite per cookie instead (see the table below)
});
app.UseCookiePolicy(); // the options above only apply when this middleware is in the pipeline
```

Report any `MinimumSameSitePolicy` of `Lax` or `Strict` as High when the app signs in through OpenID Connect; Microsoft's policy matrix shows `None` cookies being raised to the minimum (https://learn.microsoft.com/aspnet/core/security/samesite).

**Cookies that are exceptions by design (never report these):**

| Cookie | Required setting | Why |
|--------|------------------|-----|
| `.AspNetCore.Correlation.*`, `.AspNetCore.OpenIdConnect.Nonce.*` | `SameSite=None; Secure` | Set by the OIDC handler; the IdP POSTs back cross-site. `Strict` or `Lax` produces "Correlation failed" |
| Authentication cookie (`.AspNetCore.Cookies` / `YourApp.Auth`) | `SameSite=Lax` (framework default), `HttpOnly`, `Secure` | Must be sent on the top-level `/signin-oidc` navigation |
| Antiforgery cookie (`.AspNetCore.Antiforgery.*`) | `SameSite=Strict`, `HttpOnly` | Framework default; same-site only |
| `XSRF-TOKEN` (Angular `withXsrfConfiguration` / `HttpClientXsrfModule`) | **not** `HttpOnly`, `Secure`, `SameSite=Lax` or `Strict` | Angular reads it from JavaScript to send the `X-XSRF-TOKEN` header |

A missing `SameSite` attribute means the browser applies `Lax`; report that as Low "attribute not explicit", not as a CSRF vulnerability. Cookies used in third-party contexts (iframes) need `SameSite=None; Secure` plus the CHIPS `Partitioned` attribute (`options.Extensions.Add("Partitioned")`).

**Cookie prefixes:** name authentication, session and antiforgery cookies `__Host-...` (`options.Cookie.Name = "__Host-..."`, also in `AddAntiforgery`; the browser rejects the cookie unless it is `Secure`, has `Path=/` and no `Domain`) and other first-party cookies `__Secure-...`. An authentication, session or antiforgery cookie without a prefix = Low.

**`CookieSecurePolicy.SameAsRequest` is the framework default.** Behind TLS termination at Front Door, Application Gateway or a reverse proxy the request reaches Kestrel as HTTP, so `Secure` is not set unless `UseForwardedHeaders` runs before authentication or `SecurePolicy = Always` is configured. An authentication or session cookie without `Secure` on the live response is High.

## 2. Backend Cookie Creation and Modification

Search `Response.Cookies.Append(`, `Response.Cookies.Delete(` and `new CookieOptions`; an `Append` without options, or with `HttpOnly`, `Secure` or `SameSite` missing, is rated by the cookie's purpose in section 8.

An explicit `Domain` shares the cookie with every subdomain and rules out the `__Host-` prefix; an explicit `Domain` on an authentication, session or antiforgery cookie = Low.

## 3. Cookie Content Analysis

**Search for sensitive data in cookie values:**
```csharp
// RED FLAGS - Sensitive data in cookies
Response.Cookies.Append("Email", user.Email);  // Medium - PII, should not be in a cookie
Response.Cookies.Append("Password", password);  // Critical - never store passwords
Response.Cookies.Append("Token", token);  // High unless HttpOnly+Secure and signed/encrypted
Response.Cookies.Append("SSN", ssn);  // Critical - never store SSN in cookies
Response.Cookies.Append("CreditCard", cardNumber);  // Critical - never

// Questionable - Depends on sensitivity
Response.Cookies.Append("Username", username);  // Consider necessity
Response.Cookies.Append("Role", userRole);  // High if trusted server-side without a signature - authorization data can be tampered with
Response.Cookies.Append("Preferences", jsonPreferences);  // Check content
```

A plain user id (`UserId`) in a cookie is not sensitive on its own and is not a finding; only report it when it is trusted server-side for authorization without a signature.

## 4. Angular Cookie Usage

**Check Angular cookie operations:**

**Files to examine:**
- `*.component.ts` - Component files
- `*.service.ts` - Service files, especially auth services
- Search for cookie libraries: `ngx-cookie-service`, `ngx-cookie`, `js-cookie`

**Look for cookie reading/writing:**
```typescript
// Direct document.cookie access (discouraged)
document.cookie = "username=John; path=/";
const cookies = document.cookie;

// Using ngx-cookie-service
import { CookieService } from 'ngx-cookie-service';

constructor(private cookieService: CookieService) {}

// Check for security flags
this.cookieService.set('token', token);  // BAD - No security options

this.cookieService.set('token', token, {
  expires: 1,
  path: '/',
  secure: true,      // GOOD - but check if always set
  httpOnly: false,   // NOTE: Cannot be set from JavaScript
  sameSite: 'Strict' // GOOD
});
```

`HttpOnly` cannot be set from JavaScript, so a cookie written client-side is always XSS-readable: a token or credential written this way is rated as unencrypted sensitive data (section 8); a preference cookie without `secure: true` is Low.

## 5. Local Storage Usage (Angular)

**Files to search:**
- `*.component.ts`
- `*.service.ts`
- `*storage.service.ts` - Custom storage services
- Search for: `localStorage`, `sessionStorage`, `StorageMap`

## 6. Local Storage Content Analysis

Rate every stored value by the sensitivity scale in section 8; theme, language, cart contents, timestamps and UI settings are not findings.

**Token caches of the standard OIDC libraries are rated by cache location, not as home-grown storage:**
- MSAL (`@azure/msal-angular`, `cacheLocation`) or `oidc-client-ts` / `angular-auth-oidc-client` using `sessionStorage` → not a finding (library default, tab-scoped)
- The same libraries configured for `localStorage` → Medium (persists across tabs and restarts; recommend `sessionStorage`)
- Any home-grown `localStorage.setItem('token', ...)` of a JWT or bearer token → High

## 7. Encryption Requirements for Local Storage

Client-side encryption is a weak control (the key is in the browser and readable by the same XSS); the only acceptable primitive is the Web Crypto API (`crypto.subtle`, AES-GCM, PBKDF2 with a random salt). `crypto-js` and hardcoded keys are rated by check 13 (cryptography_security.md) section 6. Prefer not storing the data client-side at all.

## 8. What to Report

### Unsafe Cookie Configuration:

**Report cookies missing security flags.** Severity depends on the cookie's purpose:

| Cookie | Missing `Secure` or `HttpOnly` | `SameSite` not explicit |
|--------|-------------------------------|-------------------------|
| Authentication, session or antiforgery cookie | High | Low |
| OIDC correlation / nonce cookie (`SameSite=None; Secure` required) | High if `Secure` is missing | not a finding (`None` is by design) |
| `XSRF-TOKEN` (must be JavaScript-readable) | High if `Secure` is missing; `HttpOnly` absence is by design | Low |
| Preference or UI cookie | Low | Low |

Also Low: an authentication, session or antiforgery cookie whose name lacks the `__Host-` prefix, or that sets an explicit `Domain` (sections 1 and 2).

For each finding, provide:
- **Location**: File path and line number
- **Cookie name**: Name of the cookie
- **Missing flag**: Which security flag is missing
  - Missing `HttpOnly = true`
  - Missing `Secure = true`
  - Missing `SameSite` setting
- **Cookie purpose**: What the cookie is used for
- **Risk**: Specific vulnerability (XSS, MITM, CSRF)
- **Recommendation**: Add the missing security flag

### Unencrypted Sensitive Data:

**Report sensitive data in cookies or local storage:**

For each finding, provide:
- **Location**: File path and line number
- **Storage type**: Cookie, localStorage, or sessionStorage
- **Data type**: What sensitive information is stored
- **Data sensitivity** (this is the finding's severity):
  - **Critical**: Passwords, SSN / national id, card numbers (PAN / CVV), private keys
  - **High**: Home-grown JWT or bearer token in localStorage, session id, API key, authorization data (`Role`, `IsAdmin`) trusted without a signature
  - **Medium**: Email, phone, address and other PII in plaintext; OIDC library token cache configured for `localStorage`
- **Encryption status**: Encrypted or plaintext
- **Usage**: How the data is used in the application
- **Risk level**: Impact if data is compromised
- **Recommendation**: 
  - **REMOVE**: Don't store this data client-side
  - **ENCRYPT**: Encrypt before storing (if unavoidable)
  - **SERVER-SIDE**: Move to server-side storage
  - **HTTPONLY COOKIE**: Use HttpOnly cookie instead of localStorage

## 9. Testing and Verification

**Verification steps:**

1. **`Set-Cookie` header diff from the live URL** (when `PRODUCTION_URL` is available; this is the ground truth with the `edge` modifier):
   ```bash
   curl -sSI -L "$PRODUCTION_URL" | grep -i '^set-cookie'
   curl -sSI -L "$PRODUCTION_URL/api/health" | grep -i '^set-cookie'
   ```
   (PowerShell 7: `(Invoke-WebRequest -Uri $env:PRODUCTION_URL -Method Head -SkipHttpErrorCheck).Headers['Set-Cookie']`.) For every `Set-Cookie` line, diff the attributes present (`Secure`, `HttpOnly`, `SameSite`, `Path`, `Max-Age`/`Expires`, `Partitioned`) against the required settings in the section 1 table; report each gap with the severity from section 8. A cookie seen without `Secure` while the code sets `CookieSecurePolicy.SameAsRequest` behind a TLS-terminating edge means `UseForwardedHeaders` is missing; with `Always` the `Secure` flag does not depend on the scheme, so look for another cookie writer, the deployed configuration or response rewriting.

2. **DevTools Application tab checklist** (ask the user to open the app, sign in, and read the panel; nothing is executed in the page):
   - Cookies → per cookie, the `Secure`, `HttpOnly`, `SameSite` and `Partitioned` columns match the section 1 table
   - Local Storage → no key holding a JWT (`eyJ...`), bearer token, password, email or other PII; MSAL / oidc-client cache keys appear here only if `cacheLocation` was changed to `localStorage` (Medium)
   - Session Storage → OIDC library cache keys are expected here (Low, note only); no home-grown token keys
   - Note every key name and the first characters of its value in the finding; never copy a full token into the report

3. **Network tab review** (or the `curl` output above):
   - Cookies are sent only over HTTPS requests
   - Tokens travel in the `Authorization` header or a cookie, never in the query string. See check 6 (sensitive_query_strings.md) for tokens in query strings.
