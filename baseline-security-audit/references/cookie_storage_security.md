# Cookie and Local Storage Security Analysis

Analyze the codebase to identify insecure usage of cookies and local storage that could expose sensitive information:

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A02 Security Misconfiguration, A07 Authentication Failures · **ASVS 5.0:** V7 Session Management, V3 Web Frontend Security
> **Owns:** —
> **Defers to:** —

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
        options.Cookie.Name = "YourApp.Auth";
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
    options.Cookie.Name = "YourApp.Session";
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

A missing `SameSite` attribute means the browser applies `Lax`; report that as Low "attribute not explicit", not as a CSRF vulnerability.

**Required security flags:**
- **HttpOnly = true**: Prevents JavaScript access (mitigates XSS)
- **Secure = Always**: Only transmit over HTTPS (prevents MITM)
- **SameSite = Strict/Lax**: Prevents CSRF attacks

## 2. Backend Cookie Creation and Modification

**Check manual cookie operations in controllers:**

**Search for cookie manipulation:**
```csharp
// Look for Response.Cookies usage
Response.Cookies.Append("key", "value");
Response.Cookies.Delete("key");
HttpContext.Response.Cookies.Append("key", "value");

// Check CookieOptions configuration
var cookieOptions = new CookieOptions
{
    HttpOnly = true,     // MUST be true for sensitive cookies
    Secure = true,       // MUST be true
    SameSite = SameSiteMode.Strict,  // SHOULD be Strict or Lax
    Expires = DateTimeOffset.UtcNow.AddDays(7),
    Path = "/",
    Domain = ".yourdomain.com"
};
Response.Cookies.Append("PreferenceKey", "value", cookieOptions);
```

**Flags to raise:**
```csharp
// BAD - Missing security flags
Response.Cookies.Append("SessionToken", token);

// BAD - HttpOnly not set (vulnerable to XSS)
Response.Cookies.Append("AuthToken", token, new CookieOptions
{
    Secure = true
    // Missing HttpOnly = true
});

// BAD - Not secure (vulnerable to MITM)
Response.Cookies.Append("AuthToken", token, new CookieOptions
{
    HttpOnly = true
    // Missing Secure = true
});

// BAD - No SameSite protection (vulnerable to CSRF)
Response.Cookies.Append("AuthToken", token, new CookieOptions
{
    HttpOnly = true,
    Secure = true
    // Missing SameSite setting
});

// GOOD - All security flags set
Response.Cookies.Append("AuthToken", token, new CookieOptions
{
    HttpOnly = true,
    Secure = true,
    SameSite = SameSiteMode.Strict,
    MaxAge = TimeSpan.FromHours(1)
});
```

## 3. Cookie Content Analysis

**Check what data is stored in cookies:**

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

**Sensitive data that should NEVER be in cookies:**
- Passwords (plain or hashed)
- Social Security Numbers
- Credit card numbers
- Bank account information
- Medical information
- Authentication secrets
- Unencrypted personal identifiable information (PII)

**Data that requires encryption if stored in cookies:**
- Email addresses
- Session identifiers (should be random, not contain user info)
- Any personal data
- Authorization information (`Role`, `IsAdmin` and similar must be signed or kept server-side)

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

// Using js-cookie library
import Cookies from 'js-cookie';

Cookies.set('token', token);  // BAD - No security options

Cookies.set('token', token, {
  expires: 7,
  secure: true,      // GOOD
  sameSite: 'Strict' // GOOD
  // HttpOnly CANNOT be set from client-side JavaScript
});
```

**Important limitation:**
- **HttpOnly flag CANNOT be set from JavaScript** - It must be set server-side
- Client-side cookies are always accessible to JavaScript (XSS risk)
- Sensitive data should NEVER be stored in client-side cookies

**Flags to raise in Angular:**
```typescript
// BAD - Storing sensitive data client-side
this.cookieService.set('password', password);  // Critical
this.cookieService.set('ssn', ssn);  // Critical
this.cookieService.set('email', email);  // Medium - PII, avoid

// BAD - Missing secure flag
this.cookieService.set('preferences', prefs);  // Missing secure: true

// QUESTIONABLE - Client-side authentication token
this.cookieService.set('authToken', token);  // Should be HttpOnly from server
```

## 5. Local Storage Usage (Angular)

**Check localStorage and sessionStorage usage:**

**Search patterns:**
```typescript
// Direct localStorage access
localStorage.setItem('key', 'value');
localStorage.getItem('key');
localStorage.removeItem('key');
localStorage.clear();

// Direct sessionStorage access
sessionStorage.setItem('key', 'value');
sessionStorage.getItem('key');
sessionStorage.removeItem('key');
sessionStorage.clear();

// Using @ngx-pwa/local-storage or similar
import { StorageMap } from '@ngx-pwa/local-storage';
this.storage.set('key', value).subscribe();
this.storage.get('key').subscribe();
```

**Files to search:**
- `*.component.ts`
- `*.service.ts`
- `*storage.service.ts` - Custom storage services
- Search for: `localStorage`, `sessionStorage`, `StorageMap`

## 6. Local Storage Content Analysis

**Check what data is stored in local/session storage:**

**Critical - Data that should NEVER be in local storage:**
```typescript
// Critical violations
localStorage.setItem('password', password);  // Never store passwords!
localStorage.setItem('ssn', user.ssn);  // Never store SSN!
localStorage.setItem('creditCard', cardNumber);  // Never!
localStorage.setItem('privateKey', privateKey);  // Never client-side!
```

**High - Home-grown credentials in localStorage:**
```typescript
localStorage.setItem('token', authToken);  // Home-grown JWT/bearer storage - XSS-readable, cannot be invalidated
localStorage.setItem('sessionId', sessionId);  // Use HttpOnly cookies instead
localStorage.setItem('apiKey', apiKey);  // Should be server-side only
```

**Token caches of the standard OIDC libraries are rated by cache location, not as home-grown storage:**
- MSAL (`@azure/msal-angular`, `cacheLocation`) or `oidc-client-ts` / `angular-auth-oidc-client` using `sessionStorage` → Low (library default, tab-scoped; note it, recommend keeping the default)
- The same libraries configured for `localStorage` → Medium (persists across tabs and restarts; recommend `sessionStorage`)
- Any home-grown `localStorage.setItem('token', ...)` of a JWT or bearer token → High

**Medium - Sensitive data requiring encryption:**
```typescript
// Should be encrypted if storage is necessary
localStorage.setItem('email', user.email);  // PII - encrypt or avoid
localStorage.setItem('phoneNumber', user.phone);  // PII - encrypt or avoid
localStorage.setItem('address', user.address);  // PII - encrypt or avoid
localStorage.setItem('personalData', JSON.stringify(user));  // Encrypt!
```

**Not a finding - Non-sensitive data (acceptable):**
```typescript
// Generally safe to store unencrypted
localStorage.setItem('theme', 'dark');  // User preference
localStorage.setItem('language', 'en');  // Language preference
localStorage.setItem('cartItems', JSON.stringify(cart));  // Shopping cart
localStorage.setItem('lastVisit', new Date().toISOString());  // Timestamp
localStorage.setItem('settings', JSON.stringify(settings));  // UI settings
```

## 7. Encryption Requirements for Local Storage

**If sensitive data must be stored in local storage, verify encryption:**

**Check for encryption usage:**
```typescript
// RED FLAG - crypto-js is discontinued ("no longer maintained" per its README) and
// CVE-2023-46233 made its PBKDF2 default to SHA-1 with 1 iteration before 4.2.0.
// Passphrase-based CryptoJS.AES.encrypt(data, 'passphrase') derives key and IV with MD5.
import * as CryptoJS from 'crypto-js';          // Medium: unmaintained dependency
CryptoJS.AES.encrypt(data, passphrase)           // High: weak key derivation

// ACCEPTABLE - Web Crypto API (built into every supported browser)
const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt', 'decrypt']);
const iv = crypto.getRandomValues(new Uint8Array(12));
const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
```

**Encryption considerations:**
```typescript
// BAD - Storing encryption key in code
const ENCRYPTION_KEY = 'hardcoded-key-12345';  // Never hardcode!

// BAD - Static salt and low iteration count
CryptoJS.PBKDF2(password, 'salt', { iterations: 1000 })

// BETTER - Web Crypto PBKDF2 with a random salt and >= 600,000 iterations (SHA-256)
const salt = crypto.getRandomValues(new Uint8Array(16));
const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
const derived = await crypto.subtle.deriveKey(
  { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
  baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);

// NOTE: Client-side encryption provides limited security
// If data is truly sensitive, store server-side instead
```

**Important limitations of client-side encryption:**
- Encryption key must be available client-side (exposure risk)
- Vulnerable to sophisticated XSS attacks
- Does not protect against malicious browser extensions
- User can inspect/modify encrypted data
- **Best practice: Don't store sensitive data client-side at all**

## 8. What to Report

### Unsafe Cookie Configuration:

**Report cookies missing security flags.** Severity depends on the cookie's purpose:

| Cookie | Missing `Secure` or `HttpOnly` | `SameSite` not explicit |
|--------|-------------------------------|-------------------------|
| Authentication, session or antiforgery cookie | High | Low |
| OIDC correlation / nonce cookie (`SameSite=None; Secure` required) | High if `Secure` is missing | not a finding (`None` is by design) |
| `XSRF-TOKEN` (must be JavaScript-readable) | High if `Secure` is missing; `HttpOnly` absence is by design | Low |
| Preference or UI cookie | Low | Low |

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

**Example report:**
```
Finding: Cookie Missing HttpOnly Flag
- Location: Controllers/AuthController.cs, line 45
- Cookie Name: "UserPreferences"
- Missing Flag: HttpOnly = true
- Purpose: Storing user UI preferences
- Risk: Low - Cookie accessible to JavaScript (XSS risk)
- Recommendation: Add HttpOnly = true to CookieOptions
```

```
Finding: Authentication Cookie Missing Secure Flag
- Location: Program.cs, line 61 (AddCookie options)
- Cookie Name: ".AspNetCore.Cookies"
- Missing Flag: SecurePolicy = CookieSecurePolicy.Always
- Purpose: Authentication session
- Risk: High - Session cookie can be sent over plain HTTP and captured in transit
- Recommendation: Set options.Cookie.SecurePolicy = CookieSecurePolicy.Always (and configure UseForwardedHeaders behind Front Door / Application Gateway)
```

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
  - **Low**: OIDC library token cache in `sessionStorage` (library default)
- **Encryption status**: Encrypted or plaintext
- **Usage**: How the data is used in the application
- **Risk level**: Impact if data is compromised
- **Recommendation**: 
  - **REMOVE**: Don't store this data client-side
  - **ENCRYPT**: Encrypt before storing (if unavoidable)
  - **SERVER-SIDE**: Move to server-side storage
  - **HTTPONLY COOKIE**: Use HttpOnly cookie instead of localStorage

**Example report:**
```
Finding: Unencrypted Email Address in Local Storage
- Location: services/user.service.ts, line 67
- Storage Type: localStorage
- Data Type: Email address (PII)
- Sensitivity: Medium
- Encryption: None (plaintext)
- Usage: Displayed in user profile header
- Risk: Medium - Email exposed to XSS attacks, browser extensions
- Recommendation: 
  1. PRIMARY: Fetch email from server when needed (don't store)
  2. ALTERNATIVE: Encrypt with the Web Crypto API (AES-GCM) before storing; never crypto-js
  3. BETTER: Use server-side session with HttpOnly cookie
```

```
Finding: Authentication Token in Local Storage
- Location: services/auth.service.ts, line 34
- Storage Type: localStorage
- Data Type: JWT authentication token (home-grown storage, not an OIDC library cache)
- Sensitivity: High
- Encryption: None (plaintext JWT)
- Usage: Sent with API requests for authentication
- Risk: High - Token accessible to XSS, cannot be invalidated client-side
- Recommendation: 
  1. REQUIRED: Move to HttpOnly cookie set by server
  2. Update API to accept cookie-based authentication
  3. Remove localStorage.setItem('token', ...) completely
```

## 9. SameSite Attribute Details

**Understand SameSite modes:**

```csharp
// Strict - Most secure, may break some legitimate scenarios
SameSite = SameSiteMode.Strict
// Cookie sent only for same-site requests
// Use for: Session cookies, authentication cookies
// Limitation: May break OAuth flows, payment gateways

// Lax - Good balance of security and usability
SameSite = SameSiteMode.Lax
// Cookie sent for same-site + top-level GET navigation
// Use for: Most application cookies
// Good default choice

// None - Least secure, requires Secure flag
SameSite = SameSiteMode.None, Secure = true
// Cookie sent for all requests (including cross-site)
// Use for: Third-party contexts (iframes, CORS APIs)
// Must be combined with Secure = true
```

**Recommendations:**
- **Authentication/Session cookies**: Use `Lax` (the ASP.NET Core default); `Strict` breaks OpenID Connect sign-in with Entra ID
- **Antiforgery cookie**: `Strict` (framework default)
- **OIDC correlation and nonce cookies**: `None` with `Secure = true`; never flag these
- **Third-party contexts (iframes)**: Use `None` with `Secure = true` and add the CHIPS `Partitioned` attribute via `options.Extensions.Add("Partitioned")`
- **Default**: `Lax` is the right default for most cookies

## 10. Best Practices Verification

**Verify that the application follows these practices:**

✅ **Cookie security:**
- All cookies have `HttpOnly = true` except cookies that are JavaScript-readable by design (`XSRF-TOKEN`, client-side preference cookies)
- All cookies have `Secure = true` (require HTTPS); `UseForwardedHeaders` is configured behind Front Door or Application Gateway so `CookieSecurePolicy` sees HTTPS
- All cookies have appropriate `SameSite` setting
- Authentication cookies use `SameSite = Lax`; OIDC correlation/nonce cookies use `None; Secure`
- Cookie names don't reveal sensitive information
- Cookies have appropriate expiration times

✅ **Local storage security:**
- No authentication tokens in localStorage
- No passwords or secrets in localStorage
- No unencrypted sensitive data (email, SSN, etc.)
- Sensitive data is encrypted if storage is unavoidable
- Regular cleanup of stored data
- Minimal data stored client-side

✅ **Alternative approaches:**
- Use HttpOnly cookies for authentication instead of localStorage
- Fetch sensitive data from server when needed
- Use server-side sessions for sensitive state
- Use secure token storage mechanisms
- Implement proper session management

✅ **Angular specific:**
- Authentication service uses HttpOnly cookies (set by backend)
- No client-side token storage in localStorage
- Encryption utilities if client-side storage is required
- Clear documentation of what's stored and why

## 11. Testing and Verification

**Verification steps:**

1. **`Set-Cookie` header diff from the live URL** (when `PRODUCTION_URL` is available; this is the ground truth with the `edge` modifier):
   ```bash
   curl -sSI -L "$PRODUCTION_URL" | grep -i '^set-cookie'
   curl -sSI -L "$PRODUCTION_URL/api/health" | grep -i '^set-cookie'
   ```
   (PowerShell 7: `(Invoke-WebRequest -Uri $env:PRODUCTION_URL -Method Head -SkipHttpErrorCheck).Headers['Set-Cookie']`.) For every `Set-Cookie` line, diff the attributes present (`Secure`, `HttpOnly`, `SameSite`, `Path`, `Max-Age`/`Expires`, `Partitioned`) against the required settings in the section 1 table; report each gap with the severity from section 8. A cookie seen without `Secure` while the code sets `CookieSecurePolicy.Always` means `UseForwardedHeaders` is missing behind the edge.

2. **DevTools Application tab checklist** (ask the user to open the app, sign in, and read the panel; nothing is executed in the page):
   - Cookies → per cookie, the `Secure`, `HttpOnly`, `SameSite` and `Partitioned` columns match the section 1 table
   - Local Storage → no key holding a JWT (`eyJ...`), bearer token, password, email or other PII; MSAL / oidc-client cache keys appear here only if `cacheLocation` was changed to `localStorage` (Medium)
   - Session Storage → OIDC library cache keys are expected here (Low, note only); no home-grown token keys
   - Note every key name and the first characters of its value in the finding; never copy a full token into the report

3. **Network tab review** (or the `curl` output above):
   - Cookies are sent only over HTTPS requests
   - Tokens travel in the `Authorization` header or a cookie, never in the query string (query-string tokens are Owned by check 7 (sensitive_query_strings.md); reference that finding instead of reporting it here)
