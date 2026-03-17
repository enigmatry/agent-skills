# Cookie and Local Storage Security Analysis

Analyze the codebase to identify insecure usage of cookies and local storage that could expose sensitive information:

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
        options.Cookie.SameSite = SameSiteMode.Strict;  // SHOULD be Strict or Lax
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
    options.Cookie.SameSite = SameSiteMode.Strict;  // SHOULD be Strict or Lax
    options.Cookie.Name = "YourApp.Session";
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.IsEssential = true;
});
```

**Application cookie defaults:**
```csharp
services.Configure<CookiePolicyOptions>(options =>
{
    options.HttpOnly = HttpOnlyPolicy.Always;  // MUST be Always
    options.Secure = CookieSecurePolicy.Always;  // MUST be Always
    options.MinimumSameSitePolicy = SameSiteMode.Strict;  // SHOULD be Strict or Lax
});
```

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
Response.Cookies.Append("UserId", user.Id.ToString());  // Potentially sensitive
Response.Cookies.Append("Email", user.Email);  // PII - should not be in cookie
Response.Cookies.Append("Password", password);  // CRITICAL - Never store passwords!
Response.Cookies.Append("Token", token);  // Ensure it's encrypted/signed
Response.Cookies.Append("SSN", ssn);  // CRITICAL - Never store SSN in cookies!
Response.Cookies.Append("CreditCard", cardNumber);  // CRITICAL - Never!

// Questionable - Depends on sensitivity
Response.Cookies.Append("Username", username);  // Consider necessity
Response.Cookies.Append("Role", userRole);  // Could be tampered with
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
- User IDs (consider signed tokens instead)
- Email addresses
- Session identifiers (should be random, not contain user info)
- Any personal data
- Authorization information

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
this.cookieService.set('password', password);  // CRITICAL
this.cookieService.set('ssn', ssn);  // CRITICAL
this.cookieService.set('email', email);  // Should avoid
this.cookieService.set('userId', userId);  // Consider alternatives

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

**CRITICAL - Data that should NEVER be in local storage:**
```typescript
// CRITICAL VIOLATIONS
localStorage.setItem('password', password);  // Never store passwords!
localStorage.setItem('ssn', user.ssn);  // Never store SSN!
localStorage.setItem('creditCard', cardNumber);  // Never!
localStorage.setItem('token', authToken);  // Vulnerable to XSS - use HttpOnly cookies
localStorage.setItem('sessionId', sessionId);  // Use HttpOnly cookies instead
localStorage.setItem('apiKey', apiKey);  // Should be server-side only
localStorage.setItem('privateKey', privateKey);  // Never client-side!
```

**MEDIUM PRIORITY - Sensitive data requiring encryption:**
```typescript
// Should be encrypted if storage is necessary
localStorage.setItem('email', user.email);  // PII - encrypt or avoid
localStorage.setItem('phoneNumber', user.phone);  // PII - encrypt or avoid
localStorage.setItem('address', user.address);  // PII - encrypt or avoid
localStorage.setItem('userId', user.id);  // Could be encrypted
localStorage.setItem('personalData', JSON.stringify(user));  // Encrypt!
```

**LOW PRIORITY - Non-sensitive data (acceptable):**
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
// Look for encryption libraries
import * as CryptoJS from 'crypto-js';
import { AES, enc } from 'crypto-js';

// Example encrypted storage
const encryptData = (data: string, key: string): string => {
  return CryptoJS.AES.encrypt(data, key).toString();
};

const decryptData = (ciphertext: string, key: string): string => {
  const bytes = CryptoJS.AES.decrypt(ciphertext, key);
  return bytes.toString(CryptoJS.enc.Utf8);
};

// Usage
const encrypted = encryptData(sensitiveData, encryptionKey);
localStorage.setItem('userData', encrypted);

const retrieved = localStorage.getItem('userData');
const decrypted = decryptData(retrieved, encryptionKey);
```

**Encryption considerations:**
```typescript
// BAD - Storing encryption key in code
const ENCRYPTION_KEY = 'hardcoded-key-12345';  // Never hardcode!

// BETTER - Derive key from user password or session
const deriveKey = (password: string): string => {
  return CryptoJS.PBKDF2(password, 'salt', {
    keySize: 256/32,
    iterations: 1000
  }).toString();
};

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

### Low Priority - Unsafe Cookie Configuration:

**Report cookies missing security flags:**

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
- Risk: LOW - Cookie accessible to JavaScript (XSS risk)
- Recommendation: Add HttpOnly = true to CookieOptions
```

### Medium Priority - Unencrypted Sensitive Data:

**Report sensitive data in cookies or local storage:**

For each finding, provide:
- **Location**: File path and line number
- **Storage type**: Cookie, localStorage, or sessionStorage
- **Data type**: What sensitive information is stored
- **Data sensitivity**:
  - **CRITICAL**: Passwords, SSN, credit cards, auth tokens
  - **HIGH**: Email, phone, address, user IDs
  - **MEDIUM**: Personal preferences with PII
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
- Sensitivity: HIGH
- Encryption: None (plaintext)
- Usage: Displayed in user profile header
- Risk: MEDIUM - Email exposed to XSS attacks, browser extensions
- Recommendation: 
  1. PRIMARY: Fetch email from server when needed (don't store)
  2. ALTERNATIVE: Encrypt with CryptoJS before storing
  3. BETTER: Use server-side session with HttpOnly cookie
```

```
Finding: Authentication Token in Local Storage
- Location: services/auth.service.ts, line 34
- Storage Type: localStorage
- Data Type: JWT authentication token
- Sensitivity: CRITICAL
- Encryption: None (plaintext JWT)
- Usage: Sent with API requests for authentication
- Risk: HIGH - Token accessible to XSS, cannot be invalidated client-side
- Recommendation: 
  1. REQUIRED: Move to HttpOnly cookie set by server
  2. Update API to accept cookie-based authentication
  3. Remove localStorage.setItem('token', ...) completely
```

## 10. SameSite Attribute Details

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
- **Authentication/Session cookies**: Use `Strict` or `Lax`
- **CSRF protection**: `Strict` or `Lax` provides protection
- **Third-party contexts**: Use `None` with `Secure = true` (only if necessary)
- **Default**: `Lax` is a good default for most cookies

## 11. Best Practices Verification

**Verify that the application follows these practices:**

✅ **Cookie security:**
- All cookies have `HttpOnly = true` (except client-side preference cookies)
- All cookies have `Secure = true` (require HTTPS)
- All cookies have appropriate `SameSite` setting
- Authentication cookies use `SameSite = Strict` or `Lax`
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

## 13. Testing and Verification

**Manual verification steps:**

1. **Check browser DevTools:**
   - Open Application/Storage tab
   - Inspect Cookies - verify Secure, HttpOnly, SameSite flags
   - Inspect Local Storage - check for sensitive data
   - Inspect Session Storage - check for sensitive data

2. **Test cookie flags:**
   - Verify cookies are only sent over HTTPS (Secure flag)
   - Try to access HttpOnly cookies via JavaScript (should fail)
   - Test CSRF protection with SameSite settings

3. **Test XSS scenarios:**
   - Attempt to steal localStorage data via JavaScript
   - Verify sensitive data isn't accessible to malicious scripts
   - Test that HttpOnly cookies aren't accessible

4. **Review network traffic:**
   - Ensure cookies are sent with requests
   - Verify sensitive data isn't exposed in URLs
   - Check that tokens are in headers/cookies, not query strings
