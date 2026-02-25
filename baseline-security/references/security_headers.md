# Security Headers Configuration Analysis

Analyze the configuration to identify missing or misconfigured security headers that protect against common web vulnerabilities:

## Core Security Principle
**Security headers provide defense-in-depth protection against XSS, clickjacking, MIME-sniffing, and other attacks. Proper configuration of these headers is essential for web application security.**

## 1. Front-End Application Headers (web.config)

**Files to examine:**
- `web.config` - IIS configuration for Angular application
- `Web.config` - Check both capitalizations
- Look in the Angular project's published output folder

**Configuration location in web.config:**
```xml
<configuration>
  <system.webServer>
    <httpProtocol>
      <customHeaders>
        <!-- Security headers go here -->
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
```

## 2. Content Security Policy (CSP)

**CRITICAL - Most important security header**

**GOOD configuration:**
```xml
<add name="Content-Security-Policy" value="
  default-src 'none';
  base-uri 'self';
  script-src 'self' 'nonce-{RANDOM}';
  style-src 'self' 'nonce-{RANDOM}';
  img-src 'self' data: https:;
  font-src 'self';
  connect-src 'self';
  frame-ancestors 'none';
  form-action 'self';
" />
```

**Required directives:**

**1. default-src 'none'** (MUST start with this):
- Denies everything by default (whitelist approach)
- Other directives explicitly allow what's needed

**2. base-uri 'self'** (MUST include):
- Prevents base tag injection attacks
- Only allows base URI from same origin

**3. script-src** (CRITICAL - no unsafe values):
```xml
<!-- GOOD -->
script-src 'self' 'nonce-{random}';
script-src 'self' 'sha256-{hash}';

<!-- BAD - NEVER use these -->
script-src 'unsafe-inline';   <!-- Allows any inline script - XSS risk -->
script-src 'unsafe-eval';     <!-- Allows eval() - XSS risk -->
script-src data:;             <!-- Allows data: URIs - XSS risk -->
script-src blob:;             <!-- Allows blob: URIs - XSS risk -->
```

**Inline scripts handling:**
- **Preferred**: Use nonces (cryptographically random, unique per request)
- **Alternative**: Use SHA-256/SHA-384/SHA-512 hashes
- **Never**: Use 'unsafe-inline'

**4. style-src** (IMPORTANT - avoid unsafe-inline):
```xml
<!-- GOOD -->
style-src 'self' 'nonce-{random}';
style-src 'self' 'sha256-{hash}';

<!-- BAD -->
style-src 'unsafe-inline';  <!-- CSS injection, data exfiltration risk -->
```

**5. frame-ancestors** (MUST specify - not covered by default-src):
```xml
<!-- GOOD - Disallow all framing -->
frame-ancestors 'none';

<!-- GOOD - Allow same-origin framing only -->
frame-ancestors 'self';

<!-- BAD - Missing this directive -->
```

**RED FLAGS:**
```xml
<!-- Missing CSP entirely -->
<!-- No Content-Security-Policy header -->

<!-- Weak CSP -->
<add name="Content-Security-Policy" value="default-src *" />
<add name="Content-Security-Policy" value="script-src 'unsafe-inline'" />
<add name="Content-Security-Policy" value="default-src 'self'; script-src 'unsafe-eval'" />

<!-- Missing frame-ancestors -->
<add name="Content-Security-Policy" value="default-src 'self'" />
<!-- Missing base-uri -->

<!-- Not starting with default-src 'none' -->
<add name="Content-Security-Policy" value="script-src 'self'; style-src 'self'" />
```

## 3. X-Frame-Options

**Purpose**: Prevents clickjacking attacks

**GOOD configuration:**
```xml
<!-- Deny all framing -->
<add name="X-Frame-Options" value="DENY" />

<!-- Allow same-origin framing only -->
<add name="X-Frame-Options" value="SAMEORIGIN" />
```

**MUST align with CSP frame-ancestors:**
- `frame-ancestors 'none'` ↔ `X-Frame-Options: DENY`
- `frame-ancestors 'self'` ↔ `X-Frame-Options: SAMEORIGIN`

**RED FLAGS:**
```xml
<!-- Missing X-Frame-Options -->
<!-- Misaligned with CSP frame-ancestors -->
<!-- Using deprecated ALLOW-FROM (not supported in modern browsers) -->
<add name="X-Frame-Options" value="ALLOW-FROM https://example.com" />
```

## 4. HTTP Strict Transport Security (HSTS)

**Purpose**: Enforces HTTPS connections

**GOOD configuration:**
```xml
<add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains; preload" />
```

**Parameters:**
- `max-age=31536000` - 1 year (minimum recommended)
- `includeSubDomains` - Apply to all subdomains
- `preload` - Eligible for browser preload list (optional)

**RED FLAGS:**
```xml
<!-- Missing HSTS -->
<!-- Too short max-age -->
<add name="Strict-Transport-Security" value="max-age=3600" />
<!-- Missing includeSubDomains -->
<add name="Strict-Transport-Security" value="max-age=31536000" />
```

## 5. X-Content-Type-Options

**Purpose**: Prevents MIME-sniffing attacks

**GOOD configuration:**
```xml
<add name="X-Content-Type-Options" value="nosniff" />
```

**RED FLAGS:**
```xml
<!-- Missing X-Content-Type-Options -->
<!-- Wrong value -->
<add name="X-Content-Type-Options" value="sniff" />
```

## 6. Referrer-Policy

**Purpose**: Controls referrer information in requests

**GOOD configuration:**
```xml
<!-- Most secure - no referrer information -->
<add name="Referrer-Policy" value="no-referrer" />

<!-- Balanced - send to same origin only -->
<add name="Referrer-Policy" value="same-origin" />

<!-- Acceptable - origin only for cross-origin -->
<add name="Referrer-Policy" value="strict-origin-when-cross-origin" />
```

**RED FLAGS:**
```xml
<!-- Missing Referrer-Policy -->
<!-- Insecure policy -->
<add name="Referrer-Policy" value="unsafe-url" />
<add name="Referrer-Policy" value="no-referrer-when-downgrade" />
```

## 7. Cross-Origin Resource Sharing (CORS)

**Check CORS configuration in web.config or ASP.NET Core:**

**web.config:**
```xml
<httpProtocol>
  <customHeaders>
    <!-- REVIEW - should be specific, not * -->
    <add name="Access-Control-Allow-Origin" value="https://trusted-domain.com" />
  </customHeaders>
</httpProtocol>
```

**RED FLAGS:**
```xml
<!-- Too permissive -->
<add name="Access-Control-Allow-Origin" value="*" />
<!-- With credentials allowed (dangerous combination) -->
<add name="Access-Control-Allow-Credentials" value="true" />
```

**ASP.NET Core (preferred - check Startup.cs/Program.cs):**
```csharp
services.AddCors(options =>
{
    options.AddPolicy("MyPolicy", builder =>
    {
        builder.WithOrigins("https://trusted-domain.com")  // Specific origins
               .AllowAnyMethod()
               .AllowAnyHeader()
               .AllowCredentials();
    });
});
```

## 8. Subresource Integrity (SRI)

**Check Angular index.html for external resources:**

**GOOD - Using SRI for CDN resources:**
```html
<script src="https://cdn.example.com/library.js" 
        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/ux..." 
        crossorigin="anonymous"></script>

<link rel="stylesheet" 
      href="https://cdn.example.com/styles.css" 
      integrity="sha384-..." 
      crossorigin="anonymous">
```

**RED FLAGS:**
```html
<!-- Missing integrity for CDN resources -->
<script src="https://cdn.example.com/library.js"></script>
<link rel="stylesheet" href="https://cdn.example.com/styles.css">
```

**Files to check:**
- `src/index.html`
- Any templates loading external resources

## 9. API Security Headers (Backend)

**For externally exposed APIs, configure these headers:**

**web.config configuration:**
```xml
<httpProtocol>
  <customHeaders>
    <add name="Cache-Control" value="no-store" />
    <add name="Content-Security-Policy" value="default-src 'none'; frame-ancestors 'none'" />
    <add name="X-Frame-Options" value="DENY" />
    <add name="X-Content-Type-Options" value="nosniff" />
    <add name="Referrer-Policy" value="no-referrer" />
    <add name="Permissions-Policy" value="geolocation=(), microphone=(), camera=()" />
  </customHeaders>
</httpProtocol>
```

**ASP.NET Core Middleware (Program.cs/Startup.cs):**
```csharp
app.Use(async (context, next) =>
{
    context.Response.Headers.Add("Cache-Control", "no-store");
    context.Response.Headers.Add("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
    context.Response.Headers.Add("X-Frame-Options", "DENY");
    context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Add("Referrer-Policy", "no-referrer");
    context.Response.Headers.Add("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
    
    await next();
});
```

### API-Specific Headers:

**1. Cache-Control: no-store** (MUST for APIs)
- Prevents caching of sensitive API responses
- Protects against information disclosure

**2. Content-Security-Policy: default-src 'none'; frame-ancestors 'none'**
- Minimal CSP for APIs (no content rendering)

**3. Permissions-Policy** (formerly Feature-Policy)
- Disables browser features APIs don't need

**RED FLAGS for APIs:**
```xml
<!-- Missing Cache-Control on API responses -->
<!-- Permissive CSP on APIs -->
<add name="Content-Security-Policy" value="default-src *" />
<!-- Missing headers entirely -->
```

## 10. What to Report (Medium Priority)

**For each missing or misconfigured header:**

**Report format:**
```
Finding: Missing/Misconfigured Security Header
- Header: [Header name]
- Location: web.config or Startup.cs/Program.cs
- Current Value: [Current configuration or "Not configured"]
- Issue: [What's wrong]
- Risk: [Security risk]
- Recommendation: [Correct configuration]
```

**Example reports:**

```
Finding: Missing Content Security Policy
- Header: Content-Security-Policy
- Location: web.config
- Current Value: Not configured
- Issue: No CSP header present
- Risk: MEDIUM - Application vulnerable to XSS attacks, no CSP protection
- Recommendation: Add CSP header starting with default-src 'none'; base-uri 'self'; frame-ancestors 'none'
```

```
Finding: Unsafe CSP Configuration
- Header: Content-Security-Policy
- Location: web.config, line 15
- Current Value: default-src 'self'; script-src 'self' 'unsafe-inline'
- Issue: script-src allows 'unsafe-inline'
- Risk: MEDIUM - Inline scripts allowed, reduces XSS protection
- Recommendation: Remove 'unsafe-inline', use nonces or hashes for inline scripts
```

```
Finding: Missing HSTS Header
- Header: Strict-Transport-Security
- Location: web.config
- Current Value: Not configured
- Issue: No HSTS enforcement
- Risk: MEDIUM - Users could be downgraded to HTTP, MITM attacks possible
- Recommendation: Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

```
Finding: Misaligned X-Frame-Options and CSP
- Header: X-Frame-Options vs frame-ancestors
- Location: web.config
- Current Value: X-Frame-Options: SAMEORIGIN, frame-ancestors 'none'
- Issue: Conflicting frame protection directives
- Risk: LOW - Inconsistent framing policy across browsers
- Recommendation: Align both: either DENY/'none' or SAMEORIGIN/'self'
```

```
Finding: API Missing Cache-Control Header
- Header: Cache-Control
- Location: API responses (check middleware/web.config)
- Current Value: Not configured
- Issue: API responses may be cached
- Risk: MEDIUM - Sensitive data could be stored in browser/proxy caches
- Recommendation: Add Cache-Control: no-store for all API responses
```

```
Finding: CDN Resources Missing SRI
- Header: Subresource Integrity
- Location: src/index.html, line 12
- Current Value: <script src="https://cdn.../library.js"></script>
- Issue: No integrity attribute for external resource
- Risk: MEDIUM - CDN compromise could inject malicious code
- Recommendation: Add integrity="sha384-..." and crossorigin="anonymous"
```

## 11. Search Patterns

**Search web.config for security headers:**
```xml
<!-- Search for these header names -->
Content-Security-Policy
Strict-Transport-Security
X-Frame-Options
X-Content-Type-Options
Referrer-Policy
Cache-Control
Permissions-Policy
Access-Control-Allow-Origin

<!-- Check for unsafe CSP values -->
unsafe-inline
unsafe-eval
data:
blob:
```

**Search ASP.NET Core configuration:**
```csharp
// Program.cs / Startup.cs
app.Use
Response.Headers.Add
UseHsts
UseXContentTypeOptions
UseReferrerPolicy
UseCsp
AddCors
```

**Search Angular index.html:**
```html
<!-- Look for CDN resources -->
<script src="https://cdn
<link.*href="https://cdn

<!-- Check for integrity attributes -->
integrity=
crossorigin=
```

## 12. Complete Configuration Examples

**Front-end web.config (Angular application):**
```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <httpProtocol>
      <customHeaders>
        <add name="Content-Security-Policy" value="default-src 'none'; base-uri 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'" />
        <add name="X-Frame-Options" value="DENY" />
        <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains; preload" />
        <add name="X-Content-Type-Options" value="nosniff" />
        <add name="Referrer-Policy" value="no-referrer" />
        <add name="Permissions-Policy" value="geolocation=(), microphone=(), camera=()" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
```

**API web.config:**
```xml
<httpProtocol>
  <customHeaders>
    <add name="Cache-Control" value="no-store" />
    <add name="Content-Security-Policy" value="default-src 'none'; frame-ancestors 'none'" />
    <add name="X-Frame-Options" value="DENY" />
    <add name="X-Content-Type-Options" value="nosniff" />
    <add name="Referrer-Policy" value="no-referrer" />
    <add name="Permissions-Policy" value="geolocation=(), microphone=(), camera=()" />
  </customHeaders>
</httpProtocol>
```

**ASP.NET Core API (Program.cs):**
```csharp
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.Use(async (context, next) =>
{
    context.Response.Headers.Add("Cache-Control", "no-store");
    context.Response.Headers.Add("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
    context.Response.Headers.Add("X-Frame-Options", "DENY");
    context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Add("Referrer-Policy", "no-referrer");
    context.Response.Headers.Add("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
    await next();
});

app.Run();
```

## 13. Best Practices Verification

**Verify the application follows:**

✅ **Front-end (Angular):**
- CSP header present, starts with `default-src 'none'`
- CSP includes `base-uri 'self'` and `frame-ancestors 'none'`
- No `unsafe-inline`, `unsafe-eval`, `data:`, `blob:` in script-src
- No `unsafe-inline` in style-src
- X-Frame-Options aligns with CSP frame-ancestors
- HSTS with max-age ≥ 31536000
- X-Content-Type-Options: nosniff
- Referrer-Policy configured
- SRI for all CDN resources

✅ **API (Backend):**
- Cache-Control: no-store on responses
- Minimal CSP: default-src 'none'; frame-ancestors 'none'
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy: no-referrer
- Permissions-Policy configured

✅ **General:**
- Headers configured in web.config or middleware
- No conflicting header values
- CORS properly configured (not *)
- Regular security header audits

## 14. Testing Security Headers

**Manual verification:**

1. **Browser DevTools:**
   - Open Network tab
   - Refresh page
   - Click on document request
   - Check Response Headers section

2. **Online tools:**
   - https://securityheaders.com
   - https://observatory.mozilla.org
   - Enter your URL for automated analysis

3. **Command line (curl):**
   ```bash
   curl -I https://your-app.com
   ```

4. **Verify CSP:**
   - Check browser console for CSP violations
   - Test that inline scripts are blocked
   - Verify frame-ancestors prevents framing
