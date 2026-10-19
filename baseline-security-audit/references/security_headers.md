# Security Headers Configuration Analysis

Analyze response security headers and removal of version-disclosing headers to identify missing or misconfigured values that protect against common web vulnerabilities.

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A02 Security Misconfiguration · **ASVS 5.0:** V3 Web Frontend Security, V13 Configuration

> **Hosting model:** this check depends on `HOSTING_MODEL` from SKILL.md Step 0b. `web.config` sections apply only when it is `iis`; for `linux` use the middleware or platform equivalents named in this file and do not report missing `web.config` entries; with the `edge` modifier the live `PRODUCTION_URL` response is the ground truth and `UseForwardedHeaders` must be configured.

## Core Security Principle
**Security headers provide defense-in-depth protection against XSS, clickjacking, MIME-sniffing, and other attacks. Proper configuration of these headers is essential for web application security. Headers that disclose the platform (`Server`, `X-Powered-By`) must be removed from all responses.**

## 1. Inspection Priority

**Always prefer live URL inspection over static code/config analysis.**

| Situation | Approach |
|-----------|----------|
| `PRODUCTION_URL` is available | Fetch actual response headers from the live URL — this is the ground truth. Use a shell command that returns raw headers: `curl -sSI -L "$PRODUCTION_URL"` (Bash) or `(Invoke-WebRequest -Uri $env:PRODUCTION_URL -Method Head -SkipHttpErrorCheck).Headers` (PowerShell 7). Do not use a page-fetching tool that converts the response to text; it drops the headers. Base all findings on what the server actually returns. |
| `PRODUCTION_URL` is not available | Fall back to inspecting `web.config`, middleware (`Program.cs` / `Startup.cs`), and any other config files as described in the sections below. Clearly note in each finding that it is based on static analysis only. |

> When using the live URL, request both the front-end root (`/`) and a known API endpoint (e.g. `/api/health` or `/swagger`) so headers for both the Angular front-end and the API backend can be assessed independently.

## 2. Front-End Application Headers (web.config)

**Files to examine:**
- `web.config` / `Web.config` — may exist in multiple locations; identify each file's owner before evaluating it
- `web.release.config` — XDT transform applied on top of `web.config` for non-development environments; always check this alongside `web.config` and apply its transforms mentally to determine the effective header values in production
- Look in the Angular project's published output folder
- `Deployment/*.proj` — deployment profiles may override the CSP header per environment via `<ParameterValue>` elements; search for `<ParameterValue Include="Content Security Policy">` and evaluate the `<Value>` against the CSP rules below

> On `linux` hosting the front-end headers are set by whatever serves the Angular bundle instead of `web.config`: nginx `add_header`, Azure Static Web Apps `staticwebapp.config.json` (`globalHeaders`), or the ASP.NET Core host's header middleware (section 10) when the SPA is served by the API.

> ⚠️ **Multi-app projects** (e.g. a project with both a frontoffice and a backoffice) will have multiple `web.config` files. Before evaluating any `web.config`, determine whether it belongs to a **frontend** (Angular) app or a **backend** (API) app by inspecting its parent folder and sibling files (e.g. presence of `index.html`, `*.js` bundles → frontend; presence of `*.dll`, `appsettings.json` → backend). Apply the front-end header rules to frontend configs and the API header rules to backend configs. Report findings per app, not as a single combined result.

**Complete front-end web.config (the API block is in section 10):**
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
        <add name="Permissions-Policy" value="camera=(), microphone=(), geolocation=(), payment=()" />
        <add name="Cross-Origin-Opener-Policy" value="same-origin" />
        <add name="Cross-Origin-Resource-Policy" value="same-origin" />
        <add name="X-Permitted-Cross-Domain-Policies" value="none" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
```

## 3. Content Security Policy (CSP)

**Most important security header — a missing CSP is rated High; a CSP with unsafe values is rated Medium**

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

**1. default-src** (MUST be present; `'none'` or `'self'`):
- `default-src 'none'` denies everything by default and is the strictest option
- `default-src 'self'` is the OWASP Secure Headers Project baseline and is **compliant**; do not report it as weak
- Directive **order is irrelevant** in CSP; never flag a policy because `default-src` is not the first token
- Flag: `default-src` missing, `default-src *`, or scheme-wide sources (`https:`, `data:`) in `default-src`

**2. base-uri 'self'** (MUST include):
- Prevents base tag injection attacks
- Only allows base URI from same origin

**3. script-src** (no unsafe values; any of the values below is a Medium finding):
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
style-src 'unsafe-inline';  <!-- CSS injection, data exfiltration risk; Low on an Angular app (see below) -->
```

**Angular CSP reality:** a `'nonce-...'` value in a static `web.config` is a fixed string, which equals no nonce (Medium). The supported options are a server-injected nonce via `ngCspNonce` / `CSP_NONCE` (SSR or a rewrite step), build-time `security.autoCsp` in `angular.json` (hash-based, scripts only, not with SSR), or accepting `style-src 'unsafe-inline'` because Angular injects component styles at runtime. Rate `style-src 'unsafe-inline'` Low with that remediation; `script-src 'unsafe-inline'` stays Medium.

**5. frame-ancestors** (MUST specify - not covered by default-src):
```xml
<!-- GOOD - Disallow all framing -->
frame-ancestors 'none';

<!-- GOOD - Allow same-origin framing only -->
frame-ancestors 'self';

<!-- BAD - Missing this directive -->
```

**6. object-src 'none' and upgrade-insecure-requests** (OWASP baseline; each absent = Medium): `object-src 'none'` is only implied when `default-src` is `'none'`, so add it explicitly with `default-src 'self'`; `upgrade-insecure-requests` rewrites mixed-content requests to HTTPS.

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

<!-- Missing default-src entirely -->
<add name="Content-Security-Policy" value="script-src 'self'; style-src 'self'" />
```

## 4. X-Frame-Options

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

## 5. HTTP Strict Transport Security (HSTS)

**Purpose**: Enforces HTTPS connections

**GOOD configuration:**
```xml
<add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains; preload" />
```

**Parameters:**
- `max-age=31536000` - 1 year (minimum recommended)
- `includeSubDomains` - Apply to all subdomains
- `preload` - Eligible for browser preload list (optional)

**HSTS may also be configured via the `Enigmatry.Entry.AspNetCore` package** using the `AddEntryHttps` / `UseEntryHttps` extension methods in `Program.cs` / `Startup.cs`. Search for these calls before concluding HSTS is missing:
```csharp
services.AddEntryHttps();
app.UseEntryHttps();
```
If the project uses the `Enigmatry.Entry` HTTPS helpers, verify the effective HSTS value on the live URL or in the package source; do not assume it meets the one-year `max-age` / `includeSubDomains` minimum. On `linux` hosting (no `web.config`) the equivalent is `builder.Services.AddHsts(o => { o.MaxAge = TimeSpan.FromDays(365); o.IncludeSubDomains = true; })` with `app.UseHsts()`.

**RED FLAGS:**
```xml
<!-- Missing HSTS -->
<!-- Too short max-age -->
<add name="Strict-Transport-Security" value="max-age=3600" />
<!-- Missing includeSubDomains -->
<add name="Strict-Transport-Security" value="max-age=31536000" />
```

## 6. X-Content-Type-Options

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

## 7. Referrer-Policy

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

A missing `Referrer-Policy` is Low: every current browser defaults to `strict-origin-when-cross-origin`. An explicit insecure value (`unsafe-url`, `no-referrer-when-downgrade`) is Medium.

## 8. Cross-Origin Resource Sharing (CORS)

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

## 9. Subresource Integrity (SRI)

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

## 10. API Security Headers (Backend)

**For externally exposed APIs, configure these headers** (this is the single canonical API header block; the `web.config` form applies to `iis`, the middleware form to `linux`):

**web.config configuration:**
```xml
<httpProtocol>
  <customHeaders>
    <add name="Cache-Control" value="no-store" />
    <add name="Content-Security-Policy" value="default-src 'none'; frame-ancestors 'none'" />
    <add name="X-Frame-Options" value="DENY" />
    <add name="X-Content-Type-Options" value="nosniff" />
    <add name="Referrer-Policy" value="no-referrer" />
    <add name="Permissions-Policy" value="camera=(), microphone=(), geolocation=(), payment=()" />
    <add name="Cross-Origin-Opener-Policy" value="same-origin" />
    <add name="Cross-Origin-Resource-Policy" value="same-origin" />
    <add name="X-Permitted-Cross-Domain-Policies" value="none" />
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
    context.Response.Headers.Add("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
    context.Response.Headers.Add("Cross-Origin-Opener-Policy", "same-origin");
    context.Response.Headers.Add("Cross-Origin-Resource-Policy", "same-origin");
    context.Response.Headers.Add("X-Permitted-Cross-Domain-Policies", "none");
    
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
- Disables browser features APIs don't need; minimum feature list `camera=(), microphone=(), geolocation=(), payment=()` (a shorter list = Medium)

**4. Remaining OWASP baseline headers (front-end and API; each missing = Medium):**
- `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, `X-Permitted-Cross-Domain-Policies: none`
- `Cross-Origin-Embedder-Policy: require-corp` only where the app tolerates it (it blocks cross-origin resources that lack CORP/CORS); otherwise not a finding
- `Clear-Site-Data: "cache","cookies","storage"` on the logout response (check the sign-out action, not the global header block)

**RED FLAGS for APIs:**
```xml
<!-- Missing Cache-Control on API responses -->
<!-- Permissive CSP on APIs -->
<add name="Content-Security-Policy" value="default-src *" />
<!-- Missing headers entirely -->
```

## 11. Version-Disclosing Headers (Server, X-Powered-By, X-AspNet-Version)

**Information disclosure headers like `Server` and `X-Powered-By` reveal platform details and versions that attackers can use to identify known vulnerabilities. They must be removed from all HTTP responses (API and front-end). Every finding in this section is rated Low (information disclosure with no exploit path on its own).**

**Headers to remove:**
- **Server** - Reveals web server type and version (e.g., "Microsoft-IIS/10.0")
- **X-Powered-By** - Reveals framework and version (e.g., "ASP.NET", "ASP.NET Core 6.0")
- **X-AspNet-Version** - Reveals specific ASP.NET version (e.g., "4.0.30319") — legacy (.NET Framework), not expected on this stack
- **X-AspNetMvc-Version** - Reveals ASP.NET MVC version — legacy (.NET Framework), not expected on this stack

> `X-AspNet-Version`, `X-AspNetMvc-Version` and `<httpRuntime enableVersionHeader="false" />` exist only on .NET Framework. ASP.NET Core never emits these headers, so their absence (and the absence of `enableVersionHeader`) is **not** a finding on an ASP.NET Core project; only report them if the live response actually contains them.

**Files to examine:** the API and front-end `web.config` / `Web.config` files and their `web.release.config` transforms listed in section 2 (the removal configuration must be present in both apps), plus `Program.cs` / `Startup.cs` and `appsettings*.json` for the Kestrel setting.

On `linux` hosting `web.config` is ignored: the equivalent is `AddServerHeader = false` on Kestrel (below) and, with the `edge` modifier, a Front Door rules-engine or Application Gateway rewrite rule that strips `Server` / `X-Powered-By` at the edge.

**GOOD configuration - web.config (both API and front-end):**
```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <!-- Remove Server header -->
    <security>
      <requestFiltering removeServerHeader="true" />
    </security>

    <!-- Remove X-Powered-By header -->
    <httpProtocol>
      <customHeaders>
        <remove name="X-Powered-By" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
```

**For legacy .NET Framework applications only (not expected on this stack), also add to web.config:**
```xml
<configuration>
  <system.web>
    <!-- Remove X-AspNet-Version header -->
    <httpRuntime enableVersionHeader="false" />
  </system.web>

  <system.webServer>
    <security>
      <requestFiltering removeServerHeader="true" />
    </security>

    <httpProtocol>
      <customHeaders>
        <remove name="X-Powered-By" />
        <remove name="X-AspNet-Version" />
        <remove name="X-AspNetMvc-Version" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
```

**ASP.NET Core / Kestrel (Program.cs/Startup.cs):**
```csharp
var builder = WebApplication.CreateBuilder(args);

// Configure Kestrel to remove Server header
builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.AddServerHeader = false;
});

var app = builder.Build();
app.Run();
```

> **Do not accept middleware that calls `Response.Headers.Remove("Server")` as a remediation.** Kestrel adds its `Server` header when the response starts, after middleware has run, so only `AddServerHeader = false` removes it. Under IIS (in-process or out-of-process) the `Server` and `X-Powered-By` headers are added by IIS after the ASP.NET Core pipeline completes, so application code cannot remove them; only `removeServerHeader="true"` on `<requestFiltering>` and `<remove name="X-Powered-By" />` under `<httpProtocol><customHeaders>` in `web.config` work. Report such middleware as a non-working remediation.

**Alternative - appsettings.json configuration:**
```json
{
  "Kestrel": {
    "AddServerHeader": false
  }
}
```

## 12. What to Report

**Severity per header** (impact-based; the same header carries the same severity on the front-end and on the API):

| Finding | Severity |
|---------|----------|
| `Content-Security-Policy` missing | High |
| `Strict-Transport-Security` missing, `max-age` below one year, or `includeSubDomains` absent | High |
| CSP present but weak (`unsafe-inline` / `unsafe-eval` / `data:` / `blob:` in `script-src`, `default-src *`, missing `base-uri`, missing `frame-ancestors`, `object-src 'none'` or `upgrade-insecure-requests` absent, static `'nonce-...'` string in `web.config`) | Medium |
| `X-Content-Type-Options`, `Permissions-Policy` (or without the minimum feature list), `Cross-Origin-Opener-Policy` / `Cross-Origin-Resource-Policy`, `X-Permitted-Cross-Domain-Policies` missing; `Clear-Site-Data` absent on logout; `Cross-Origin-Embedder-Policy` absent where the app tolerates it | Medium |
| `style-src 'unsafe-inline'` on an Angular app (runtime component styles; see section 3) | Low |
| `Referrer-Policy` set to `unsafe-url` or `no-referrer-when-downgrade` | Medium |
| `Cache-Control: no-store` missing on API responses; CDN resource without SRI; CORS `*` combined with credentials | Medium |
| `X-Frame-Options` missing while CSP `frame-ancestors` is present, or misaligned with it | Low |
| HSTS `preload` absent | Low |
| `Referrer-Policy` absent (browser default `strict-origin-when-cross-origin` applies) | Low |
| `Server`, `X-Powered-By`, `X-AspNet-Version` or `X-AspNetMvc-Version` present in a live response (version information disclosure) | Low |
| `Response.Headers.Remove("Server")` middleware used as the remediation for version-disclosing headers (non-working; see section 11) | Low |

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

**Example report:**

```
Finding: Missing Content Security Policy
- Header: Content-Security-Policy
- Location: web.config
- Current Value: Not configured
- Issue: No CSP header present
- Risk: High - Application vulnerable to XSS attacks, no CSP protection
- Recommendation: Add CSP header starting with default-src 'none'; base-uri 'self'; frame-ancestors 'none'
```

## 13. Search Patterns

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
Cross-Origin-Opener-Policy
Cross-Origin-Resource-Policy
X-Permitted-Cross-Domain-Policies
Clear-Site-Data
Access-Control-Allow-Origin

<!-- Check for version-header removal -->
removeServerHeader
<remove name="X-Powered-By" />
enableVersionHeader

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
AddServerHeader
Response.Headers.Remove
```

**Search Angular index.html:**
```html
<!-- Look for CDN resources -->
<script src="https://cdn
<link.*href="https://cdn

<!-- Check for integrity attributes -->
integrity=
crossorigin=

<!-- CSP nonce / hash support (index.html, main.ts, angular.json) -->
ngCspNonce
CSP_NONCE
autoCsp
```

## 14. Testing Security Headers

**Manual verification:**

1. **Browser DevTools:**
   - Open Network tab
   - Refresh page
   - Click on document request (and an API call)
   - Check Response Headers section; verify `Server` and `X-Powered-By` are absent

2. **Online tools:**
   - MDN HTTP Observatory: https://developer.mozilla.org/en-US/observatory — successor of Mozilla Observatory (`observatory.mozilla.org` moved to MDN in July 2024; do not cite the old host). New scoring model: maximum 145 points, bonus points only count from a base score of 90 or more. Source: https://developer.mozilla.org/en-US/blog/mdn-observatory
   - https://securityheaders.com — second tool, for a cross-check of the header grade
   - Enter your URL for automated analysis

3. **Command line (curl):**
   ```bash
   curl -I https://your-app.com

   # Version-disclosing headers: should return nothing if they are removed correctly
   curl -I https://your-app.com | grep -i "server\|powered"
   curl -I https://api.your-app.com/api/endpoint | grep -i "server\|powered"
   ```
   PowerShell: `Invoke-WebRequest -Uri "https://your-app.com" -Method Head | Select-Object -ExpandProperty Headers` and look for `Server` or `X-Powered-By` in the output.

4. **Verify CSP:**
   - Check browser console for CSP violations
   - Test that inline scripts are blocked
   - Verify frame-ancestors prevents framing
