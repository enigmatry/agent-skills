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
        <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
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

**3. script-src**: `'self'` with per-request nonces or hashes; `'unsafe-inline'`, `'unsafe-eval'`, `data:` or `blob:` in `script-src` = Medium.

**4. style-src**: `'self'` with nonces or hashes; `'unsafe-inline'` is a CSS-injection risk, rated Low on an Angular app (see below).

**Angular CSP reality:** a `'nonce-...'` value in a static `web.config` is a fixed string, which equals no nonce (Medium). The supported options are a server-injected nonce via `ngCspNonce` / `CSP_NONCE` (SSR or a rewrite step), build-time `security.autoCsp` in `angular.json` (hash-based, scripts only, not with SSR), or accepting `style-src 'unsafe-inline'` because Angular injects component styles at runtime. Rate `style-src 'unsafe-inline'` Low with that remediation; `script-src 'unsafe-inline'` stays Medium.

**CSP Level 3:** the preferred script policy is `script-src 'nonce-{RANDOM}' 'strict-dynamic'` (or hashes with `'strict-dynamic'`), which lets nonced scripts load their own dependencies; send violation reports with `report-to` plus a `Reporting-Endpoints` header (`report-uri` is deprecated). A `Content-Security-Policy-Report-Only` header is monitoring, not enforcement: without an enforcing `Content-Security-Policy` header, report CSP as missing (High). Angular supports Trusted Types via `require-trusted-types-for 'script'; trusted-types angular angular#bundler`; their absence is not a finding (recommendation only).

**5. frame-ancestors** (MUST be present; not covered by `default-src`): `'none'` or `'self'`.

**6. object-src 'none' and upgrade-insecure-requests** (OWASP baseline; each absent = Medium): `object-src 'none'` is only implied when `default-src` is `'none'`, so add it explicitly with `default-src 'self'`; `upgrade-insecure-requests` rewrites mixed-content requests to HTTPS.

## 4. X-Frame-Options

`DENY` or `SAMEORIGIN`, aligned with CSP `frame-ancestors` (`'none'` ↔ `DENY`, `'self'` ↔ `SAMEORIGIN`); `ALLOW-FROM` is deprecated and ignored by browsers. Missing or misaligned while `frame-ancestors` is present = Low.

## 5. HTTP Strict Transport Security (HSTS)

**GOOD configuration:**
```xml
<add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
```

**Parameters:**
- `max-age=31536000` - 1 year (minimum recommended)
- `includeSubDomains` - Apply to all subdomains
- `preload` - optional opt-in for the browser preload list; hstspreload.org advises against adding it by default and inclusion is near-irreversible, so never flag its absence (not a finding)

**HSTS may also be configured via the `Enigmatry.Entry.AspNetCore` package** using the `AddEntryHttps` / `UseEntryHttps` extension methods in `Program.cs` / `Startup.cs`. Search for these calls before concluding HSTS is missing:
```csharp
services.AddEntryHttps();
app.UseEntryHttps();
```
If the project uses the `Enigmatry.Entry` HTTPS helpers, verify the effective HSTS value on the live URL or in the package source; do not assume it meets the one-year `max-age` / `includeSubDomains` minimum. On `linux` hosting (no `web.config`) the equivalent is `builder.Services.AddHsts(o => { o.MaxAge = TimeSpan.FromDays(365); o.IncludeSubDomains = true; })` with `app.UseHsts()`.

**Other sources that count as configured (read them before concluding HSTS is missing):**
- `app.UseHsts()` without `AddHsts(options => ...)` defaults to a 30-day `max-age` without `includeSubDomains` (High per section 12); the options must set both
- IIS 10 (1709+) native `<hsts enabled="true" max-age="31536000" includeSubDomains="true" />` under `<site>` in `applicationHost.config` or `web.config`
- `NetEscapades.AspNetCore.SecurityHeaders` (`AddSecurityHeaderPolicies`, `UseSecurityHeaders`) emits HSTS, CSP and the other headers from a policy object; read the policy instead of grepping for header names

## 6. X-Content-Type-Options

`X-Content-Type-Options: nosniff` on every response; missing or any other value = Medium.

## 7. Referrer-Policy

Acceptable values: `no-referrer`, `same-origin`, `strict-origin-when-cross-origin`. A missing `Referrer-Policy` is Low: every current browser defaults to `strict-origin-when-cross-origin`. An explicit insecure value (`unsafe-url`, `no-referrer-when-downgrade`) is Medium.

## 8. Cross-Origin Resource Sharing (CORS)

Check `AddCors` policies in `Program.cs` / `Startup.cs` (or `Access-Control-Allow-*` custom headers in `web.config`): origins must be explicit; `AllowAnyOrigin()` or `*` combined with `AllowCredentials()` = Medium.
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

Every external `<script>` / `<link>` in `src/index.html` (or any template loading a CDN resource) needs `integrity="sha384-..."` and `crossorigin="anonymous"`; a CDN resource without SRI = Medium.

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
    context.Response.Headers.Append("Cache-Control", "no-store");
    context.Response.Headers.Append("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("Referrer-Policy", "no-referrer");
    context.Response.Headers.Append("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
    context.Response.Headers.Append("Cross-Origin-Opener-Policy", "same-origin");
    context.Response.Headers.Append("Cross-Origin-Resource-Policy", "same-origin");
    context.Response.Headers.Append("X-Permitted-Cross-Domain-Policies", "none");
    
    await next();
});
```

**One source per header:** `IHeaderDictionary.Add` throws on a duplicate key (analyzer ASP0019), so samples use `Append` or the indexer. When `web.config` `customHeaders` and middleware (or a library) both set the same header, IIS appends a second copy: two CSP headers are enforced as their intersection and two HSTS headers take the first. Exactly one source per header is expected; the same header emitted twice on the live response = Medium.

**API-specific and remaining baseline headers:**
- `Cache-Control: no-store` on API responses (missing = Medium)
- `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` is the minimal CSP for an API that renders no content; a permissive CSP (`default-src *`) on an API = Medium
- `Permissions-Policy` with at least `camera=(), microphone=(), geolocation=(), payment=()` (a shorter list = Medium)
- `Cross-Origin-Opener-Policy: same-origin` (`same-origin-allow-popups` where sign-in uses a popup, such as MSAL `loginPopup`; no COOP at all on the MSAL Browser v5 redirect bridge route, which must be served without it), `Cross-Origin-Resource-Policy: same-origin`, `X-Permitted-Cross-Domain-Policies: none` on front-end and API (each missing = Medium)
- `Cross-Origin-Embedder-Policy: require-corp` only where the app tolerates it (it blocks cross-origin resources that lack CORP/CORS); otherwise not a finding
- `Clear-Site-Data: "cache","cookies","storage"` on the logout response (check the sign-out action, not the global header block)

## 11. Version-Disclosing Headers (Server, X-Powered-By, X-AspNet-Version)

**Information disclosure headers like `Server` and `X-Powered-By` reveal platform details and versions that attackers can use to identify known vulnerabilities. They must be removed from all HTTP responses (API and front-end). Every finding in this section is rated Low (information disclosure with no exploit path on its own).**

**Headers to remove:**
- **Server** - Reveals web server type and version (e.g., "Microsoft-IIS/10.0")
- **X-Powered-By** - Reveals framework and version (e.g., "ASP.NET", "ASP.NET Core 6.0")
- **X-AspNet-Version** - Reveals specific ASP.NET version (e.g., "4.0.30319") — legacy (.NET Framework), not expected on this stack
- **X-AspNetMvc-Version** - Reveals ASP.NET MVC version — legacy (.NET Framework), not expected on this stack
- **X-SourceFiles** - IIS Express / Visual Studio debugging header (base64-encoded local path); must never reach production
- **SourceMap** / **X-SourceMap** - point the browser at source maps; see check 10 (code_minification.md) for the `.map` files themselves
- Developer exception pages and default IIS error pages that name the platform; see check 4 (exception_handling.md) for the exception page itself
- **Server** added in front of the app by Front Door, Application Gateway or nginx (`edge` modifier): only visible on the live response; the Kestrel / IIS settings below do not reach it, strip it at the edge

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

**ASP.NET Core / Kestrel:** `builder.WebHost.ConfigureKestrel(o => o.AddServerHeader = false)` in `Program.cs`. A `Kestrel:AddServerHeader` value in `appsettings.json` works only with an explicit `Configure<KestrelServerOptions>` binding.

> **Do not accept middleware that calls `Response.Headers.Remove("Server")` as a remediation.** Kestrel adds its `Server` header when the response starts, after middleware has run, so only `AddServerHeader = false` removes it. Under IIS (in-process or out-of-process) the `Server` and `X-Powered-By` headers are added by IIS after the ASP.NET Core pipeline completes, so application code cannot remove them; only `removeServerHeader="true"` on `<requestFiltering>` and `<remove name="X-Powered-By" />` under `<httpProtocol><customHeaders>` in `web.config` work. Report such middleware as a non-working remediation.

## 12. What to Report

Group header findings per severity: report **one** finding per severity level that lists every missing or misconfigured header at that level, with its location and the value to set.

**Severity per header** (impact-based; the same header carries the same severity on the front-end and on the API):

| Finding | Severity |
|---------|----------|
| `Content-Security-Policy` missing (a `Content-Security-Policy-Report-Only` header alone does not count as present) | High |
| `Strict-Transport-Security` missing, `max-age` below one year, or `includeSubDomains` absent | High |
| CSP present but weak (`unsafe-inline` / `unsafe-eval` / `data:` / `blob:` in `script-src`, `default-src *`, missing `base-uri`, missing `frame-ancestors`, `object-src 'none'` or `upgrade-insecure-requests` absent, static `'nonce-...'` string in `web.config`) | Medium |
| `X-Content-Type-Options`, `Permissions-Policy` (or without the minimum feature list), `Cross-Origin-Opener-Policy` / `Cross-Origin-Resource-Policy`, `X-Permitted-Cross-Domain-Policies` missing; `Clear-Site-Data` absent on logout; `Cross-Origin-Embedder-Policy` absent where the app tolerates it (COOP absent on the MSAL Browser v5 redirect bridge route is not a finding) | Medium |
| `style-src 'unsafe-inline'` on an Angular app (runtime component styles; see section 3) | Low |
| `Referrer-Policy` set to `unsafe-url` or `no-referrer-when-downgrade` | Medium |
| `Cache-Control: no-store` missing on API responses; CDN resource without SRI; CORS `*` combined with credentials | Medium |
| Same header emitted twice on the live response (`web.config` `customHeaders` plus middleware or a library; see section 10) | Medium |
| `X-Frame-Options` missing while CSP `frame-ancestors` is present, or misaligned with it | Low |
| HSTS `preload` absent | not a finding |
| `Referrer-Policy` absent (browser default `strict-origin-when-cross-origin` applies) | Low |
| `Server` (including one added by Front Door, Application Gateway or nginx), `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-SourceFiles`, `SourceMap` / `X-SourceMap` present in a live production response, or an error page naming the platform (version information disclosure) | Low |
| `Response.Headers.Remove("Server")` middleware used as the remediation for version-disclosing headers (non-working; see section 11) | Low |
| Deprecated header present: `X-XSS-Protection` (OWASP: omit or `0`), `Expect-CT`, `Public-Key-Pins`, `Feature-Policy` (replaced by `Permissions-Policy`), `Report-To` (replaced by `Reporting-Endpoints`) | Low |

**Example report:**

```
Finding: Security headers missing or misconfigured (Medium)
- Cross-Origin-Opener-Policy missing (web.config customHeaders): add same-origin
- X-Permitted-Cross-Domain-Policies missing (web.config customHeaders): add none
- CSP without upgrade-insecure-requests (web.config:20): add the directive
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
Content-Security-Policy-Report-Only
Reporting-Endpoints
<hsts enabled=

<!-- Check for version-header removal -->
removeServerHeader
<remove name="X-Powered-By" />
enableVersionHeader

<!-- Deprecated headers: present = Low, recommend removal -->
X-XSS-Protection
Expect-CT
Public-Key-Pins
Feature-Policy
Report-To

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
Response.Headers.Append
UseHsts
AddHsts
AddSecurityHeaderPolicies
UseSecurityHeaders
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

1. **Browser DevTools:** Network tab, the document request and an API call; verify `Server` and `X-Powered-By` are absent.

2. **Online tools:**
   - MDN HTTP Observatory: https://developer.mozilla.org/en-US/observatory — successor of Mozilla Observatory (`observatory.mozilla.org` moved to MDN in July 2024; do not cite the old host). New scoring model: maximum 145 points, bonus points only count from a base score of 90 or more. Source: https://developer.mozilla.org/en-US/blog/mdn-observatory
   - https://securityheaders.com — second tool, for a cross-check of the header grade

3. **Command line (curl):**
   ```bash
   curl -I https://your-app.com

   # Version-disclosing headers: should return nothing if they are removed correctly
   curl -I https://your-app.com | grep -i "server\|powered"
   curl -I https://api.your-app.com/api/endpoint | grep -i "server\|powered"
   ```
   PowerShell: `Invoke-WebRequest -Uri "https://your-app.com" -Method Head | Select-Object -ExpandProperty Headers` and look for `Server` or `X-Powered-By` in the output.
