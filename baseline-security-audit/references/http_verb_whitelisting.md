# HTTP Verb Whitelisting Analysis

Analyze the application to ensure only necessary HTTP verbs are allowed, reducing the attack surface by blocking unused HTTP methods.

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A02 Security Misconfiguration · **ASVS 5.0:** V4 API and Web Service, V13 Configuration

> **Hosting model:** this check depends on `HOSTING_MODEL` from SKILL.md Step 0b. `web.config` sections apply only when it is `iis`; for `linux` use the middleware or platform equivalents named in this file and do not report missing `web.config` entries; with the `edge` modifier the live `PRODUCTION_URL` response is the ground truth and `UseForwardedHeaders` must be configured.

## Core Security Principle
**Only allow HTTP verbs that are actually used by the application. Unused verbs should be blocked in web.config to prevent potential abuse and reduce attack surface. The DEBUG verb is a legacy .NET Framework/ISAPI debugging mechanism that ASP.NET Core never uses; if it appears in any web.config, flag it.**

## 1. What to Check

Inventory the verbs from `[HttpGet]` / `[HttpPost]` / `[HttpPut]` / `[HttpDelete]` / `[HttpPatch]` / `[HttpHead]` / `[HttpOptions]` and `[AcceptVerbs]` on controller actions, plus minimal-API and non-controller endpoints (`Map*`; section 7 patterns). Legacy .NET Framework Web API controllers (`ApiController`, `IHttpActionResult`) use the same attributes but are not expected on this stack.

**Common verbs used in typical REST APIs:**
- **GET** - Retrieve resources (almost always used)
- **POST** - Create resources (commonly used)
- **PUT** - Update/replace resources (commonly used)
- **DELETE** - Delete resources (commonly used)
- **PATCH** - Partial update (less common)
- **OPTIONS** - CORS preflight (required whenever the Angular front-end is served from a different origin than the API, which is the normal setup).
- **HEAD** - Must be allowed whenever GET is allowed. It never appears in controller attributes but is used by Azure Front Door and Application Gateway health probes (Front Door defaults to HEAD), the IIS static-file handler and uptime monitors; blocking it can take an origin out of rotation.

**Verbs that should typically be blocked:**
- **TRACE** - Used for debugging, can expose sensitive information
- **TRACK** - Similar to TRACE
- **CONNECT** - Tunnel protocol, not used in REST APIs
- **DEBUG** - Legacy .NET Framework/ISAPI verb; never needed by ASP.NET Core in any environment
- **PROPFIND** - WebDAV verb, not used unless WebDAV is enabled
- **PROPPATCH** - WebDAV verb
- **MKCOL** - WebDAV verb
- **COPY** - WebDAV verb
- **MOVE** - WebDAV verb
- **LOCK** - WebDAV verb
- **UNLOCK** - WebDAV verb

## 2. web.config Configuration

On `linux` hosting `<requestFiltering>` is ignored; the equivalent is a method-filtering middleware registered before routing (`app.Use(async (ctx, next) => { if (!allowed.Contains(ctx.Request.Method)) { ctx.Response.StatusCode = StatusCodes.Status405MethodNotAllowed; return; } await next(); });`) or, with the `edge` modifier, a Front Door WAF / Application Gateway rule; verify the effective behaviour with `curl -X TRACE` against `PRODUCTION_URL`.

**GOOD configuration - Whitelist approach:**

**Example: Only GET, POST, PUT, DELETE, OPTIONS are used (HEAD follows GET):**
```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <security>
      <requestFiltering>
        <verbs allowUnlisted="false">
          <add verb="GET" allowed="true" />
          <add verb="HEAD" allowed="true" />
          <add verb="POST" allowed="true" />
          <add verb="PUT" allowed="true" />
          <add verb="DELETE" allowed="true" />
          <add verb="OPTIONS" allowed="true" />
        </verbs>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
```

**Key configuration:**
- `allowUnlisted="false"` - Critical! Blocks all verbs not explicitly allowed
- Only list verbs that are actually used in controllers, plus HEAD whenever GET is listed

## 3. DEBUG Verb - Legacy Only

**The DEBUG verb belongs to .NET Framework/ISAPI debugging. ASP.NET Core (AspNetCoreModuleV2, in-process or out-of-process) does not use it and Visual Studio does not need it. Do not recommend allowing DEBUG anywhere; the only check is that it is absent.** Absence of a `Web.Release.config` transform for DEBUG is **not** a finding on an ASP.NET Core project.

On a legacy .NET Framework project, verify that `Web.Release.config` removes DEBUG (`<verbs xdt:Transform="Replace">` without it, or `<add verb="DEBUG" allowed="false" xdt:Transform="SetAttributes" xdt:Locator="Match(verb)" />`).

## 4. RED FLAGS

**BAD - no `<requestFiltering><verbs>` section at all:** IIS accepts every verb.

**BAD - allowUnlisted="true" allows all unlisted verbs:**
```xml
<requestFiltering>
  <verbs allowUnlisted="true">  <!-- BAD - allows TRACE, TRACK, etc. -->
    <add verb="GET" allowed="true" />
    <add verb="POST" allowed="true" />
  </verbs>
</requestFiltering>
```

**BAD - Allowing unused verbs:**
```xml
<verbs allowUnlisted="false">
  <add verb="GET" allowed="true" />
  <add verb="POST" allowed="true" />
  <add verb="PUT" allowed="true" />
  <add verb="DELETE" allowed="true" />
  <add verb="PATCH" allowed="true" />     <!-- Not used in any controller -->
  <add verb="HEAD" allowed="true" />      <!-- Fine: HEAD follows GET (health probes) -->
  <add verb="TRACE" allowed="true" />     <!-- Should NEVER be allowed -->
  <add verb="CONNECT" allowed="true" />   <!-- Should NEVER be allowed -->
</verbs>
```

## 5. Analysis Steps

### Step 1: Inventory All Controllers

List every controller and endpoint file (section 7 search patterns) and consolidate the verbs used per file; add OPTIONS when CORS is configured (`AddCors` in `Program.cs` / `Startup.cs`) and HEAD whenever GET is used.

### Step 2: Check web.config Verb Whitelist

**Compare web.config against used verbs:**

**web.config content:**
```xml
<verbs allowUnlisted="false">
  <add verb="GET" allowed="true" />      <!-- Used ✓ -->
  <add verb="HEAD" allowed="true" />     <!-- Follows GET ✓ -->
  <add verb="POST" allowed="true" />     <!-- Used ✓ -->
  <add verb="PUT" allowed="true" />      <!-- Used ✓ -->
  <add verb="DELETE" allowed="true" />   <!-- Used ✓ -->
  <add verb="PATCH" allowed="true" />    <!-- NOT USED ✗ - Report this -->
  <add verb="OPTIONS" allowed="true" />  <!-- Check if CORS is enabled -->
</verbs>
```

## 6. What to Report

| Finding | Severity |
|---------|----------|
| Dangerous verb allowed: TRACE, TRACK, CONNECT or DEBUG present with `allowed="true"`, or confirmed accepted on the live URL | Medium |
| No verb filtering at all (`<requestFiltering>` absent or `allowUnlisted="true"`) — confirm with a live `curl -X TRACE -i "$PRODUCTION_URL"` before reporting; a `405` or `404` from the edge or middleware means the gap is already closed | Low |
| Unused verb allowed (listed with `allowed="true"` but used by no controller) | Low |

**Report format:**
```
Finding: Dangerous HTTP Verb Allowed
- Verb: TRACE / TRACK / CONNECT / DEBUG
- Location: web.config (or live response when HOSTING_MODEL is linux/edge)
- Issue: Verb accepted by the server; TRACE/TRACK enable cross-site tracing, DEBUG is a legacy debugging hook
- Risk: Medium - Exposes request internals or debugging behaviour to an attacker
- Recommendation: Set allowUnlisted="false" and do not list the verb; on linux/edge block it in middleware or the WAF rule
```

## 7. Search Patterns

### Search Controllers for HTTP Verbs:

**ASP.NET Core:**
```csharp
\[HttpGet\]
\[HttpPost\]
\[HttpPut\]
\[HttpDelete\]
\[HttpPatch\]
\[HttpHead\]
\[HttpOptions\]

// Also check for AcceptVerbs
\[AcceptVerbs\("([^"]+)"\)\]

// Minimal APIs and non-controller endpoints (Program.cs, *Endpoints.cs, extension methods)
\bMap(Get|Post|Put|Delete|Patch|Methods|Group|HealthChecks|Hub|GraphQL|OpenApi)\(
\[EnableQuery\]
```

**Files to search:**
```
*Controller.cs
Controllers/**/*.cs
Program.cs, Startup.cs, **/*Endpoints.cs
```

### Search web.config Files:

```xml
<requestFiltering>
<verbs
allowUnlisted
<add verb=
DEBUG
TRACE
TRACK
CONNECT
```

**Files to check:**
```
web.config
Web.config
Web.Debug.config
Web.Release.config
Web.Staging.config
Web.Production.config
```
