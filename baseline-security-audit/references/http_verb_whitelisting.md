# HTTP Verb Whitelisting Analysis

Analyze the application to ensure only necessary HTTP verbs are allowed, reducing the attack surface by blocking unused HTTP methods.

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A02 Security Misconfiguration · **ASVS 5.0:** V4 API and Web Service, V13 Configuration

> **Hosting model:** this check depends on `HOSTING_MODEL` from SKILL.md Step 0b. `web.config` sections apply only when it is `iis`; for `linux` use the middleware or platform equivalents named in this file and do not report missing `web.config` entries; with the `edge` modifier the live `PRODUCTION_URL` response is the ground truth and `UseForwardedHeaders` must be configured.

## Core Security Principle
**Only allow HTTP verbs that are actually used by the application. Unused verbs should be blocked in web.config to prevent potential abuse and reduce attack surface. The DEBUG verb is a legacy .NET Framework/ISAPI debugging mechanism that ASP.NET Core never uses; if it appears in any web.config, flag it.**

## 1. What to Check

### Step 1: Identify Used HTTP Verbs

**Examine all API controllers to find which HTTP verbs are used:**

**ASP.NET Core Controllers:**
```csharp
[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    [HttpGet]                    // GET verb used
    public IActionResult GetAll() { }
    
    [HttpGet("{id}")]           // GET verb used
    public IActionResult GetById(int id) { }
    
    [HttpPost]                  // POST verb used
    public IActionResult Create([FromBody] User user) { }
    
    [HttpPut("{id}")]           // PUT verb used
    public IActionResult Update(int id, [FromBody] User user) { }
    
    [HttpDelete("{id}")]        // DELETE verb used
    public IActionResult Delete(int id) { }
    
    [HttpPatch("{id}")]         // PATCH verb used
    public IActionResult Patch(int id, [FromBody] JsonPatchDocument patch) { }
}
```

**ASP.NET MVC/Web API Controllers** — legacy (.NET Framework), not expected on this stack:
```csharp
public class ProductsController : ApiController
{
    [HttpGet]                   // GET verb used
    public IHttpActionResult GetProducts() { }
    
    [HttpPost]                  // POST verb used
    public IHttpActionResult CreateProduct(Product product) { }
    
    [HttpPut]                   // PUT verb used
    public IHttpActionResult UpdateProduct(int id, Product product) { }
    
    [HttpDelete]                // DELETE verb used
    public IHttpActionResult DeleteProduct(int id) { }
}
```

**Search for HTTP verb attributes:**
```csharp
[HttpGet]
[HttpPost]
[HttpPut]
[HttpDelete]
[HttpPatch]
[HttpHead]
[HttpOptions]
```

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

### Step 2: Whitelist Only Used Verbs in web.config

**After identifying used verbs, configure web.config to allow only those verbs.**

## 2. web.config Configuration

On `linux` hosting `<requestFiltering>` is ignored; the equivalent is a method-filtering middleware registered before routing (`app.Use(async (ctx, next) => { if (!allowed.Contains(ctx.Request.Method)) { ctx.Response.StatusCode = StatusCodes.Status405MethodNotAllowed; return; } await next(); });`) or, with the `edge` modifier, a Front Door WAF / Application Gateway rule; verify the effective behaviour with `curl -X TRACE` against `PRODUCTION_URL`.

**GOOD configuration - Whitelist approach:**

**Example: Only GET, POST, PUT, DELETE, OPTIONS are used:**
```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <security>
      <requestFiltering>
        <verbs allowUnlisted="false">
          <add verb="GET" allowed="true" />
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
- Only list verbs that are actually used in controllers

**Example: Only GET and POST are used:**
```xml
<requestFiltering>
  <verbs allowUnlisted="false">
    <add verb="GET" allowed="true" />
    <add verb="POST" allowed="true" />
    <add verb="OPTIONS" allowed="true" />  <!-- For CORS if needed -->
  </verbs>
</requestFiltering>
```

## 3. DEBUG Verb - Legacy Only

**The DEBUG verb belongs to .NET Framework/ISAPI debugging. ASP.NET Core (AspNetCoreModuleV2, in-process or out-of-process) does not use it and Visual Studio does not need it. Do not recommend allowing DEBUG anywhere; the only check is that it is absent.** Absence of a `Web.Release.config` transform for DEBUG is **not** a finding on an ASP.NET Core project.

The following examples are kept only for legacy .NET Framework projects that still carry the verb:

### web.config (legacy .NET Framework development - allows DEBUG):
```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <security>
      <requestFiltering>
        <verbs allowUnlisted="false">
          <add verb="GET" allowed="true" />
          <add verb="POST" allowed="true" />
          <add verb="PUT" allowed="true" />
          <add verb="DELETE" allowed="true" />
          <add verb="OPTIONS" allowed="true" />
          <add verb="DEBUG" allowed="true" />  <!-- legacy .NET Framework only; never on ASP.NET Core -->
        </verbs>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
```

### Web.Release.config (Production - blocks DEBUG):
```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration xmlns:xdt="http://schemas.microsoft.com/XML-Document-Transform">
  <system.webServer>
    <security>
      <requestFiltering>
        <verbs xdt:Transform="Replace">
          <add verb="GET" allowed="true" />
          <add verb="POST" allowed="true" />
          <add verb="PUT" allowed="true" />
          <add verb="DELETE" allowed="true" />
          <add verb="OPTIONS" allowed="true" />
          <!-- DEBUG verb removed for production -->
        </verbs>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
```

**Alternative - Explicitly block DEBUG in release:**
```xml
<configuration xmlns:xdt="http://schemas.microsoft.com/XML-Document-Transform">
  <system.webServer>
    <security>
      <requestFiltering>
        <verbs>
          <add verb="DEBUG" allowed="false" xdt:Transform="SetAttributes" xdt:Locator="Match(verb)" />
        </verbs>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
```

## 4. RED FLAGS

**BAD - All verbs allowed (default IIS behavior):**
```xml
<!-- No verb filtering configured -->
<configuration>
  <system.webServer>
    <!-- Missing requestFiltering section -->
  </system.webServer>
</configuration>
```

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

**BAD - DEBUG verb in production:**
```xml
<!-- Web.Release.config still allows DEBUG -->
<verbs allowUnlisted="false">
  <add verb="GET" allowed="true" />
  <add verb="POST" allowed="true" />
  <add verb="DEBUG" allowed="true" />  <!-- BAD - should be removed in release -->
</verbs>
```

**BAD - DEBUG present in any web.config of an ASP.NET Core project:**
```xml
<add verb="DEBUG" allowed="true" />  <!-- Legacy verb; remove -->
```

**GOOD - Only necessary verbs:**
```xml
<requestFiltering>
  <verbs allowUnlisted="false">
    <add verb="GET" allowed="true" />
    <add verb="POST" allowed="true" />
    <add verb="PUT" allowed="true" />
    <add verb="DELETE" allowed="true" />
    <add verb="OPTIONS" allowed="true" />
    <!-- Only verbs actually used in controllers -->
  </verbs>
</requestFiltering>
```

## 5. Analysis Steps

### Step 1: Inventory All Controllers

**Search for all controller files:**
```
Controllers/
├── UsersController.cs
├── ProductsController.cs
├── OrdersController.cs
└── AuthController.cs
```

**For each controller, identify HTTP verb attributes:**

**Example inventory:**
```
UsersController.cs:
  - HttpGet (lines 15, 22)
  - HttpPost (line 30)
  - HttpPut (line 38)
  - HttpDelete (line 46)

ProductsController.cs:
  - HttpGet (lines 12, 18)
  - HttpPost (line 25)
  - HttpPut (line 33)

OrdersController.cs:
  - HttpGet (lines 10, 16, 23)
  - HttpPost (line 30)
  - HttpDelete (line 38)

AuthController.cs:
  - HttpPost (lines 12, 20)
```

**Consolidated list of used verbs:**
- GET (all controllers)
- POST (all controllers)
- PUT (UsersController, ProductsController)
- DELETE (UsersController, OrdersController)
- OPTIONS (if CORS is configured - check Startup.cs/Program.cs)

### Step 2: Check web.config Verb Whitelist

**Compare web.config against used verbs:**

**web.config content:**
```xml
<verbs allowUnlisted="false">
  <add verb="GET" allowed="true" />      <!-- Used ✓ -->
  <add verb="POST" allowed="true" />     <!-- Used ✓ -->
  <add verb="PUT" allowed="true" />      <!-- Used ✓ -->
  <add verb="DELETE" allowed="true" />   <!-- Used ✓ -->
  <add verb="PATCH" allowed="true" />    <!-- NOT USED ✗ - Report this -->
  <add verb="OPTIONS" allowed="true" />  <!-- Check if CORS is enabled -->
</verbs>
```

### Step 3: Verify DEBUG Verb Configuration

**Check web.config for DEBUG:**
```xml
<!-- On an ASP.NET Core project any occurrence is a finding (Medium); on a legacy .NET Framework project verify it is removed in Web.Release.config -->
<add verb="DEBUG" allowed="true" />
```

**Check Web.Release.config (legacy .NET Framework only):**
```xml
<!-- Should either: -->
<!-- 1. Replace entire verbs section without DEBUG -->
<verbs xdt:Transform="Replace">
  <!-- DEBUG not listed here -->
</verbs>

<!-- OR 2. Explicitly block DEBUG -->
<add verb="DEBUG" allowed="false" xdt:Transform="SetAttributes" xdt:Locator="Match(verb)" />
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

```
Finding: HTTP Verbs Not Filtered
- Location: web.config (no <requestFiltering><verbs> section) / middleware
- Issue: All verbs are accepted; `curl -X TRACE` returned [status]
- Risk: Low - Increases attack surface; only exploitable together with another weakness
- Recommendation: Whitelist the verbs used by the controllers with allowUnlisted="false" (or the middleware equivalent)
```

```
Finding: Unused HTTP Verb Allowed
- Verb: [Verb name]
- Location: web.config
- Issue: Verb is allowed but not used by any controller
- Risk: Low - Increases attack surface unnecessarily
- Recommendation: Remove unused verb from web.config
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
```

**ASP.NET MVC/Web API** — legacy (.NET Framework), not expected on this stack:
```csharp
\[HttpGet\]
\[HttpPost\]
\[HttpPut\]
\[HttpDelete\]
\[AcceptVerbs\(
```

**Files to search:**
```
*Controller.cs
Controllers/**/*.cs
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

## 8. Best Practices

✅ **Configuration:**
- Always set `allowUnlisted="false"` in web.config
- Whitelist only verbs that are actually used in controllers
- DEBUG must not appear in any web.config of an ASP.NET Core project (legacy .NET Framework projects remove it in Web.Release.config)
- Verify verb filtering in all environment configurations (staging, production)

✅ **Controller Analysis:**
- Review all controllers systematically
- Document which verbs are used and why
- Remove unused HTTP verb attributes from controllers
- Use specific verb attributes ([HttpGet], [HttpPost]) rather than [AcceptVerbs]

✅ **Dangerous Verbs - Never Allow:**
- **TRACE** - Can expose sensitive information via XST (Cross-Site Tracing) attacks
- **TRACK** - Similar to TRACE
- **CONNECT** - Used for tunneling, not needed for REST APIs
- **DEBUG** - Legacy .NET Framework verb; never needed by ASP.NET Core

✅ **Common Verbs:**
- **GET** - Almost always needed for retrieving data
- **POST** - Commonly needed for creating resources
- **PUT** - Needed for full updates (if your API uses PUT)
- **DELETE** - Needed if your API allows deletions
- **PATCH** - Only if you implement partial updates (less common)
- **OPTIONS** - Needed whenever the front-end calls the API cross-origin (preflight)
- **HEAD** - Allow whenever GET is allowed (health probes, static-file handler, monitoring)

✅ **Environment-Specific Configuration:**
- All environments: identical verb list; DEBUG is never allowed on ASP.NET Core
- Production: Minimal set of verbs

✅ **Documentation:**
- Document why each verb is allowed
- Include verb analysis in security review checklist
- Update web.config when adding new controller actions with different verbs

✅ **Regular Review:**
- Review verb configuration when adding new controllers
- Audit unused verbs quarterly
- Verify Web.Release.config transformations are applied correctly
- Test verb filtering in each environment
