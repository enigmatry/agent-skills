# HTTP Verb Whitelisting Analysis

Analyze the application to ensure only necessary HTTP verbs are allowed, reducing the attack surface by blocking unused HTTP methods.

## Core Security Principle
**Only allow HTTP verbs that are actually used by the application. Unused verbs should be blocked in web.config to prevent potential abuse and reduce attack surface. The DEBUG verb should only be allowed in local development environments.**

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

**ASP.NET MVC/Web API Controllers:**
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
- **OPTIONS** - CORS preflight (used if CORS is configured)
- **HEAD** - Get headers only (rarely used)

**Verbs that should typically be blocked:**
- **TRACE** - Used for debugging, can expose sensitive information
- **TRACK** - Similar to TRACE
- **CONNECT** - Tunnel protocol, not used in REST APIs
- **DEBUG** - Debugging verb, should only be in development
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

## 3. DEBUG Verb - Development Only

**CRITICAL: DEBUG verb should only be allowed in local development, never in production.**

### web.config (Development - allows DEBUG):
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
          <add verb="DEBUG" allowed="true" />  <!-- Only in development -->
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
  <add verb="HEAD" allowed="true" />      <!-- Not used in any controller -->
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

**BAD - Missing Web.Release.config transformation:**
```
<!-- No Web.Release.config file exists to remove DEBUG verb -->
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
<!-- If DEBUG is present, verify it's removed in Web.Release.config -->
<add verb="DEBUG" allowed="true" />
```

**Check Web.Release.config:**
```xml
<!-- Should either: -->
<!-- 1. Replace entire verbs section without DEBUG -->
<verbs xdt:Transform="Replace">
  <!-- DEBUG not listed here -->
</verbs>

<!-- OR 2. Explicitly block DEBUG -->
<add verb="DEBUG" allowed="false" xdt:Transform="SetAttributes" xdt:Locator="Match(verb)" />
```

## 6. What to Report (Low Priority)

**Report format:**
```
Finding: Unused HTTP Verb Allowed
- Verb: [Verb name]
- Location: web.config
- Issue: Verb is allowed but not used by any controller
- Risk: LOW - Increases attack surface unnecessarily
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

**ASP.NET MVC/Web API:**
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

## 10. Best Practices

✅ **Configuration:**
- Always set `allowUnlisted="false"` in web.config
- Whitelist only verbs that are actually used in controllers
- Remove DEBUG verb in Web.Release.config for production
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
- **DEBUG** - Only in development, never production

✅ **Common Verbs:**
- **GET** - Almost always needed for retrieving data
- **POST** - Commonly needed for creating resources
- **PUT** - Needed for full updates (if your API uses PUT)
- **DELETE** - Needed if your API allows deletions
- **PATCH** - Only if you implement partial updates (less common)
- **OPTIONS** - Needed if CORS is configured for preflight requests
- **HEAD** - Rarely needed, only allow if specifically used

✅ **Environment-Specific Configuration:**
- Development: May allow DEBUG for local debugging
- Staging: Should match production (no DEBUG)
- Production: Minimal set of verbs, no DEBUG

✅ **Documentation:**
- Document why each verb is allowed
- Include verb analysis in security review checklist
- Update web.config when adding new controller actions with different verbs

✅ **Regular Review:**
- Review verb configuration when adding new controllers
- Audit unused verbs quarterly
- Verify Web.Release.config transformations are applied correctly
- Test verb filtering in each environment
