# Version Information in Headers Analysis

Analyze HTTP responses to identify headers that disclose platform and version information, which could aid attackers in targeting known vulnerabilities.

## Core Security Principle
**Information disclosure headers like `Server` and `X-Powered-By` reveal platform details and versions that attackers can use to identify known vulnerabilities. These headers should be removed from all HTTP responses.**

## 1. Headers to Remove

**Target headers that disclose information:**
- **Server** - Reveals web server type and version (e.g., "Microsoft-IIS/10.0")
- **X-Powered-By** - Reveals framework and version (e.g., "ASP.NET", "ASP.NET Core 6.0")
- **X-AspNet-Version** - Reveals specific ASP.NET version (e.g., "4.0.30319")
- **X-AspNetMvc-Version** - Reveals ASP.NET MVC version

## 2. web.config Configuration (Both API and Front-End)

**Files to examine:**
- API `web.config` files
- Front-end Angular application `web.config`
- Any `Web.config` (check capitalization variants)

**GOOD configuration - Remove headers:**
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

**For ASP.NET applications, also add to web.config:**
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

## 3. ASP.NET Core Configuration (Program.cs/Startup.cs)

**For ASP.NET Core APIs, configure in Program.cs:**

```csharp
var builder = WebApplication.CreateBuilder(args);

// Configure Kestrel to remove Server header
builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.AddServerHeader = false;
});

var app = builder.Build();

// Remove any remaining version headers via middleware
app.Use(async (context, next) =>
{
    context.Response.Headers.Remove("Server");
    context.Response.Headers.Remove("X-Powered-By");
    context.Response.Headers.Remove("X-AspNet-Version");
    context.Response.Headers.Remove("X-AspNetMvc-Version");
    
    await next();
});

app.Run();
```

**Alternative - appsettings.json configuration:**
```json
{
  "Kestrel": {
    "AddServerHeader": false
  }
}
```

## 7. What to Report (Low Priority)

**Report format:**
```
Finding: Version Information Disclosure via HTTP Headers
- Header(s): [Header names found]
- Location: [API/Front-end application]
- Current Value: [Header value]
- Issue: [What's being disclosed]
- Risk: LOW - Information disclosure aids attackers in targeting vulnerabilities
- Recommendation: [How to fix]
```

**Example reports:**

```
Finding: Server Header Discloses IIS Version
- Header(s): Server
- Location: API responses (all endpoints)
- Current Value: Server: Microsoft-IIS/10.0
- Issue: Server header reveals IIS version
- Risk: LOW - Attackers can identify platform and target known IIS 10.0 vulnerabilities
- Recommendation: Add removeServerHeader="true" to web.config under <security><requestFiltering>
```

## 10. Testing and Verification

### Manual Testing:

**1. Using Browser DevTools:**
- Open application in browser
- Press F12 to open DevTools
- Go to Network tab
- Refresh page
- Click on any request (document or API call)
- Check Response Headers
- Verify `Server` and `X-Powered-By` are absent

**2. Using curl:**
```bash
# Test and display only headers
curl -I https://api.yourapp.com/api/endpoint

# Test and search for specific headers
curl -I https://api.yourapp.com/api/endpoint | grep -i "server\|powered"

# Should return empty if headers are removed correctly
```

**3. Using PowerShell:**
```powershell
# Test API endpoint
Invoke-WebRequest -Uri "https://api.yourapp.com/api/endpoint" -Method Head | 
    Select-Object -ExpandProperty Headers

# Test front-end
Invoke-WebRequest -Uri "https://app.yourapp.com/" -Method Head | 
    Select-Object -ExpandProperty Headers

# Look for Server or X-Powered-By in output
```

## 11. Best Practices

✅ **Configuration:**
- Remove `Server` header via `removeServerHeader="true"` in web.config
- Remove `X-Powered-By` via `<remove name="X-Powered-By" />` in web.config
- Set `enableVersionHeader="false"` for ASP.NET applications
- Configure `AddServerHeader = false` for ASP.NET Core/Kestrel
- Apply configuration to both API and front-end web.config files

✅ **Verification:**
- Test all public endpoints (API and front-end)
- Verify in multiple environments (dev, staging, production)
- Include header checks in automated tests
- Perform regular security header audits
- Use online tools (securityheaders.com) for validation

✅ **Defense in Depth:**
- Combine with other security headers (CSP, HSTS, X-Frame-Options)
- Use web application firewall (WAF) as additional protection
- Keep frameworks and platforms updated regardless of header disclosure
- Don't rely solely on header removal for security

✅ **Documentation:**
- Document configuration in deployment guides
- Include in security baseline requirements
- Add to CI/CD pipeline verification
- Train team on information disclosure risks
