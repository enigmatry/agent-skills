# CORS Configuration Analysis

Analyze the codebase to verify that Cross-Origin Resource Sharing (CORS) is configured correctly and does not allow untrusted origins to make authenticated cross-origin requests.

## Core Security Principle
**CORS must be configured with an explicit allowlist of trusted origins. Wildcard origins (`*`) must never be combined with `AllowCredentials`. Overly permissive CORS policies allow malicious sites to make cross-origin requests on behalf of authenticated users.**

## 1. ASP.NET Core CORS Setup

CORS is configured in `Program.cs` or `Startup.cs` using `AddCors` and `UseCors`.

**Check how CORS is registered and which policy is applied:**
```csharp
// GOOD — named policy with explicit origins
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        policy.WithOrigins("https://app.example.com")
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
});

app.UseCors("AllowFrontend");

// GOOD — per-environment origin list from configuration
policy.WithOrigins(
    configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? []);
```

**RED FLAGS:**
```csharp
// CRITICAL — wildcard + AllowCredentials (a configuration error; browsers will reject it)
policy.AllowAnyOrigin().AllowCredentials();

// BAD — wildcard allows any site to make cross-origin reads
policy.AllowAnyOrigin();

// BAD — SetIsOriginAllowed with a catch-all predicate
policy.SetIsOriginAllowed(_ => true).AllowCredentials();
```

**Search for:**
- `AddCors`, `UseCors` — in `Program.cs` / `Startup.cs`; verify a policy is actually applied
- `AllowAnyOrigin` — must never appear in the primary API policy
- `AllowCredentials()` — must only appear alongside `WithOrigins(...)`, never with `AllowAnyOrigin`

## 2. Origin Allowlist Configuration

Origins must be environment-specific and stored in configuration, not hardcoded in code.

**GOOD — origins from appsettings per environment:**
```json
// appsettings.Development.json
{
  "Cors": {
    "AllowedOrigins": ["http://localhost:4200", "https://localhost:4200"]
  }
}

// appsettings.Production.json
{
  "Cors": {
    "AllowedOrigins": ["https://app.example.com"]
  }
}
```

**RED FLAGS:**
```csharp
// BAD — production domain hardcoded alongside localhost in a single call
policy.WithOrigins("http://localhost:4200", "https://app.example.com");

// BAD — HTTP origin in production (only HTTPS is acceptable)
policy.WithOrigins("http://app.example.com");

// BAD — trailing slash (browsers never include one in the Origin header)
policy.WithOrigins("https://app.example.com/");
```

**Search for:**
- `WithOrigins(` — review each call for hardcoded or non-HTTPS origins
- `"http://"` in any CORS origin list — all production origins must use HTTPS
- `"localhost"` appearing outside a Development-specific config file

## 3. Credentials and Sensitive Headers

When the Angular SPA sends cookies or `Authorization` headers cross-origin, `AllowCredentials()` is required on the server and the origin must be explicitly specified.

**GOOD:**
```csharp
policy.WithOrigins("https://app.example.com")
      .AllowAnyHeader()
      .AllowAnyMethod()
      .AllowCredentials();
```

**RED FLAGS:**
```csharp
// CRITICAL — wildcard + credentials
policy.AllowAnyOrigin().AllowCredentials();

// BAD — predicate that always returns true with credentials
policy.SetIsOriginAllowed(_ => true).AllowCredentials();
```

**Check Angular HTTP client configuration:**
```typescript
// GOOD — withCredentials only when required by the backend
this.http.get('/api/data', { withCredentials: true });

// BAD — withCredentials: true sent to an endpoint backed by a wildcard CORS policy
```

**Search for:**
- `withCredentials: true` in Angular — verify the corresponding backend CORS policy uses `WithOrigins`, not `AllowAnyOrigin`

## 4. Angular Development Proxy vs Production

Angular's development proxy (`proxy.conf.json`) forwards requests from `localhost:4200` to the backend, bypassing CORS entirely during development. This must not replace proper CORS configuration.

**Files to check:**
- `proxy.conf.json` or `proxy.conf.js` — development only
- `angular.json` — verify `proxyConfig` is referenced only under the `development` build configuration

**RED FLAGS:**
- No CORS policy configured on the backend while a development proxy is in use — CORS may be broken in all non-local environments
- `"proxyConfig"` referenced under a `production` or `staging` build configuration in `angular.json`
- Backend never tested for CORS without the proxy (test by running the Angular app pointing directly at the API without the proxy)

**Search for:**
- `"proxyConfig"` in `angular.json` — must appear only inside the `development` configuration block
- `proxy.conf.json` / `proxy.conf.js` — confirm it is not deployed or referenced in CI/CD pipelines

## 5. Pre-flight and Method/Header Allowances

Over-broad allowances become critical when combined with `AllowAnyOrigin`. In isolation they are lower risk.

**GOOD — restrict to what the API actually uses:**
```csharp
policy.WithMethods("GET", "POST", "PUT", "DELETE")
      .WithHeaders("Content-Type", "Authorization");
```

**Note:** `AllowAnyMethod` and `AllowAnyHeader` are generally acceptable for authenticated APIs where origin restrictions are the primary control. Flag them only when combined with `AllowAnyOrigin`.

## What to Report

For each finding, provide:
- **Location**: file and line number
- **Issue**: description of the CORS misconfiguration
- **Risk**: HIGH (`AllowAnyOrigin` combined with `AllowCredentials`, no CORS policy configured on an API consumed cross-origin) / MEDIUM (`AllowAnyOrigin` without credentials, HTTP origins in production, hardcoded origins mixing environments) / LOW (`AllowAnyMethod`/`AllowAnyHeader` without `AllowAnyOrigin`, localhost origins present in non-development configuration)
- **Recommendation**: the specific configuration change required
