# Authentication Security Analysis

Analyze the codebase to verify that a standard, secure authentication protocol is used consistently across all API endpoints, and that key policy settings meet minimum security requirements.

## Core Security Principle
**All API endpoints must require authentication by default. The application must use OpenID Connect with Authorization Code flow and PKCE. Custom authentication solutions are not acceptable; any deviation from a standard protocol must be treated as a high-priority finding.**

## 1. Default Authorization on API Endpoints

Every API endpoint must require authorization unless explicitly and intentionally opted out with `[AllowAnonymous]`.

**Check for a global authorization policy or fallback policy:**
```csharp
// GOOD — fallback policy requires authenticated user for everything
builder.Services.AddAuthorizationBuilder()
    .SetFallbackPolicy(new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build());

// GOOD — minimal API: require authorization on all mapped controllers
app.MapControllers().RequireAuthorization();

// GOOD — MVC global filter
services.AddControllers(options =>
{
    options.Filters.Add(new AuthorizeFilter());
});
```

**RED FLAGS:**
```csharp
// BAD — no fallback policy; undecorated endpoints are anonymous by default
services.AddAuthorization();  // no FallbackPolicy set

// BAD — controller or action reachable without [Authorize] and no global policy
[HttpGet]
public IActionResult GetSensitiveData() { ... }
```

**Search for:**
- `[AllowAnonymous]` — each occurrence must be intentional and justified
- Controllers or actions without `[Authorize]` when no global policy is configured
- `FallbackPolicy` or `RequireAuthorization()` in `Program.cs` or `Startup.cs`

## 2. Swagger UI Restricted to Development

Swagger/OpenAPI UI exposes the full API surface and must not be accessible on Acceptance or Production environments.

**GOOD — gated behind environment check:**
```csharp
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
```

**RED FLAGS:**
```csharp
// BAD — Swagger enabled unconditionally
app.UseSwagger();
app.UseSwaggerUI();

// BAD — enabled outside Development
if (!app.Environment.IsProduction())
{
    app.UseSwagger();  // still accessible on Staging/Acceptance
}

// BAD — Swagger enabled via feature flag without environment guard
app.UseSwaggerUI(c => { ... });
```

**Search for:**
- `UseSwagger`, `UseSwaggerUI`, `MapSwagger` — verify each is inside an `IsDevelopment()` block
- NSwag: `app.UseOpenApi()`, `app.UseSwaggerUi()` — same requirement

## 3. OpenID Connect with Authorization Code Flow and PKCE

The application must use OpenID Connect (OIDC) with the Authorization Code flow and Proof Key for Code Exchange (PKCE). Implicit flow and Resource Owner Password Credentials flow are not acceptable.

**Backend (ASP.NET Core) — check OIDC configuration:**
```csharp
// GOOD — Authorization Code + PKCE
services.AddAuthentication()
    .AddOpenIdConnect(options =>
    {
        options.ResponseType = "code";           // Authorization Code flow
        options.UsePkce = true;                  // PKCE required
        options.Authority = "https://login.microsoftonline.com/{tenantId}/v2.0";
        options.ClientId = "...";
        // ClientSecret optional with PKCE; if used, must come from Key Vault
    });
```

**RED FLAGS:**
```csharp
// BAD — Implicit flow
options.ResponseType = "token";
options.ResponseType = "id_token token";

// BAD — PKCE disabled
options.UsePkce = false;

// BAD — Resource Owner Password Credentials (ROPC)
// typically seen as a direct call to the token endpoint with grant_type=password
```

**Frontend (Angular) — check OIDC client library configuration:**

Common libraries: `angular-oauth2-oidc`, `@azure/msal-angular`, `oidc-client-ts`

```typescript
// GOOD — angular-oauth2-oidc with PKCE
this.oauthService.configure({
  responseType: 'code',
  useSilentRefresh: false,  // use refresh tokens, not silent renew via iframe
  // ...
});

// GOOD — MSAL (always uses Authorization Code + PKCE by default for SPAs)
const msalConfig: Configuration = {
  auth: { clientId: '...', authority: '...' }
};
```

**RED FLAGS in Angular:**
```typescript
// BAD — Implicit flow in angular-oauth2-oidc
responseType: 'token'
responseType: 'id_token token'

// BAD — older MSAL v1 implicit flow configuration
```

**Search for:**
- `responseType`, `response_type` — must be `"code"` everywhere
- `UsePkce`, `usePkce`, `pkce` — must be `true` or enabled by default
- `grant_type=password` — ROPC, never acceptable
- `grant_type=implicit` — never acceptable

## 4. Non-User Account Authentication

Applications that accept requests from other applications or automated processes (service-to-service, background jobs, CI/CD pipelines) must also use a standard and secure method.

**Preferred approaches:**
```csharp
// BEST — Managed Identity (no credentials to manage)
var credential = new DefaultAzureCredential();
var token = await credential.GetTokenAsync(...);

// GOOD — Client Credentials flow with certificate (not secret)
services.AddAuthentication()
    .AddMicrosoftIdentityWebApi(configuration)
    .EnableTokenAcquisitionToCallDownstreamApi()
    .AddInMemoryTokenCaches();
// With certificate-based client assertion, not client secret
```

**RED FLAGS:**
```csharp
// BAD — Basic authentication for service accounts
client.DefaultRequestHeaders.Authorization =
    new BasicAuthenticationHeaderValue("user", "password");

// BAD — Long-lived shared API keys with no expiry
httpClient.DefaultRequestHeaders.Add("X-Api-Key", "hardcoded-or-config-key");

// BAD — Client secret instead of certificate or managed identity
options.ClientSecret = "...";  // secrets can leak; certificates or managed identities are preferred
```

**Search for:**
- `BasicAuthentication`, `Basic ` in authorization headers
- Static or long-lived API keys used for service authentication
- `ClientSecret` in OIDC or Azure AD configurations — flag if not sourced from Key Vault and recommend migration to certificate or managed identity

## 5. Role and Claims-Based Authorization

Requiring authentication on every endpoint (§1) ensures a user is logged in. This section checks that the application also enforces *what* an authenticated user is allowed to do.

**Check for coarse-grained `[Authorize]` without role or policy restrictions:**
```csharp
// BAD — any authenticated user can access admin functionality
[Authorize]
[HttpDelete("users/{id}")]
public async Task<IActionResult> DeleteUser(int id) { ... }

// GOOD — restricted to a specific role
[Authorize(Roles = "Admin")]
[HttpDelete("users/{id}")]
public async Task<IActionResult> DeleteUser(int id) { ... }

// GOOD — policy-based (preferred over hard-coded role strings)
[Authorize(Policy = "CanManageUsers")]
[HttpDelete("users/{id}")]
public async Task<IActionResult> DeleteUser(int id) { ... }
```

**Check that authorization policies are registered with meaningful requirements:**
```csharp
// GOOD — policy tied to a specific claim or role
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("CanManageUsers", policy =>
        policy.RequireRole("Admin")
              .RequireClaim("department", "IT"))
    .AddPolicy("CanViewReports", policy =>
        policy.RequireRole("Admin", "Manager"));

// BAD — policy that only checks authentication (no stricter requirement)
.AddPolicy("CanManageUsers", policy =>
    policy.RequireAuthenticatedUser());  // same as plain [Authorize]
```

**Search for:**
- Endpoints that modify or delete data without a role/policy restriction beyond `[Authorize]`
- `AddPolicy` definitions that call only `RequireAuthenticatedUser()` — these add no value over the global fallback policy
- `Roles = "..."` strings — verify roles actually exist in the identity provider and are assigned to real users

**Angular route guards — check alignment with backend roles:**
```typescript
// GOOD — Angular guard checks the same role the backend enforces
canActivate(): boolean {
  return this.authService.hasRole('Admin');
}

// BAD — route guard allows access but backend rejects the call (misleading UX, not a security bypass)
// BAD — no route guard on admin routes (user reaches the page, then sees an error)
```

**Note:** Angular route guards are a UX concern, not a security boundary. The backend must always enforce authorization independently. Missing or mismatched Angular guards are a LOW-severity finding.

**RED FLAGS:**
- Admin, management, or bulk-operation endpoints decorated only with `[Authorize]` and no role or policy
- Authorization policies that do not restrict beyond `RequireAuthenticatedUser()`
- Role strings that do not match what the identity provider issues (e.g. `"Administrator"` vs `"Admin"`)
- Angular admin routes with no route guard (LOW severity)

## 6. Environment Policy Checks (Requires Human Input)

The following settings cannot be verified from source code alone. Ask someone with access to the Acceptance and Production environments to confirm:

> **Please verify the following in the Acceptance and Production environments:**
>
> 1. **Access token lifetime** — What is the configured lifetime of access tokens? It must be no longer than **1 hour**.
>    - In Azure AD / Entra ID: check the Token Lifetime Policy assigned to the application registration
>    - Default Azure AD access token lifetime is 1 hour; confirm no policy extends this
>
> 2. **Password policy** — Does the identity provider enforce a complex password policy?
>    - In Azure AD / Entra ID: check the Password Protection and Authentication Methods policies in the tenant
>    - Minimum requirements: mixed case, numbers, special characters, minimum length of 12 characters
>    - Confirm MFA is enforced for all user accounts

## What to Report

For each finding, provide:
- **Location**: file and line number (for code findings) or environment/configuration name (for policy findings)
- **Issue**: description of the problem
- **Risk**: HIGH (no default authorization, implicit flow, ROPC, Swagger on production) / MEDIUM (PKCE missing, non-user accounts using secrets instead of certificates, Swagger on Acceptance) / LOW (token lifetime slightly above threshold, weak password policy)
- **Recommendation**: the specific configuration change or policy update required
