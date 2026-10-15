# Secrets and Credentials Analysis

Analyze the codebase to identify hardcoded secrets, credentials, and sensitive configuration data that could pose security risks if exposed, and credential reuse across environments (development, test, acceptance, production) that increases the blast radius of a security incident:

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A02 Security Misconfiguration · **ASVS 5.0:** V13 Configuration

## Core Security Principle
**No secrets, credentials, API keys, or sensitive configuration should be hardcoded in source code. All sensitive data must be externalized to secure configuration stores and properly protected. Each environment (development, test, acceptance, production) MUST use different credentials for accessing resources like databases, APIs, storage accounts, and third-party services: credential reuse across environments increases the blast radius of security incidents and can lead to accidental data corruption or exposure.**

## Not a Finding: Public Identifiers

**Do not report public, non-secret identifiers as hardcoded secrets.** These values are designed to be visible (they ship in every SPA bundle and in OpenID discovery documents) and grant no access on their own:

- Microsoft Entra ID / Azure AD / CIAM: `Instance`, `Authority`, `TenantId`, `ClientId` (application ID), `Audience`, `Scope` / `api://...` URIs, redirect URIs, certificate thumbprints
- Other OAuth/OIDC providers: public client IDs, issuer and authority URLs
- Application Insights connection strings and instrumentation keys, Azure resource names, subscription and tenant GUIDs
- Third-party public keys: analytics IDs, Google Maps browser keys, reCAPTCHA site keys, Stripe publishable keys

Committed values like these in `appsettings*.json`, `environment.ts` or pipeline variables are **not** a Secrets Management finding. Only report them when a credential is committed alongside them — a `ClientSecret`, certificate/private key, password, or a connection string with embedded credentials — and in that case report the credential, not the identifier. When one of these identifiers is reused across environments, report it once as a **Low** hygiene finding (separate app registrations and telemetry resources per environment are good practice), never as credential reuse.

## 1. Hardcoded Secrets Detection

**Search for common secret patterns in all files:**
- API keys, access tokens, and authentication credentials
- Database connection strings with embedded passwords
- Service account keys and certificates
- JWT signing secrets and encryption keys
- Third-party service credentials

**Search for:**
```regex
// API Keys and Tokens (charset includes base64 +/= and JWT/prefixed-token characters _-.)
(api[_-]?key|apikey|access[_-]?token|secret[_-]?key|private[_-]?key)\s*[=:]\s*["']?[A-Za-z0-9_\-\.+/=]{16,}["']?

// Connection Strings — only a hit when a credential term is present
// (Server=/Data Source= with Integrated Security=true or Authentication=Active Directory Default contain no secret)
(Password|Pwd|AccountKey|SharedAccessKey|SharedAccessSignature)\s*=\s*[^;"'\s]{4,}

// Passwords and Secrets — assigned to a literal
(password|pwd|pass|secret|token)\s*[=:]\s*["'][^"']{3,}["']

// Azure/Cloud Service Keys — require an assignment to a literal; the bare word list
// matches identifiers such as AzureKeyVault or DefaultAzureCredential
(azure|aws|gcp)[_-]?(key|secret|token|credential)\s*[=:]\s*["'][^"']{8,}["']
```

**Exclude from the patterns above** (otherwise every i18n label, test fixture and placeholder becomes a finding):
- Paths: `*.resx`, `**/i18n/**`, `**/assets/i18n/**`, `**/*.spec.*`, `**/*.test.*`, `**/test*/**`, `**/__mocks__/**`, `**/node_modules/**`
- Placeholder values: `<...>`, `changeme`, `your-*`, `xxx`, `***`, `#{Token}#`, `$(Var)`, `${{ }}`, `@Microsoft.KeyVault(SecretUri=...)`, `TODO`, `REPLACE`
- Public keys that look like secrets: Stripe `pk_live_`/`pk_test_`, reCAPTCHA site keys, Firebase web API keys, Sentry DSNs, Mapbox `pk.`, Google Maps browser keys, MSAL/Auth0 client IDs

```regex
// JWT and Encryption
(jwt[_-]?secret|signing[_-]?key|encryption[_-]?key|hmac[_-]?secret)
```

## 2. Configuration File Analysis

**Examine all configuration files for sensitive data:**
- Application configuration files (appsettings.json, web.config)
- Environment configuration files (.env, .env.local)
- Build and deployment configuration
- Docker and containerization files
- CI/CD pipeline configuration

**Search in:**
```bash
// Configuration file patterns
*.json, *.config, *.xml, *.env, *.yml, *.yaml
// Build configuration
*.proj, *.targets, Dockerfile, docker-compose.yml
// CI/CD files
*.yml (Azure Pipelines), .github/workflows/*.yml (GitHub Actions)
```

## 3. Source Code Secret Patterns

**Identify dangerous coding patterns that expose secrets:**
- Hardcoded connection strings in C# code
- API keys embedded in HTTP client configurations
- Passwords in authentication code
- Service URLs with embedded credentials
- Private keys and certificate files (`.pfx`/`.p12`) with their passwords

**High-risk patterns to identify:**
```csharp
// DANGEROUS: Hardcoded connection strings
var connectionString = "Server=prod-server;Database=mydb;User=sa;Password=MyPassword123;";

// DANGEROUS: API keys in code
var apiKey = "sk-1234567890abcdef1234567890abcdef";
httpClient.DefaultRequestHeaders.Add("X-API-Key", "live-key-12345");

// DANGEROUS: Hardcoded credentials
var username = "admin";
var password = "SuperSecret123!";

// SAFER: Using configuration
var connectionString = _configuration.GetConnectionString("DefaultConnection");
var apiKey = _configuration["ExternalApi:ApiKey"];
```

## 4. Environment-Specific Configuration Security

**Verify proper secret management across environments:**
- Development vs. Production configuration separation
- Secret rotation and management practices
- Use of secure configuration providers (Azure Key Vault, AWS Secrets Manager)
- Environment variable usage for sensitive data

**Check for:**
```csharp
// Proper secret management patterns
services.AddAzureKeyVault(configuration);
Environment.GetEnvironmentVariable("SECRET_NAME");
_configuration["ConnectionStrings:Database"]; // From secure store

// AVOID: Environment-specific hardcoding
#if DEBUG
    var apiUrl = "https://dev-api.example.com/key123";
#else
    var apiUrl = "https://prod-api.example.com/livekey456"; // ❌ Still hardcoded
#endif
```

**Check the infrastructure repository for Key Vault configuration:**

**Infrastructure repository**: The shared Bicep files for all projects are at `https://dev.azure.com/enigmatry/Enigmatry%20-%20CICD%20Azure%20Infra/_git/enigmatry-cicd-azure-infra`. 
Clone it with git — no special tooling is required. Ask the user for the project folder path (e.g. /tenants/enigmatry/projects/my-project) before cloning

```bicep
// GOOD — soft delete and purge protection guard against accidental or malicious deletion
resource keyVault 'Microsoft.KeyVault/vaults@2022-07-01' = {
  properties: {
    enableSoftDelete: true
    enablePurgeProtection: true
    enableRbacAuthorization: true  // Prefer RBAC over legacy access policies
  }
}

// RED FLAG — purge protection disabled (secrets can be permanently and immediately deleted)
properties: {
  enableSoftDelete: true
  enablePurgeProtection: false
}

// RED FLAG — secrets hardcoded as Bicep parameters passed at deploy time
// (values end up in deployment history in plain text)
param mySecret string  // if wired to a Key Vault secret value, this is acceptable;
                       // if the actual secret string is passed directly, flag it
```

## 5. Credential Types to Verify

**Audit every credential type below, both for hardcoded values (sections 1–4) and for reuse across environments (section 8):**

**Database credentials:**
- Connection strings with embedded passwords
- SQL Server, PostgreSQL and MySQL users
- MongoDB and Redis connection strings
- Cosmos DB account keys

**Azure/Cloud credentials:**
- Service principal client secrets and certificates (client IDs are public identifiers — Low if shared)
- Managed Identity names
- Storage account names and keys (Azure Blob, AWS S3)
- App Service deployment credentials
- Function App keys
- Service Bus and Event Hub connection strings
- Application Insights instrumentation keys and connection strings (public identifier — Low if shared)

**Third-party service credentials:**
- Payment gateway API keys (Stripe, PayPal)
- Email service API keys (SendGrid, Mailgun)
- SMS/Communication service credentials
- Monitoring and logging service credentials
- CDN credentials
- Webhook secrets and signing keys
- Analytics tracking IDs, map service browser keys, reCAPTCHA site keys, Stripe publishable keys (public identifiers — Low if shared)

**Identity and authentication:**
- Azure AD app registrations (separate per environment)
- OAuth client secrets (client IDs are public identifiers — Low if shared)
- JWT signing keys
- API authentication tokens
- Service account credentials

## 6. Certificate and Key Management

**Examine certificate and cryptographic key handling:**
- SSL/TLS certificate private keys
- Code signing certificates
- JWT signing certificates
- Encryption keys for data protection
- Service-to-service authentication certificates

**Search for:**
```csharp
// Certificate and key patterns
*.pfx, *.p12, *.pem, *.key file references and committed files
X509Certificate, RSA, HMAC implementations
PFX password configuration keys (CertificatePassword, PfxPassword)
SigningCredentials and SymmetricSecurityKey usage
// Not a finding: CertificateThumbprint configurations (a thumbprint is a public identifier)
```

## 7. Version Control and Git History Analysis

**Check for secrets in version control:**
- Committed configuration files with secrets
- Git history containing removed secrets
- Branch protection and secret scanning
- .gitignore effectiveness for sensitive files

**Files that should never contain secrets:**
```bash
# Configuration files in source control
appsettings.json, appsettings.Production.json
web.config, app.config
# Environment files
.env, .env.production, .env.local
# Build files
*.csproj, *.props, Dockerfile
```

## 8. Credential Separation per Environment

**Compare the environment-specific configuration files against each other.** Every credential type in section 5 must differ per environment; public identifiers (see Not a Finding: Public Identifiers) are compared too but rate Low only. A secret-bearing value (password, client secret, account key, API secret, connection string with embedded credentials) that is committed in any of these files is a hardcoded-secret finding under sections 1–7, whether or not it is reused.

### ASP.NET Core configuration files

**Files to examine:**
- `appsettings.json` - Base configuration
- `appsettings.Development.json` - Development environment
- `appsettings.Test.json` - Test environment
- `appsettings.Staging.json` - Staging/Acceptance environment
- `appsettings.Production.json` - Production environment
- `appsettings.*.json` - Any other environment-specific files

**Credentials to compare across environments:**

**Database connection strings:**
```json
// Check for identical values across environments
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=...;Database=...;User Id=sa;Password=...",
    "AppDatabase": "Server=...;User Id=appuser;Password=..."
  }
}
```

**Azure/Cloud service credentials:**
```json
{
  "AzureAd": {
    "ClientId": "...",        // Application/Client ID — public identifier, Low if reused
    "ClientSecret": "...",    // Client secret — credential
    "TenantId": "..."         // Tenant ID — public identifier, may legitimately be the same
  },
  "Storage": {
    "AccountName": "...",     // Storage account name
    "AccountKey": "...",      // Storage account key
    "ConnectionString": "..." // Full connection string
  },
  "ServiceBus": {
    "ConnectionString": "...",
    "Namespace": "..."
  },
  "KeyVault": {
    "VaultUri": "...",
    "ClientId": "...",        // public identifier, Low if reused
    "ClientSecret": "..."     // credential
  }
}
```

**API credentials and keys:**
```json
{
  "ExternalApis": {
    "PaymentGateway": {
      "ApiKey": "...",
      "ApiSecret": "...",
      "MerchantId": "..."
    },
    "EmailService": {
      "ApiKey": "...",
      "SenderId": "..."
    }
  }
}
```

**Service account credentials:**
```json
{
  "ServiceAccounts": {
    "Username": "...",
    "Password": "...",
    "Domain": "..."
  }
}
```

### Angular environment files

**Files to examine:**
- `src/environments/environment.ts` - Production (the default build target since Angular 15)
- `src/environments/environment.development.ts` - Development override
- `src/environments/environment.<env>.ts` - Test, staging or any other override
- Derive the actual mapping from `angular.json`: `projects.<name>.architect.build.configurations.<config>.fileReplacements` names the file that replaces `environment.ts` for each configuration; older projects may still use `environment.prod.ts` as the production override

**Compare configuration values:**
```typescript
export const environment = {
  production: false,
  apiUrl: 'https://api.dev.example.com',
  apiKey: 'dev_api_key_...',  // Secret-bearing value: a hardcoded-secret finding (section 1), not a reuse comparison

  // Azure AD configuration
  clientId: '...',             // Public identifier — Low hygiene finding if reused across environments
  tenantId: '...',             // Public identifier — may legitimately be the same
  authority: '...',

  // Third-party public keys
  googleMapsApiKey: '...',     // Browser key — public identifier, Low if reused
  analyticsId: '...',          // Public identifier — Low if reused

  // Feature flags
  features: {
    enableBetaFeatures: true
  }
};
```

**Checks:**
- OAuth client IDs reused across environments (public identifier; separate app registrations per environment — Low)
- Third-party public keys reused across environments (Google Maps browser keys, reCAPTCHA site keys, Stripe publishable keys, analytics IDs — Low)
- Backend API URLs (should point to correct environment)

**Note:** Angular environment files are compiled into the application bundle. Sensitive credentials should NOT be stored here; any secret-bearing value found here is a hardcoded-secret finding (section 1). Only public keys and identifiers are compared for reuse.

### Azure Pipeline variable files

**Files to examine:**
- `/variables.dev.yml` - Development variables
- `/variables.test.yml` - Test variables
- `/variables.acceptance.yml` - Staging/Acceptance variables
- `/variables.prod.yml` - Production variables
- `/variables.[env].yml` - Any environment-specific variable files

**Credentials to compare:**
- Database usernames and server names
- Azure AD Client IDs / Application IDs (public identifiers — Low if shared)
- Storage account names
- Service principal IDs (public identifiers — Low if shared)
- API keys and endpoints
- Service connection names
- Key Vault names and URIs

**Flags to raise:**
- Identical `DatabaseUsername` across environments
- Same `AzureClientId` or `ServicePrincipalId` values (Low — public identifier, hygiene)
- Shared `ApiKey` values
- Same `StorageAccountName` (should be globally unique per environment)

### Deployment profiles

**Files to examine:**
- `publish-web-profile-dev-*.proj` - Development deployment profile
- `publish-web-profile-test-*.proj` - Test deployment profile
- `publish-web-profile-acc-*.proj` - Staging/Acceptance deployment profile
- `publish-web-profile-prod-*.proj` - Production deployment profile
- `publish-web-profile-[env]-*.proj` - Any environment-specific deployment profiles

### Remediation recommendations

**For database credentials:**
1. Create separate database users per environment
2. Grant minimum required permissions per environment
3. Use different passwords per environment
4. Consider using managed identities (no passwords needed)

**For Azure resources:**
1. Create separate app registrations per environment
2. Use separate service principals per environment
3. Implement separate managed identities per environment
4. Use environment-specific resource groups and subscriptions

**For third-party APIs:**
1. Request separate API keys per environment from vendors
2. Use environment-specific accounts/tenants where available
3. Implement proper key rotation
4. Use test/sandbox APIs for non-production environments

**For deployment:**
1. Use separate service connections per environment in CI/CD
2. Implement environment-specific variable groups
3. Use Azure KeyVault references for secrets
4. Implement approval gates for production deployments

## What to Report

### Hardcoded secrets

For each finding, provide:
- **File** and line number
- **Secret type**: API key, password, connection string, certificate, etc.
- **Code snippet** showing the hardcoded or exposed value (redact actual secret in report)
- **Severity**: Critical (production credentials, encryption or signing keys, payment API keys — a secret in source, config or logs per the Severity Scale) / High (credentials for shared non-production environments such as test or acceptance, internal service tokens) / Low (real but local-only credentials, e.g. the SA password in `docker-compose.yml` for a developer database). Placeholder or example values (see the exclusions in section 1) are not findings.
- **Recommendation**: move to a secure configuration store (Azure Key Vault, environment variables, user secrets) and rotate any exposed credentials immediately

### Credential reuse across environments

**Report ALL instances of credential reuse (severity varies by environment pair and by whether the value is a credential or a public identifier):**

**Critical:**
- **Production credentials reused in Test/Development**
  - Immediate security risk
  - Could lead to production data exposure
  - Accidental production changes from non-prod code

- **Production credentials reused in Staging/Acceptance**
  - High risk of production impact
  - Testing could affect production systems

**High:**
- **Staging/Acceptance credentials reused in Test/Development**
  - Risk of environment contamination
  - Staging should mirror production security

- **Same service principal/app registration across all environments** (the client secret or certificate is shared; a shared `ClientId` alone is Low)
  - Compromised dev credentials affect all environments
  - Difficult to audit and track environment-specific access

**Medium:**
- **Test credentials reused in Development**
  - Less critical but still not best practice
  - Makes access auditing difficult

- **Shared secret API keys across any environments**
  - Cannot revoke for one environment without affecting others
  - Difficult to track usage per environment

**Low:**
- **Public identifiers shared across environments** (ClientId, TenantId, service principal IDs, Application Insights instrumentation keys or connection strings, analytics IDs, Google Maps browser keys, reCAPTCHA site keys, Stripe publishable keys)
  - Hygiene only: no access is granted by the value itself
  - Separate app registrations and telemetry resources per environment keep audit trails clean

- **Same database username with a different password on a different server**
  - Hygiene only; becomes the same credential (rate per the matrix above) when the password or the server is also shared

**For each credential reuse instance, provide:**
1. **File paths** where credentials appear
2. **Credential type** (database user, API key, client ID, etc.)
3. **Credential identifier** (username, account name, app ID - NOT the password/secret)
4. **Environments affected** (which environments share the credential)
5. **Severity** (Critical / High / Medium / Low) based on the matrix above
6. **Impact assessment**:
   - What resources does this credential access?
   - What could happen if dev/test credential is compromised?
   - Could this lead to production data access?
7. **Recommended remediation**:
   - Create separate credentials per environment
   - Use environment-specific app registrations
   - Implement proper key rotation strategy

**Example report format:**
```
Finding: Database Username Reused Across Environments
- File 1: appsettings.Development.json
- File 2: appsettings.Production.json
- Credential Type: SQL Database Username
- Value: "app_user"
- Severity: Low (the servers and the passwords differ; when the password is also shared or both files point at the same server it is the same credential and is rated per the matrix above — Critical for a production credential in Development)
- Impact: A shared login name makes per-environment auditing and revocation harder
- Recommendation: Create separate database users (e.g., app_user_dev, app_user_prod)
```
