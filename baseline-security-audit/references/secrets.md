# Secrets and Credential Security Analysis

Analyze the codebase to identify hardcoded secrets, credentials, and sensitive configuration data that could pose security risks if exposed:

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A02 Security Misconfiguration · **ASVS 5.0:** V13 Configuration
> **Owns:** Credential-bearing value in an Angular environment file (also encountered in check 12)
> **Defers to:** Public identifiers (client id, tenant id, instrumentation key) shared across environments → check 12 (environment_credentials.md)

## Core Security Principle
**No secrets, credentials, API keys, or sensitive configuration should be hardcoded in source code. All sensitive data must be externalized to secure configuration stores and properly protected.**

## Not a Finding: Public Identifiers

**Do not report public, non-secret identifiers as hardcoded secrets.** These values are designed to be visible (they ship in every SPA bundle and in OpenID discovery documents) and grant no access on their own:

- Microsoft Entra ID / Azure AD / CIAM: `Instance`, `Authority`, `TenantId`, `ClientId` (application ID), `Audience`, `Scope` / `api://...` URIs, redirect URIs, certificate thumbprints
- Other OAuth/OIDC providers: public client IDs, issuer and authority URLs
- Application Insights connection strings and instrumentation keys, Azure resource names, subscription and tenant GUIDs

Committed values like these in `appsettings*.json`, `environment.ts` or pipeline variables are **not** a Secrets Management finding. Only report them when a credential is committed alongside them — a `ClientSecret`, certificate/private key, password, or a connection string with embedded credentials — and in that case report the credential, not the identifier. Reuse of such an identifier across environments is a Low hygiene finding owned by check 12 (environment_credentials.md); reference that finding instead of reporting it here.

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

## 5. Third-Party Service Credentials

**Audit integration credentials and service connections:**
- Database connection strings
- External API credentials (payment processors, email services)
- Cloud service authentication (Azure, AWS, Google)
- OAuth client secrets
- Webhook secrets and signing keys

**Common third-party services to check:**
- Payment gateways (Stripe, PayPal)
- Email services (SendGrid, Mailgun)
- SMS/Communication services
- Storage services (Azure Blob, AWS S3)
- Monitoring and logging services

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

## What to Report

For each finding, provide:
- **File** and line number
- **Secret type**: API key, password, connection string, certificate, etc.
- **Code snippet** showing the hardcoded or exposed value (redact actual secret in report)
- **Severity**: Critical (production credentials, encryption or signing keys, payment API keys — a secret in source, config or logs per the Severity Scale) / High (credentials for shared non-production environments such as test or acceptance, internal service tokens) / Low (real but local-only credentials, e.g. the SA password in `docker-compose.yml` for a developer database). Placeholder or example values (see the exclusions in section 1) are not findings.
- **Recommendation**: move to a secure configuration store (Azure Key Vault, environment variables, user secrets) and rotate any exposed credentials immediately

