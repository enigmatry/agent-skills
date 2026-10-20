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

**Also examine (high-yield, often overlooked; a production credential in any of them is Critical per What to Report):**
- `Properties/launchSettings.json`, `*.pubxml` / `*.pubxml.user`, `local.settings.json`, Data Protection `key-*.xml`
- `.npmrc` (`_authToken`, `:_password=`), `nuget.config` `<packageSourceCredentials>` with `ClearTextPassword`
- `web.config` `<aspNetCore><environmentVariables>`, `Jwt:Key` / signing keys in `appsettings*.json`
- `*.bicepparam` and `*.parameters.json`, `docker-compose*.yml` `environment:`, inline `variables:` in `azure-pipelines*.yml`
- Tool configs: `.mcp.json`, `.vscode/settings.json`

## 3. Source Code Secret Patterns

**Identify dangerous coding patterns that expose secrets:**
- Hardcoded connection strings in C# code
- API keys embedded in HTTP client configurations
- Passwords in authentication code
- Service URLs with embedded credentials
- Private keys and certificate files (`.pfx`/`.p12`) with their passwords

## 4. Environment-Specific Configuration Security

**Verify proper secret management across environments:**
- Development vs. Production configuration separation
- Secret rotation and management practices
- Use of secure configuration providers (Azure Key Vault, AWS Secrets Manager)
- Environment variable usage for sensitive data

Secure patterns: `builder.Configuration.AddAzureKeyVault(new Uri(vaultUri), new ManagedIdentityCredential())` (`Azure.Extensions.AspNetCore.Configuration.Secrets`), environment variables, user secrets in development. A `#if DEBUG` switch between two literal values is still a hardcoded secret.

**Key Vault definition in the infrastructure repository (SKILL.md Step 1):**

```bicep
// GOOD — soft delete and purge protection guard against accidental or malicious deletion
resource keyVault 'Microsoft.KeyVault/vaults@2024-11-01' = {
  properties: {
    enableSoftDelete: true
    enablePurgeProtection: true
    enableRbacAuthorization: true  // Prefer RBAC over legacy access policies
  }
}

// RED FLAG — secrets hardcoded as Bicep parameters passed at deploy time
// (values end up in deployment history in plain text)
param mySecret string  // if wired to a Key Vault secret value, this is acceptable;
                       // if the actual secret string is passed directly, flag it
```

Soft delete can no longer be disabled (the opt-out was removed in February 2025) and purge protection is irreversible once enabled, so `enableSoftDelete` needs no check: the only red flag is `enablePurgeProtection` absent or `false` (Medium). Use API version `2024-11-01` or later in new vault resources. Source: https://learn.microsoft.com/en-US/Azure/key-vault/general/key-vault-recovery

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

**Run the scan:**
```bash
gitleaks git . --redact --report-format json --report-path gitleaks-history.json   # full git history
gitleaks dir . --redact                                                            # working tree
# `gitleaks detect` / `gitleaks protect` are deprecated since gitleaks 8.19
```
Source: https://github.com/gitleaks/gitleaks

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

**Base-file inheritance:** a value in `appsettings.json` applies to every environment whose override file does not replace it, so compare the effective value per environment (base plus override), not the files in isolation. A production connection string or credential in the base file is effectively shared with every environment (High).

**Keys to compare** (effective value per environment): `ConnectionStrings:*`; `AzureAd:ClientSecret` (credential) next to `ClientId` / `TenantId` (public identifiers, Low); `Storage:AccountKey` / `ConnectionString`; `ServiceBus:ConnectionString` / `Namespace`; `KeyVault:VaultUri` / `ClientSecret`; `ExternalApis:*:ApiKey` / `ApiSecret` / `MerchantId`; `ServiceAccounts:Username` / `Password`.

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

Also compare the backend API URLs; each must point at its own environment.

### Azure Pipeline variable files

**Files to examine:**
- `/variables.dev.yml` - Development variables
- `/variables.test.yml` - Test variables
- `/variables.acceptance.yml` - Staging/Acceptance variables
- `/variables.prod.yml` - Production variables
- `/variables.[env].yml` - Any environment-specific variable files

**Flags to raise:**
- Identical `DatabaseUsername` across environments
- Same `AzureClientId` or `ServicePrincipalId` values (Low — public identifier, hygiene)
- Shared `ApiKey` values
- Same `StorageAccountName`, SQL Server host, Key Vault name or URI, Service Bus namespace or app registration — shared infrastructure between two environments (Medium; production sharing with any non-production environment = High)

**Secret handling in pipeline steps:** secret variables (variable-group secrets, Key Vault task outputs, `isSecret`) reach scripts only through an explicit `env:` mapping on the step, never as command-line arguments (`-Password $(DbPassword)`) or `echo`ed; a value derived from a secret is re-marked with `##vso[task.setvariable variable=x;issecret=true]`; masking is best-effort and never masks substrings or transformed values. A secret on a command line or echoed = Medium.

### Deployment profiles

**Files to examine:** `publish-web-profile-<env>-*.proj` (dev, test, acc, prod and any other environment); compare the same keys as above.

### Remediation

Separate database users, app registrations, service principals, managed identities, API keys and CI/CD service connections per environment, with environment-specific variable groups and Key Vault references. **Prefer eliminating secrets altogether:** managed identity, workload identity federation or certificates instead of client secrets (rated by check 19 (authentication_security.md) section 4), and Entra authentication with `disableLocalAuth` instead of SQL passwords and Storage / Service Bus / Cosmos DB account keys (Medium where possible).

## What to Report

### Hardcoded secrets

For each finding, provide:
- **File** and line number
- **Secret type**: API key, password, connection string, certificate, etc.
- **Code snippet** showing the hardcoded or exposed value (redact actual secret in report)
- **Severity**: Critical (production credentials, encryption or signing keys, payment API keys — a secret in source, config or logs per the Severity Scale) / High (credentials for shared non-production environments such as test or acceptance, internal service tokens) / Low (real but local-only credentials, e.g. the SA password in `docker-compose.yml` for a developer database). Placeholder or example values (see the exclusions in section 1) are not findings.
- **Recommendation**: move to a secure configuration store (Azure Key Vault, environment variables, user secrets) and rotate any exposed credentials immediately

### Configuration and tooling

- **Medium**: SQL passwords or Storage / Service Bus / Cosmos DB account keys used where Entra authentication with `disableLocalAuth` is possible (section 8); Key Vault with `enablePurgeProtection` absent or `false` (section 4). `ClientSecret` where managed identity or federation is possible is rated by check 19 (authentication_security.md)
- **Medium**: a pipeline secret passed as a command-line argument or echoed instead of mapped through `env:` (section 8)

### Credential reuse across environments

**Credential reuse severity** (by environment pair and by whether the value is a credential or a public identifier):

| Reuse | Severity |
|-------|----------|
| Production credential reused in any non-production environment | Critical |
| Staging/Acceptance credential reused in Test/Development; the same service principal or app registration secret or certificate across environments (a shared `ClientId` alone is Low) | High |
| Test credential reused in Development; shared infrastructure between two environments (SQL Server host, Key Vault, storage account, Service Bus namespace, app registration; High when production is one of them); a secret API key shared across environments | Medium |
| Public identifiers shared (ClientId, TenantId, service principal ids, Application Insights keys, analytics ids, browser keys); the same database username with a different password on a different server | Low |

**For each credential reuse instance, provide:** file paths, credential type, credential identifier (username, account name, app id, never the secret), environments affected, severity from the table, what the credential can access, and the remediation (separate credentials or app registrations per environment, rotation).
