# Secrets and Credential Security Analysis

Analyze the codebase to identify hardcoded secrets, credentials, and sensitive configuration data that could pose security risks if exposed:

## Core Security Principle
**No secrets, credentials, API keys, or sensitive configuration should be hardcoded in source code. All sensitive data must be externalized to secure configuration stores and properly protected.**

## 1. Hardcoded Secrets Detection

**Search for common secret patterns in all files:**
- API keys, access tokens, and authentication credentials
- Database connection strings with embedded passwords
- Service account keys and certificates
- JWT signing secrets and encryption keys
- Third-party service credentials

**Search for:**
```regex
// API Keys and Tokens
(api[_-]?key|apikey|access[_-]?token|secret[_-]?key|private[_-]?key)\s*[=:]\s*["']?[a-zA-Z0-9]{20,}["']?

// Connection Strings with Credentials
(connection[_-]?string|server\s*=|data\s*source\s*=|password\s*=|pwd\s*=|user\s*id\s*=)

// Passwords and Secrets
(password|pwd|pass|secret|token)\s*[=:]\s*["'][^"']{3,}["']

// Azure/Cloud Service Keys
(azure|aws|gcp)[_-]?(key|secret|token|credential)

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
*.yml (pipelines), *.json (GitHub Actions)
```

## 3. Source Code Secret Patterns

**Identify dangerous coding patterns that expose secrets:**
- Hardcoded connection strings in C# code
- API keys embedded in HTTP client configurations
- Passwords in authentication code
- Service URLs with embedded credentials
- Certificate thumbprints and private keys

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
- OAuth client secrets and redirect URIs
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
*.pfx, *.p12, *.pem, *.key file references
X509Certificate, RSA, HMAC implementations
CertificateThumbprint configurations
SigningCredentials and SymmetricSecurityKey usage
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
- **Risk**: HIGH (production credentials, encryption keys, payment API keys) / MEDIUM (non-production credentials, internal service tokens) / LOW (placeholder or example values that may be real)
- **Recommendation**: move to a secure configuration store (Azure Key Vault, environment variables, user secrets) and rotate any exposed credentials immediately

