# Environment Credentials Separation Analysis

Analyze the codebase to identify credential reuse across different environments (development, test, acceptance, production) that could lead to security breaches and environment contamination:

## Core Security Principle
**Each environment (development, test, acceptance, production) MUST use different credentials for accessing resources like databases, APIs, storage accounts, and third-party services. Credential reuse across environments increases the blast radius of security incidents and can lead to accidental data corruption or exposure.**

## 1. ASP.NET Core Configuration Files

**Check all appsettings files for credential reuse:**

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
    "ClientId": "...",        // Application/Client ID
    "ClientSecret": "...",    // Client secret
    "TenantId": "..."         // Tenant ID
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
    "ClientId": "...",
    "ClientSecret": "..."
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

## 2. Angular Environment Files

**Angular-specific configuration:**

**Files to examine:**
- `src/environments/environment.ts` - Development (default)
- `src/environments/environment.prod.ts` - Production
- `src/environments/environment.test.ts` - Test
- `src/environments/environment.staging.ts` - Staging
- Any custom environment files

**Compare configuration values:**
```typescript
export const environment = {
  production: false,
  apiUrl: 'https://api.dev.example.com',
  apiKey: 'dev_api_key_...',  // Should differ per environment
  
  // Azure AD configuration
  clientId: '...',             // Should differ per environment
  tenantId: '...',             // May be same or different
  authority: '...',
  
  // Third-party service keys
  googleMapsApiKey: '...',     // Should differ per environment
  analyticsId: '...',          // Should differ per environment
  
  // Feature flags
  features: {
    enableBetaFeatures: true
  }
};
```

**Critical checks:**
- API keys embedded in environment files
- OAuth client IDs (should have separate apps per environment)
- Third-party service keys
- Backend API URLs (should point to correct environment)

**Note:** Angular environment files are compiled into the application bundle. Sensitive credentials should NOT be stored here; instead use backend configuration.

## 3. Azure Pipeline Variable Files

**Check Azure DevOps pipeline variable files:**

**Files to examine:**
- `/variables.dev.yml` - Development variables
- `/variables.test.yml` - Test variables
- `/variables.acceptance.yml` - Staging/Acceptance variables
- `/variables.prod.yml` - Production variables
- `/variables.[env].yml` - Any environment-specific variable files

**Credentials to compare:**
- Database usernames and server names
- Azure AD Client IDs / Application IDs
- Storage account names
- Service principal IDs
- API keys and endpoints
- Service connection names
- Key Vault names and URIs

**Flags to raise:**
- Identical `DatabaseUsername` across environments
- Same `AzureClientId` or `ServicePrincipalId` values
- Shared `ApiKey` values
- Same `StorageAccountName` (should be globally unique per environment)

## 4. Deployment Profiles

**Check deployment profile project files:**

**Files to examine:**
- `publish-web-profile-dev-*.proj` - Development deployment profile
- `publish-web-profile-test-*.proj` - Test deployment profile
- `publish-web-profile-acc-*.proj` - Staging/Acceptance deployment profile
- `publish-web-profile-prod-*.proj` - Production deployment profile
- `publish-web-profile-[env]-*.proj` - Any environment-specific deployment profiles

## 8. What to Report

**Report ALL instances of credential reuse (priority varies by environment pair):**

### High Priority (CRITICAL):
- **Production credentials reused in Test/Development**
  - Immediate security risk
  - Could lead to production data exposure
  - Accidental production changes from non-prod code

- **Production credentials reused in Staging/Acceptance**
  - High risk of production impact
  - Testing could affect production systems

### Medium-High Priority:
- **Staging/Acceptance credentials reused in Test/Development**
  - Risk of environment contamination
  - Staging should mirror production security

- **Same service principal/app registration across all environments**
  - Compromised dev credentials affect all environments
  - Difficult to audit and track environment-specific access

### Medium Priority:
- **Test credentials reused in Development**
  - Less critical but still not best practice
  - Makes access auditing difficult

- **Shared API keys across any environments**
  - Cannot revoke for one environment without affecting others
  - Difficult to track usage per environment

### What to document for each finding:

**For each credential reuse instance, provide:**
1. **File paths** where credentials appear
2. **Credential type** (database user, API key, client ID, etc.)
3. **Credential identifier** (username, account name, app ID - NOT the password/secret)
4. **Environments affected** (which environments share the credential)
5. **Risk level** based on priority matrix above
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
- Risk Level: HIGH
- Impact: Development database credentials could potentially access production
- Recommendation: Create separate database users (e.g., app_user_dev, app_user_prod)
```

## 10. Credential Types to Verify

**Database credentials:**
- SQL Server usernames
- PostgreSQL users
- MySQL users
- MongoDB connection strings
- Redis connection strings
- Cosmos DB account keys

**Azure/Cloud credentials:**
- Service Principal Client IDs
- Managed Identity names
- Storage Account names and keys
- App Service deployment credentials
- Function App keys
- Service Bus connection strings
- Event Hub connection strings
- Application Insights instrumentation keys

**Third-party service credentials:**
- Payment gateway API keys
- Email service API keys
- SMS service credentials
- Analytics tracking IDs
- Map service API keys
- CDN credentials
- OAuth provider client IDs

**Identity and authentication:**
- Azure AD App Registrations (separate per environment)
- OAuth client IDs and secrets
- JWT signing keys
- API authentication tokens
- Service account credentials

## 13. Remediation Recommendations

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
