# Database Field Encryption Analysis

Analyze the codebase to verify that sensitive fields stored in the database are protected with encryption, so that anyone with direct database access cannot read them in plain text.

## Core Security Principle
**Fields that must remain unreadable to database administrators and anyone with direct database access — such as credit card numbers, social security numbers, and bank account details — must be encrypted at the column level or encrypted/decrypted transparently by the application. Passwords are out of scope here; they must be hashed (see Cryptography Security check).**

## 1. Identify Sensitive Fields Requiring Encryption

Search entity classes and DTOs for fields that should never be readable in plain text:

**High-sensitivity fields that must be encrypted:**
```csharp
// Identity and government identifiers
public string SocialSecurityNumber { get; set; }
public string NationalId { get; set; }
public string PassportNumber { get; set; }
public string DriverLicenseNumber { get; set; }
public string TaxId { get; set; }

// Payment data
public string CreditCardNumber { get; set; }
public string BankAccountNumber { get; set; }
public string IBAN { get; set; }
public string RoutingNumber { get; set; }
public string CardVerificationCode { get; set; }

// Medical and biometric data
public string MedicalRecordNumber { get; set; }
public string Diagnosis { get; set; }
public byte[] BiometricData { get; set; }
```

**Files to examine:**
- `Models/`, `Entities/`, `Domain/` — entity class definitions
- `*DbContext.cs` — which entities are mapped
- `Migrations/*.cs` — to see column types and names added over time

**Note:** Passwords must be *hashed*, not encrypted. If you encounter a `Password` field that is encrypted rather than hashed, flag it as a separate issue.

## 2. SQL Server Always Encrypted

Always Encrypted performs column-level encryption entirely within the database driver. The database engine itself never sees plain text.

**Check the connection string for the setting:**
```json
// appsettings.json — GOOD
"ConnectionStrings": {
  "DefaultConnection": "Server=...;Column Encryption Setting=Enabled;..."
}
```

**Check Entity Framework configuration:**
```csharp
// GOOD — column marked for Always Encrypted
modelBuilder.Entity<Customer>()
    .Property(c => c.SocialSecurityNumber)
    .HasColumnType("nvarchar(256)");
// Always Encrypted is enforced at driver level; verify via SSMS column master key setup
```

**RED FLAGS:**
- Sensitive columns present in the database schema but `Column Encryption Setting` is absent from all connection strings
- No column master key or column encryption key objects configured in the database
- Sensitive fields stored as plain `nvarchar` or `varchar` without any encryption wrapper

## 3. Application-Level Encryption (EF Core Value Converters)

If Always Encrypted is not used, the application must encrypt and decrypt values transparently before writing to and after reading from the database.

**GOOD — EF Core value converter pattern:**
```csharp
// Encryption service interface
public interface IEncryptionService
{
    string Encrypt(string plainText);
    string Decrypt(string cipherText);
}

// Entity configuration
modelBuilder.Entity<Customer>()
    .Property(c => c.SocialSecurityNumber)
    .HasConversion(
        v => encryptionService.Encrypt(v),
        v => encryptionService.Decrypt(v));
```

**GOOD — Dedicated encrypted value type:**
```csharp
public class EncryptedString
{
    private readonly string _cipherText;
    public EncryptedString(string cipherText) => _cipherText = cipherText;
    public string Decrypt(IEncryptionService svc) => svc.Decrypt(_cipherText);
}
```

**RED FLAGS:**
- Sensitive fields stored and retrieved without any call to an encryption or decryption service
- Encryption called only on some code paths (e.g. only during writes but not verified on reads)
- Plain-text values written directly via `context.SaveChanges()` without a value converter in place

## 4. .NET Data Protection API

The .NET Data Protection API (`IDataProtector`) is suitable for encrypting short-lived or per-application sensitive values.

**GOOD — Data Protection for field-level encryption:**
```csharp
public class SensitiveDataService
{
    private readonly IDataProtector _protector;

    public SensitiveDataService(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("SensitiveFields.v1");
    }

    public string Protect(string plainText) => _protector.Protect(plainText);
    public string Unprotect(string cipherText) => _protector.Unprotect(cipherText);
}
```

**RED FLAGS:**
- `IDataProtector` used but keys not persisted (data becomes unreadable after app restart)
- Purpose string changed across deployments (breaks decryption of existing data)

## 5. Encryption Key Management

Encryption is only as strong as the protection of its keys.

**RED FLAGS:**
```csharp
// CRITICAL — hardcoded encryption key
private static readonly byte[] Key = new byte[] { 0x12, 0x34, ... };
private const string EncryptionKey = "MySuperSecretKey123!";

// BAD — key derived from application configuration without key vault
var key = Encoding.UTF8.GetBytes(config["Encryption:Key"]);
```

**GOOD:**
```csharp
// Key retrieved from Azure Key Vault at runtime
var keyBytes = await keyVaultClient.GetSecretAsync("FieldEncryptionKey");
```

**Check for:**
- Encryption keys stored in `appsettings.json` or source code rather than a key vault
- Keys derived from weak or guessable strings
- No key rotation strategy in place

## 6. Transparent Data Encryption (TDE)

Transparent Data Encryption encrypts the entire database at rest — data files, log files, and backups — protecting against exposure from physical media theft or file-level access. **TDE is enabled by default on Azure SQL and requires no configuration. Only flag this if it has been explicitly disabled.**

**Only search for evidence of TDE being turned off:**

```bicep
// RED FLAG — TDE explicitly disabled in Bicep
resource sqlDb 'Microsoft.Sql/servers/databases@2021-11-01' = {
  properties: {
    transparentDataEncryption: {
      state: 'Disabled'  // flag this; absence of this block is fine (defaults to Enabled)
    }
  }
}
```

**Infrastructure repository**: The shared Bicep files for all projects are at `https://dev.azure.com/enigmatry/Enigmatry%20-%20CICD%20Azure%20Infra/_git/enigmatry-cicd-azure-infra`. Look only at the folder or module that corresponds to the project currently being audited (ask the user for the project/folder name if unclear). Check there for Azure SQL database definitions.

**Search for:**
- `state: 'Disabled'` near `transparentDataEncryption` in Bicep files
- `az sql db tde set --status Disabled` in Azure CLI scripts or pipeline YAML
- If neither is found, TDE is enabled — no finding needed

**Note:** TDE protects data at the file level only. It does not prevent a user with valid database credentials from reading sensitive column values — column-level encryption (sections 2–3) is still required for fields such as SSN and credit card numbers.

## What to Report

For each finding, provide:
- **Entity/table** and **field/column** name (for column-level findings), or **infrastructure file** and line number (for TDE findings)
- **Data type**: SSN, credit card, IBAN, biometric, medical record, TDE configuration, etc.
- **Current state**: plain text, hashed (wrong approach for this data), application-encrypted, column-encrypted, or TDE disabled
- **Risk**: HIGH (SSN, credit card, bank account, biometric — unencrypted; or TDE explicitly disabled) / MEDIUM (medical or other sensitive personal data — unencrypted) / LOW (encryption present but key management is weak)
- **Recommendation**: preferred approach (Always Encrypted, EF Core value converter, or Data Protection API for column-level; ensure TDE is enabled for database-level) and any key management improvements required
