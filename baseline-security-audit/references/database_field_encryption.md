# Database Field Encryption Analysis

Analyze the codebase to verify that sensitive fields stored in the database are protected with encryption, so that anyone with direct database access cannot read them in plain text.

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A04 Cryptographic Failures · **ASVS 5.0:** V14 Data Protection, V11 Cryptography

## Core Security Principle
**Fields that must remain unreadable to database administrators and anyone with direct database access — such as credit card numbers, social security numbers, and bank account details — must be encrypted at the column level or encrypted/decrypted transparently by the application. Passwords are out of scope here; they must be hashed (see Cryptography Security check).**

## 1. Identify Sensitive Fields Requiring Encryption

Search entity classes and DTOs for fields that should never be readable in plain text:

**Fields that must be encrypted** (the full property-name list is in check 11 (data_minimization.md) section 7): government identifiers (`SocialSecurityNumber`, `Bsn`, `NationalId`, `PassportNumber`, `DriverLicenseNumber`, `TaxId`), payment data (`CreditCardNumber`, `BankAccountNumber`, `IBAN`, `RoutingNumber`), medical and biometric data (`MedicalRecordNumber`, `Diagnosis`, `BiometricData`).

**PCI DSS v4.0.1 requirement 3.3.1** forbids storing sensitive authentication data (CVV/CVC, full track data, PIN) after authorisation, even encrypted: a `CardVerificationCode` column is a Critical "remove" finding, not an encryption finding. Full PANs should be tokenised by the payment service provider rather than stored.

**Files to examine:**
- `Models/`, `Entities/`, `Domain/` — entity class definitions
- `*DbContext.cs` — which entities are mapped
- `Migrations/*.cs` — to see column types and names added over time

## 2. SQL Server Always Encrypted

Always Encrypted performs column-level encryption entirely within the database driver. The database engine itself never sees plain text.

**Check the connection string for the setting:**
```json
// appsettings.json — GOOD
"ConnectionStrings": {
  "DefaultConnection": "Server=...;Column Encryption Setting=Enabled;..."
}
```

**Always Encrypted is declared in T-SQL, not through EF column types** (`HasColumnType` says nothing about encryption). Search migrations, `*.sql` scripts and DACPAC projects for:
- `ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY = ...)` on the column definition (often inside `migrationBuilder.Sql(...)`); the column master and encryption keys themselves are created outside source control
- The `Microsoft.Data.SqlClient.AlwaysEncrypted.AzureKeyVaultProvider` package and `SqlConnection.RegisterColumnEncryptionKeyStoreProviders(...)` at startup when the column master key lives in Key Vault
- `Column Encryption Setting=Enabled` in the connection string (above); without it the driver returns ciphertext and the application breaks, so its presence is a strong signal that encryption is in use

**RED FLAGS:**
- Sensitive columns present in the database schema but `Column Encryption Setting` is absent from all connection strings
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

**RED FLAGS:**
- Sensitive fields stored and retrieved without any call to an encryption or decryption service
- Encryption called only on some code paths (e.g. only during writes but not verified on reads)
- Plain-text values written directly via `context.SaveChanges()` without a value converter in place

## 4. .NET Data Protection API

The .NET Data Protection API (`IDataProtector`) is suitable for encrypting short-lived or per-application sensitive values.

Pattern: `IDataProtectionProvider.CreateProtector("SensitiveFields.v1")` with `Protect` / `Unprotect` around the sensitive value.

**RED FLAGS:**
- Key ring not persisted to a shared store (rated by check 13 (cryptography_security.md) section 5)
- Purpose string changed across deployments (breaks decryption of existing data)

## 5. Encryption Key Management

Encryption is only as strong as the protection of its keys.

Keys belong in Azure Key Vault (or, for Always Encrypted, a column master key in Key Vault); check for a rotation strategy.

Report missing key-rotation evidence for the column-encryption key as Low; hard-coded or static keys are reported by check 13 (cryptography_security.md).

## 6. Transparent Data Encryption (TDE)

Transparent Data Encryption encrypts the entire database at rest — data files, log files, and backups — protecting against exposure from physical media theft or file-level access. **TDE is on by default for Azure SQL Database and for Managed Instance databases created after February 2019; flag those only when it has been explicitly disabled. SQL Server on VMs or on-premises is not encrypted by default: require `sys.dm_database_encryption_keys` evidence or `ALTER DATABASE ... SET ENCRYPTION ON` in scripts, otherwise report TDE not enabled = High.**

**Only search for evidence of TDE being turned off:**

```bicep
// RED FLAG — TDE explicitly disabled in Bicep (child resource of the database, always named 'current')
resource tde 'Microsoft.Sql/servers/databases/transparentDataEncryption@2021-11-01' = {
  parent: sqlDb
  name: 'current'
  properties: { state: 'Disabled' }  // flag this; absence of the resource is fine (defaults to Enabled)
}
```

Check the Azure SQL database definitions in the project's module of the infrastructure repository (SKILL.md Step 1).

**Search for:**
- `state: 'Disabled'` in a `Microsoft.Sql/servers/databases/transparentDataEncryption` resource (or an inline `transparentDataEncryption` property in older templates) in Bicep files
- `az sql db tde set --status Disabled` in Azure CLI scripts or pipeline YAML
- If neither is found on Azure SQL Database or Managed Instance, TDE is enabled — no finding needed; for SQL Server on a VM or on-premises search `SET ENCRYPTION ON` and `dm_database_encryption_keys` instead

**Note:** TDE protects data at the file level only. It does not prevent a user with valid database credentials from reading sensitive column values — column-level encryption (sections 2–3) is still required for fields such as SSN and credit card numbers.

## What to Report

For each finding, provide:
- **Entity/table** and **field/column** name (for column-level findings), or **infrastructure file** and line number (for TDE findings)
- **Data type**: SSN, credit card, IBAN, biometric, medical record, TDE configuration, etc.
- **Current state**: plain text, application-encrypted, column-encrypted (Always Encrypted), or TDE disabled
- **Severity** (by data class of an unencrypted column): Critical (CVV/CVC or full track data stored at all; full PAN stored in clear) / High (BSN/SSN, bank account, IBAN, biometric or health data unencrypted; TDE explicitly disabled, or not enabled on SQL Server on a VM or on-premises) / Medium (other PII unencrypted) / Low (no key rotation evidence for the column-encryption key). A hard-coded or static key is reported under check 13 (cryptography_security.md), not here.
- **Recommendation**: preferred approach (Always Encrypted, EF Core value converter, or Data Protection API for column-level; ensure TDE is enabled for database-level) and any key management improvements required
