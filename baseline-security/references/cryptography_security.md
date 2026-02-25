# Cryptography Security Analysis

Analyze the codebase to identify weak or insecure cryptographic implementations that could compromise data security:

## Core Security Principle
**Industry-standard and secure algorithms must be used for hashing and encrypting data with strong keys. Weak cryptographic algorithms can be easily broken, exposing sensitive data.**

## 1. Password Hashing (ASP.NET Core)

**Files to examine:**
- `Startup.cs` / `Program.cs` - Identity configuration
- Custom password hashers implementing `IPasswordHasher<TUser>`

**GOOD - ASP.NET Core Identity default (PBKDF2):**
```csharp
services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();
// Default uses PBKDF2 with HMAC-SHA256, 100,000 iterations (secure)
```

**GOOD - Custom implementations:**
```csharp
// PBKDF2
KeyDerivation.Pbkdf2(password, salt, KeyDerivationPrf.HMACSHA256, 
    iterationCount: 100000, numBytesRequested: 32);

// BCrypt
BCrypt.HashPassword(password, workFactor: 12);

// Argon2 (best for new implementations)
```

**RED FLAGS - Insecure password hashing:**
```csharp
// CRITICAL - Never use for passwords!
MD5.Create().ComputeHash(...)           // Broken
SHA1.Create().ComputeHash(...)          // Broken
SHA256.Create().ComputeHash(...)        // Too fast, no salt
```

## 2. General Data Hashing

**GOOD - Recommended algorithms:**
```csharp
SHA256.Create()   // GOOD
SHA384.Create()   // GOOD
SHA512.Create()   // GOOD
SHA3_256.Create() // BEST (.NET 8+)
```

**RED FLAGS:**
```csharp
MD5.Create()      // CRITICAL - Broken (collision attacks)
SHA1.Create()     // CRITICAL - Deprecated (collision attacks)
```

## 3. Data Encryption/Decryption

**GOOD - AES encryption:**
```csharp
using (var aes = Aes.Create())
{
    aes.KeySize = 256;              // 256-bit key (MUST)
    aes.Mode = CipherMode.GCM;      // GCM (BEST) or CBC
    aes.GenerateKey();
    aes.GenerateIV();               // Random IV per encryption
}
```

**RED FLAGS - Weak algorithms:**
```csharp
DES.Create()        // CRITICAL - Broken
TripleDES.Create()  // CRITICAL - Deprecated
RC2.Create()        // CRITICAL - Weak
```

**RED FLAGS - Insecure modes:**
```csharp
aes.Mode = CipherMode.ECB;              // NEVER use ECB!
aes.IV = new byte[16];                  // BAD - Zero IV
aes.IV = Encoding.UTF8.GetBytes("..."); // BAD - Static IV
```

## 4. Random Number Generation

**GOOD - Cryptographically secure:**
```csharp
RandomNumberGenerator.GetBytes(32);     // Secure
RandomNumberGenerator.GetInt32(1, 100); // Secure
```

**RED FLAGS - Not cryptographically secure:**
```csharp
new Random().Next()              // BAD - Predictable
Guid.NewGuid()                   // BAD - Not cryptographic
```

**Use cryptographic random for:**
- Encryption keys, IVs, salts
- Session tokens, password reset tokens
- API keys, CSRF tokens
- Any security-sensitive value

## 5. Key Management

**RED FLAGS:**
```csharp
byte[] key = new byte[] { 0x01, 0x02, ... };  // CRITICAL - Hardcoded
string key = "MySecretKey12345";               // CRITICAL - Hardcoded
byte[] key = Encoding.UTF8.GetBytes(password); // BAD - Weak derivation
```

**GOOD:**
```csharp
// Azure Key Vault
var client = new SecretClient(new Uri(vaultUrl), new DefaultAzureCredential());
var secret = await client.GetSecretAsync("EncryptionKey");

// Data Protection API
services.AddDataProtection()
    .ProtectKeysWithAzureKeyVault(...);

// Strong key generation
aes.KeySize = 256;
aes.GenerateKey();
```

## 6. Angular Client-Side Cryptography

**Files to examine:**
- `*.service.ts` - Search for: `CryptoJS`, `bcrypt`, `forge`, `crypto.subtle`

**RED FLAGS:**
```typescript
CryptoJS.MD5(data)              // Weak
CryptoJS.SHA1(data)             // Weak
CryptoJS.DES.encrypt(data, key) // Weak
CryptoJS.TripleDES.encrypt(...) // Deprecated
const key = 'hardcoded-key';    // Never hardcode
```

**GOOD:**
```typescript
CryptoJS.SHA256(data)           // Good
CryptoJS.SHA512(data)           // Good
CryptoJS.AES.encrypt(data, key) // Good
crypto.subtle.digest('SHA-256', data) // Web Crypto API (best)
```

**Note:** Most cryptographic operations should happen server-side, not in Angular.

## 7. SonarQube Security Hotspots

**Check SonarQube for cryptography issues:**

**Common rules to review:**
- `S2245` - Pseudorandom number generators (use RandomNumberGenerator)
- `S4790` - Weak hashing algorithms (MD5, SHA-1)
- `S5547` - Weak cipher algorithms (DES, TripleDES, RC2)
- `S5542` - Weak encryption modes (ECB)
- `S4426` - Weak cryptographic key sizes

**Steps:**
1. Navigate to SonarQube project → "Security Hotspots"
2. Filter by category: "Cryptography"
3. Review and remediate each hotspot

## 8. What to Report

### High Priority - Password-Related Issues:

**Example report format:**
```
Finding: Weak Password Hashing Algorithm
- Location: Services/AuthService.cs, line 45
- Current Algorithm: SHA-256 without salt
- Use Case: User password hashing
- Risk Level: HIGH
- Issue: Too fast, no salt, no iterations - vulnerable to brute-force
- Impact: All user passwords at risk
- Recommendation: Use ASP.NET Core Identity (PBKDF2) or BCrypt (work factor 12+)
```

### Medium Priority - General Cryptography Issues:

**Report for each finding:**
- **Location**: File path and line number
- **Current algorithm**: MD5, SHA-1, DES, TripleDES, Random, etc.
- **Use case**: What it's used for
- **Risk level**: Based on data sensitivity and algorithm weakness
- **Recommendation**: Specific secure alternative

**Example - Weak hashing:**
```
Finding: Weak Hashing Algorithm (MD5)
- Location: Services/FileService.cs, line 123
- Current: MD5
- Use Case: File integrity verification
- Risk: MEDIUM - MD5 is broken (collision attacks)
- Recommendation: Replace with SHA-256 or SHA-512
```

**Example - Weak encryption:**
```
Finding: Deprecated Encryption Algorithm
- Location: Services/DataEncryptionService.cs, line 67
- Current: TripleDES
- Use Case: Encrypting customer PII
- Risk: HIGH - TripleDES deprecated, known vulnerabilities
- Recommendation: Migrate to AES-256-GCM, re-encrypt existing data
```

**Example - Weak random:**
```
Finding: Non-Cryptographic Random Generator
- Location: Services/TokenService.cs, line 34
- Current: new Random()
- Use Case: Password reset tokens
- Risk: HIGH - Predictable tokens, account hijacking possible
- Recommendation: Use RandomNumberGenerator.GetBytes(32)
```

**Example - Insecure mode:**
```
Finding: Insecure Encryption Mode (ECB)
- Location: Utilities/EncryptionHelper.cs, line 89
- Current: CipherMode.ECB with AES
- Risk: HIGH - ECB reveals patterns in encrypted data
- Recommendation: Use CipherMode.GCM or CBC with random IV
```

## 9. Search Patterns

**Search for weak cryptography:**

```regex
// Weak hashing
MD5\.Create|MD5CryptoServiceProvider|HMACMD5
SHA1\.Create|SHA1CryptoServiceProvider|SHA1Managed|HMACSHA1

// Weak encryption
DES\.Create|DESCryptoServiceProvider
TripleDES\.Create|TripleDESCryptoServiceProvider
RC2\.Create|RC2CryptoServiceProvider

// Weak random
new Random\(|\.Next\(|\.NextBytes
Guid\.NewGuid

// Insecure modes
CipherMode\.ECB

// Hardcoded keys (review carefully)
new byte\[\]\s*\{.*\}.*[Kk]ey
```

**Files to search:**
- Backend: `**/*.cs` (focus on Services, Utilities, Helpers)
- Angular: `**/*.ts` (focus on services)
- Configuration: `Startup.cs`, `Program.cs`

## 10. Recommended Algorithms Summary

**Password Hashing (ranked):**
1. ✅ **Argon2** (best)
2. ✅ **BCrypt** (good, work factor 12+)
3. ✅ **scrypt** (good)
4. ✅ **PBKDF2** (acceptable, 100,000+ iterations)
5. ❌ **MD5, SHA-1, SHA-256 without salt** (never)

**Data Hashing:**
1. ✅ **SHA-3** (best)
2. ✅ **SHA-512** (good)
3. ✅ **SHA-256** (good)
4. ❌ **MD5, SHA-1** (never)

**Encryption:**
1. ✅ **AES-256-GCM** (best - authenticated)
2. ✅ **AES-256-CBC** (good - with random IV)
3. ✅ **AES-192** (acceptable)
4. ❌ **DES, TripleDES, RC2, ECB mode** (never)

**Random Generation:**
1. ✅ **RandomNumberGenerator** (required for security)
2. ❌ **Random class, Guid** (never for security)

**Key Sizes:**
- **AES**: 256-bit (preferred), 128-bit minimum
- **RSA**: 2048-bit minimum, 3072-bit recommended

## 11. Best Practices Verification

**Verify the application follows:**

✅ **Password security:**
- Using ASP.NET Core Identity default or BCrypt/Argon2
- Minimum 100,000 iterations for PBKDF2
- Unique salt per password

✅ **Data hashing:**
- SHA-256 or stronger
- HMAC for message authentication

✅ **Encryption:**
- AES-256 for symmetric encryption
- GCM or CBC mode (never ECB)
- Random IV per encryption

✅ **Key management:**
- No hardcoded keys
- Keys in Azure Key Vault
- Proper key rotation

✅ **Random generation:**
- RandomNumberGenerator for security
- 32+ bytes for tokens

✅ **SonarQube:**
- Security hotspots reviewed
- Weak algorithms remediated
