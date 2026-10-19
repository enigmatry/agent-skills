# Cryptography Security Analysis

Analyze the codebase to identify weak or insecure cryptographic implementations that could compromise data security:

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A04 Cryptographic Failures · **ASVS 5.0:** V11 Cryptography

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
// Default (PasswordHasher V3): PBKDF2-HMAC-SHA512, 128-bit salt, 256-bit subkey, 100,000 iterations
// (PasswordHasherOptions.IterationCount). The framework default is acceptable; do not flag it.
```

**GOOD - Custom implementations:**
```csharp
// PBKDF2 (custom code: 600,000+ iterations with SHA-256, 210,000+ with SHA-512)
KeyDerivation.Pbkdf2(password, salt, KeyDerivationPrf.HMACSHA512,
    iterationCount: 210_000, numBytesRequested: 32);

// BCrypt (work factor 10+; input is truncated at 72 bytes — pre-hash or reject longer passwords)
BCrypt.HashPassword(password, workFactor: 12);

// Argon2id (best for new implementations): m=19 MiB, t=2, p=1 minimum; scrypt: N=2^17, r=8, p=1 (OWASP)
```

**RED FLAGS - Insecure password hashing:**
```csharp
// CRITICAL - Never use for passwords!
MD5.Create().ComputeHash(...)           // Broken
SHA1.Create().ComputeHash(...)          // Broken
SHA256.Create().ComputeHash(...)        // Too fast, no salt
```

**Severity:** MD5 or SHA-1 for passwords = Critical; unsalted or un-iterated SHA-2 = High; custom `KeyDerivation.Pbkdf2` / `Rfc2898DeriveBytes.Pbkdf2` below 600,000 iterations (SHA-256) or 210,000 (SHA-512) = High (OWASP Password Storage Cheat Sheet); Argon2id below m=19 MiB/t=2/p=1, scrypt below N=2^17/r=8/p=1, bcrypt work factor below 10 or bcrypt with silently truncated input = Medium; the Identity default above is not a finding. See check 19 (authentication_security.md) for password policy.

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

**GOOD - AES-GCM (authenticated encryption):**
```csharp
// AES-GCM is a separate class; CipherMode has no GCM member.
var nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize); // 12 bytes, fresh per message
var tag = new byte[AesGcm.TagByteSizes.MaxSize];                             // 16 bytes
var ciphertext = new byte[plaintext.Length];
using (var aesGcm = new AesGcm(key, tagSizeInBytes: 16))                     // 256-bit key
{
    aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
}
// Store nonce + ciphertext + tag together. Never reuse a nonce with the same key.
```

**ACCEPTABLE - AES-CBC only with a MAC (encrypt-then-HMAC):**
```csharp
using (var aes = Aes.Create())
{
    aes.KeySize = 256;
    aes.Mode = CipherMode.CBC;      // Aes.Create() default; unauthenticated without an HMAC
    aes.GenerateIV();               // Random IV per encryption
}
```
Flag CBC-encrypted data that is returned to clients (cookies, tokens) without an HMAC as High (padding-oracle class).

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

`new Random()` or `Guid.NewGuid()` is a finding (High) only when the value is used as a secret (reset token, API key, session id, OTP); entity ids, correlation ids and file names are not findings.

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

// Data Protection API: ProtectKeysWithAzureKeyVault alone keeps the key ring on local disk; pair it with a shared repository
services.AddDataProtection()
    .PersistKeysToAzureBlobStorage(...)
    .ProtectKeysWithAzureKeyVault(...);

// Strong key generation
aes.KeySize = 256;
aes.GenerateKey();
```

**Severity:** a hard-coded or static key in source or configuration (`appsettings*.json`, Bicep parameters, pipeline variables) = Critical; a key that comes from a vault or Data Protection but has no documented rotation = Low; `ProtectKeysWithAzureKeyVault` without `PersistKeysTo*` on multi-instance App Service or containers = Medium.

**JWT signing (`AddJwtBearer`, `JwtSecurityTokenHandler`, `JsonWebTokenHandler`):** `alg: none` accepted (`RequireSignedTokens = false`, `ValidateIssuerSigningKey = false`), HS256 with a symmetric key shorter than 256 bits or a password-like `Jwt:Key` string, `new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]))` = High (a key committed in config is also check 1 (secrets.md)). `IdentityModelEventSource.ShowPII = true` outside Development = Medium; the search pattern is owned by check 5 (logging.md) section 5.

### Crypto-agility inventory (post-quantum readiness)

NIST IR 8547 (initial public draft, November 2024) deprecates RSA, ECDSA and ECDH at 112-bit security after 2030 and disallows quantum-vulnerable public-key algorithms after 2035; the EU coordinated PQC implementation roadmap (June 2025) asks member states to start the transition by the end of 2026 and to migrate high-risk systems by 2030. .NET 10 ships `MLKem` (FIPS 203) plus `MLDsa` and `SlhDsa` (FIPS 204/205, `[Experimental]` SYSLIB5006), which require OpenSSL 3.5+ or Windows CNG with PQC support.

For a baseline audit this is Low and informational; do not raise findings for using RSA or ECDSA today. Instead:
- Inventory asymmetric usage: `RSA.Create(`, `ECDsa.Create(`, `ECDiffieHellman.Create(`, `X509Certificate2` signing or key exchange, certificate pinning, JWT signing algorithms (`RS256`, `ES256`, `SecurityAlgorithms.Rsa*` / `Ecdsa*`)
- Note long-lived encrypted or signed data that must stay confidential or verifiable past 2030 (harvest-now-decrypt-later risk)
- Recommend a migration plan: isolate algorithm choices behind configuration, track library and platform PQC support, prefer TLS with hybrid key exchange (see ssl_tls_configuration.md)
Sources: https://csrc.nist.gov/pubs/ir/8547/ipd , https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography , https://learn.microsoft.com/en-us/dotnet/core/whats-new/dotnet-10/libraries

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
crypto.subtle.digest('SHA-256', data)            // Web Crypto API (best)
crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data) // Web Crypto API (best)
crypto.getRandomValues(new Uint8Array(16))       // CSPRNG
```

**RED FLAGS - crypto-js:**
```typescript
import * as CryptoJS from 'crypto-js';   // MEDIUM: the library is discontinued and unmaintained
CryptoJS.AES.encrypt(data, 'passphrase') // HIGH: key and IV derived with MD5 (OpenSSL EvpKDF, 1 iteration)
CryptoJS.PBKDF2(password, salt)          // HIGH before 4.2.0: SHA-1 with 1 iteration (CVE-2023-46233)
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
2. Filter by category: `weak-cryptography`
3. Review and remediate each hotspot

## 8. What to Report

**Severity:**
- **Critical**: MD5/SHA-1 for passwords; DES or RC2; ECB protecting secrets or PII; hard-coded or static key; home-made cipher or hash protecting secrets
- **High**: TripleDES; unsalted or low-iteration SHA-2 for passwords; custom PBKDF2 below 600,000 (SHA-256) / 210,000 (SHA-512) iterations; `PasswordDeriveBytes` or the SHA-1/1000-iteration `Rfc2898DeriveBytes` constructor for passwords; unauthenticated CBC handed to clients; zero or static IV; `Random`/`Guid` for a secret; `CryptoJS.AES.encrypt` passphrase mode; `CryptoJS.PBKDF2` before 4.2.0; JWT `alg: none` accepted or a short or password-like HS256 signing key
- **Medium**: MD5/SHA-1 for non-security integrity checks; Argon2id, scrypt or bcrypt below the section 1 parameters or bcrypt with truncated input; `ProtectKeysWithAzureKeyVault` without a shared key repository on multi-instance hosting; `IdentityModelEventSource.ShowPII = true` outside Development; obsolete .NET crypto APIs (SYSLIB0021/0022/0023/0033/0041/0045/0053: `Rijndael*`, `*CryptoServiceProvider`, `*Managed`, `RNGCryptoServiceProvider`, `HashAlgorithm.Create(string)`, `AesGcm(key)` without a tag size); discontinued `crypto-js` dependency; unreviewed `weak-cryptography` hotspots
- **Low**: key sizes above the minimum but below the recommendation (AES-128, RSA-2048); key without documented rotation; crypto-agility inventory (RSA/ECDSA/ECDH usage with no post-quantum migration plan — informational)

### Password hashing findings:

**Example report format:**
```
Finding: Weak Password Hashing Algorithm
- Location: Services/AuthService.cs, line 45
- Current Algorithm: SHA-256 without salt
- Use Case: User password hashing
- Severity: High
- Issue: Too fast, no salt, no iterations - vulnerable to brute-force
- Impact: All user passwords at risk
- Recommendation: Use ASP.NET Core Identity (PBKDF2) or BCrypt (work factor 12+)
```

### General cryptography findings:

**Report for each finding:**
- **Location**: File path and line number
- **Current algorithm**: MD5, SHA-1, DES, TripleDES, Random, etc.
- **Use case**: What it's used for
- **Severity**: per the scale above (data sensitivity and algorithm weakness)
- **Recommendation**: Specific secure alternative

**Example - Weak hashing:**
```
Finding: Weak Hashing Algorithm (MD5)
- Location: Services/FileService.cs, line 123
- Current: MD5
- Use Case: File integrity verification
- Severity: Medium - MD5 is broken (collision attacks); non-security use
- Recommendation: Replace with SHA-256 or SHA-512
```

**Example - Weak encryption:**
```
Finding: Deprecated Encryption Algorithm
- Location: Services/DataEncryptionService.cs, line 67
- Current: TripleDES
- Use Case: Encrypting customer PII
- Severity: High - TripleDES deprecated, known vulnerabilities
- Recommendation: Migrate to AES-256-GCM, re-encrypt existing data
```

**Example - Weak random:**
```
Finding: Non-Cryptographic Random Generator
- Location: Services/TokenService.cs, line 34
- Current: new Random()
- Use Case: Password reset tokens
- Severity: High - Predictable tokens, account hijacking possible
- Recommendation: Use RandomNumberGenerator.GetBytes(32)
```

**Example - Insecure mode:**
```
Finding: Insecure Encryption Mode (ECB)
- Location: Utilities/EncryptionHelper.cs, line 89
- Current: CipherMode.ECB with AES
- Severity: High - ECB reveals patterns in encrypted data
- Recommendation: Use the `AesGcm` class with a fresh 96-bit nonce per message, or CBC with a random IV plus encrypt-then-HMAC
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
new Random\(|\.Next\(|\.NextBytes   // flag only when the value is used as a secret
Guid\.NewGuid                       // flag only when the value is used as a secret (reset token, API key, session id); exclude entity ids

// Insecure modes
CipherMode\.ECB

// Hardcoded keys (review carefully)
new byte\[\]\s*\{.*\}.*[Kk]ey

// Obsolete .NET crypto APIs (SYSLIB0021/0022/0023/0033/0041/0045/0053) — Medium; High for PasswordDeriveBytes or new Rfc2898DeriveBytes(...) without HashAlgorithmName (SHA-1, 1000 iterations) used for passwords
\bRijndael(Managed)?\b|\w+CryptoServiceProvider\b|\b(SHA(1|256|384|512)|Aes)Managed\b|RNGCryptoServiceProvider
new Rfc2898DeriveBytes\(|PasswordDeriveBytes|HashAlgorithm\.Create\(\s*"|new AesGcm\(\s*\w+\s*\)

// Crypto-agility inventory (informational, Low — see section 5)
RSA\.Create|ECDsa\.Create|ECDiffieHellman\.Create|RS256|ES256

// JWT signing and Data Protection key ring (section 5)
SymmetricSecurityKey\(Encoding\.|RequireSignedTokens\s*=\s*false|ValidateIssuerSigningKey\s*=\s*false|HmacSha256|ProtectKeysWithAzureKeyVault|PersistKeysTo
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
4. ✅ **PBKDF2** (acceptable: the Identity default, or 600,000+ SHA-256 / 210,000+ SHA-512 iterations in custom code)
5. ❌ **MD5, SHA-1, SHA-256 without salt** (never)

**Data Hashing:**
1. ✅ **SHA-3** (best)
2. ✅ **SHA-512** (good)
3. ✅ **SHA-256** (good)
4. ❌ **MD5, SHA-1** (never)

**Encryption:**
1. ✅ **AES-256-GCM** (best - authenticated)
2. ✅ **AES-256-CBC** (acceptable - random IV and encrypt-then-HMAC; unauthenticated CBC is malleable)
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
- PBKDF2: Identity default, or 600,000+ (SHA-256) / 210,000+ (SHA-512) iterations in custom code
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
