# Data Minimization Analysis

Analyze the codebase to ensure the application handles only the minimum data it needs: data exposed through APIs and the frontend, and sensitive data stored in the database.

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A04 Cryptographic Failures, A06 Insecure Design · **ASVS 5.0:** V14 Data Protection

## Core Security Principle
**APIs must implement data minimization - only return fields that are actually consumed by the frontend application. Unused data in responses creates unnecessary attack surface. Likewise, only data which is strictly required for the application should be stored: storing unnecessary sensitive or personal data increases privacy risks, regulatory compliance burden, and potential breach impact. This is GDPR art. 5(1)(c) (data minimisation); art. 9 special categories need an explicit legal basis and, where processing is likely high-risk, a DPIA (art. 35); UAVG art. 46 permits the BSN only with a statutory basis.**

## 1. API Response Analysis

**Map all API endpoints and their returned data:**
- Document all fields returned in each API response
- Identify response DTOs/models and their properties
- Check for over-fetching patterns (returning full entities vs. specific fields)
- Look for sensitive fields that might be unnecessarily exposed

**Files to examine:**
- `**/*Controller.cs`, `**/Endpoints/**/*.cs` — actions and minimal-API handlers
- `**/*Dto.cs`, `**/*Response.cs`, `**/*Model.cs` — response contracts
- `**/*Profile.cs`, `**/*MappingProfile.cs` — AutoMapper profiles
- `**/Entities/**/*.cs`, `**/Domain/**/*.cs` — entity classes (compare against the DTOs)

**Search patterns:**
```regex
return\s+Ok\(\s*\w*(entity|user|User)\w*\s*\)       // entity returned directly
Ok\(await\s+_?context\.\w+                            // DbSet returned without projection
\.ToListAsync\(\)\s*\)                                 // ToListAsync() returned directly from a DbSet
return\s+(await\s+)?_?(db|context|dbContext)\.\w+\.(FirstOrDefault|Single|Find)
\[JsonIgnore\]                                         // on an entity class: the entity is being serialised directly
ReverseMap\(\)                                         // AutoMapper two-way map: entity <-> DTO with every field
ProjectTo<\w*(Entity|User)\w*>|Map<\w*Entity\w*>
```

## 2. Frontend Data Consumption Mapping

Tracing every response field through Angular templates is not reliably executable; use these three steps instead:

1. **DTO-vs-entity comparison:** for each response DTO, diff its property list against the entity it is mapped from. Properties present on both that have no business reason to leave the server are candidates.
2. **Grep TypeScript interface property names:** for each property of the matching `*.model.ts` / `*.interface.ts` type, search `**/*.html` and `**/*.ts` (excluding the type's own file) for `\.<name>\b` and `\b<name>\s*[:=]`; zero hits = the field is unused.
3. **Generic names:** for properties such as `id`, `name`, `type`, `status`, `value` the grep is inconclusive; report them as **unverified**, not as findings.

**Files to examine:**
- `**/*.model.ts`, `**/*.interface.ts`, `**/*.dto.ts` — response types
- `**/*.service.ts` — `HttpClient` calls that name the response type
- `**/*.component.html`, `**/*.component.ts` — property usage

**Search patterns:**
```regex
this\.http\.(get|post|put)<(\w+)>                       // response type per call
export\s+interface\s+\w*(User|Account|Profile|Customer)\w*
(passwordHash|password|salt|secret|token|bsn|ssn|iban|creditCard|internalNotes)\s*\??:   // sensitive property in a frontend type
```

## 3. Cross-Reference Analysis

**For each API endpoint, verify:**
- ✅ **JUSTIFIED**: Every returned field is used somewhere in the frontend
- ⚠️ **QUESTIONABLE**: Fields returned but usage unclear/minimal
- ❌ **EXCESSIVE**: Fields returned but never used in UI

**Critical security fields to check:**
- User IDs, email addresses, phone numbers
- Internal system identifiers
- Audit fields (CreatedBy, ModifiedBy, etc.)
- Database primary/foreign keys
- Configuration values
- Error details and debugging info

Ids, foreign keys and `CreatedBy`/`ModifiedBy` are not findings unless they expose another user's PII to non-admins.

## 4. Sensitive Data Exposure Patterns

**High-risk patterns to identify:**
```csharp
// DANGEROUS: Returning full entities
return Ok(user); // Might expose password hashes, roles, etc.

// DANGEROUS: No field filtering
return await context.Users.ToListAsync();

// SAFER: Specific field selection
return users.Select(u => new { u.Id, u.Name, u.Email });
```

See check 9 (input_validation.md) for inbound over-posting.

**Frontend over-consumption patterns:**
```typescript
// DANGEROUS: Requesting more than needed
interface UserResponse {
  id: number;
  name: string;
  email: string;
  passwordHash: string; // ❌ Should never be in frontend
  internalNotes: string; // ❌ Likely not for UI display
}
```

## 5. Specific Checkpoints

**For each controller/endpoint:**
1. **List all returned properties** from the response model
2. **Find corresponding frontend usage** in Angular components/services
3. **Identify unused fields** that could be removed
4. **Check for sensitive data** accidentally exposed
5. **Verify proper DTO mapping** instead of returning entities directly

**For each Angular component:**
1. **Document API calls made** and data requested
2. **Map template usage** of response properties
3. **Identify over-fetching** where components request but don't use data
4. **Check for client-side data storage** of sensitive fields

## 6. Security Risk Assessment

**Rate each finding (an endpoint assessed QUESTIONABLE or EXCESSIVE in section 3):**
- **Critical**: sensitive field (password hash, token, BSN/SSN, PAN, health data) exposed to unauthenticated callers or to other users
- **High**: the same sensitive field exposed only to the authenticated owner or to admins
- **Medium**: other PII (email, phone, address, date of birth) exposed without a frontend need
- **Low**: non-sensitive over-fetch (unused ordinary fields, full entity in a lookup, legacy fields kept for backward compatibility)
- **Not a finding**: ids, foreign keys and `CreatedBy`/`ModifiedBy`, unless they expose another user's PII to non-admins

**Common violations to check:**
- User management APIs returning password hashes/salts
- List endpoints returning full entity details instead of summaries
- Lookup/dropdown APIs returning more than ID+display text
- Search results including internal metadata
- Audit logs exposing system internals

## 7. Database Schema Analysis

**Check Entity Framework Core entity definitions:**

**Files to examine:**
- `*.cs` files in `Models/`, `Entities/`, `Domain/` folders
- Entity classes with `DbSet<T>` references
- Classes inheriting from base entity classes
- Data Transfer Objects (DTOs) that map to database entities
- Angular form controls (a `bsn` or `dateOfBirth` control points at the entity field to assess under sections 8–9)

**Entity classes to focus on:**
```csharp
// Entities that commonly contain sensitive data
public class User { }
public class Customer { }
public class Employee { }
public class Patient { }
public class Person { }
public class Profile { }
public class UserProfile { }
public class Account { }
public class Member { }
```

## 8. Sensitive Data Fields to Identify

**Personal Identifiable Information (PII):**

**High-sensitivity fields to scrutinize:**
```csharp
// Biometric and identification
public string SocialSecurityNumber { get; set; }
public string TaxId { get; set; }
public string PassportNumber { get; set; }
public string DriverLicenseNumber { get; set; }
public string NationalId { get; set; }
public string Bsn { get; set; }                    // BurgerServiceNummer (NL) — UAVG art. 46: only with a statutory basis
public string BurgerServiceNummer { get; set; }
public byte[] FingerprintData { get; set; }
public byte[] BiometricData { get; set; }

// Financial information
public string CreditCardNumber { get; set; }
public string BankAccountNumber { get; set; }
public string IBAN { get; set; }
public string RoutingNumber { get; set; }
public decimal Salary { get; set; }
public decimal Income { get; set; }
public int CreditScore { get; set; }

// Medical/Health data
public string MedicalRecordNumber { get; set; }
public string BloodType { get; set; }
public string Diagnosis { get; set; }
public string Medication { get; set; }
public string HealthCondition { get; set; }
public string Disability { get; set; }

// Demographic data (often unnecessary)
public DateTime DateOfBirth { get; set; }
public int Age { get; set; }
public string Race { get; set; }
public string Ethnicity { get; set; }
public string Religion { get; set; }
public string MaritalStatus { get; set; }
public string Gender { get; set; }
public string SexualOrientation { get; set; }
public string Nationality { get; set; }

// Contact information (evaluate necessity)
public string HomeAddress { get; set; }
public string PhoneNumber { get; set; }
public string MobileNumber { get; set; }
public string PersonalEmail { get; set; }

// Employment details
public decimal CurrentSalary { get; set; }
public string PreviousEmployer { get; set; }
public DateTime TerminationDate { get; set; }
public string TerminationReason { get; set; }

// Family information
public string SpouseName { get; set; }
public int NumberOfChildren { get; set; }
public string EmergencyContactName { get; set; }
public string EmergencyContactRelationship { get; set; }

// Location tracking
public string CurrentLocation { get; set; }
public decimal Latitude { get; set; }
public decimal Longitude { get; set; }
public string GPSCoordinates { get; set; }

// Behavioral data
public string BrowsingHistory { get; set; }
public string SearchHistory { get; set; }
public string PurchaseHistory { get; set; }
public string LastLoginLocation { get; set; }
```

## 9. Questions to Ask for Each Sensitive Field

**For each identified sensitive data field, verify:**

1. **Business Necessity:**
   - Is this data required for core business functionality?
   - Can the application function without this data?
   - Is there a specific feature that requires this data?

2. **Legal/Regulatory Requirement:**
   - Is this data required by law or regulation?
   - Is it needed for KYC (Know Your Customer) compliance?
   - Is it required for tax reporting or legal obligations?

3. **Alternative Approaches:**
   - Can we derive this information when needed instead of storing it?
   - Can we use a less sensitive alternative? (e.g., age range instead of date of birth)
   - Can we store only a hash or anonymized version?
   - Can we request this data only when specifically needed?

4. **Retention Period:**
   - How long is this data kept?
   - Is there a deletion policy in place?
   - Can it be automatically purged after a certain period?

## 10. Common Unnecessary Data Examples

**Typical cases of unnecessary data storage:**

**Date of Birth when only age verification is needed:**
```csharp
// UNNECESSARY - Storing full date of birth
public DateTime DateOfBirth { get; set; }

// BETTER - Store only what's needed
public bool IsOver18 { get; set; }
// OR
public int AgeRange { get; set; } // 1: 18-25, 2: 26-35, etc.
// OR
public int BirthYear { get; set; } // If only year is needed
```

**Full address when only city/country is needed:**
```csharp
// UNNECESSARY - Full address for shipping calculator
public string StreetAddress { get; set; }
public string ApartmentNumber { get; set; }

// BETTER - Only what's needed for functionality
public string City { get; set; }
public string PostalCode { get; set; }
public string Country { get; set; }
```

**Gender when not required for functionality:**
```csharp
// UNNECESSARY - If application doesn't need this
public string Gender { get; set; }

// QUESTION: Is this required for:
// - Personalization? (Consider if truly needed)
// - Analytics? (Can be anonymized)
// - Legal requirements? (Verify)
```

**Multiple contact methods when one suffices:**
```csharp
// POTENTIALLY UNNECESSARY
public string HomePhone { get; set; }
public string WorkPhone { get; set; }
public string MobilePhone { get; set; }
public string Fax { get; set; }

// BETTER - Store only what's needed
public string PrimaryPhone { get; set; }
```

**Financial data for non-financial applications:**
```csharp
// UNNECESSARY - In a content management system
public decimal Income { get; set; }
public string CreditCardNumber { get; set; }
public int CreditScore { get; set; }

// QUESTION: Why does this application need financial data?
```

**Excessive employment history:**
```csharp
// POTENTIALLY UNNECESSARY - Detailed history
public string PreviousEmployer1 { get; set; }
public string PreviousEmployer2 { get; set; }
public string PreviousEmployer3 { get; set; }
public DateTime EmploymentStartDate1 { get; set; }
public DateTime EmploymentEndDate1 { get; set; }

// QUESTION: Is this employment data needed?
// If it's not a recruiting/HR application, probably not
```

## 11. Database Migration Analysis

**Check Entity Framework migrations for sensitive columns:**

**Files to examine:**
- `Migrations/*.cs` - All migration files
- Look for `AddColumn` operations with sensitive data types

**Example migration analysis:**
```csharp
// Migration file: 20240101_AddUserDetails.cs
migrationBuilder.AddColumn<DateTime>(
    name: "DateOfBirth",
    table: "Users",
    nullable: false);

migrationBuilder.AddColumn<string>(
    name: "SocialSecurityNumber",
    table: "Users",
    maxLength: 11,
    nullable: true);

// QUESTIONS:
// - Why was DateOfBirth added? What feature requires it?
// - Why is SSN stored? Is this legally required?
```

## 12. DbContext and Configuration Analysis

**Check DbContext configurations:**

**Files to examine:**
- `*DbContext.cs` files
- `EntityConfigurations/*.cs` - Entity type configurations

**Look for sensitive data configuration:**
```csharp
public class ApplicationDbContext : DbContext
{
    public DbSet<User> Users { get; set; }
    public DbSet<Customer> Customers { get; set; }
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Check what entities and properties are configured
        modelBuilder.Entity<User>()
            .Property(u => u.SocialSecurityNumber) // RED FLAG if present
            .HasMaxLength(11);
            
        modelBuilder.Entity<Customer>()
            .Property(c => c.DateOfBirth); // Verify if needed
    }
}
```

## 13. Best Practices Verification

**Verify that the application follows these practices:**

✅ **Data minimization principles:**
- Only collect data that is absolutely necessary
- Have documented justification for each sensitive field
- Regular review of stored data for necessity
- Delete data when no longer needed

✅ **Privacy by Design:**
- Consider privacy implications in entity design
- Use least-privilege data access
- Implement data retention policies
- Provide data deletion capabilities

✅ **Alternative approaches:**
- Derive data when needed instead of storing
- Use aggregated/anonymized data where possible
- Store partial data (year instead of full date)
- Use tokens/references instead of actual data

✅ **Regulatory compliance:**
- GDPR art. 5(1)(c) - data minimisation
- GDPR art. 9 - special categories need an explicit legal basis; a DPIA (art. 35) where processing is likely high-risk
- GDPR art. 8 - age of consent for information-society services (16 in the Netherlands)
- UAVG art. 46 - BSN only with a statutory basis
- PCI DSS for payment data (should not be stored directly)

✅ **Documentation:**
- Data inventory documenting what is stored and why
- Privacy impact assessments for sensitive data
- Retention policies for each data type
- Legal basis for processing personal data

## 14. Usage Verification Steps

**For each potentially unnecessary field, verify usage:**

1. **Search for property access:**
   ```regex
   \bDateOfBirth\b                                   // every reference to the property
   \.DateOfBirth\b|\bDateOfBirth\s*=                 // reads and assignments
   \b(Bsn|BurgerServiceNummer|SocialSecurityNumber|NationalId)\b
   \b(Gender|Religion|Ethnicity|Race|SexualOrientation)\b
   ```

2. **Check controller/API usage:**
   - Is it in API request/response models?
   - Is it displayed in any views?
   - Is it used in calculations?

3. **Check business logic usage:**
   - Is it used in any business rules?
   - Is it required for any workflows?
   - Is it part of any validations?

4. **Check reporting/analytics:**
   - Is it used in reports?
   - Is it part of analytics queries?
   - Can reports work without it?

5. **If usage is found:**
   - Evaluate if usage is justified
   - Consider if alternative approaches exist
   - Document the business need

6. **If no usage found:**
   - Strong candidate for removal
   - Check if it was planned for future features
   - Consider technical debt cleanup

## 15. Special Considerations

**Data that should NEVER be stored (unless specific legal requirement):**
- Full credit card numbers (use tokenization)
- Plain-text passwords (use hashing)
- BSN / Social Security Numbers (UAVG art. 46: only with a statutory basis, e.g. payroll)
- Medical diagnoses (unless healthcare application)
- Biometric data (unless specifically needed)
- Children's data (GDPR art. 8: parental consent below the age of 16 in the Netherlands)
- Religion, political affiliation (discrimination risk)
- Race, ethnicity (only if legally required for reporting)

**Data to store with extreme caution:**
- Date of birth (consider age ranges instead)
- Full addresses (consider city/postal code only)
- Phone numbers (consider optional/verified only)
- Financial information (ensure PCI DSS compliance)
- Location data (consider city-level vs. GPS coordinates)

**Acceptable data storage (when needed):**
- Name (required for personalization)
- Email (required for communication/authentication)
- Username (required for identification)
- Preferences/settings (improves user experience)
- Order history (required for business operations)
- Billing information (when using payment processor tokens)

## What to Report

**Exposure findings (sections 1–6)** — for each finding, provide:
- **Endpoint** (file and line number)
- **Response field(s)** or **data category** that is unnecessarily exposed
- **Assessment**: JUSTIFIED / QUESTIONABLE / EXCESSIVE (section 3); only QUESTIONABLE and EXCESSIVE produce findings
- **Recommendation**: remove the field from the response DTO, apply field selection, or scope the query

**Storage findings (sections 7–15)** — report every instance of unnecessary sensitive data storage; for each finding, provide:

1. **Entity/Table name** - Where the data is stored
2. **Field/Property name** - The specific sensitive field
3. **Data type** - What kind of sensitive information
4. **Business justification assessment:**
   - **NOT JUSTIFIED**: No clear business need identified
   - **QUESTIONABLE**: Weak justification, alternatives available
   - **POTENTIALLY JUSTIFIED**: May be needed, requires verification
   - **JUSTIFIED**: Clear business or legal requirement

5. **Usage analysis:**
   - Is this field used in the codebase? (Search for property usage)
   - In how many places is it accessed?
   - Is it displayed in the UI?
   - Is it used in business logic?
   - Is it required for any API endpoints?

6. **Recommendation:**
   - **REMOVE**: Delete the field entirely
   - **REPLACE**: Use less sensitive alternative (e.g., age range instead of DOB)
   - **DERIVE**: Calculate on-demand instead of storing
   - **JUSTIFY**: Document why this data is necessary
   - **ENCRYPT**: If data must be stored, ensure proper encryption — see check 17 (database_field_encryption.md) for whether a sensitive column is encrypted
   - **ANONYMIZE**: Store in anonymized form when possible

**Severity** (one rating for both kinds of finding):
- **Critical**: sensitive field (password hash, token, BSN/SSN, PAN, health data) exposed to unauthenticated callers or to other users; BSN/SSN, PAN, CVV or health data stored without a legal basis or business need
- **High**: the same sensitive field exposed only to the authenticated owner or to admins; other special-category data (GDPR art. 9: race, ethnicity, religion, sexual orientation, biometric) or financial data (bank account, IBAN, salary, credit score) stored without need
- **Medium**: other PII (email, phone, address, date of birth) exposed without a frontend need; ordinary PII (date of birth, full address, phone numbers, gender, marital status, precise location) stored without need
- **Low**: non-sensitive over-fetch (unused ordinary fields, full entity in a lookup, legacy fields kept for backward compatibility); non-sensitive data stored without need (age range, city/country, preferences)
- **Not a finding**: ids, foreign keys and `CreatedBy`/`ModifiedBy`, unless they expose another user's PII to non-admins; a stored field assessed JUSTIFIED. QUESTIONABLE or POTENTIALLY JUSTIFIED stored fields are rated one level lower than NOT JUSTIFIED.

Remediate in the order of that severity; there is no separate priority scale. Within one severity, remove unused fields first (no functional cost), then REPLACE or DERIVE fields that have a less sensitive alternative (age range instead of date of birth, city/postal code instead of a full address), then JUSTIFY and document the remaining fields.

**Example report format:**
```
Finding: Unnecessary Storage of Date of Birth
- Entity: User (Users table)
- Field: DateOfBirth (DateTime)
- Severity: Medium
- Business Justification: NOT JUSTIFIED
- Usage Analysis: 
  * Field is set during registration
  * Never displayed in UI
  * Not used in any business logic
  * Only used to calculate age in 1 location
- Risk: 
  * Stores more data than needed (full DOB vs. just age)
  * GDPR violation if not properly justified
  * Increases breach impact
- Recommendation: REPLACE
  * Remove DateOfBirth property
  * Add IsOver18 or AgeRange property instead
  * Update registration to only capture necessary information
  * Create migration to drop column
```
