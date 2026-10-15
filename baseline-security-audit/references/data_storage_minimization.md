# Data Storage Minimization Analysis

Analyze the codebase to identify unnecessary storage of sensitive or personal data that violates the principle of data minimization:

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A04 Cryptographic Failures, A06 Insecure Design · **ASVS 5.0:** V14 Data Protection
> **Owns:** —
> **Defers to:** frontend models or interfaces exposing sensitive fields → check 13 (data_minimization.md); encryption state of a sensitive database column → check 21 (database_field_encryption.md)

## Core Security Principle
**Only data which is strictly required for the application should be stored. Storing unnecessary sensitive or personal data increases privacy risks, regulatory compliance burden, and potential breach impact. This is GDPR art. 5(1)(c) (data minimisation); art. 9 special categories need an explicit legal basis and, where processing is likely high-risk, a DPIA (art. 35); UAVG art. 46 permits the BSN only with a statutory basis.**

## 1. Database Schema Analysis

**Check Entity Framework Core entity definitions:**

**Files to examine:**
- `*.cs` files in `Models/`, `Entities/`, `Domain/` folders
- Entity classes with `DbSet<T>` references
- Classes inheriting from base entity classes
- Data Transfer Objects (DTOs) that map to database entities

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

## 2. Sensitive Data Fields to Identify

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

## 3. Questions to Ask for Each Sensitive Field

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

## 4. Common Unnecessary Data Examples

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

## 5. Database Migration Analysis

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
// - Are these fields encrypted at rest? (encryption state is owned by check 21, database_field_encryption.md)
```

## 6. DbContext and Configuration Analysis

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

## 7. What to Report

**Report every instance of unnecessary sensitive data storage:**

**For each finding, provide:**

1. **Entity/Table name** - Where the data is stored
2. **Field/Property name** - The specific sensitive field
3. **Data type** - What kind of sensitive information
4. **Severity** (data class × justification; the single rating used throughout this check):
   - **Critical**: BSN/SSN, PAN, CVV or health data stored without a legal basis or business need
   - **High**: other special-category data (GDPR art. 9: race, ethnicity, religion, sexual orientation, biometric) or financial data (bank account, IBAN, salary, credit score) stored without need
   - **Medium**: ordinary PII (date of birth, full address, phone numbers, gender, marital status, precise location) stored without need
   - **Low**: non-sensitive data stored without need (age range, city/country, preferences)
   A field assessed JUSTIFIED below is not a finding; QUESTIONABLE or POTENTIALLY JUSTIFIED fields are rated one level lower than NOT JUSTIFIED.

5. **Business justification assessment:**
   - **NOT JUSTIFIED**: No clear business need identified
   - **QUESTIONABLE**: Weak justification, alternatives available
   - **POTENTIALLY JUSTIFIED**: May be needed, requires verification
   - **JUSTIFIED**: Clear business or legal requirement

6. **Usage analysis:**
   - Is this field used in the codebase? (Search for property usage)
   - In how many places is it accessed?
   - Is it displayed in the UI?
   - Is it used in business logic?
   - Is it required for any API endpoints?

7. **Recommendation:**
   - **REMOVE**: Delete the field entirely
   - **REPLACE**: Use less sensitive alternative (e.g., age range instead of DOB)
   - **DERIVE**: Calculate on-demand instead of storing
   - **JUSTIFY**: Document why this data is necessary
   - **ENCRYPT**: If data must be stored, ensure proper encryption — the encryption state of the column is owned by check 21 (database_field_encryption.md); reference that finding instead of reporting it here
   - **ANONYMIZE**: Store in anonymized form when possible

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

## 8. Best Practices Verification

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

## 9. Usage Verification Steps

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

## 10. Special Considerations

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

## 11. Remediation Priority

Remediate in the order of the severity assigned in section 7 (data class × justification); there is no separate priority scale. Within one severity, remove unused fields first (no functional cost), then REPLACE or DERIVE fields that have a less sensitive alternative (age range instead of date of birth, city/postal code instead of a full address), then JUSTIFY and document the remaining fields. Unencrypted sensitive columns are owned by check 21 (database_field_encryption.md); reference that finding instead of reporting it here.

## 12. Angular Considerations

Frontend models, interfaces and forms that expose or collect sensitive fields are owned by check 13 (data_minimization.md); reference that finding instead of reporting it here. Use Angular forms only as evidence of which backend entity fields are populated (a `bsn` or `dateOfBirth` form control points at the entity field to assess under sections 2–3).
