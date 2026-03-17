# Data Storage Minimization Analysis

Analyze the codebase to identify unnecessary storage of sensitive or personal data that violates the principle of data minimization:

## Core Security Principle
**Only data which is strictly required for the application should be stored. Storing unnecessary sensitive or personal data increases privacy risks, regulatory compliance burden, and potential breach impact. This principle is fundamental to GDPR, CCPA, and other privacy regulations.**

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
public DateTime LastLoginLocation { get; set; }
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

## 6. Database Migration Analysis

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
// - Are these fields encrypted at rest?
```

## 7. DbContext and Configuration Analysis

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

## 8. What to Report

**Report ALL instances of unnecessary sensitive data storage (MEDIUM PRIORITY):**

**For each finding, provide:**

1. **Entity/Table name** - Where the data is stored
2. **Field/Property name** - The specific sensitive field
3. **Data type** - What kind of sensitive information
4. **Sensitivity level:**
   - **CRITICAL**: SSN, credit cards, biometric data, medical records
   - **HIGH**: Full date of birth, financial data, precise location
   - **MEDIUM**: Gender, ethnicity, full address, phone numbers
   - **LOW**: Age ranges, general location (city/country)

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
   - **ENCRYPT**: If data must be stored, ensure proper encryption
   - **ANONYMIZE**: Store in anonymized form when possible

**Example report format:**
```
Finding: Unnecessary Storage of Date of Birth
- Entity: User (Users table)
- Field: DateOfBirth (DateTime)
- Sensitivity Level: HIGH
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

## 10. Best Practices Verification

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
- GDPR Article 5(1)(c) - Data minimization
- CCPA requirements for data collection
- HIPAA for medical data (if applicable)
- PCI DSS for payment data (should not be stored directly)

✅ **Documentation:**
- Data inventory documenting what is stored and why
- Privacy impact assessments for sensitive data
- Retention policies for each data type
- Legal basis for processing personal data

## 11. Usage Verification Steps

**For each potentially unnecessary field, verify usage:**

1. **Search for property access:**
   ```
   Search: "user.DateOfBirth", ".DateOfBirth", "DateOfBirth ="
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

## 12. Special Considerations

**Data that should NEVER be stored (unless specific legal requirement):**
- Full credit card numbers (use tokenization)
- Plain-text passwords (use hashing)
- Social Security Numbers (unless legally required, e.g., payroll)
- Medical diagnoses (unless healthcare application)
- Biometric data (unless specifically needed)
- Children's data (additional COPPA compliance)
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

## 13. Remediation Priority

**Prioritize remediation based on:**

1. **CRITICAL (Immediate action):**
   - Sensitive data stored without clear legal/business need
   - Unencrypted sensitive data (SSN, financial, medical)
   - Data that violates regulations (GDPR, CCPA, HIPAA)
   - Data that poses discrimination risk (religion, race without justification)

2. **HIGH (Short-term):**
   - Excessive personal data without strong justification
   - Full date of birth when age range suffices
   - Detailed addresses when city/postal code suffices
   - Unused fields that contain sensitive data

3. **MEDIUM (Medium-term):**
   - Demographic data with weak business justification
   - Redundant contact information
   - Historical data that could be archived/deleted
   - Optional fields that could be removed

4. **LOW (Long-term):**
   - Fields with questionable value
   - Data that could be derived instead of stored
   - Optimization opportunities for data storage

## 14. Angular Considerations

**While Angular is the front-end framework, check:**

**TypeScript models/interfaces:**
- `*.model.ts`, `*.interface.ts` files
- DTOs that mirror backend entities
- Forms that collect sensitive data

**Verify forms don't request unnecessary data:**
```typescript
// registration.component.ts or user-form.component.ts
export interface RegistrationForm {
  email: string;
  password: string;
  dateOfBirth: Date;        // Is this needed?
  ssn: string;              // Should NOT be requested!
  phoneNumber: string;      // Required or optional?
  gender: string;           // Necessary for application?
  address: string;          // Needed or can use city/postal?
}
```

**Check that UI doesn't display unnecessary sensitive data:**
- User profile pages showing too much information
- Admin panels displaying sensitive fields
- Forms collecting more data than needed

**Note:** The primary check is backend entity definitions, but Angular forms indicate what data is being collected from users.
