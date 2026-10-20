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
IncludeExceptionDetails|ExposeExceptionDetails|EnableDetailedErrors|EnableQueryFeatures|\.Expand\(\)|MaxExpansionDepth   // section 4, error and protocol payloads
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

**Angular state:** NgRx or signal stores (`createFeature`, `signalStore`, `patchState`) and services that keep the full user or customer object where the templates use two fields = Low; `console.log` of API responses carrying personal data = Medium (tokens in `console.log` are check 5 (logging.md)); HTTP interceptors or `shareReplay` caches holding responses with personal data = Low.

## 3. Cross-Reference Analysis

**For each API endpoint, verify:**
- ✅ **JUSTIFIED**: Every returned field is used somewhere in the frontend
- ⚠️ **QUESTIONABLE**: Fields returned but usage unclear/minimal
- ❌ **EXCESSIVE**: Fields returned but never used in UI

**Scope of the "used in the frontend" test (sections 1–3):** it applies to private BFF-style endpoints consumed only by this Angular app. For a shared or public API with other consumers (mobile apps, partners, an API product) the test is "no sensitive field exposed without need": unused ordinary fields are not findings there, sensitive fields keep their What to Report severities.

## 4. Sensitive Data Exposure Patterns

See check 9 (input_validation.md) for inbound over-posting.

**Error and protocol payloads:** stack traces or `ex.Message` in `ProblemDetails` are owned by check 4 (exception_handling.md); logged request/response bodies (`AddHttpLogging`) by check 5 (logging.md). Owned here: GraphQL exception details (Hot Chocolate `IncludeExceptionDetails`, GraphQL.NET `ExposeExceptionDetails`) and SignalR `EnableDetailedErrors = true` outside Development = High; OData `$expand`/`$select` enabled on navigation properties (`.Expand()`, `EnableQueryFeatures()`) without `MaxExpansionDepth`/`SetMaxTop` so a client can pull whole object graphs = Medium (High when the graph reaches other users' PII).

## 5. Security Risk Assessment

Rate each endpoint assessed QUESTIONABLE or EXCESSIVE in section 3 per the Severity list under What to Report.

**Common violations to check:**
- User management APIs returning password hashes/salts
- List endpoints returning full entity details instead of summaries
- Lookup/dropdown APIs returning more than ID+display text
- Search results including internal metadata
- Audit logs exposing system internals

## 6. Database Schema Analysis

**Check Entity Framework Core entity definitions:**

**Files to examine:**
- `*.cs` files in `Models/`, `Entities/`, `Domain/` folders
- Entity classes with `DbSet<T>` references
- Classes inheriting from base entity classes
- Data Transfer Objects (DTOs) that map to database entities
- Angular form controls (a `bsn` or `dateOfBirth` control points at the entity field to assess under sections 7–8)
- `Migrations/*.cs` — `AddColumn` operations show which sensitive columns were introduced, and when

**Entity classes to focus on:** `User`, `Customer`, `Employee`, `Patient`, `Person`, `Profile`, `Account`, `Member`.

**PII in secondary stores (rated as if stored unencrypted in the primary table):** audit tables with before/after JSON blobs (`OldValues`/`NewValues`, Audit.NET, `SaveChangesInterceptor`), outbox or event tables, Application Insights custom dimensions (`TrackEvent`/`TelemetryClient` properties), blob uploads (ID scans, contracts), search indexes (Azure AI Search, Elasticsearch), Redis / `IDistributedCache`, Service Bus or Event Grid messages. Search: `AuditLog|OutboxMessage|TrackEvent|TelemetryClient|SearchClient|IDistributedCache|ServiceBusMessage|BlobClient\.Upload`. A copy of BSN/SSN, PAN or health data in any of these without its own retention and encryption = High; other PII = Medium.

## 7. Sensitive Data Fields to Identify

Storage findings cover only the groups below. Contact data the application needs for a feature (name, e-mail address, phone number, address) is not a storage finding.

**High-sensitivity fields to scrutinize** (property names to search for):
- Identification and biometric: `SocialSecurityNumber`, `TaxId`, `PassportNumber`, `DriverLicenseNumber`, `NationalId`, `Bsn` / `BurgerServiceNummer` (UAVG art. 46: only with a statutory basis), `FingerprintData`, `BiometricData`
- Financial: `CreditCardNumber`, `BankAccountNumber`, `IBAN`, `RoutingNumber`, `Salary`, `Income`, `CreditScore`
- Medical: `MedicalRecordNumber`, `BloodType`, `Diagnosis`, `Medication`, `HealthCondition`, `Disability`
- Demographic (often unnecessary): `DateOfBirth`, `Age`, `Race`, `Ethnicity`, `Religion`, `MaritalStatus`, `Gender`, `SexualOrientation`, `Nationality`
- Employment, family, location and behavioural: `CurrentSalary`, `PreviousEmployer`, `TerminationReason`, `SpouseName`, `EmergencyContact*`, `Latitude` / `Longitude` / `GPSCoordinates`, `BrowsingHistory`, `SearchHistory`, `PurchaseHistory`, `LastLoginLocation`

**Uncontrolled PII sinks:** free-text columns (`Notes`, `Comments`, `Description`, `Remarks`), JSON columns (`nvarchar(max)` holding serialised objects, `OwnsOne(...).ToJson()`) and file-upload columns (`byte[]`, `varbinary(max)`, blob references for ID scans) can hold personal data outside the modelled fields. Present without a retention or classification rule = Medium.

**Entra ID attribute duplication:** when sign-in is delegated to Entra ID, copying profile attributes (phone, address, date of birth, manager, job title) into the application's user table duplicates data available from the token claims or Microsoft Graph = Medium unless a business need is documented. Search: `GraphServiceClient`, `OnTokenValidated` handlers that persist claims, `User` entities carrying those columns.

## 8. Questions to Ask for Each Sensitive Field

**For each identified sensitive data field, verify:**

1. **Business necessity:** which feature needs it; can the application work without it?
2. **Legal basis:** required by law, KYC or tax reporting?
3. **Alternatives:** derive it when needed, store a less sensitive form (age range instead of date of birth), a hash, or request it only when needed?
4. **Retention:** how long is it kept? Ask the user; not a finding on its own.

## 9. Regulatory Basis

- GDPR art. 5(1)(c) - data minimisation
- GDPR art. 9 - special categories need an explicit legal basis; a DPIA (art. 35) where processing is likely high-risk
- GDPR art. 8 - age of consent for information-society services (16 in the Netherlands)
- UAVG art. 46 - BSN only with a statutory basis
- PCI DSS for payment data (should not be stored directly)
- EU Data Act (Regulation (EU) 2023/2854, applies since 12 September 2025) - relevant only when the product is a connected product or related service (IoT data access and B2B data-sharing obligations). If so, report one Low "verify with the product owner" item; otherwise not applicable. Source: https://digital-strategy.ec.europa.eu/en/policies/data-act
- EU AI Act - relevant only when the application profiles people or makes automated decisions about them with an AI component (look for ML/LLM SDK packages such as `Microsoft.ML`, `Azure.AI.*`, `OpenAI`, or scoring/ranking of persons). If so, report one Low "verify with the product owner" item, not a code finding; the Digital Omnibus agreement postponed the Annex III high-risk obligations to 2 December 2027. Source: https://www.gibsondunn.com/eu-ai-act-omnibus-agreement-postponed-high-risk-deadlines-and-other-key-changes/

## 10. Usage Verification Steps

**For each potentially unnecessary field, verify usage:**

1. **Search for property access:**
   ```regex
   \bDateOfBirth\b                                   // every reference to the property
   \.DateOfBirth\b|\bDateOfBirth\s*=                 // reads and assignments
   \b(Bsn|BurgerServiceNummer|SocialSecurityNumber|NationalId)\b
   \b(Gender|Religion|Ethnicity|Race|SexualOrientation)\b
   ```

2. Zero hits outside the entity, its configuration and migrations = unused, a removal candidate; hits only in request or response models = an exposure finding (sections 1–3); hits in business logic or reports = evaluate the justification (section 8).

## What to Report

**Exposure findings (sections 1–5)** — report every unused or dead response field (never read by the frontend, or never assigned) together as **one Low finding** that lists each endpoint and field. Sensitive fields rated Critical or High below stay separate findings. For each finding, provide:
- **Endpoint** (file and line number)
- **Response field(s)** or **data category** that is unnecessarily exposed
- **Assessment**: JUSTIFIED / QUESTIONABLE / EXCESSIVE (section 3); only QUESTIONABLE and EXCESSIVE produce findings
- **Recommendation**: remove the field from the response DTO, apply field selection, or scope the query

**Storage findings (sections 6–10)** — report every instance of unnecessary sensitive data storage; for each finding, provide:

1. **Entity/Table name** - Where the data is stored
2. **Field/Property name** - The specific sensitive field
3. **Data type** - What kind of sensitive information
4. **Business justification assessment:**
   - **NOT JUSTIFIED**: No clear business need identified
   - **QUESTIONABLE**: Weak justification, alternatives available
   - **POTENTIALLY JUSTIFIED**: May be needed, requires verification
   - **JUSTIFIED**: Clear business or legal requirement

5. **Usage analysis** (section 10): where it is read, displayed or used in logic

6. **Recommendation:**
   - **REMOVE**: Delete the field entirely
   - **REPLACE**: Use less sensitive alternative (e.g., age range instead of DOB)
   - **DERIVE**: Calculate on-demand instead of storing
   - **JUSTIFY**: Document why this data is necessary
   - **ENCRYPT**: If data must be stored, ensure proper encryption — see check 17 (database_field_encryption.md) for whether a sensitive column is encrypted
   - **ANONYMIZE**: Store in anonymized form when possible

**Severity** (one rating for both kinds of finding):
- **Critical**: sensitive field (password hash, token, BSN/SSN, PAN, health data) exposed to unauthenticated callers or to other users; BSN/SSN, PAN, CVV or health data stored without a legal basis or business need
- **High**: the same sensitive field exposed only to the authenticated owner or to admins; GraphQL or SignalR detailed errors outside Development; other special-category data (GDPR art. 9: race, ethnicity, religion, sexual orientation, biometric) or financial data (bank account, IBAN, salary, credit score) stored without need; BSN/SSN, PAN or health data copied into a secondary store without its own retention and encryption
- **Medium**: OData `$expand` without `MaxExpansionDepth`; date of birth, gender, marital status or precise location stored without need; ordinary PII copied into a secondary store; free-text, JSON or file-upload columns without a retention or classification rule; Entra ID profile attributes duplicated into the user table; `console.log` of API responses carrying personal data
- **Low**: the grouped unused-field finding (unused ordinary fields and ordinary PII the frontend never reads, dead properties, full entity in a lookup, legacy fields kept for backward compatibility); non-sensitive data stored without need (age range, city/country, preferences); full user or customer object retained in Angular state or an interceptor cache where two fields are used
- **Low**: EU Data Act or EU AI Act applicability "verify with the product owner" item (section 9); not a code finding
- **Not a finding**: ids, foreign keys and `CreatedBy`/`ModifiedBy`, unless they expose another user's PII to non-admins; a stored field assessed JUSTIFIED. QUESTIONABLE or POTENTIALLY JUSTIFIED stored fields are rated one level lower than NOT JUSTIFIED.

Remediate in the order of that severity; there is no separate priority scale. Within one severity, remove unused fields first (no functional cost), then REPLACE or DERIVE fields that have a less sensitive alternative (age range instead of date of birth, city/postal code instead of a full address), then JUSTIFY and document the remaining fields.
