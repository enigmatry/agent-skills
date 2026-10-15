# Data Minimization Analysis

Analyze the codebase to ensure API endpoints only return the minimum data required by the frontend, preventing unnecessary sensitive data exposure:

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A04 Cryptographic Failures, A06 Insecure Design · **ASVS 5.0:** V14 Data Protection
> **Owns:** frontend models or interfaces exposing sensitive fields (also encountered in 14)
> **Defers to:** mass assignment / over-posting of `Id`, `OwnerId`, `TenantId`, `Role` (BOPLA) → check 10 (input_validation.md)

## Core Security Principle
**APIs must implement data minimization - only return fields that are actually consumed by the frontend application. Unused data in responses creates unnecessary attack surface.**

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

Inbound over-posting (`Id`, `OwnerId`, `TenantId`, `Role` accepted from the request body) is owned by check 10 (input_validation.md); reference that finding instead of reporting it here.

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

## What to Report

For each finding, provide:
- **Endpoint** (file and line number)
- **Response field(s)** or **data category** that is unnecessarily exposed
- **Assessment**: JUSTIFIED / QUESTIONABLE / EXCESSIVE (section 3); only QUESTIONABLE and EXCESSIVE produce findings
- **Severity**: Critical / High / Medium / Low per section 6
- **Recommendation**: remove the field from the response DTO, apply field selection, or scope the query

