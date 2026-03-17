Analyze the codebase to ensure API endpoints only return the minimum data required by the frontend, preventing unnecessary sensitive data exposure:

## Core Security Principle
**APIs must implement data minimization - only return fields that are actually consumed by the frontend application. Unused data in responses creates unnecessary attack surface.**

## 1. API Response Analysis

**Map all API endpoints and their returned data:**
- Document all fields returned in each API response
- Identify response DTOs/models and their properties
- Check for over-fetching patterns (returning full entities vs. specific fields)
- Look for sensitive fields that might be unnecessarily exposed

**Search for:**
```csharp
// Controller actions returning data
[HttpGet], [HttpPost], return Ok(), return Json()
// Response DTOs and models
public class *Response, public class *Dto
// Entity mappings that might expose too much
AutoMapper, .Select(), .ProjectTo()
```

## 2. Frontend Data Consumption Mapping

**Trace which API response fields are actually used:**
- Angular components and services consuming APIs
- TypeScript interfaces and models
- HTML templates displaying data
- Form bindings and data transformations

**Search for:**
```typescript
// HTTP client calls
this.http.get(), this.http.post()
// Interface definitions
interface *, export interface
// Template usage
{{ }}, [ngModel], formControlName
// Service data usage
subscribe(), .pipe(), .map()
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

**Rate each endpoint's data exposure:**
- 🟢 **MINIMAL**: Only necessary fields returned and used
- 🟡 **MODERATE**: Some extra fields but no sensitive data
- 🔴 **EXCESSIVE**: Sensitive or unnecessary data exposed

**Common violations to check:**
- User management APIs returning password hashes/salts
- List endpoints returning full entity details instead of summaries
- Lookup/dropdown APIs returning more than ID+display text
- Search results including internal metadata
- Audit logs exposing system internals

## 7. Remediation Priorities

**High Priority (Fix Immediately):**
- Sensitive personal data unnecessarily exposed
- Authentication/authorization details in responses
- Internal system configuration leaked
- Database schemas revealed through over-detailed responses

**Medium Priority (Plan Fixes):**
- Non-sensitive but unused fields cluttering responses
- Performance impact from over-fetching
- Frontend requesting more data than displayed

**Low Priority (Optimize Later):**
- Minor inefficiencies in data transfer
- Legacy fields maintained for backward compatibility

## Expected Deliverables

1. **Endpoint Inventory** - Complete list of API endpoints with returned fields
2. **Usage Matrix** - Mapping of which response fields are used where in frontend
3. **Vulnerability Report** - Specific instances of unnecessary data exposure
4. **Remediation Plan** - Prioritized list of changes needed
5. **Code Examples** - Before/after examples showing proper data minimization

## Implementation Recommendations

**Backend (C#/.NET):**
```csharp
// Use specific DTOs instead of entities
public class UserSummaryDto 
{
    public int Id { get; set; }
    public string Name { get; set; }
    // Only include what frontend needs
}

// Implement field selection
[HttpGet]
public async Task<IActionResult> GetUsers([FromQuery] string[] fields)
{
    // Return only requested fields
}
```

**Frontend (Angular/TypeScript):**
```typescript
// Define minimal interfaces
interface UserSummary {
    id: number;
    name: string;
    // Only properties actually used in templates
}

// Request specific fields when possible
getUsers(fields?: string[]): Observable<UserSummary[]> {
    const params = fields ? { fields: fields.join(',') } : {};
    return this.http.get<UserSummary[]>('/api/users', { params });
}
```

## Success Criteria
- Zero sensitive data unnecessarily exposed in API responses
- >90% of returned API fields actively used in frontend
- Clear documentation of data flow from API to UI
- Performance improvement from reduced data transfer
- Reduced attack surface through minimized data exposure