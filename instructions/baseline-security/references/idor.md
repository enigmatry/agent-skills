# IDOR (Insecure Direct Object References) Analysis

Scan the codebase for Insecure Direct Object Reference vulnerabilities where API endpoints or data-access operations accept resource identifiers from the caller without verifying the caller is authorized to access that specific resource.

## Core Security Principle
**Every request that accesses a resource by ID must verify that the authenticated user is authorized to access that specific resource. Authentication (confirming who you are) is not the same as authorization (confirming what you may access).**

## 1. Direct ID Usage in API Endpoints

Identify endpoints where resource IDs come from the caller:
- Route parameters that access resources by ID (e.g. `/api/users/{userId}`, `/documents/{documentId}`)
- Query parameters that reference object IDs directly
- RESTful endpoints that expose internal database IDs
- Bulk endpoints accepting lists of IDs from the caller

## 2. Missing Authorization Checks

Look for data access without ownership or permission validation:
- Controllers that fetch objects by ID without checking user ownership
- Database queries using caller-supplied IDs without access control validation
- Repository methods like `GetById(id)` called without a prior ownership check
- File access operations using caller-provided paths or IDs

## 3. Vulnerable Code Patterns

Flag these patterns for closer review:
```csharp
// Direct lookup without ownership check
var document = await context.Documents.FindAsync(documentId);

// File access with user-controlled path
var content = File.ReadAllText(filePath);

// Bulk query without user-scoped filter
return await context.Orders.Where(o => ids.Contains(o.Id)).ToListAsync();
```

## 4. Authentication vs. Authorization Gaps

- Endpoints that verify the user is authenticated but not that they own the resource
- Role-based checks that do not include resource-level ownership verification
- JWT or session validation without object-level access control
- Admin endpoints that fail to scope resources to the admin's tenant or domain

## 5. Data Exposure Risks

- API responses returning data belonging to other users
- Bulk or listing operations without user-based filtering
- Search endpoints returning records the caller is not authorized to see
- Error messages that reveal information about resources the caller cannot access

## 6. Framework-Specific Checks

- **ASP.NET Core**: Missing `[Authorize]` attributes or resource-based authorization policies
- **Entity Framework**: Direct `context` access without a user-scoped filter
- **Repository patterns**: Generic repositories lacking built-in ownership enforcement
- **Service layer**: Business logic that does not validate resource ownership before returning data

## 7. Common Vulnerable Scenarios

- User profile: `/users/{id}` without confirming the `id` matches the authenticated user
- Documents: `/documents/{id}` without verifying the user has permission
- Orders: `/orders/{id}` accessible by any authenticated user, not just the owner
- Admin functions: `/admin/users/{id}` without tenant-scoped role validation
- API keys: `/api-keys/{id}` without confirming the key belongs to the caller

## What to Report

For each finding, provide:
- **File** and line number
- **Endpoint or method** where the unchecked access occurs
- **ID parameter** used (route, query string, or body)
- **Risk**: HIGH (user data accessible without any ownership check) / MEDIUM (partial checks present with gaps) / LOW (admin-only endpoint with incomplete scope validation)
- **Recommendation**: resource-based authorization check or ownership filter to apply
