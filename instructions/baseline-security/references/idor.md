Please scan my codebase for Insecure Direct Object References (IDOR) vulnerabilities. Check for:

**1. Direct ID Usage in API Endpoints**
- Route parameters that directly access resources by ID without authorization checks
- Path parameters like `/api/users/{userId}` or `/documents/{documentId}`
- Query parameters that reference object IDs directly
- RESTful endpoints that expose internal database IDs

**2. Missing Authorization Checks**
- Controllers/endpoints that don't verify user ownership of requested resources
- Methods that fetch objects by ID without checking user permissions
- Database queries using user-supplied IDs without access control validation
- File access operations using user-provided file paths or IDs

**3. Vulnerable Patterns**
- Repository methods like `GetById(id)` called without prior authorization
- Direct database queries: `context.Users.Find(userId)` without ownership validation
- File operations: `File.ReadAllText(filePath)` with user-controlled paths
- URL generation that exposes internal object references

**4. Authentication vs Authorization Gaps**
- Endpoints that check if user is authenticated but not if they own the resource
- Role-based checks that don't include resource-specific permissions
- JWT/session validation without object-level access control
- Admin endpoints that don't validate admin scope for specific resources

**5. Data Exposure Risks**
- API responses that return data belonging to other users
- Bulk operations that don't filter by user ownership
- Search/listing endpoints that show unauthorized data
- Error messages that leak information about unauthorized resources

**6. Framework-Specific Checks**
- ASP.NET Core: Missing `[Authorize]` attributes or custom authorization filters
- Entity Framework: Direct context access without user filtering
- Repository patterns: Generic repositories without built-in access control
- Service layer: Business logic that doesn't validate resource ownership

**7. Common Vulnerable Scenarios**
- User profile access: `/users/{id}` without ownership check
- Document/file access: `/documents/{id}` without permission validation
- Order/transaction access: `/orders/{id}` accessible by any authenticated user
- Admin functions: `/admin/users/{id}` without proper role validation
- API keys/secrets: `/api-keys/{id}` without user ownership verification

**8. Input Sources to Examine**
- URL route parameters and query strings
- Form data and request bodies containing object IDs
- Hidden form fields with resource identifiers
- AJAX requests with embedded object references
- Mobile API calls with direct ID parameters

Please provide:
- Specific file locations and line numbers of vulnerable code
- Risk level assessment (Critical/High/Medium/Low)
- Examples of potentially exploitable endpoints
- Recommended authorization patterns and fixes
- Framework-specific security recommendations
- Code examples showing proper access control implementation