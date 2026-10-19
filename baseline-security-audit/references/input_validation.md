# Input Validation Security Analysis

Analyze the codebase to identify missing or insufficient input validation that could lead to security vulnerabilities:

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A05 Injection, A06 Insecure Design · **ASVS 5.0:** V2 Validation and Business Logic

## Core Security Principle
**All user input fields should be validated. Input validation must be implemented at least server-side for all input fields, and preferably also client-side for better user experience and defense-in-depth.**

## 1. Server-Side Validation (REQUIRED)

**ASP.NET Core / .NET Applications:**

**Check for validation attributes on models:**
```csharp
// Look for Data Annotation attributes
[Required]
[StringLength]
[Range]
[RegularExpression]
[EmailAddress]
[Phone]
[Url]
[CreditCard]
[Compare]
[MinLength]
[MaxLength]

// Custom validation
[CustomValidation]
IValidatableObject
ValidationAttribute
```

**Check for ModelState validation in controllers:**
```csharp
// REQUIRED pattern in API controllers/actions
if (!ModelState.IsValid)
{
    return BadRequest(ModelState);
}

// Or using ApiController attribute (automatic validation)
[ApiController]
public class MyController : ControllerBase
```

**FluentValidation usage:**
```csharp
// Validator classes
public class MyValidator : AbstractValidator<MyModel>
{
    public MyValidator()
    {
        RuleFor(x => x.Property).NotEmpty();
        RuleFor(x => x.Email).EmailAddress();
    }
}

// Check for validator registration in DI
services.AddValidatorsFromAssemblyContaining<MyValidator>();
```

**Flags to raise:**
- Actions on controllers **without** `[ApiController]` that accept user input and have no `ModelState.IsValid` check or FluentValidation auto-validation (`[ApiController]` returns 400 automatically on invalid `ModelState`; do not flag those)
- DTO/Model classes without validation attributes, only when the type is bound from a request (see section 8 for the scope)
- Direct binding of user input to database entities without validation
- Missing validation for file uploads (size, type, content)

## 2. Client-Side Validation (RECOMMENDED)

**Angular Applications:**

**Template-driven forms:**
```html
<!-- Check for validation attributes -->
<input required minlength="3" maxlength="50" pattern="[a-zA-Z]*">
<input type="email" required>
<input type="url">

<!-- Check for validation state handling (Angular 17+ control flow; `*ngIf` is legacy, same check) -->
@if (nameControl.invalid && nameControl.touched) {
  @if (nameControl.errors?.['required']) { <div>Name is required</div> }
}
```

**Reactive forms:**
```typescript
// Check for Validators usage
this.form = this.fb.group({
  name: ['', [Validators.required, Validators.minLength(3)]],
  email: ['', [Validators.required, Validators.email]],
  age: ['', [Validators.min(18), Validators.max(100)]],
  website: ['', Validators.pattern(/^https?:\/\/.+/)]
});

// Custom validators
Validators.pattern()
Validators.min()
Validators.max()
CustomValidators
```

**HTML5 validation attributes:**
```html
<input type="text" required minlength="3" maxlength="50">
<input type="email" required>
<input type="number" min="0" max="100">
<input type="url">
<input type="tel" pattern="[0-9]{3}-[0-9]{3}-[0-9]{4}">
```

## 3. Input Types and Validation Rules

**Search for input fields and verify validation:**

**Text inputs:**
- Length constraints (min/max length)
- Format validation (regex patterns)
- Character whitelist/blacklist
- Trim whitespace
- Prevent null/empty when required

**Numeric inputs:**
- Range validation (min/max values)
- Data type enforcement (integer, decimal)
- Prevent negative numbers when inappropriate
- Handle overflow/underflow

**Email addresses:**
- Email format validation
- Length limits
- Normalize (lowercase, trim)

**URLs:**
- URL format validation
- Protocol whitelist (http/https only)
- Length limits
- Prevent javascript:, data:, file: protocols

**Dates:**
- Date format validation
- Range validation (min/max dates)
- Future/past date restrictions
- Time zone handling

**File uploads:**
- File type validation (extension and MIME type)
- File size limits: `[RequestSizeLimit]`, `[RequestFormLimits]`, `FormOptions.MultipartBodyLengthLimit`, Kestrel `MaxRequestBodySize`, IIS `maxAllowedContentLength`
- Content validation (not just extension): file signature (magic bytes) check on the `IFormFile` stream
- Virus scanning — not a code check: ask the user whether uploads are scanned; do not report it as a finding
- Filename sanitization: `Path.GetFileName` on the supplied name and storage outside the web root (a caller-controlled path reaching the file system is path traversal, owned here, section 4)
- Upload endpoint with no size limit or an extension-only type check = Medium

**Passwords:** length and composition rules are owned by check 19 (authentication_security.md); hashing by check 13 (cryptography_security.md). Here only check that the password field is bound server-side and has a maximum length.

**Phone numbers:**
- Format validation
- Country code validation
- Length constraints

**Credit cards:**
- Format validation (Luhn algorithm)
- Card type detection
- Expiration date validation

## 4. Specific Validation Vulnerabilities

**Mass Assignment Protection:**
```csharp
// UNSAFE - binds all properties from request
public IActionResult Update(User user)

// SAFE - use specific DTO
public IActionResult Update(UpdateUserDto dto)

// [Bind] restricts form and query binding only, not [FromBody] JSON
public IActionResult Update([Bind("Name,Email")] User user)
// For APIs: a dedicated request DTO, or reject unknown members (.NET 8+)
new JsonSerializerOptions { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow }
```
**Mass assignment / BOPLA (owned here):** in request-bound DTOs and entities (section 8 scope) flag settable `Id`, `OwnerId`, `UserId`, `TenantId`, `Role`/`Roles`, `IsAdmin`, `IsActive`/`IsApproved`, `Price`, `Balance`, `Discount`, `Status` that the caller must not set; `TryUpdateModelAsync(model)` without an include list; AutoMapper `CreateMap<Dto, Entity>()` or `ReverseMap()` that maps those members without `.Ignore()`. High when the field drives authorization, tenancy or money; Medium otherwise.

**Integer Overflow/Underflow:**
```csharp
// Check for unchecked numeric conversions
int.Parse(userInput) // Can throw exception
Convert.ToInt32(userInput) // Can throw exception

// Better with validation
if (int.TryParse(userInput, out int value) && value >= 0 && value <= 1000)
```

**String Length Attacks:**
```csharp
// MISSING - no length validation
public string Name { get; set; }

// GOOD - length limit
[StringLength(100, MinimumLength = 2)]
public string Name { get; set; }
```

**Regex Denial of Service (ReDoS):**
```csharp
// Check for complex regex patterns that could cause ReDoS
[RegularExpression(@"^(a+)+$")] // DANGEROUS - catastrophic backtracking
[RegularExpression(@"^[a-zA-Z0-9]{3,20}$")] // SAFE - simple pattern
```

**Unsafe deserialization:** Newtonsoft `TypeNameHandling` other than `None` on untrusted input = High; `BinaryFormatter` (removed in .NET 9) = High; System.Text.Json `MaxDepth` left at its default on large untrusted payloads = Low.

**Path traversal (owned here):** `Path.Combine(root, userInput)` without `Path.GetFullPath` plus a `StartsWith(root)` check, `File.ReadAllText`/`FileStream` on a user-supplied path, `Directory.GetFiles` with user input. Reachable from user input = High.

**SSRF (OWASP 2025 folds it into A01):** server-side `HttpClient`/`WebRequest` calls with a user-supplied URL need a host allow-list, blocking of private and link-local ranges (`169.254.169.254` metadata endpoint) and no redirect following to arbitrary hosts (`AllowAutoRedirect`). User-controlled outbound URL without an allow-list = High.

## 5. Framework-Specific Validation Checks

**ASP.NET Core Minimal APIs:**
```csharp
// Check for validation in minimal APIs
app.MapPost("/api/users", async (MyModel model, IValidator<MyModel> validator) =>
{
    var result = await validator.ValidateAsync(model);
    if (!result.IsValid)
        return Results.ValidationProblem(result.ToDictionary());
    
    // Process valid input
});
```

**.NET 10 built-in minimal API validation (opt-in):**
```csharp
// GOOD — enables DataAnnotations and IValidatableObject on minimal API parameters; invalid input returns ValidationProblem (400)
builder.Services.AddValidation();

// Types that are not endpoint parameters themselves are validated when marked
[ValidatableType]
public class OrderLine { ... }

// RED FLAG — opts the endpoint out of validation
app.MapPost("/api/orders", (Order order) => ...).DisableValidation();
```
Flags: a net10.0 minimal API project that relies on DataAnnotations without `builder.Services.AddValidation()` (the attributes are silently ignored) = Medium; `.DisableValidation()` on an endpoint that takes user input = Medium.
Source: https://learn.microsoft.com/en-us/aspnet/core/fundamentals/minimal-apis/validation

**Entity Framework Core:**
```csharp
// Check for validation before SaveChanges
protected override void OnModelCreating(ModelBuilder modelBuilder)
{
    modelBuilder.Entity<User>()
        .Property(u => u.Email)
        .IsRequired()
        .HasMaxLength(256);
}
```

## 6. What to Report

**Report ALL instances of (rate each per the Risk Assessment below):**
- API endpoints accepting user input without validation
- Model/DTO classes without validation attributes
- Missing `ModelState.IsValid` checks (when not using `[ApiController]`)
- net10.0 minimal API projects using DataAnnotations without `AddValidation()`, or `.DisableValidation()` on an endpoint that takes user input (Medium)
- Mass assignment: a privileged, tenancy or monetary field settable from the request body, `TryUpdateModelAsync` without an include list, or a DTO-to-entity map covering such fields (High when it drives authorization or money, Medium otherwise)
- File upload endpoints without type/size validation: no request size limit or an extension-only type check (Medium)
- Unsafe deserialization: Newtonsoft `TypeNameHandling` other than `None` or `BinaryFormatter` on untrusted input (High); default `MaxDepth` on large untrusted payloads (Low)
- Path traversal or SSRF reachable from user input (High)
- Numeric inputs without range validation
- Text inputs without length constraints
- Email/URL inputs without format validation
- Missing client-side validation while server-side validation exists (Low)
- Direct database entity binding without DTO layer
- Query string/route parameters used without validation

**For each finding, provide:**
- File path and line number
- Code snippet showing missing validation
- Input field/parameter name and type
- Expected validation rules (based on field type and context)
- Recommended fix with validation example
- Risk level: High / Medium / Low per the Risk Assessment below

**Risk Assessment:**
- **High**: No server-side validation on an input that reaches a database, file system, external call or authorization decision
- **Medium**: Other missing server-side validation
- **Low**: Client-side validation missing while server-side validation exists. Client-side validation on its own never counts as validation: an input validated only in Angular is rated as missing server-side validation (High or Medium above)

## 7. Validation Best Practices

**Verify that the application:**
- Validates ALL user input server-side (never trust client)
- Uses whitelisting approach (allow known good) over blacklisting
- Validates data type, format, length, and range
- Provides clear validation error messages (without revealing sensitive info)
- Validates at multiple layers (client, API, business logic)
- Uses established validation libraries/frameworks
- Validates file uploads thoroughly (type, size, content)
- Protects against mass assignment vulnerabilities
- Handles validation errors gracefully
- Logs validation failures for security monitoring

**Client-side validation benefits:**
- Immediate user feedback
- Reduced server load
- Better user experience
- Defense-in-depth approach

**Server-side validation is mandatory because:**
- Client-side validation can be bypassed
- Security cannot rely on client controls
- Malicious users can craft requests directly
- Compliance and regulatory requirements (not a code check: ask the user which requirements apply; do not report them as findings)

**Recommended validation approach:**
```
1. Client-side validation (UX, immediate feedback)
2. API/Controller validation (security gate)
3. Business logic validation (domain rules)
4. Database constraints (last line of defense)
```

## 8. Search Patterns

**Look for these patterns indicating potential missing validation:**

Scope: only types that appear as controller action parameters, minimal-API endpoint parameters, or `[FromBody]`/`[FromForm]`/`[FromQuery]` arguments are in scope. A `*Dto`/`*Model`/`*Request`/`*Command` class, or a `public string X { get; set; }` property, on a type that is never bound from a request is **not** a finding. First collect the bound types, then inspect only those.

```regex
// Step 1 — collect the request-bound types (action and endpoint parameters)
\[Http(Post|Put|Patch)\][\s\S]{0,200}?\(\s*(\[From(Body|Form|Query)\]\s*)?(\w+)\s+\w+
\[From(Body|Form|Query)\]\s*(\w+)\s+\w+
Map(Post|Put|Patch)\([^,]+,\s*(async\s*)?\(\s*(\[From(Body|Form|Query)\]\s*)?(\w+)\s+\w+

// Step 2 — within those types only: properties without validation attributes on the preceding line
public string .* \{ get; set; \}
public int .* \{ get; set; \}
public decimal .* \{ get; set; \}

// .NET 10 minimal API validation (opt-in; absence or opt-out is Medium)
AddValidation\(\)|\.DisableValidation\(\)|\[ValidatableType\]

// Mass assignment — within request-bound types only (section 4)
public\s+\w+\??\s+(Id|OwnerId|UserId|TenantId|Roles?|IsAdmin|IsActive|IsApproved|Price|Balance|Discount)\s*\{\s*get;\s*(set|init);
TryUpdateModelAsync(<\w+>)?\(\s*\w+\s*\)|ReverseMap\(\)|CreateMap<\w*(Dto|Request|Command)\w*,\s*\w+>

// Direct user input usage
Request.Query\[|Request.Form\[|Request.Headers\[
HttpContext.Request

// Unsafe deserialization, path traversal, SSRF (section 4)
TypeNameHandling\.(All|Auto|Objects|Arrays)|BinaryFormatter|Path\.Combine\(|Directory\.GetFiles\(|File\.ReadAll|new HttpClient\(|GetAsync\(\s*\w*(url|uri)
```

**Check these file types:**
- Controllers: `*Controller.cs`, `*Controllers.cs`
- Models/DTOs: `*Model.cs`, `*Dto.cs`, `*Request.cs`, `*Command.cs`
- Validators: `*Validator.cs`
- API endpoints in minimal APIs: `Program.cs`, `*Endpoints.cs`
- Client-side forms: `*.component.ts`, `*.component.html`

## 9. Additional Considerations

**Business Logic Validation:**
- Check for business rule validation beyond basic format checks
- Check for concurrent modification handling
- Validate relationships and referential integrity

**Sanitization vs Validation:**
- Validation: Reject invalid input
- Sanitization: Clean/transform input to safe format
- Both should be used together, validation first
- Never sanitize to "fix" invalid input without user notification

**Internationalization:**
- Validate international characters appropriately
- Support various date/number formats
- Handle different character encodings
- Validate locale-specific formats (phone, postal codes)

