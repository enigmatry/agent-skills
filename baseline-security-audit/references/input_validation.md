# Input Validation Security Analysis

Analyze the codebase to identify missing or insufficient input validation that could lead to security vulnerabilities:

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A05 Injection, A06 Insecure Design · **ASVS 5.0:** V2 Validation and Business Logic
> **Owns:** Mass assignment / over-posting of `Id`, `OwnerId`, `TenantId`, `Role` (BOPLA); Path traversal in file access
> **Defers to:** Caller-supplied id used in a query without an ownership or tenant check → check 8 (idor.md); Password policy → check 23 (authentication_security.md); Password hashing → check 16 (cryptography_security.md)

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
services.AddFluentValidationAutoValidation();
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
- File size limits
- Content validation (not just extension)
- Virus scanning — not a code check: ask the user whether uploads are scanned; do not report it as a finding
- Filename sanitization (a caller-controlled path reaching the file system is path traversal, owned here)

**Passwords (NIST SP 800-63B-4, July 2025):**
Password policy is owned by check 23 (authentication_security.md) and password hashing by check 16 (cryptography_security.md); reference those findings instead of reporting them here.
- Minimum length 15 characters for single-factor passwords, 8 when MFA is enforced
- Maximum length at least 64 characters (prevent DoS with a sane upper bound, e.g. 128)
- No composition rules (NIST prohibits requiring mixed case, digits or symbols)
- No periodic expiry; rotate only on evidence of compromise
- Screened against a breached/common-password blocklist
- Password confirmation matching

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

// Or use [Bind] attribute
public IActionResult Update([Bind("Name,Email")] User user)
```

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
- File upload endpoints without type/size validation
- Numeric inputs without range validation
- Text inputs without length constraints
- Email/URL inputs without format validation
- Missing client-side validation while server-side validation exists (Low)
- Direct database entity binding without DTO layer
- Query string/route parameters used without validation (a route or query id used in a query without an ownership or tenant check is owned by check 8 (idor.md); reference that finding instead of reporting it here)

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

// Direct user input usage
Request.Query\[|Request.Form\[|Request.Headers\[
HttpContext.Request
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
- Verify authorization rules (user can only update their own data). Owned by check 8 (idor.md); reference that finding instead of reporting it here.
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

