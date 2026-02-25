# Input Validation Security Analysis

Analyze the codebase to identify missing or insufficient input validation that could lead to security vulnerabilities:

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
- API endpoints accepting user input without `ModelState.IsValid` check
- DTO/Model classes without validation attributes
- Controllers without `[ApiController]` attribute and no manual validation
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

<!-- Check for validation state handling -->
<div *ngIf="nameControl.invalid && nameControl.touched">
  <div *ngIf="nameControl.errors?.['required']">Name is required</div>
</div>
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
- Virus scanning
- Filename sanitization

**Passwords:**
- Minimum length (at least 8-12 characters)
- Complexity requirements (optional, but consider)
- Maximum length (prevent DoS)
- Password confirmation matching

**Phone numbers:**
- Format validation
- Country code validation
- Length constraints

**Credit cards:**
- Format validation (Luhn algorithm)
- Card type detection
- Expiration date validation

## 5. Specific Validation Vulnerabilities

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

## 6. Framework-Specific Validation Checks

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

## 7. What to Report

**Report ALL instances of (MEDIUM PRIORITY):**
- API endpoints accepting user input without validation
- Model/DTO classes without validation attributes
- Missing `ModelState.IsValid` checks (when not using `[ApiController]`)
- File upload endpoints without type/size validation
- Numeric inputs without range validation
- Text inputs without length constraints
- Email/URL inputs without format validation
- Missing client-side validation (recommended but not critical)
- Direct database entity binding without DTO layer
- Query string/route parameters used without validation

**For each finding, provide:**
- File path and line number
- Code snippet showing missing validation
- Input field/parameter name and type
- Expected validation rules (based on field type and context)
- Recommended fix with validation example
- Risk level: HIGH (no validation), MEDIUM (partial validation), LOW (client-side only)

**Risk Assessment:**
- **HIGH**: No server-side validation on critical inputs (authentication, authorization, financial)
- **MEDIUM**: Missing server-side validation on general user inputs
- **LOW**: Missing client-side validation only (server-side exists)

## 8. Validation Best Practices

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
- Compliance and regulatory requirements

**Recommended validation approach:**
```
1. Client-side validation (UX, immediate feedback)
2. API/Controller validation (security gate)
3. Business logic validation (domain rules)
4. Database constraints (last line of defense)
```

## 9. Search Patterns

**Look for these patterns indicating potential missing validation:**

```regex
// Controllers without validation
\[HttpPost\]|\[HttpPut\]|\[HttpPatch\]
(public.*IActionResult|public.*ActionResult|public.*Task<)

// Models/DTOs without attributes
public class.*Dto|public class.*Model|public class.*Request|public class.*Command
public.*\{.*get;.*set;.*\}

// Properties without validation
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
- Client-side forms: `*.component.ts`, `*.component.html`, `*.tsx`, `*.jsx`

## 10. Additional Considerations

**Business Logic Validation:**
- Check for business rule validation beyond basic format checks
- Verify authorization rules (user can only update their own data)
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
