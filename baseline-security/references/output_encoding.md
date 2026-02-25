# Output Encoding Security Analysis

Analyze the codebase to identify potential Cross-Site Scripting (XSS) vulnerabilities where output is not properly encoded before being rendered in a browser:

## Core Security Principle
**All output that is to be rendered in a browser should be encoded. Most UI frameworks do this by default, but developers can bypass these protections, creating security vulnerabilities.**

## 1. Angular Applications

**Check for unsafe DomSanitizer usage:**
- Identify all uses of `DomSanitizer` service
- Look for `bypassSecurityTrust*` methods that disable Angular's built-in sanitization
- Verify that bypassed content doesn't come from user input or untrusted sources

**Search for:**
```typescript
// DomSanitizer bypass methods (HIGH RISK)
bypassSecurityTrustHtml
bypassSecurityTrustScript
bypassSecurityTrustStyle
bypassSecurityTrustUrl
bypassSecurityTrustResourceUrl

// Common patterns
this.sanitizer.bypassSecurityTrustHtml(userInput)
DomSanitizer.bypassSecurityTrust*
```

**Flags to raise:**
- Any `bypassSecurityTrust*` usage with dynamic or user-provided content
- Sanitizer bypasses without clear justification and security review
- Direct DOM manipulation that bypasses Angular's sanitization (e.g., `innerHTML`, `outerHTML`)
- Use of `ElementRef.nativeElement.innerHTML`

**Angular-specific checks:**
```typescript
// Unsafe patterns
element.nativeElement.innerHTML = userContent;
[innerHTML]="unsafeHtml"
document.write(content);
```

**Documentation reference:** https://angular.io/guide/security#trusting-safe-values

## 2. Razor Views and Pages (ASP.NET)

**Check for Html.Raw usage:**
- Identify all instances of `Html.Raw()` in Razor views/pages
- Verify that content passed to `Html.Raw()` is safe and doesn't contain user input
- Ensure `@Html.Raw()` is not used with unvalidated data

**Search for:**
```csharp
// Razor unencoded output (HIGH RISK)
@Html.Raw(
Html.Raw(
@(new HtmlString(
@MvcHtmlString.Create(

// Also check for JavaScript context
<script>var data = @Html.Raw(Json.Serialize(model));</script>
```

**Flags to raise:**
- `Html.Raw()` with user input or database content
- `HtmlString` or `MvcHtmlString` created from untrusted sources
- Raw output in JavaScript context without proper JSON encoding
- Use of `WriteLiteral()` with dynamic content

**Safe alternatives:**
```csharp
// SAFE - Razor automatically encodes
@Model.UserInput

// SAFE - Explicitly encoded
@Html.Encode(userContent)

// SAFE - Attribute encoding
@Html.AttributeEncode(value)
```

## 3. Rich Text Editor Output

**Verify safe handling of rich text content:**
- Check configuration of rich text editors (TinyMCE, CKEditor, Quill, etc.)
- Ensure only whitelisted HTML tags are allowed
- Verify dangerous tags and attributes are stripped

**Search for:**
```javascript
// Rich text editor configurations
TinyMCE.init
CKEDITOR.config
new Quill(
ReactQuill
editor.config

// Look for sanitization configuration
valid_elements
allowedContent
formats
sanitize
```

**Required configurations:**
- Whitelist of allowed HTML tags (e.g., `<p>, <b>, <i>, <ul>, <ol>, <li>, <a>`)
- Blacklist of dangerous tags (e.g., `<script>, <iframe>, <object>, <embed>`)
- Attribute filtering (especially `onclick`, `onerror`, `onload`, etc.)
- URL protocol validation for links and images (block `javascript:`, `data:` protocols)

**Example safe configuration:**
```javascript
// TinyMCE
valid_elements: 'p,b,strong,i,em,ul,ol,li,a[href|target]',
invalid_elements: 'script,iframe,object,embed',

// CKEditor
allowedContent: 'p b i strong em ul ol li a[!href]',
disallowedContent: 'script; iframe; object; embed; *[on*]'
```

## 4. Additional Context-Specific Encoding

**Check for proper encoding in different contexts:**

**JavaScript context:**
```javascript
// UNSAFE
<script>var name = "@Model.Name";</script>

// SAFE
<script>var name = @Json.Serialize(Model.Name);</script>
```

**URL context:**
```csharp
// UNSAFE
<a href="/search?q=@Model.Query">

// SAFE
<a href="/search?q=@Uri.EscapeDataString(Model.Query)">
```

**CSS context:**
```html
<!-- UNSAFE -->
<div style="color: @Model.Color;">

<!-- SAFE - validate against whitelist -->
```

## 6. What to Report

**Report ALL instances of (HIGH PRIORITY):**
- `Html.Raw()` usage in Razor views with non-constant values
- `DomSanitizer.bypassSecurityTrust*()` usage, especially with dynamic content
- `dangerouslySetInnerHTML` in React components
- Direct `innerHTML` assignment with untrusted data
- Unencoded output in JavaScript, URL, or CSS contexts
- Rich text editors without proper whitelist configuration
- Any case where user input is rendered without encoding (except properly configured rich text fields)

**For each finding, provide:**
- File path and line number
- Code snippet showing the vulnerability
- Risk level: HIGH (user input), MEDIUM (database content), LOW (admin-only content)
- Source of the unencoded data (user input, database, API, etc.)
- Recommended fix with safe alternative
- Context (Angular, Razor, React, etc.)

**Risk Assessment:**
- **HIGH**: User-provided content rendered without encoding
- **MEDIUM**: Database or API content without encoding validation
- **LOW**: Admin-only or trusted content with security bypass (still requires justification)

## 8. Best Practices Verification

**Verify that the application:**
- Uses framework default encoding (don't disable it)
- Implements Content Security Policy (CSP) headers
- Validates and sanitizes input on the server side
- Uses secure HTTP headers (X-XSS-Protection, X-Content-Type-Options)
- Implements proper output encoding for each context (HTML, JavaScript, URL, CSS)
- Has documented justification for any security bypasses
- Performs regular security testing/scanning

**Recommended secure coding practices:**
1. Always use framework-provided encoding by default
2. Never bypass security features without thorough review
3. Implement defense-in-depth (input validation + output encoding + CSP)
4. Use established libraries for sanitization (DOMPurify, etc.)
5. Regularly update dependencies to patch XSS vulnerabilities
6. Conduct security code reviews for all security bypasses
