# Output Encoding Security Analysis

Analyze the codebase to identify potential Cross-Site Scripting (XSS) vulnerabilities where output is not properly encoded before being rendered in a browser:

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A05 Injection · **ASVS 5.0:** V1 Encoding and Sanitization, V3 Web Frontend Security

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
// Unsafe patterns (bypass Angular's sanitizer)
element.nativeElement.innerHTML = userContent;          // direct DOM write, no sanitization
renderer.setProperty(el, 'innerHTML', userContent);     // same
[innerHTML]="sanitizer.bypassSecurityTrustHtml(html)"   // explicit bypass
sanitizer.sanitize(SecurityContext.NONE, value)
document.write(content);
eval(userInput); new Function(userInput);
window.location = userValue;

// NOT a finding by itself: Angular sanitizes property bindings to innerHTML
// (strips <script>, event handlers, javascript: URLs). Only flag [innerHTML]
// when the bound value comes from a bypassSecurityTrust* call.
[innerHTML]="userHtml"
```

**Documentation reference:** https://angular.dev/best-practices/security

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
@MvcHtmlString.Create(   // legacy (.NET Framework MVC5), not expected on this stack; search term only

// JavaScript context: NOT a finding by itself. Json.Serialize (System.Text.Json default encoder,
// or Newtonsoft via AddNewtonsoftJson with EscapeHtml) escapes < > & ' as \uXXXX, so this is safe:
<script>var data = @Html.Raw(Json.Serialize(model));</script>
// The finding is the relaxed encoder that disables that escaping, or a serializer without it inside Html.Raw:
JavaScriptEncoder.UnsafeRelaxedJsonEscaping
@Html.Raw(JsonConvert.SerializeObject(
```

**Flags to raise:**
- `Html.Raw()` with user input or database content
- `HtmlString` (or legacy `MvcHtmlString`) created from untrusted sources
- Raw output in JavaScript context without proper JSON encoding: `Html.Raw` around a string that is not the output of `Json.Serialize`, or `Json.Serialize` output when `JavaScriptEncoder.UnsafeRelaxedJsonEscaping` is configured (`AddJsonOptions`, `JsonSerializerOptions.Encoder`, or options passed to `Json.Serialize`)
- Use of `WriteLiteral()` with dynamic content

**Safe alternatives:**
```csharp
// SAFE - Razor automatically encodes
@Model.UserInput

// SAFE - Explicitly encoded
@Html.Encode(userContent)

// SAFE - Razor encodes attribute values too (MVC5 Html.AttributeEncode is legacy, not needed on this stack)
<input value="@Model.Value">
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

**Server-side sanitization of stored rich text (required):**
Editor configuration (`valid_elements`, `allowedContent`) runs in the browser and is bypassed by posting HTML directly to the API, so it never replaces a sanitizer on the server.
- On input (.NET): sanitize with `Ganss.Xss.HtmlSanitizer` **9.0.892 or later** (CVE-2026-25543 fixed there) before persisting. Search `*.csproj` / `Directory.Packages.props` for `HtmlSanitizer` and its version; search the handlers that store the editor field for a `.Sanitize(` call.
- At render time (Angular), when sanitizing client-side instead: DOMPurify **3.4.0 or later** (2026 CVEs such as CVE-2026-41238 and CVE-2026-41239 fixed there); check `package.json` / the lock file for `dompurify`.
- **High**: user-supplied HTML persisted and later rendered through `bypassSecurityTrustHtml`, `nativeElement.innerHTML` or `Renderer2.setProperty(..., 'innerHTML')` without a server-side sanitizer call. A plain `[innerHTML]` binding is sanitized by Angular at render time (section 1); persisted HTML rendered only that way without a server-side sanitizer is Medium, because the server copy stays unsanitized for every other consumer.
- **Medium**: sanitizer package below the floor version.
Sources: https://mend.io/vulnerability-database/CVE-2026-25543 , https://security-tracker.debian.org/tracker/CVE-2026-41238

## 4. Additional Context-Specific Encoding

**Check for proper encoding in different contexts:**

**JavaScript context:**
```javascript
// UNSAFE
<script>var name = "@Model.Name";</script>

// SAFE unless JavaScriptEncoder.UnsafeRelaxedJsonEscaping is configured (see section 2)
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

<!-- SAFE - never interpolate into style; map the value through an allow-list to a CSS class -->
<div class="@(AllowedColors.Contains(Model.Color) ? Model.Color : "default")">
```
**Pattern:** `style="[^"]*@(Model|ViewBag|ViewData)` in `*.cshtml`; `bypassSecurityTrustStyle` in `*.ts` (Angular sanitizes `[style.*]`/`[ngStyle]` bindings, so only the bypass is a finding).

## 5. What to Report

**Report ALL instances of (rate each per the Risk Assessment below):**
- `Html.Raw()` usage in Razor views with non-constant values
- `DomSanitizer.bypassSecurityTrust*()` usage, especially with dynamic content
- Direct `innerHTML` assignment with untrusted data
- Unencoded output in JavaScript, URL, or CSS contexts
- Rich text editors without proper whitelist configuration
- Stored rich text rendered without a server-side sanitizer call, or a sanitizer package below the floor version (section 3)
- Any case where user input is rendered without encoding (except properly configured rich text fields)

**For each finding, provide:**
- File path and line number
- Code snippet showing the vulnerability
- Risk level: Critical / High / Medium / Low per the Risk Assessment below, rated by the **original** source of the data, not by where it is stored
- Source of the unencoded data (user input, database, API, etc.) traced back to who originally supplied it
- Recommended fix with safe alternative
- Context (Angular, Razor, etc.)

**Risk Assessment:**
- **Critical**: Content from unauthenticated input rendered without encoding (reflected XSS reachable without login)
- **High**: Content that originated from any user rendered without encoding, regardless of whether it is reflected or read back from the database or an API — stored XSS is High irrespective of storage location. Admin-supplied content rendered to other users is cross-user impact and is also High
- **High**: Persisted user-supplied HTML rendered through `bypassSecurityTrustHtml` or a direct DOM write without a server-side sanitizer call; Medium when it is only ever rendered through a plain `[innerHTML]` binding (section 3)
- **Medium**: Admin-supplied content rendered only back to the same admin, or system-originated content (configuration, internal service) rendered through a bypass without justification; admin-supplied input is never rated below Medium
- **Medium**: `Ganss.Xss.HtmlSanitizer` below 9.0.892 or DOMPurify below 3.4.0 (section 3)
- **Low**: Bypass applied to compile-time constant content with no documented justification

## 6. Best Practices Verification

**Verify that the application:**
- Uses framework default encoding (don't disable it)
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

