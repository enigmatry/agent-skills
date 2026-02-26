---
name: baseline-security-audit
description: Ensures baseline security practices are followed in the project. Use this when asked to perform a security audit on the codebase. Automatically creates Jira stories for each security finding.
---

# Baseline Security Audit Skill

## Overview

This skill performs a comprehensive baseline security audit of the codebase by analyzing common security vulnerabilities and misconfigurations. For each security finding, it can automatically create Jira stories for tracking and remediation.

## What This Skill Does

This skill performs the following security checks (each with detailed guidance in the references folder):

1. **Secrets Management** - Scans for hardcoded secrets, credentials, and API keys
   - *See: references/secrets.md*

2. **Package Security** - Checks for insecure dependencies and outdated packages with known vulnerabilities
   - *See: references/packages.md*

3. **SQL Injection** - Identifies potential SQL injection vulnerabilities in database queries
   - *See: references/sql_injection.md*

4. **Exception Handling** - Reviews error handling patterns to prevent information disclosure
   - *See: references/exception_handling.md*

5. **Logging Security** - Validates logging practices and checks for sensitive data in logs
   - *See: references/logging.md*

6. **Sensitive Data in Logs** - Identifies logging of passwords, tokens, and other sensitive information
   - *See: references/sensitive_data_logging.md*

7. **Sensitive Query Strings** - Checks for sensitive data exposure in URL query parameters
   - *See: references/sensitive_query_strings.md*

8. **IDOR (Insecure Direct Object References)** - Analyzes authorization checks for object access
   - *See: references/idor.md*

9. **Output Encoding** - Validates proper encoding to prevent XSS attacks
   - *See: references/output_encoding.md*

10. **Input Validation** - Ensures all user input is validated server-side and client-side
    - *See: references/input_validation.md*

11. **Code Minification** - Verifies production builds are minified and source maps are secured
    - *See: references/code_minification.md*

12. **Environment Credentials** - Ensures different credentials per environment (dev/test/staging/prod)
    - *See: references/environment_credentials.md*

13. **Data Minimization** - Identifies unnecessary storage of sensitive/personal data (GDPR compliance)
    - *See: references/data_minimization.md*

14. **Data Storage Minimization** - Reviews database entities for minimal sensitive data storage
    - *See: references/data_storage_minimization.md*

15. **Cookie and Storage Security** - Validates secure cookie configuration and localStorage usage
    - *See: references/cookie_storage_security.md*

16. **Cryptography Security** - Ensures strong cryptographic algorithms for hashing and encryption
    - *See: references/cryptography_security.md*

17. **Security Headers** - Checks proper configuration of CSP, HSTS, X-Frame-Options, and other security headers
    - *See: references/security_headers.md*

18. **Version Info Headers** - Prevents disclosure of platform/version information in HTTP headers
    - *See: references/version_info_headers.md*

19. **HTTP Verb Whitelisting** - Ensures only necessary HTTP verbs are allowed, blocks unused methods
    - *See: references/http_verb_whitelisting.md*

20. **SSL/TLS Configuration** - Validates SSL/TLS protocol versions and cipher suites using SSL Labs analysis
    - *See: references/ssl_tls_configuration.md*
    - **Note**: Requires production URL from user to perform SSL Labs scan

Each check provides:
- Specific patterns to search for
- RED FLAGS to identify
- Prioritized findings (High/Medium/Low)
- Remediation guidance
- Code examples

## How to Use

Invoke this skill by asking for a security audit:
- "Perform a baseline security audit"
- "Check the codebase for security issues"
- "Run security checks on this project"
