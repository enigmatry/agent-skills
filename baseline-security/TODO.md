- Use ssl labs to check tls version and cipher suite support for your public-facing applications. Ensure that only TLS 1.2 and TLS 1.3 are supported, and that weak ciphers (e.g., RC4, DES) are disabled.
- database encryption settings
- sonarqube security findings
- authnetication
    Check if the validity of access tokens is no longer then 1 hour.
    Check if the authentication protocol used by the application is OpenId Connect, using Authorization Code and PKCE.
    If the application allows access with non-user accounts (like other applications or automated processes), check if these are also authenticated with one of the OIDC methods.
    Check if the password policy requires complex passwords.