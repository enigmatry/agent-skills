- database encryption settings
- sonarqube security findings
- authnetication
    Check if the validity of access tokens is no longer then 1 hour.
    Check if the authentication protocol used by the application is OpenId Connect, using Authorization Code and PKCE.
    If the application allows access with non-user accounts (like other applications or automated processes), check if these are also authenticated with one of the OIDC methods.
    Check if the password policy requires complex passwords.