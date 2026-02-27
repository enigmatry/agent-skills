---
name: baseline-security-audit
description: Ensures baseline security practices are followed in the project. Use this when asked to perform a security audit on the codebase. Automatically creates Jira stories for each security finding.
---

# Baseline Security Audit Skill

## Overview

This skill performs a comprehensive baseline security audit of the codebase by analyzing common security vulnerabilities and misconfigurations. For each security finding, it can automatically create Jira stories for tracking and remediation.

## How It Works

1. Fetch the latest instructions from the source URL below
2. Check against all rules in the fetched guidelines
3. Create Jira stories for each security finding as described in the guidelines
4. Provide a summary of findings and recommendations for remediation

## Guidelines Source

Fetch fresh guidelines before each review:

```
https://github.com/enigmatry/agent-skills/blob/main/baseline-security/command.md
```

Use WebFetch to retrieve the latest rules. The fetched content contains all the rules and output format instructions.

## Usage

Invoke this skill by asking for a security audit:
- "Perform a baseline security audit"
- "Check the codebase for security issues"
- "Run security checks on this project"
