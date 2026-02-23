---
name: baseline-security-audit
description: Ensures baseline security practices are followed in the project. Use this when asked to perform a security audit on the codebase. Automatically creates Jira stories for each security finding.
---

# Baseline Security Audit Skill

## Overview

This skill performs a comprehensive baseline security audit of the codebase by analyzing common security vulnerabilities and misconfigurations. For each security finding, it can automatically create Jira stories for tracking and remediation.

## What This Skill Does

- Scans for hardcoded secrets and credentials
- Checks for insecure dependencies and outdated packages
- Reviews authentication and authorization patterns
- Identifies potential injection vulnerabilities
- Analyzes file permissions and access controls
- Validates encryption and cryptography usage
- Checks for exposed sensitive endpoints
- Reviews error handling and information disclosure
- Provides prioritized remediation roadmap

## How to Use

Invoke this skill by asking for a security audit:
- "Perform a baseline security audit"
- "Check the codebase for security issues"
- "Run security checks on this project"
