# Security Policy

## Supported Versions

We release security updates for the following versions:

| Version  | Supported          |
| -------- | ------------------ |
| latest   | :white_check_mark: |
| < latest | :x:                |

We recommend always running the latest version for security patches.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

### Private Reporting (Preferred)

Report security vulnerabilities using [GitHub Security Advisories](https://github.com/Recipe-Web-App/auth-service/security/advisories/new).

This allows us to:

- Discuss the vulnerability privately
- Develop and test a fix
- Coordinate disclosure timing
- Issue a CVE if necessary

### What to Include

When reporting a vulnerability, please include:

1. **Description** - Clear description of the vulnerability
2. **Impact** - What can an attacker achieve?
3. **Reproduction Steps** - Step-by-step instructions to reproduce
4. **Affected Components** - Which parts of the service are affected
5. **Suggested Fix** - If you have ideas for remediation
6. **Environment** - Version, configuration, deployment details
7. **Proof of Concept** - Code or requests demonstrating the issue (if safe to share)

### Example Report

```text
Title: JWT Token Signature Bypass

Description: The JWT validation does not properly verify signatures...

Impact: An attacker can forge tokens and gain unauthorized access...

Steps to Reproduce:
1. Create a JWT with algorithm "none"
2. Send to /api/v1/auth/userinfo
3. Token is accepted without signature verification

Affected: internal/token/jwt.go line 45

Suggested Fix: Enforce algorithm whitelist and reject "none"

Environment: v1.2.3, Docker deployment
```

## Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Varies by severity (critical: days, high: weeks, medium: months)

## Severity Levels

### Critical

- Remote code execution
- Authentication bypass
- Privilege escalation to admin
- Mass data exposure

### High

- Token forgery/manipulation
- SQL injection
- Unauthorized access to user data
- Denial of service affecting all users

### Medium

- Information disclosure (limited)
- CSRF vulnerabilities
- Rate limiting bypass
- Session fixation

### Low

- Verbose error messages
- Security header issues
- Best practice violations

## Security Features

This service implements multiple security layers:

### OAuth2 Security

- **PKCE Required** - All authorization code flows require PKCE (RFC 7636)
- **Token Validation** - Cryptographic signature verification for all tokens
- **Token Rotation** - Refresh tokens are rotated on use
- **Token Revocation** - Blacklist support for invalidated tokens
- **Scope Enforcement** - Strict scope validation

### Application Security

- **Rate Limiting** - Per-IP and per-client request throttling
- **CORS Protection** - Configurable cross-origin policies
- **Input Validation** - All inputs sanitized and validated
- **SQL Injection Protection** - Parameterized queries only
- **Secure Headers** - CSP, HSTS, X-Frame-Options, etc.

### Authentication

- **Password Hashing** - Bcrypt with appropriate work factor
- **Secure Random** - Cryptographically secure token generation
- **Session Management** - Secure session handling with Redis

### Infrastructure

- **Secret Management** - Secrets via environment variables (never in code)
- **Audit Logging** - Comprehensive security event logging
- **Health Monitoring** - Liveness/readiness probes
- **TLS Support** - HTTPS with configurable certificates

## Security Best Practices

### For Operators

1. **Use TLS/HTTPS** - Always encrypt traffic in production
2. **Rotate Secrets** - Regularly rotate JWT signing keys
3. **Monitor Logs** - Watch for suspicious patterns
4. **Update Dependencies** - Keep Go modules current
5. **Limit Exposure** - Use network policies and firewalls
6. **Enable PKCE** - Require PKCE for all authorization flows
7. **Configure CORS** - Whitelist only trusted origins
8. **Set Rate Limits** - Protect against brute force and DoS
9. **Database Security** - Use connection encryption and least privilege
10. **Backup Secrets** - Securely store signing key backups

### For Developers

1. **Never Commit Secrets** - Use `.env.local` (gitignored)
2. **Validate Inputs** - Sanitize all user inputs
3. **Use Parameterized Queries** - Prevent SQL injection
4. **Handle Errors Securely** - Don't leak sensitive info in errors
5. **Run Security Checks** - Use `make security` before committing
6. **Review Dependencies** - Check for known vulnerabilities
7. **Follow OAuth2 Spec** - Implement flows according to RFCs
8. **Test Security** - Include security test cases

## Security Checklist

Before deploying:

- [ ] TLS/HTTPS configured
- [ ] Strong JWT signing key (256+ bits for HS256, 2048+ for RS256)
- [ ] PKCE enforcement enabled
- [ ] Rate limiting configured
- [ ] CORS whitelist configured
- [ ] Secrets in environment variables (not code)
- [ ] Database encryption at rest and in transit
- [ ] Redis authentication enabled
- [ ] Security headers enabled
- [ ] Audit logging enabled
- [ ] Dependencies updated (`make deps`)
- [ ] Security scan passed (`make security`)
- [ ] Network policies applied
- [ ] Monitoring and alerting configured

## Known Security Considerations

### Token Storage

- Access tokens are short-lived JWTs (recommended: 15 minutes)
- Refresh tokens stored in Redis with TTL
- Revoked tokens maintained in blacklist

### Database Security

- PostgreSQL connections use connection pooling
- Credentials via environment variables
- Optional TLS for database connections
- Prepared statements prevent SQL injection

### Redis Security

- Optional authentication (recommended)
- Optional TLS (recommended in production)
- Automatic failover to in-memory storage
- TTL on all cached data

## Disclosure Policy

We follow **coordinated disclosure**:

1. Vulnerability reported privately
2. We confirm and develop fix
3. Fix tested and released
4. Public disclosure after fix is deployed
5. Credit given to reporter (if desired)

## Security Updates

Subscribe to:

- [GitHub Security Advisories](https://github.com/Recipe-Web-App/auth-service/security/advisories)
- [Release Notes](https://github.com/Recipe-Web-App/auth-service/releases)
- Watch repository for security patches

## Contact

For security concerns: Use [GitHub Security Advisories](https://github.com/Recipe-Web-App/auth-service/security/advisories/new)

For general questions: See [SUPPORT.md](SUPPORT.md)

## Acknowledgments

We thank security researchers who responsibly disclose vulnerabilities. Contributors will be acknowledged (with
permission) in:

- Security advisories
- Release notes
- This document

Thank you for helping keep this project secure!
