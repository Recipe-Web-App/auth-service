# Support

Thank you for using the OAuth2 Auth Service! This document provides resources to help you get support.

## Documentation

Before asking for help, please check our documentation:

### Primary Documentation

- **[README.md](../README.md)** - Complete feature overview, setup instructions, and API documentation
- **[CLAUDE.md](../CLAUDE.md)** - Development commands, architecture overview, and developer guide
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Contribution guidelines and development workflow
- **[SECURITY.md](SECURITY.md)** - Security features, best practices, and vulnerability reporting

### Code Examples

- **[`.env.example`](../.env.example)** - Configuration examples
- **[Docker Compose](../docker-compose.yml)** - Deployment examples
- **[Kubernetes Manifests](../k8s/)** - K8s deployment configurations

## Getting Help

### 1. Search Existing Resources

Before creating a new issue, please search:

- [Existing Issues](https://github.com/Recipe-Web-App/auth-service/issues) - Someone may have already asked
- [Closed Issues](https://github.com/Recipe-Web-App/auth-service/issues?q=is%3Aissue+is%3Aclosed) - Your question
  may already be answered
- [Discussions](https://github.com/Recipe-Web-App/auth-service/discussions) - Community Q&A

### 2. GitHub Discussions (Recommended for Questions)

For general questions, use [GitHub Discussions](https://github.com/Recipe-Web-App/auth-service/discussions):

**When to use Discussions:**

- "How do I...?" questions
- Configuration help
- Best practice advice
- Integration questions
- OAuth2 flow clarifications
- Architecture discussions
- Troubleshooting (non-bug)

**Categories:**

- **Q&A** - Ask questions and get answers
- **Ideas** - Share feature ideas and proposals
- **Show and Tell** - Share your implementations
- **General** - Everything else

### 3. GitHub Issues (For Bugs and Features)

Use [GitHub Issues](https://github.com/Recipe-Web-App/auth-service/issues/new/choose) for:

- Bug reports
- Feature requests
- Performance issues
- Documentation problems
- Security vulnerabilities (low severity - use Security Advisories for critical)

**Issue Templates:**

- **Bug Report** - Report unexpected behavior
- **Feature Request** - Suggest new functionality
- **Performance Issue** - Report performance problems
- **Documentation** - Documentation improvements
- **Security Vulnerability** - Low-severity security issues

### 4. Security Issues

**IMPORTANT:** For security vulnerabilities, use:

- [GitHub Security Advisories](https://github.com/Recipe-Web-App/auth-service/security/advisories/new) (private)
- See [SECURITY.md](SECURITY.md) for details

**Never report security issues publicly through issues or discussions.**

## Common Questions

### Setup and Configuration

**Q: How do I get started?**
A: See the Quick Start section in [README.md](../README.md#quick-start)

**Q: What environment variables are required?**
A: Check [`.env.example`](../.env.example) for all configuration options

**Q: Can I run without PostgreSQL?**
A: Yes, the service gracefully degrades to Redis-only mode. See [CLAUDE.md](../CLAUDE.md#architecture-overview)

**Q: How do I enable TLS/HTTPS?**
A: Configure `server.tls_cert_path` and `server.tls_key_path` in your YAML config file (e.g., `configs/prod.yaml`)

### OAuth2 Flows

**Q: Which OAuth2 flows are supported?**
A: Authorization Code Flow with PKCE and Client Credentials Flow. See [README.md](../README.md#features)

**Q: Is PKCE required?**
A: Yes, PKCE is enforced for Authorization Code Flow for security

**Q: How do I register a client?**
A: See the Client Management section in [README.md](../README.md)

**Q: What token lifetime should I use?**
A: Recommended: 15 minutes for access tokens, 7 days for refresh tokens

### Troubleshooting

**Q: Service fails to start?**

- Check logs: `docker logs <container-name>`
- Verify environment variables
- Check PostgreSQL/Redis connectivity
- Review [README.md](../README.md#troubleshooting) troubleshooting section

**Q: Tokens are not validating?**

- Verify JWT signing key matches between instances
- Check token expiration
- Ensure algorithm configuration is correct
- Review logs for validation errors

**Q: Performance issues?**

- Check database connection pool settings
- Verify Redis is accessible
- Review rate limiting configuration
- See [Performance Issue Template](.github/ISSUE_TEMPLATE/performance_issue.yml)

**Q: CORS errors?**

- Configure `CORS_ALLOWED_ORIGINS` environment variable
- Check request Origin header
- Review middleware configuration

### Development

**Q: How do I contribute?**
A: See [CONTRIBUTING.md](CONTRIBUTING.md) for complete guidelines

**Q: How do I run tests?**
A: Run `make test` or see [CLAUDE.md](../CLAUDE.md#testing) for test commands

**Q: What's the code structure?**
A: See Architecture Overview in [CLAUDE.md](../CLAUDE.md#architecture-overview)

## Response Times

We aim to:

- Acknowledge issues/discussions within 48 hours
- Respond to questions within 1 week
- Fix critical bugs as priority
- Review PRs within 1-2 weeks

Note: This is a community project. Response times may vary.

## Commercial Support

This is an open-source project. Commercial support is not currently available.

## Community Guidelines

When asking for help:

- **Be specific** - Include exact error messages, versions, configurations
- **Provide context** - What were you trying to do? What happened instead?
- **Include details** - Environment, deployment method, relevant logs
- **Be patient** - Maintainers and community volunteers help in their free time
- **Be respectful** - Follow the [Code of Conduct](CODE_OF_CONDUCT.md)
- **Search first** - Check if your question was already answered
- **Give back** - Help others when you can

## Bug Report Best Practices

When reporting bugs, include:

- Go version
- Deployment environment (Docker/K8s/Local)
- Exact error messages
- Steps to reproduce
- Expected vs actual behavior
- Relevant configuration (redact secrets!)
- Logs (redact sensitive info!)

Use the [Bug Report Template](.github/ISSUE_TEMPLATE/bug_report.yml) - it helps ensure you provide all needed information.

## Additional Resources

### OAuth2 Specifications

- [RFC 6749 - OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 7636 - PKCE](https://tools.ietf.org/html/rfc7636)
- [RFC 7662 - Token Introspection](https://tools.ietf.org/html/rfc7662)
- [RFC 7009 - Token Revocation](https://tools.ietf.org/html/rfc7009)

### Go Resources

- [Go Documentation](https://golang.org/doc/)
- [Effective Go](https://golang.org/doc/effective_go)

### Related Projects

- [golang-jwt/jwt](https://github.com/golang-jwt/jwt)
- [gorilla/mux](https://github.com/gorilla/mux)

## Still Need Help?

If you can't find an answer:

1. Check [Discussions](https://github.com/Recipe-Web-App/auth-service/discussions)
2. Ask a new question in [Q&A](https://github.com/Recipe-Web-App/auth-service/discussions/new?category=q-a)
3. For bugs, create an [Issue](https://github.com/Recipe-Web-App/auth-service/issues/new/choose)

We're here to help!
