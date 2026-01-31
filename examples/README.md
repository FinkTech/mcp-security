# MCP Security Examples

Production-quality Model Context Protocol (MCP) server examples demonstrating security vulnerabilities and their mitigations.

## 🎯 Overview

This directory contains practical examples of MCP servers with:
- **Vulnerable implementations** showing common security mistakes
- **Secure implementations** demonstrating best practices
- **Focused examples** for specific security patterns

All examples map to the [12 Security Rules](../docs/INDEX.md) defined in the mcp-security documentation.

---

## 🚀 Available Examples

### Node.js / TypeScript

#### [Vulnerable MCP Development Assistant](./nodejs/vulnerable-mcp-server/)
A fully-featured development assistant MCP server with **intentional security vulnerabilities** for educational purposes.

**Features:**
- 8 development tools (command execution, file ops, git, AI assistant, database, etc.)
- 4 resources (files, git status, config, logs)
- 3 prompts (code review, debug assistant, deployment guide)
- All 12 SEC rules violated with detailed comments
- Maps to OWASP Top 10 2021, SOC2, HIPAA, PCI DSS

**Status:** ⚠️ Complete (Vulnerable)  
**Use case:** Educational reference, security training, understanding attack vectors

**[→ View Documentation](./nodejs/vulnerable-mcp-server/README.md)**

---

#### [Secure MCP Development Assistant](./nodejs/secure-mcp-server/)
The same server architecture with all vulnerabilities fixed and security best practices implemented.

**Features:**
- Authentication & authorization (SEC-001)
- Input validation & sanitization (SEC-002, SEC-003)
- Secure secrets management with Vault (SEC-012)
- Rate limiting & timeouts (SEC-005, SEC-008)
- Path validation & sandboxing (SEC-006)
- Prompt injection prevention (SEC-007)
- Comprehensive security testing

**Status:** 🚧 Coming soon  
**Use case:** Production reference, secure development patterns

---

### Focused Examples

#### Authentication (`nodejs/authentication/`, `go/authentication/`)
Focused examples demonstrating **SEC-001: Authentication & Authorization**.

- OAuth 2.0 / JWT implementation
- API key validation
- Role-based access control (RBAC)
- Multi-factor authentication (MFA)

**Status:** 📝 Planned

---

#### Encryption (`nodejs/encryption/`, `go/encryption/`)
Focused examples demonstrating **SEC-010: Secure Communications** and **SEC-012: Secrets Management**.

- TLS/SSL configuration
- At-rest encryption patterns
- Key rotation strategies
- Secrets vault integration

**Status:** 📝 Planned

---

#### Validation (`nodejs/validation/`, `go/validation/`)
Focused examples demonstrating **SEC-003: Input Validation** and **SEC-006: Path Traversal**.

- Schema validation (Zod, Joi)
- Path sanitization
- SQL injection prevention
- Command injection prevention

**Status:** 📝 Planned

---

## 📚 Learning Path

### 1️⃣ Start Here
Read the [MCP Security Documentation](../docs/) to understand the 12 security rules.

### 2️⃣ Study Vulnerabilities
Explore the [Vulnerable MCP Server](./nodejs/vulnerable-mcp-server/) to see common mistakes:
- Read the commented code showing each SEC-XXX violation
- Review the README's exploit examples
- Try to exploit vulnerabilities in a safe environment

### 3️⃣ Learn Secure Patterns
Compare with the [Secure MCP Server](./nodejs/secure-mcp-server/) (coming soon):
- See how each vulnerability is fixed
- Understand defense-in-depth strategies
- Study the testing approach

### 4️⃣ Apply to Your Projects
Use focused examples for specific security patterns in your own MCP servers.

---

## 🛠️ Running Examples

Each example includes:
- `README.md` - Full documentation
- `package.json` / `go.mod` - Dependencies
- `.env.example` - Configuration template
- Test suite (where applicable)

### Quick Start (Node.js examples)

```bash
# Navigate to example
cd nodejs/vulnerable-mcp-server/

# Install dependencies
npm install

# Copy environment template
cp .env.example .env

# Build
npm run build

# Run
npm start
```

---

## ⚠️ Security Notice

**Vulnerable examples are for educational purposes only.**

- **DO NOT** use vulnerable examples in production
- **DO NOT** expose vulnerable examples to the internet
- **DO NOT** use with real credentials or sensitive data
- **ALWAYS** run in isolated, controlled environments

The secure examples demonstrate production-ready patterns but should still be:
- Reviewed for your specific use case
- Tested thoroughly
- Kept up to date with security patches

---

## 🤝 Contributing

To add a new example:

1. Follow the structure of existing examples
2. Include comprehensive README with:
   - Overview and use case
   - Installation instructions
   - Security considerations
   - Vulnerability/security mapping
3. Add comments explaining security decisions
4. Include tests where applicable
5. Update this README with your example

See [CONTRIBUTING.md](../CONTRIBUTING.md) for detailed guidelines.

---

## 🔗 Related Resources

- [MCP Security Documentation](../docs/)
- [Security Rules Index](../docs/INDEX.md)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)

---

## 📜 License

All examples are licensed under MIT License. See [LICENSE](../LICENSE) for details.

---

**Questions?** Open an issue or discussion in the [mcp-security repository](https://github.com/FinkTech/mcp-security).