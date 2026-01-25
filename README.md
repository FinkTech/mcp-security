# MCP Security Documentation

Comprehensive security rules and best practices for MCP (Model Context Protocol) servers.

## 📚 What's Included

- **12 Security Rules** - Complete OWASP Top 10 2021 coverage
- **English & Spanish** - Full documentation in both languages
- **Code Examples** - Vulnerable and secure implementations
- **Compliance Mapping** - SOC2, HIPAA, PCI DSS, CWE standards
- **Automated PDFs** - GitHub Actions generates PDFs automatically

## 🚀 Quick Start

```bash
# Read documentation
cat docs/en/sec-rules/SEC-001.md

# Generate PDFs locally
chmod +x scripts/generate-pdfs.sh
./scripts/generate-pdfs.sh

# Push to GitHub
git init
git add .
git commit -m "docs: add MCP security documentation"
git remote add origin https://github.com/YOUR_USER/mcp-security.git
git branch -M main
git push -u origin main
```

## 📋 Documentation

- **[START-HERE.md](START-HERE.md)** - Quick orientation guide
- **[docs/INDEX.md](docs/INDEX.md)** - Complete rules index
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - How to contribute
- **[SECURITY.md](SECURITY.md)** - Security policy

## 🔐 Security Rules

All 12 rules with vulnerable/secure code examples:

### 🔴 Critical (4)
- SEC-001: Authentication Bypass
- SEC-002: Command Injection
- SEC-003: SQL Injection
- SEC-006: Insecure Deserialization

### 🟠 High (5)
- SEC-004: Server-Side Request Forgery
- SEC-005: XML External Entity
- SEC-007: Path Traversal
- SEC-009: Sensitive Data Exposure
- SEC-012: Weak Cryptography

### 🟡 Medium (3)
- SEC-008: Data Leakage in Responses
- SEC-010: Missing Rate Limiting
- SEC-011: Regular Expression DoS

## 📂 Directory Structure

```
mcp-security/
├── docs/
│   ├── INDEX.md
│   ├── en/sec-rules/        (12 English rules)
│   ├── es/sec-rules/        (12 Spanish rules)
│   ├── es/README.es.md      (Spanish introduction)
│   └── pdf/                 (auto-generated PDFs)
├── scripts/generate-pdfs.sh
├── .github/workflows/pdf-generation.yml
└── LICENSE (MIT)
```

## 🤖 Automation

GitHub Actions automatically:
- Generates PDFs from markdown
- Validates markdown syntax
- Runs security checks
- Creates release artifacts

## 📊 Standards

✅ OWASP Top 10 2021  
✅ SOC2 Type II (CC6, CC7)  
✅ HIPAA §164.312  
✅ PCI DSS v4.0  
✅ CWE/MITRE 13 weakness IDs

## 📄 Languages

- **English**: Primary documentation (docs/en/)
- **Spanish**: Full translation (docs/es/)

## 📝 License

MIT License - Free for commercial and personal use

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 🔒 Security Policy

Found a vulnerability? See [SECURITY.md](SECURITY.md)

---

**Version:** 1.0.0  
**Status:** Production Ready  
**Last Updated:** January 25, 2026