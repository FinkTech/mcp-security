# 🔒 MCP Security

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.0.1-blue.svg)](https://github.com/FinkTech/mcp-security/releases)
[![Documentation](https://img.shields.io/badge/docs-latest-blue.svg)](./docs/INDEX.md)
[![Security](https://img.shields.io/badge/security-policy-red.svg)](./SECURITY.md)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](./CONTRIBUTING.md)

**Comprehensive security guidelines for Model Context Protocol (MCP) servers** with compliance mapping (SOC2, HIPAA, PCI DSS).

---

## 📚 Quick Navigation

| What | Where |
|------|-------|
| 📋 Complete index | [`docs/INDEX.md`](./docs/INDEX.md) |
| 🇬🇧 English docs | [`docs/en/`](./docs/en/) |
| 🇪🇸 Documentación español | [`docs/es/`](./docs/es/) |
| 💻 Code examples | [`examples/`](./examples/) |
| 📄 PDFs | Auto-generated (GitHub Actions) or local: `scripts/generate-pdfs.sh` |
| 🤝 Contributing | [`CONTRIBUTING.md`](./CONTRIBUTING.md) |
| 🔒 Security policy | [`SECURITY.md`](./SECURITY.md) |

---

## ✨ Features

- **12 Security Rules (SEC-001 to SEC-012)**: Each with vulnerable vs secure examples
- **OWASP/CWE Mapping** + Compliance (SOC2, HIPAA, PCI DSS)
- **Multi-language examples**: Go, Node.js, Python
- **Bilingual documentation**: English + Spanish
- **Auto-generated PDFs**: Available in `docs/pdf/en/` and `docs/pdf/es/`

---

## 📂 Repository Structure

```text
mcp-security/
├── docs/
│   ├── INDEX.md              # Complete index
│   ├── en/                   # English documentation
│   │   ├── README.md
│   │   ├── START-HERE.md
│   │   ├── SECURITY.md
│   │   └── sec-rules/        # SEC-001 to SEC-012
│   ├── es/                   # Spanish documentation
│   │   ├── README.md
│   │   ├── START-HERE.md
│   │   ├── SECURITY.md
│   │   └── sec-rules/        # SEC-001 a SEC-012
│   └── pdf/                  # Auto-generated PDFs
│       ├── en/
│       └── es/
├── examples/                 # Code examples by language
│   ├── go/
│   ├── nodejs/
│   └── python/
├── scripts/
│   └── generate-pdfs.sh      # PDF generation script
├── .github/
│   ├── workflows/            # CI/CD automation
│   ├── ISSUE_TEMPLATE/
│   └── PULL_REQUEST_TEMPLATE.md
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
└── README.md                 # This file
```

---

## 🎯 Use Cases

### For Developers
- Apply security rules to your MCP servers
- Use code examples as reference
- Integrate compliance requirements

### For Security Teams
- Audit MCP implementations
- Map controls to frameworks (SOC2, HIPAA, PCI DSS)
- Use PDFs for documentation

### For Organizations
- Establish security baselines
- Train development teams
- Maintain compliance

---

## 🌍 Available Languages

- 🇬🇧 **English**: [`docs/en/`](./docs/en/)
- 🇪🇸 **Español**: [`docs/es/`](./docs/es/)

---

## 📄 PDF Generation

PDFs are automatically generated on push via GitHub Actions.

**Manual generation:**
```bash
./scripts/generate-pdfs.sh
```

PDFs will be created in:
- `docs/pdf/en/` (English)
- `docs/pdf/es/` (Spanish)

---

## 🤝 Contributing

We welcome contributions! See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for:
- How to propose new rules
- Documentation guidelines
- Code examples standards
- Translation workflow

---

## 🔒 Security

Found a vulnerability? Please report responsibly.

See [`SECURITY.md`](./SECURITY.md) for:
- How to report security issues
- Response time expectations
- Disclosure process

---

## 📜 License

MIT License - see [`LICENSE`](./LICENSE) for details.

---

## 💬 Support

- 🐛 **Bug reports**: [Open an issue](https://github.com/FinkTech/mcp-security/issues)
- 💡 **Feature requests**: [Start a discussion](https://github.com/FinkTech/mcp-security/discussions)
- 📧 **Contact**: hello.finksystems@gmail.com

---

## 🙏 Acknowledgments

Special thanks to all contributors and security researchers who help improve MCP security.

---

**Start here**: [`docs/INDEX.md`](./docs/INDEX.md) → Choose a rule → Apply it to your code 🚀