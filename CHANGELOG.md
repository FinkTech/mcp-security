# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-01-31

### Fixed
- Fixed PDF generation for SEC-002 (Command Injection) - escaped `\n` metacharacters in EN and ES versions
- Corrected OWASP mapping for SEC-001 (A01 → A07) in INDEX.md
- Standardized INDEX.md language to English
- Fixed Coverage Matrix inconsistency
- Fixed Spanish documentation links in `docs/es/README.md` (pdfs → docs/pdf)

### Added
- CHANGELOG.md for version tracking
- CODE_OF_CONDUCT.md (Contributor Covenant v2.1)
- CONTRIBUTING.md with contribution guidelines and new security rules proposal process
- CONTRIBUTORS.md for community recognition
- Issue templates (bug report, feature request, security vulnerability)
- Pull request template with checklist
- SUPPORT.md for community support
- Improved INDEX.md navigation with filters and better categorization
- Placeholder READMEs for future authentication/encryption/validation examples (nodejs, python, go)
- Folder structure for PDF generation (docs/pdf/en/ and docs/pdf/es/)

### Changed
- Enhanced INDEX.md structure with better OWASP categorization
- Updated "By OWASP Category" section to include A07
- Improved root documentation structure
- Enhanced CONTRIBUTING.md with guidelines for proposing new security rules (SEC-013+)

## [1.0.0] - 2026-01-25

### Added
- Initial release with 12 security rules (SEC-001 to SEC-012)
- Complete bilingual documentation (English + Spanish)
- OWASP Top 10 2021, SOC2, HIPAA, PCI DSS compliance mapping
- Vulnerable and secure code examples (Node.js/Express)
- GitHub Actions automation for PDF generation
- MIT License
- Comprehensive README, SECURITY.md, and START-HERE.md guides

---

**Note**: All releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).