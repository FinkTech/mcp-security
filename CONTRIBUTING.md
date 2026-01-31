# Contributing to MCP Security Documentation

Thank you for your interest in contributing! This document provides guidelines for contributions.

## How to Contribute

### Reporting Issues

Found a problem? Open an issue:

1. Go to **Issues** → **New Issue**
2. Describe the problem clearly
3. Include relevant details (rule number, file, error message)
4. Provide suggestions if you have them

### Suggesting Improvements

Have an idea? We'd love to hear it:

1. Open an **Issue** with label "enhancement"
2. Describe what should be improved
3. Explain why it matters
4. Provide examples if possible

### Submitting Code/Documentation

Ready to contribute code or documentation?

1. **Fork** this repository
2. Create a new branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Test your changes locally
5. Commit with clear messages: `git commit -m "docs: description"`
6. Push to your fork: `git push origin feature/your-feature`
7. Open a **Pull Request** with description of changes

## Guidelines

### Code/Documentation Standards

- ✅ Use clear, professional English
- ✅ Follow existing formatting
- ✅ Include examples where applicable
- ✅ Reference official sources
- ✅ Test markdown syntax

### Commit Messages

Use clear commit messages:

```text
# Good
docs: improve SEC-001 example code

# Good
fix: typo in SECURITY.md

# Avoid
update file
fix stuff
changes
```

### Pull Request Process

1. Update README.md if needed
2. Update INDEX.md if adding rules
3. Ensure all tests pass
4. Provide clear description of changes
5. Reference any related issues

## What Can You Contribute?

### Documentation
- Improve existing rules
- Fix typos or clarifications
- Add more examples
- Enhance explanations
- Propose new security rules (SEC-013+)

### New Security Rules

Want to propose a new rule?

1. Check if it's not already covered (SEC-001 to SEC-012)
2. Open an **Issue** with label "new-rule"
3. Include:
   - Rule name and category
   - OWASP/CWE mapping
   - Vulnerable example
   - Secure implementation
   - Compliance impact (SOC2, HIPAA, PCI DSS)
4. Wait for community feedback before submitting PR

### Translations
- Translate to new languages
- Improve Spanish/English translations
- Ensure terminology consistency

### Code Examples
- Better vulnerable code examples
- More comprehensive secure implementations
- Examples in other languages (Python, Go, etc.)

### Infrastructure
- Improve CI/CD workflows
- Enhance PDF generation
- Better automation scripts

### Community
- Report bugs
- Suggest improvements
- Share in your network
- Help others in Discussions

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](./CODE_OF_CONDUCT.md). 

By participating, you are expected to uphold this code. Please report unacceptable behavior to hello.finksystems@gmail.com.

## Questions?

- Check existing issues/discussions first
- Ask in GitHub Discussions
- Review SECURITY.md for security concerns

---

**Thank you for making this project better! 🚀**