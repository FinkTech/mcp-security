#!/bin/bash
set -e

echo "📄 Creating sample documentation files..."

# SEC-001 English
cat > docs/en/sec-rules/SEC-001-Authentication.md << 'EOF'
# SEC-001: Authentication Bypass

**Severity:** Critical  
**OWASP:** A07:2021 - Identification and Authentication Failures  
**CWE:** CWE-287, CWE-306

## Description

Missing or inadequate authentication mechanisms that allow unauthorized access to protected resources.

## Compliance Mapping

- **SOC2:** CC6.1, CC6.2
- **HIPAA:** §164.312(a)(1), §164.312(d)
- **PCI DSS:** 6.2.4, 8.3.1, 8.4.1

## Vulnerable Code Example

```javascript
// ❌ NO AUTHENTICATION
app.get('/admin/users', (req, res) => {
  const users = db.getAllUsers();
  res.json(users);
});
