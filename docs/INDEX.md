# 📋 Index - MCP Security Documentation

**Índice completo de todas las reglas de seguridad**

---

## 📊 Resumen Ejecutivo

- **Total Rules:** 12
- **Languages:** English + Spanish (24 files)
- **Coverage:** OWASP Top 10 2021, SOC2, HIPAA, PCI DSS
- **Status:** ✅ Production Ready
- **Last Updated:** January 25, 2026

---

## 🔴 CRITICAL (4 Rules - 33%)

### SEC-001: Authentication Bypass
**OWASP:** A01:2021 - Broken Access Control  
**Severity:** 🔴 CRITICAL  
**CWE:** CWE-287 (Improper Authentication)

**English:** `docs/en/sec-rules/SEC-001.md`  
**Español:** `docs/es/sec-rules/SEC-001.md`

**Keywords:** Authentication, JWT, Credentials, Password  
**Impact:** Unauthorized access to entire application

---

### SEC-002: Command Injection
**OWASP:** A03:2021 - Injection  
**Severity:** 🔴 CRITICAL  
**CWE:** CWE-78 (Improper Neutralization of Special Elements used in an OS Command)

**English:** `docs/en/sec-rules/SEC-002.md`  
**Español:** `docs/es/sec-rules/SEC-002.md`

**Keywords:** Command Execution, Shell, OS Commands  
**Impact:** Complete system compromise

---

### SEC-003: SQL Injection
**OWASP:** A03:2021 - Injection  
**Severity:** 🔴 CRITICAL  
**CWE:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)

**English:** `docs/en/sec-rules/SEC-003.md`  
**Español:** `docs/es/sec-rules/SEC-003.md`

**Keywords:** SQL, Database, Queries, Parameterized Statements  
**Impact:** Data breach, data manipulation, database compromise

---

### SEC-006: Insecure Deserialization
**OWASP:** A08:2021 - Software and Data Integrity Failures  
**Severity:** 🔴 CRITICAL  
**CWE:** CWE-502 (Deserialization of Untrusted Data)

**English:** `docs/en/sec-rules/SEC-006.md`  
**Español:** `docs/es/sec-rules/SEC-006.md`

**Keywords:** Serialization, Object, Untrusted Data, Gadget Chains  
**Impact:** Remote code execution, data tampering

---

## 🟠 HIGH (5 Rules - 42%)

### SEC-004: Server-Side Request Forgery (SSRF)
**OWASP:** A06:2021 - Vulnerable and Outdated Components (indirect)  
**Severity:** 🟠 HIGH  
**CWE:** CWE-918 (Server-Side Request Forgery)

**English:** `docs/en/sec-rules/SEC-004.md`  
**Español:** `docs/es/sec-rules/SEC-004.md`

**Keywords:** SSRF, URL Validation, Internal Resources, Proxy  
**Impact:** Internal network access, credential theft

---

### SEC-005: XML External Entity (XXE)
**OWASP:** A05:2021 - Security Misconfiguration  
**Severity:** 🟠 HIGH  
**CWE:** CWE-611 (Improper Restriction of XML External Entity Reference)

**English:** `docs/en/sec-rules/SEC-005.md`  
**Español:** `docs/es/sec-rules/SEC-005.md`

**Keywords:** XXE, XML, External Entities, DTD, ENTITY  
**Impact:** Information disclosure, DoS, SSRF

---

### SEC-007: Path Traversal
**OWASP:** A01:2021 - Broken Access Control  
**Severity:** 🟠 HIGH  
**CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)

**English:** `docs/en/sec-rules/SEC-007.md`  
**Español:** `docs/es/sec-rules/SEC-007.md`

**Keywords:** Directory Traversal, Path Validation, File Access  
**Impact:** Unauthorized file access, information disclosure

---

### SEC-009: Sensitive Data Exposure in Code/Logs
**OWASP:** A02:2021 - Cryptographic Failures  
**Severity:** 🟠 HIGH  
**CWE:** CWE-532 (Insertion of Sensitive Information into Log Files)

**English:** `docs/en/sec-rules/SEC-009.md`  
**Español:** `docs/es/sec-rules/SEC-009.md`

**Keywords:** Logging, Secrets, API Keys, Passwords, PII  
**Impact:** Credential theft, privacy violation

---

### SEC-012: Weak Cryptography
**OWASP:** A02:2021 - Cryptographic Failures  
**Severity:** 🟠 HIGH  
**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)

**English:** `docs/en/sec-rules/SEC-012.md`  
**Español:** `docs/es/sec-rules/SEC-012.md`

**Keywords:** Encryption, Hashing, Weak Algorithms, MD5, SHA1  
**Impact:** Data compromise, decryption attacks

---

## 🟡 MEDIUM (3 Rules - 25%)

### SEC-008: Data Leakage in Responses
**OWASP:** A01:2021 - Broken Access Control  
**Severity:** 🟡 MEDIUM  
**CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)

**English:** `docs/en/sec-rules/SEC-008.md`  
**Español:** `docs/es/sec-rules/SEC-008.md`

**Keywords:** Information Disclosure, Response Data, Error Messages  
**Impact:** Information disclosure, reconnaissance

---

### SEC-010: Missing Rate Limiting
**OWASP:** A04:2021 - Insecure Design  
**Severity:** 🟡 MEDIUM  
**CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)

**English:** `docs/en/sec-rules/SEC-010.md`  
**Español:** `docs/es/sec-rules/SEC-010.md`

**Keywords:** Rate Limiting, Throttling, Brute Force, DoS  
**Impact:** Brute force attacks, DoS

---

### SEC-011: Regular Expression Denial of Service (ReDoS)
**OWASP:** A04:2021 - Insecure Design  
**Severity:** 🟡 MEDIUM  
**CWE:** CWE-1333 (Inefficient Regular Expression Complexity)

**English:** `docs/en/sec-rules/SEC-011.md`  
**Español:** `docs/es/sec-rules/SEC-011.md`

**Keywords:** ReDoS, Regex, Catastrophic Backtracking, DoS  
**Impact:** Denial of service, performance degradation

---

## 🗂️ Búsqueda por Tema

### By OWASP Category

**A01:2021 - Broken Access Control**
- SEC-001: Authentication Bypass
- SEC-007: Path Traversal
- SEC-008: Data Leakage in Responses

**A02:2021 - Cryptographic Failures**
- SEC-009: Sensitive Data Exposure in Code/Logs
- SEC-012: Weak Cryptography

**A03:2021 - Injection**
- SEC-002: Command Injection
- SEC-003: SQL Injection

**A04:2021 - Insecure Design**
- SEC-010: Missing Rate Limiting
- SEC-011: Regular Expression DoS

**A05:2021 - Security Misconfiguration**
- SEC-005: XML External Entity

**A06:2021 - Vulnerable and Outdated Components**
- SEC-004: Server-Side Request Forgery (indirect)

**A08:2021 - Software & Data Integrity Failures**
- SEC-006: Insecure Deserialization

---

### By Technology

**JavaScript/Node.js Focus:**
- All rules include Node.js/Express examples
- Modern framework patterns
- Production-ready implementations

**Database Security:**
- SEC-003: SQL Injection
- SEC-008: Data Leakage

**Cryptography & Encoding:**
- SEC-009: Sensitive Data Exposure
- SEC-012: Weak Cryptography

**Input Validation:**
- SEC-001: Authentication Bypass
- SEC-002: Command Injection
- SEC-003: SQL Injection
- SEC-004: SSRF
- SEC-005: XXE
- SEC-007: Path Traversal
- SEC-011: ReDoS

---

### By Compliance Standard

**SOC2 Type II Covered:**
All 12 rules → CC6, CC7 sections

**HIPAA §164.312 Covered:**
All 12 rules → Multiple sections per rule

**PCI DSS v4.0 Covered:**
All 12 rules → Requirements 3, 4, 6, 8, 10

**CWE Coverage:**
- CWE-22: SEC-007
- CWE-78: SEC-002
- CWE-89: SEC-003
- CWE-200: SEC-008
- CWE-287: SEC-001
- CWE-327: SEC-012
- CWE-502: SEC-006
- CWE-532: SEC-009
- CWE-611: SEC-005
- CWE-770: SEC-010
- CWE-918: SEC-004
- CWE-1333: SEC-011

---

## 📊 Coverage Matrix

| Rule | OWASP | CWE | SOC2 | HIPAA | PCI DSS |
|------|-------|-----|------|-------|---------|
| SEC-001 | A01 | 287 | ✅ | ✅ | ✅ |
| SEC-002 | A03 | 78 | ✅ | ✅ | ✅ |
| SEC-003 | A03 | 89 | ✅ | ✅ | ✅ |
| SEC-004 | A06 | 918 | ✅ | ✅ | ✅ |
| SEC-005 | A05 | 611 | ✅ | ✅ | ✅ |
| SEC-006 | A08 | 502 | ✅ | ✅ | ✅ |
| SEC-007 | A01 | 22 | ✅ | ✅ | ✅ |
| SEC-008 | A01 | 200 | ✅ | ✅ | ✅ |
| SEC-009 | A02 | 532 | ✅ | ✅ | ✅ |
| SEC-010 | A04 | 770 | ✅ | ✅ | ✅ |
| SEC-011 | A04 | 1333 | ✅ | ✅ | ✅ |
| SEC-012 | A02 | 327 | ✅ | ✅ | ✅ |

---

## 🎯 Reading Recommendations

**For Complete Beginners:**
1. SEC-001 - Authentication Bypass
2. SEC-003 - SQL Injection
3. SEC-007 - Path Traversal

**For Backend Developers:**
1. SEC-002 - Command Injection
2. SEC-003 - SQL Injection
3. SEC-004 - SSRF
4. SEC-005 - XXE
5. SEC-006 - Deserialization

**For DevOps/Infrastructure:**
1. SEC-004 - SSRF
2. SEC-009 - Sensitive Data Exposure
3. SEC-010 - Rate Limiting
4. SEC-012 - Weak Cryptography

**For Compliance Officers:**
1. Read: COMPLIANCE.md
2. Check coverage matrix above
3. Review specific requirements per standard

---

## 📥 How to Use This Index

1. **Find by Severity:** Use 🔴🟠🟡 sections above
2. **Find by Topic:** Use "Búsqueda por Tema" section
3. **Find by Technology:** Use technology category
4. **Find by Standard:** Use compliance standard
5. **Check Coverage:** Use coverage matrix

---

## 📄 File Locations

**All English Rules:** `docs/en/sec-rules/`  
**All Spanish Rules:** `docs/es/sec-rules/`  
**Generated PDFs (after CI/CD):** `docs/pdf/en/` and `docs/pdf/es/`

---

**Last Updated:** January 25, 2026  
**Version:** 1.0.0  
**Status:** ✅ Complete