#!/bin/bash
set -e

echo "📝 Creating root configuration files..."

# .gitignore
cat > .gitignore << 'EOF'
# OS
.DS_Store
Thumbs.db

# Editor
.vscode/
.idea/
*.swp

# Temp
tmp/
temp/
*.tmp

# Node (if using for PDF generation)
node_modules/
package-lock.json

# Logs
*.log
EOF

# README.md (English)
cat > README.md << 'EOF'
# 🔒 MCP Security Documentation

> Comprehensive security guides for Model Context Protocol servers with SOC2, HIPAA & PCI-DSS compliance mapping

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Documentation](https://img.shields.io/badge/docs-latest-blue)](docs/)

[🇪🇸 Español](./README.es.md)

## 📚 Documentation

This repository contains comprehensive security documentation for MCP servers, including:

- **SEC-001 to SEC-012**: Detailed security rule documentation
- **Compliance Mapping**: SOC2, HIPAA, PCI-DSS controls
- **Code Examples**: Node.js, Python, Go implementations
- **PDF Downloads**: Available in English and Spanish

## 📥 Download PDFs

### English
- [SEC-001: Authentication Bypass](pdfs/en/SEC-001-Authentication.pdf)
- [SEC-002: Command Injection](pdfs/en/SEC-002-CommandInjection.pdf)
- [Complete Guide (All Rules)](pdfs/en/MCP-Security-Complete-Guide.pdf)

### Español
- [SEC-001: Falta de Autenticación](pdfs/es/SEC-001-Autenticacion.pdf)
- [SEC-002: Inyección de Comandos](pdfs/es/SEC-002-InyeccionComandos.pdf)
- [Guía Completa (Todas las Reglas)](pdfs/es/MCP-Security-Guia-Completa.pdf)

## 📖 Documentation Structure

docs/
├── en/ # English documentation
│ ├── sec-rules/ # SEC-001 to SEC-012
│ ├── guides/ # Implementation guides
│ └── references/ # Quick references
└── es/ # Spanish documentation
├── sec-rules/
├── guides/
└── references/

text

## 💻 Code Examples

Working code examples available in:
- **Node.js/TypeScript**: Modern JavaScript implementations
- **Python**: Python 3.10+ with type hints
- **Go**: Go 1.21+ with best practices

See [examples/](examples/) directory.

## 🔗 Related Projects

- [mcp-verify](https://github.com/YOUR_USERNAME/mcp-verify) - Security auditing CLI tool for MCP servers

## 🤝 Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md).

## 📄 License

MIT © 2026 MCP Security Contributors

---

**Built with ❤️ for the MCP community**
EOF

# README.es.md (Español)
cat > README.es.md << 'EOF'
# 🔒 Documentación de Seguridad MCP

> Guías completas de seguridad para servidores Model Context Protocol con mapeo de cumplimiento SOC2, HIPAA y PCI-DSS

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Documentation](https://img.shields.io/badge/docs-latest-blue)](docs/)

[🇬🇧 English](./README.md)

## 📚 Documentación

Este repositorio contiene documentación completa de seguridad para servidores MCP, incluyendo:

- **SEC-001 a SEC-012**: Documentación detallada de reglas de seguridad
- **Mapeo de Cumplimiento**: Controles SOC2, HIPAA, PCI-DSS
- **Ejemplos de Código**: Implementaciones en Node.js, Python, Go
- **Descargas PDF**: Disponibles en inglés y español

## 📥 Descargar PDFs

### Español
- [SEC-001: Falta de Autenticación](pdfs/es/SEC-001-Autenticacion.pdf)
- [SEC-002: Inyección de Comandos](pdfs/es/SEC-002-InyeccionComandos.pdf)
- [Guía Completa (Todas las Reglas)](pdfs/es/MCP-Security-Guia-Completa.pdf)

### English
- [SEC-001: Authentication Bypass](pdfs/en/SEC-001-Authentication.pdf)
- [SEC-002: Command Injection](pdfs/en/SEC-002-CommandInjection.pdf)
- [Complete Guide (All Rules)](pdfs/en/MCP-Security-Complete-Guide.pdf)

## 📖 Estructura de Documentación

docs/
├── en/ # Documentación en inglés
│ ├── sec-rules/ # SEC-001 a SEC-012
│ ├── guides/ # Guías de implementación
│ └── references/ # Referencias rápidas
└── es/ # Documentación en español
├── sec-rules/
├── guides/
└── references/

text

## 💻 Ejemplos de Código

Ejemplos de código funcionales disponibles en:
- **Node.js/TypeScript**: Implementaciones JavaScript modernas
- **Python**: Python 3.10+ con type hints
- **Go**: Go 1.21+ con mejores prácticas

Ver directorio [examples/](examples/).

## 🔗 Proyectos Relacionados

- [mcp-verify](https://github.com/YOUR_USERNAME/mcp-verify) - Herramienta CLI de auditoría de seguridad para servidores MCP

## 🤝 Contribuir

¡Las contribuciones son bienvenidas! Lee [CONTRIBUTING.md](CONTRIBUTING.md).

## 📄 Licencia

MIT © 2026 MCP Security Contributors

---

**Hecho con ❤️ para la comunidad MCP**
EOF

# LICENSE
cat > LICENSE << 'EOF'
MIT License

Copyright (c) 2026 MCP Security Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
EOF

# CONTRIBUTING.md
cat > CONTRIBUTING.md << 'EOF'
# Contributing to MCP Security Documentation

Thank you for your interest in contributing!

## How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-sec-rule`)
3. Make your changes
4. Test documentation builds
5. Commit with clear messages (`git commit -m "docs: add SEC-013 rule"`)
6. Push to your fork
7. Open a Pull Request

## Documentation Guidelines

- Use clear, concise language
- Include code examples for all rules
- Maintain bilingual parity (EN/ES)
- Follow existing formatting conventions
- Include compliance mappings (SOC2, HIPAA, PCI-DSS)

## Reporting Issues

Use GitHub Issues with appropriate labels:
- `bug`: Documentation errors
- `enhancement`: New content suggestions
- `translation`: Translation improvements
EOF

echo "✅ Root files created"