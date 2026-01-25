#!/bin/bash
set -e

echo "📚 Creating mcp-security documentation repository structure..."

# Main directories
mkdir -p docs/{en,es}
mkdir -p pdfs/{en,es}
mkdir -p examples/{nodejs,python,go}
mkdir -p scripts
mkdir -p .github/workflows

# Subdirectories for organized docs
mkdir -p docs/en/{sec-rules,guides,references}
mkdir -p docs/es/{sec-rules,guides,references}

# Example subdirectories
mkdir -p examples/nodejs/{authentication,validation,encryption}
mkdir -p examples/python/{authentication,validation,encryption}
mkdir -p examples/go/{authentication,validation,encryption}

echo "✅ Documentation structure created"
