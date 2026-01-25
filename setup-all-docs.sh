#!/bin/bash
set -e

echo "╔════════════════════════════════════════╗"
echo "║   📚 MCP Security Docs - Setup        ║"
echo "╚════════════════════════════════════════╝"
echo ""

chmod +x *.sh

echo "📁 Step 1/3: Creating directory structure..."
./bootstrap-docs-structure.sh
echo ""

echo "📝 Step 2/3: Creating root files..."
./create-root-files.sh
echo ""

echo "📄 Step 3/3: Creating sample documentation..."
./create-sample-docs.sh
echo ""

echo "╔════════════════════════════════════════╗"
echo "║         ✨ Setup Complete! ✨          ║"
echo "╚════════════════════════════════════════╝"
echo ""
echo "📚 Documentation repository created"
echo ""
echo "🚀 Next steps:"
echo ""
echo "  1. Add your markdown documentation to docs/"
echo "  2. Generate PDFs with: ./scripts/generate-pdfs.sh"
echo "  3. Initialize Git:"
echo "     git init"
echo "     git add ."
echo "     git commit -m \"docs: initial documentation structure\""