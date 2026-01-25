#!/bin/bash

# MCP Security Documentation - PDF Generation Script
# Convierte todos los markdown a PDF usando Pandoc

set -e

echo "🔒 MCP Security Documentation - PDF Generator"
echo "=============================================="
echo ""

# Verificar si Pandoc está instalado
if ! command -v pandoc &> /dev/null; then
    echo "❌ Pandoc no está instalado. Instálalo con:"
    echo "   macOS: brew install pandoc"
    echo "   Ubuntu/Debian: sudo apt-get install pandoc"
    echo "   Windows: choco install pandoc"
    exit 1
fi

# Crear directorios de salida
mkdir -p docs/pdf/en docs/pdf/es

# Contador de progreso
total=24
count=0

# Colores
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# Función para convertir markdown a PDF
convert_md_to_pdf() {
    local input_file=$1
    local output_file=$2
    local title=$3
    
    count=$((count + 1))
    echo -e "${BLUE}[$count/$total]${NC} Convirtiendo: $title"
    
    pandoc \
        --from markdown \
        --to pdf \
        --pdf-engine=xelatex \
        --variable mainfont="DejaVu Sans" \
        --variable monofont="DejaVu Sans Mono" \
        --variable fontsize=11pt \
        --variable geometry:margin=1in \
        --variable colorlinks=true \
        --variable linkcolor=blue \
        --variable urlcolor=blue \
        --toc \
        --toc-depth=2 \
        --number-sections \
        --output "$output_file" \
        "$input_file"
    
    echo -e "${GREEN}✓${NC} Generado: $output_file"
}

echo ""
echo "📄 Generando PDFs en inglés..."
echo "=============================="

# Archivos en inglés
for i in {001..012}; do
    input="docs/en/sec-rules/SEC-$i"*.md
    if ls $input 1> /dev/null 2>&1; then
        output="docs/pdf/en/SEC-$i.pdf"
        title=$(grep "^# SEC-" $input | head -1 | sed 's/# //')
        convert_md_to_pdf "$input" "$output" "$title"
    fi
done

echo ""
echo "📄 Generando PDFs en español..."
echo "=============================="

# Archivos en español
for i in {001..012}; do
    input="docs/es/sec-rules/SEC-$i"*.md
    if ls $input 1> /dev/null 2>&1; then
        output="docs/pdf/es/SEC-$i.pdf"
        title=$(grep "^# SEC-" $input | head -1 | sed 's/# //')
        convert_md_to_pdf "$input" "$output" "$title"
    fi
done

echo ""
echo "=============================================="
echo -e "${GREEN}✓ ¡Generación de PDFs completada!${NC}"
echo "=============================================="
echo ""
echo "📊 Resumen:"
echo "   PDFs en inglés: $(ls docs/pdf/en/ 2>/dev/null | wc -l) archivos"
echo "   PDFs en español: $(ls docs/pdf/es/ 2>/dev/null | wc -l) archivos"
echo ""
echo "📂 Ubicación de salida:"
echo "   docs/pdf/en/  (versiones en inglés)"
echo "   docs/pdf/es/  (versiones en español)"
echo ""