#!/bin/bash

# Script para comparar package-lock.json contra la lista de GitHub
# Uso: ./compare-packages.sh [ruta-al-package-lock.json]

set -e

# URL de la lista de paquetes
LIST_URL="https://raw.githubusercontent.com/sng-jroji/hulud-party/refs/heads/main/list.txt"

# Archivo package-lock.json (por defecto en el directorio actual)
PACKAGE_LOCK_FILE="${1:-package-lock.json}"

# Colores para output
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Verificar que el archivo package-lock.json existe
if [ ! -f "$PACKAGE_LOCK_FILE" ]; then
    echo "❌ Error: No se encontró el archivo $PACKAGE_LOCK_FILE"
    exit 1
fi

# Verificar que jq está instalado
if ! command -v jq &> /dev/null; then
    echo "❌ Error: jq no está instalado. Por favor instálalo con: brew install jq"
    exit 1
fi

# Crear archivos temporales
TEMP_DIR=$(mktemp -d)
REMOTE_LIST="$TEMP_DIR/remote_list.txt"
LOCAL_PACKAGES="$TEMP_DIR/local_packages.txt"
MATCHES="$TEMP_DIR/matches.txt"

# Función de limpieza
cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

echo "📦 Extrayendo librerías de $PACKAGE_LOCK_FILE..."
echo "🌐 Descargando lista de GitHub..."

# Descargar lista de paquetes remotos
if ! curl -s "$LIST_URL" > "$REMOTE_LIST"; then
    echo "❌ Error: No se pudo descargar la lista de paquetes"
    exit 1
fi

# Convertir la lista de GitHub (una línea separada por espacios) a formato de líneas
tr ' ' '\n' < "$REMOTE_LIST" | grep -v '^$' > "$REMOTE_LIST.tmp" && mv "$REMOTE_LIST.tmp" "$REMOTE_LIST"

# Extraer TODAS las librerías del package-lock.json
# Para npm v6 y anteriores (formato dependencies)
if jq -e '.dependencies' "$PACKAGE_LOCK_FILE" > /dev/null 2>&1; then
    echo "🔍 Analizando formato npm v6 (dependencies)..."
    jq -r '
    def extract_all_deps(obj):
        if obj | type == "object" then
            obj | to_entries[] | 
            select(.value | type == "object" and has("version")) |
            "\(.key)@\(.value.version)" as $dep |
            $dep,
            (.value.dependencies // {} | extract_all_deps),
            (.value.devDependencies // {} | extract_all_deps)
        else empty end;
    
    .dependencies | extract_all_deps
    ' "$PACKAGE_LOCK_FILE" > "$LOCAL_PACKAGES" 2>/dev/null || true
fi

# Para npm v7+ (formato packages)
if jq -e '.packages' "$PACKAGE_LOCK_FILE" > /dev/null 2>&1; then
    echo "🔍 Analizando formato npm v7+ (packages)..."
    jq -r '
    .packages | to_entries[] | 
    select(.value.version != null and .key != "") | 
    "\(.key | ltrimstr("node_modules/"))@\(.value.version)"
    ' "$PACKAGE_LOCK_FILE" >> "$LOCAL_PACKAGES" 2>/dev/null || true
fi

# Método alternativo para npm v7+ - buscar en toda la estructura
if jq -e '.packages' "$PACKAGE_LOCK_FILE" > /dev/null 2>&1; then
    echo "🔍 Analizando dependencias en toda la estructura..."
    jq -r '
    .. | objects | 
    to_entries[] | 
    select(.key | startswith("@") or (. | test("^[a-zA-Z]"))) |
    select(.value | type == "string" and (. | test("^[0-9]"))) |
    "\(.key)@\(.value)"
    ' "$PACKAGE_LOCK_FILE" >> "$LOCAL_PACKAGES" 2>/dev/null || true
fi

# Limpiar y ordenar
sort -u "$LOCAL_PACKAGES" > "$LOCAL_PACKAGES.tmp" && mv "$LOCAL_PACKAGES.tmp" "$LOCAL_PACKAGES"

echo "🔍 Comparando paquetes..."

# Encontrar coincidencias exactas
comm -12 <(sort "$LOCAL_PACKAGES") <(sort "$REMOTE_LIST") > "$MATCHES"

# Mostrar solo las coincidencias
if [ -s "$MATCHES" ]; then
    echo ""
    echo -e "${GREEN}✅ COINCIDENCIAS EXACTAS: $(wc -l < "$MATCHES") paquetes${NC}"
    echo ""
    cat "$MATCHES" | sed 's/^/  ✓ /'
    echo ""
    echo -e "${GREEN}📊 Total paquetes en package-lock: $(wc -l < "$LOCAL_PACKAGES")${NC}"
    echo -e "${GREEN}📊 Total paquetes en lista remota: $(wc -l < "$REMOTE_LIST")${NC}"
    echo -e "${GREEN}📊 Coincidencias encontradas: $(wc -l < "$MATCHES")${NC}"
else
    echo ""
    echo "❌ No se encontraron coincidencias exactas"
    echo ""
    echo "📊 Total paquetes en package-lock: $(wc -l < "$LOCAL_PACKAGES")"
    echo "📊 Total paquetes en lista remota: $(wc -l < "$REMOTE_LIST")"
fi
