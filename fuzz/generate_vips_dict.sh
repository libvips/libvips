#!/bin/sh
#
# Generate a libFuzzer dictionary for vips_fuzzer from the installed
# vips binary. This ensures the dictionary matches the exact set of
# operations, arguments, and enum values available in the build.
#
# Usage: ./generate_vips_dict.sh [path/to/vips] > vips_fuzzer.dict

set -e

VIPS="${1:-vips}"

if ! command -v "$VIPS" >/dev/null 2>&1; then
    echo "error: vips binary not found: $VIPS" >&2
    exit 1
fi

emit() {
    echo "\"$1\""
}

ops=$(VIPS_WARNING=0 "$VIPS" -c 2>/dev/null | grep -v "^Vips" | sort -u)

cat <<'EOF'
# Auto-generated libFuzzer dictionary for vips_fuzzer.
# Regenerate with: ./generate_vips_dict.sh [path/to/vips]

EOF

# Operation nicknames (concrete, instantiable operations).
echo "# operation nicknames"
echo "$ops" | while read -r op; do
    emit "$op"
done

echo ""
echo "# optional argument syntax"
emit "--"
emit "="

# Collect optional argument names and enum values from every operation.
all_usage=""
echo "$ops" | while read -r op; do
    VIPS_WARNING=0 "$VIPS" "$op" 2>&1 || true
done | {
    all_usage=$(cat)

    echo ""
    echo "# optional argument names"
    echo "$all_usage" | \
        sed -n '/^optional arguments:/,/^operation flags:/p' | \
        grep "^   [a-zA-Z]" | \
        awk '{print $1}' | \
        sort -u | while read -r name; do
            emit "--${name}="
        done

    echo ""
    echo "# enum values"
    echo "$all_usage" | \
        grep "allowed enums:" | \
        sed 's/.*allowed enums: //' | \
        tr ',' '\n' | \
        tr -d ' ' | \
        sort -u | while read -r val; do
            [ -n "$val" ] && emit "$val"
        done
}

# Static entries that don't come from introspection.
cat <<'EOF'

# common argument values
"true"
"false"
"uchar"
"char"
"ushort"
"short"
"uint"
"int"
"float"
"double"
"complex"
"dpcomplex"
"notset"

# interpolator names (not in enum introspection)
"bicubic"
"bilinear"
"lbb"
"nohalo"
"vsqbs"

# array syntax
" "
"0"
"1"
"128"
"255"
"0.0"
"0.5"
"1.0"
"0 0 0"
"1 2 3"
"128 128 128"
"255 255 255"
"0.0 0.0 0.0"
"1.0 1.0 1.0"
"1.0 2.0 3.0"
"1 0 0 0 1 0 0 0 1"
EOF
