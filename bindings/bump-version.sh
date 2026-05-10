#!/bin/bash
# HTTPCloak Version Bump Script
# Usage: ./bump-version.sh <new_version>
# Example: ./bump-version.sh 1.0.7

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <new_version>"
    echo "Example: $0 1.0.7"
    exit 1
fi

NEW_VERSION="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Bumping all versions to $NEW_VERSION..."

# Validate version format
if ! [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version must be in format X.Y.Z (e.g., 1.0.6)"
    exit 1
fi

# Update main Node.js package.json (version + optionalDependencies)
echo "  -> nodejs/package.json"
cd "$SCRIPT_DIR/nodejs"
# Use node to update JSON properly
node -e "
const fs = require('fs');
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
pkg.version = '$NEW_VERSION';
for (const dep of Object.keys(pkg.optionalDependencies || {})) {
    pkg.optionalDependencies[dep] = '$NEW_VERSION';
}
fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2) + '\n');
"

# Update all platform package.json files
for platform in linux-x64 linux-arm64 darwin-x64 darwin-arm64 win32-x64 win32-arm64; do
    if [ -f "$SCRIPT_DIR/nodejs/npm/$platform/package.json" ]; then
        echo "  -> nodejs/npm/$platform/package.json"
        cd "$SCRIPT_DIR/nodejs/npm/$platform"
        node -e "
const fs = require('fs');
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
pkg.version = '$NEW_VERSION';
fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2) + '\n');
"
    fi
done

# Update Python pyproject.toml
echo "  -> python/pyproject.toml"
cd "$SCRIPT_DIR/python"
sed -i "s/^version = \".*\"/version = \"$NEW_VERSION\"/" pyproject.toml

# Update clib sensor.go version string
echo "  -> clib/sensor.go"
cd "$SCRIPT_DIR/clib"
sed -i "s/return C.CString(\"[0-9]*\.[0-9]*\.[0-9]*\")/return C.CString(\"$NEW_VERSION\")/" sensor.go

# Update Python __init__.py version string
echo "  -> python/sensor/__init__.py"
cd "$SCRIPT_DIR/python"
sed -i "s/__version__ = \"[0-9]*\.[0-9]*\.[0-9]*\"/__version__ = \"$NEW_VERSION\"/" sensor/__init__.py

# Update .NET Sensor.csproj version
if [ -f "$SCRIPT_DIR/dotnet/Sensor/Sensor.csproj" ]; then
    echo "  -> dotnet/Sensor/Sensor.csproj"
    cd "$SCRIPT_DIR/dotnet/Sensor"
    sed -i "s/<Version>[0-9]*\.[0-9]*\.[0-9]*<\/Version>/<Version>$NEW_VERSION<\/Version>/" Sensor.csproj
fi

echo ""
echo "Version bumped to $NEW_VERSION successfully!"
echo ""
echo "Files updated:"
echo "  - bindings/nodejs/package.json (version + optionalDependencies)"
echo "  - bindings/nodejs/npm/*/package.json (6 platform packages)"
echo "  - bindings/python/pyproject.toml"
echo "  - bindings/python/sensor/__init__.py"
echo "  - bindings/clib/sensor.go"
echo "  - bindings/dotnet/Sensor/Sensor.csproj (if exists)"
echo ""
echo "Next steps:"
echo "  1. Rebuild native libraries: cd bindings && make build"
echo "  2. Test locally"
echo "  3. Commit and tag: git tag v$NEW_VERSION"
echo "  4. Push: git push && git push --tags"
