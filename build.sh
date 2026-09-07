#!/bin/bash
set -e

echo " Building MailScript..."

# Version: an exact release tag wins; otherwise the VERSION file plus the short
# commit so untagged builds are still attributable (e.g. 1.0.0+b0ba851).
if VERSION=$(git describe --tags --exact-match 2>/dev/null); then
  :
else
  VERSION="$(cat "$(dirname "$0")/VERSION")+$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
  [ -n "$(git status --porcelain 2>/dev/null)" ] && VERSION="$VERSION-dirty"
fi
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
GO_VERSION=$(go version | awk '{print $3}')

# Build flags
LDFLAGS="-s -w"
LDFLAGS="$LDFLAGS -X main.Version=$VERSION"
LDFLAGS="$LDFLAGS -X main.BuildTime=$BUILD_TIME"
LDFLAGS="$LDFLAGS -X main.GoVersion=$GO_VERSION"

# Ensure dependencies
echo " Downloading dependencies..."
go mod download

# Build for current platform
echo " Building mailscript binary..."
go build -ldflags="$LDFLAGS" -o mailscript ./cmd/mailscript

echo " Build complete!"
echo " Binary: ./mailscript"
echo "Version: $VERSION"

# Show binary info
ls -lh mailscript
