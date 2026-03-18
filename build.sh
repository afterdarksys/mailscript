#!/bin/bash
set -e

echo "🔨 Building MailScript..."

# Get version from git or use default
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
GO_VERSION=$(go version | awk '{print $3}')

# Build flags
LDFLAGS="-s -w"
LDFLAGS="$LDFLAGS -X main.Version=$VERSION"
LDFLAGS="$LDFLAGS -X main.BuildTime=$BUILD_TIME"
LDFLAGS="$LDFLAGS -X main.GoVersion=$GO_VERSION"

# Ensure dependencies
echo "📦 Downloading dependencies..."
go mod download

# Build for current platform
echo "🔧 Building mailscript binary..."
go build -ldflags="$LDFLAGS" -o mailscript ./cmd/mailscript

echo "✅ Build complete!"
echo "📍 Binary: ./mailscript"
echo "🏷️  Version: $VERSION"

# Show binary info
ls -lh mailscript
