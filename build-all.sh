#!/bin/bash
set -e

echo "🌍 Building MailScript for multiple platforms..."

VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
GO_VERSION=$(go version | awk '{print $3}')

LDFLAGS="-s -w"
LDFLAGS="$LDFLAGS -X main.Version=$VERSION"
LDFLAGS="$LDFLAGS -X main.BuildTime=$BUILD_TIME"
LDFLAGS="$LDFLAGS -X main.GoVersion=$GO_VERSION"

# Create dist directory
mkdir -p dist

# Build for multiple platforms
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
)

for PLATFORM in "${PLATFORMS[@]}"; do
    GOOS=${PLATFORM%/*}
    GOARCH=${PLATFORM#*/}

    OUTPUT="dist/mailscript-${VERSION}-${GOOS}-${GOARCH}"
    if [ "$GOOS" = "windows" ]; then
        OUTPUT="${OUTPUT}.exe"
    fi

    echo "🔨 Building for $GOOS/$GOARCH..."
    GOOS=$GOOS GOARCH=$GOARCH go build -ldflags="$LDFLAGS" -o "$OUTPUT" ./cmd/mailscript

    # Create tarball (except for Windows)
    if [ "$GOOS" != "windows" ]; then
        tar -czf "${OUTPUT}.tar.gz" -C dist "$(basename $OUTPUT)"
        rm "$OUTPUT"
        echo "   ✅ ${OUTPUT}.tar.gz"
    else
        echo "   ✅ $OUTPUT"
    fi
done

echo ""
echo "✅ Build complete! Binaries in dist/"
ls -lh dist/
