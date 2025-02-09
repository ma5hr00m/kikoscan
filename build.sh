#!/bin/bash

BUILD_DIR="build"

if [ ! -d "$BUILD_DIR" ]; then
    mkdir -p "$BUILD_DIR"
fi

echo "Building for multiple platforms..."

# Windows build
echo "Building Windows executable..."
GOOS=windows GOARCH=amd64 go build -o "$BUILD_DIR/kikoscan.exe" -ldflags="-s -w"

# Linux build
echo "Building Linux executable..."
GOOS=linux GOARCH=amd64 go build -o "$BUILD_DIR/kikoscan_linux" -ldflags="-s -w"

# macOS build
echo "Building macOS executable..."
GOOS=darwin GOARCH=amd64 go build -o "$BUILD_DIR/kikoscan_darwin" -ldflags="-s -w"

# Set execute permission for Unix-like systems
chmod +x "$BUILD_DIR/kikoscan_linux" "$BUILD_DIR/kikoscan_darwin"

echo "Build completed!"
echo "Executables location:"
echo "Windows: $BUILD_DIR/kikoscan.exe"
echo "Linux: $BUILD_DIR/kikoscan_linux"
echo "macOS: $BUILD_DIR/kikoscan_darwin"
