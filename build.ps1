$buildDir = "build"

if (!(Test-Path -Path $buildDir)) {
    New-Item -ItemType Directory -Path $buildDir
}

Write-Host "Building for multiple platforms..."

# Windows build
Write-Host "Building Windows executable..."
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -o "$buildDir\kikoscan.exe" -ldflags="-s -w"

# Linux build
Write-Host "Building Linux executable..."
$env:GOOS = "linux"
$env:GOARCH = "amd64"
go build -o "$buildDir\kikoscan_linux" -ldflags="-s -w"

# macOS build
Write-Host "Building macOS executable..."
$env:GOOS = "darwin"
$env:GOARCH = "amd64"
go build -o "$buildDir\kikoscan_darwin" -ldflags="-s -w"

Write-Host "Build completed!"
Write-Host "Executables location:"
Write-Host "Windows: $buildDir\kikoscan.exe"
Write-Host "Linux: $buildDir\kikoscan_linux"
Write-Host "macOS: $buildDir\kikoscan_darwin"
