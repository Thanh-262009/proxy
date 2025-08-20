@echo off
setlocal enabledelayedexpansion

echo ========================================
echo 🚀 Rust Proxy Server - Windows Builder
echo ========================================

:: Check if Rust is installed
where cargo >nul 2>nul
if %errorlevel% neq 0 (
    echo ❌ Rust not found! Installing...
    call :install_rust
)

:: Check if Visual Studio Build Tools are available
where cl >nul 2>nul
if %errorlevel% neq 0 (
    echo ⚠️  Visual Studio Build Tools not found!
    echo Please install Visual Studio Build Tools or Visual Studio Community
    echo https://visualstudio.microsoft.com/downloads/
    pause
    exit /b 1
)

:: Set optimization flags
set RUSTFLAGS=-C target-cpu=native -C opt-level=3 -C lto=fat

echo 📦 Installing dependencies...
cargo fetch

echo 🔨 Building release version...
cargo build --release --verbose

if %errorlevel% equ 0 (
    echo ✅ Build successful!
    echo 📁 Binary location: target\release\proxy-server.exe
    echo 📏 Binary size:
    dir /s target\release\proxy-server.exe | findstr proxy-server.exe
    
    :: Create distribution folder
    if not exist "dist" mkdir dist
    copy target\release\proxy-server.exe dist\
    copy config.toml dist\
    copy README.md dist\
    
    echo 📦 Distribution created in 'dist' folder
    echo.
    echo 🎯 To run the proxy server:
    echo    cd dist
    echo    proxy-server.exe
) else (
    echo ❌ Build failed!
    exit /b 1
)

pause
exit /b 0

:install_rust
echo 📥 Downloading Rust installer...
powershell -Command "Invoke-WebRequest -Uri 'https://win.rustup.rs/x86_64' -OutFile 'rustup-init.exe'"
echo 🔧 Installing Rust...
rustup-init.exe -y --default-toolchain stable --profile complete
call refreshenv
del rustup-init.exe
goto :eof
