# 🔧 Hướng dẫn Build Rust Proxy Server

## 📦 Windows Build

### **Bước 1: Cài đặt Rust**
```powershell
# Tải và cài đặt Rust từ rustup
# Vào https://rustup.rs/ và tải rustup-init.exe
# Hoặc dùng PowerShell:
Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile "rustup-init.exe"
./rustup-init.exe
```

### **Bước 2: Setup Build Tools**
```powershell
# Cài đặt Visual Studio Build Tools (cần thiết cho Windows)
# Tải Visual Studio Installer và chọn "C++ build tools"
# Hoặc dùng chocolatey:
choco install visualstudio2022buildtools
choco install visualstudio2022-workload-vctools
```

### **Bước 3: Tạo Project**
```powershell
# Tạo thư mục project
mkdir rust-proxy
cd rust-proxy

# Khởi tạo Rust project
cargo init

# Tạo file Cargo.toml
```

### **Bước 4: Cấu hình Cargo.toml**
```toml
[package]
name = "rust-proxy"
version = "1.0.0"
edition = "2021"
authors = ["Your Name <your.email@example.com>"]
description = "High Performance Proxy Server"

[dependencies]
tokio = { version = "1.35", features = ["full"] }
log = "0.4"
env_logger = "0.10"
rand = "0.8"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
clap = { version = "4.0", features = ["derive"] }
anyhow = "1.0"

[profile.release]
lto = true
codegen-units = 1
panic = "abort"
strip = true
opt-level = 3

[profile.dev]
opt-level = 1

[[bin]]
name = "proxy-server"
path = "src/main.rs"
```

### **Bước 5: Build cho Windows**
```powershell
# Development build
cargo build

# Release build (optimized)
cargo build --release

# Build với target cụ thể
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc

# Cross-compile cho Windows 32-bit
rustup target add i686-pc-windows-msvc
cargo build --release --target i686-pc-windows-msvc
```

### **Bước 6: Tạo Executable**
```powershell
# Copy executable từ target/release/
copy target\release\rust-proxy.exe proxy-server.exe

# Hoặc install globally
cargo install --path .
```

---

## 🐧 Linux Build

### **Bước 1: Cài đặt Rust (Ubuntu/Debian)**
```bash
# Cập nhật system
sudo apt update && sudo apt upgrade -y

# Cài đặt dependencies
sudo apt install -y curl build-essential gcc make cmake pkg-config libssl-dev

# Cài đặt Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Verify installation
rustc --version
cargo --version
```

### **Bước 2: Cài đặt Rust (CentOS/RHEL/Fedora)**
```bash
# CentOS/RHEL
sudo yum groupinstall -y "Development Tools"
sudo yum install -y openssl-devel cmake

# Fedora
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y openssl-devel cmake

# Cài đặt Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### **Bước 3: Tạo Project Linux**
```bash
# Tạo project directory
mkdir -p ~/rust-proxy
cd ~/rust-proxy

# Initialize project
cargo init --name proxy-server

# Copy Cargo.toml configuration từ trên
```

### **Bước 4: Build cho Linux**
```bash
# Development build
cargo build

# Release build (highly optimized)
cargo build --release

# Build với musl (static linking)
rustup target add x86_64-unknown-linux-musl
sudo apt install -y musl-tools  # Ubuntu/Debian
cargo build --release --target x86_64-unknown-linux-musl

# Cross-compile cho ARM64
rustup target add aarch64-unknown-linux-gnu
sudo apt install -y gcc-aarch64-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
```

### **Bước 5: Tạo Portable Binary**
```bash
# Copy binary
cp target/release/proxy-server ./proxy-server

# Make executable
chmod +x proxy-server

# Strip symbols để giảm size
strip proxy-server

# Check binary info
file proxy-server
ldd proxy-server  # Check dependencies
```

---

## 🚀 Quick Setup Script

### **Windows PowerShell Script:**
```powershell
# setup-windows.ps1
Write-Host "🚀 Setting up Rust Proxy Server for Windows..." -ForegroundColor Green

# Check if Rust is installed
if (!(Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "📥 Downloading Rust..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile "rustup-init.exe"
    ./rustup-init.exe -y
    $env:PATH += ";$env:USERPROFILE\.cargo\bin"
}

# Create project
mkdir rust-proxy -Force
cd rust-proxy

# Initialize and build
cargo init --name proxy-server
# (Paste Cargo.toml content here)
cargo build --release

Write-Host "✅ Build completed! Binary at: target/release/proxy-server.exe" -ForegroundColor Green
```

### **Linux Setup Script:**
```bash
#!/bin/bash
# setup-linux.sh

echo "🚀 Setting up Rust Proxy Server for Linux..."

# Install Rust if not exists
if ! command -v cargo &> /dev/null; then
    echo "📥 Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
fi

# Install dependencies
if command -v apt &> /dev/null; then
    sudo apt update && sudo apt install -y build-essential libssl-dev pkg-config
elif command -v yum &> /dev/null; then
    sudo yum groupinstall -y "Development Tools" && sudo yum install -y openssl-devel
elif command -v dnf &> /dev/null; then
    sudo dnf groupinstall -y "Development Tools" && sudo dnf install -y openssl-devel
fi

# Create project
mkdir -p ~/rust-proxy
cd ~/rust-proxy

# Build
cargo init --name proxy-server
cargo build --release

echo "✅ Build completed! Binary at: target/release/proxy-server"
chmod +x target/release/proxy-server
```

---

## 📁 File Structure
```
rust-proxy/
├── Cargo.toml          # Project config
├── Cargo.lock          # Dependencies lock
├── src/
│   └── main.rs         # Main proxy code
├── target/
│   ├── debug/          # Debug builds
│   └── release/        # Release builds
├── README.md
└── scripts/
    ├── start.sh        # Linux startup script
    └── start.bat       # Windows startup script
```

---

## 🏃‍♂️ Running the Proxy

### **Windows:**
```cmd
# Run directly
target\release\proxy-server.exe

# Or with parameters
proxy-server.exe --port 28265 --host 0.0.0.0

# Run as Windows Service (advanced)
sc create RustProxy binPath= "C:\path\to\proxy-server.exe"
sc start RustProxy
```

### **Linux:**
```bash
# Run directly
./target/release/proxy-server

# Run in background
nohup ./target/release/proxy-server > proxy.log 2>&1 &

# Run as systemd service
sudo systemctl enable --now rust-proxy.service

# With custom config
./proxy-server --config config.toml
```

---

## 🐳 Docker Build (Bonus)

### **Dockerfile:**
```dockerfile
FROM rust:1.75-alpine AS builder

WORKDIR /app
COPY . .

RUN apk add --no-cache musl-dev openssl-dev
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/proxy-server /usr/local/bin/

EXPOSE 28265
CMD ["proxy-server"]
```

### **Build Docker:**
```bash
# Build image
docker build -t rust-proxy:latest .

# Run container
docker run -d -p 28265:28265 --name rust-proxy rust-proxy:latest

# Docker Compose
docker-compose up -d
```

---

## ⚡ Performance Tips

### **Optimization Flags:**
```toml
[profile.release]
lto = "fat"              # Link Time Optimization
codegen-units = 1        # Single codegen unit
panic = "abort"          # Smaller binary
strip = "symbols"        # Remove debug symbols
opt-level = 3           # Maximum optimization
target-cpu = "native"   # CPU-specific optimizations
```

### **Environment Variables:**
```bash
# Linux performance tuning
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-cpu=native"
export RUSTFLAGS="-C target-cpu=native -C opt-level=3"

# Windows
set RUSTFLAGS=-C target-cpu=native -C opt-level=3
```

## 📊 Binary Sizes
- **Debug build:** ~50-80MB
- **Release build:** ~5-10MB  
- **Stripped release:** ~3-5MB
- **Musl static:** ~8-12MB

Proxy server sẽ có hiệu suất tối ưu với release build!

## 🔍 Troubleshooting

**Common Issues:**
- **OpenSSL errors:** Install `libssl-dev` (Linux) or use `rustls` feature
- **Linker errors:** Install build tools và C compiler
- **Permission denied:** Run as administrator (Windows) hoặc sudo (Linux)
- **Port binding:** Check if port 28265 is already in use

**Performance Monitoring:**
```bash
# Check resource usage
htop
netstat -tulpn | grep 28265

# Windows
tasklist | findstr proxy-server
netstat -an | findstr 28265
```
