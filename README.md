# 🚀 Rust High Performance Proxy Server - Complete Setup

## 📁 Project Structure
```
rust-proxy/
├── README.md                 # This documentation
├── Cargo.toml               # Dependencies & build config
├── Cargo.lock               # Generated dependencies lock
├── build.rs                 # Build script
├── config.toml              # Runtime configuration
├── Dockerfile               # Docker build
├── docker-compose.yml       # Docker Compose
├── .gitignore              # Git ignore patterns
├── src/
│   ├── main.rs             # Main application
│   ├── lib.rs              # Library modules
│   ├── config.rs           # Configuration handling
│   ├── proxy.rs            # Proxy logic
│   ├── stats.rs            # Statistics & monitoring
│   └── utils.rs            # Utility functions
├── scripts/
│   ├── build-windows.bat   # Windows build script
│   ├── build-linux.sh     # Linux build script
│   ├── install-windows.ps1 # Windows installer
│   ├── install-linux.sh   # Linux installer
│   ├── start.bat           # Windows startup
│   ├── start.sh            # Linux startup
│   └── service-install.sh  # Linux service installer
├── configs/
│   ├── proxy.conf          # Nginx proxy config
│   ├── systemd.service     # Linux systemd service
│   └── windows.service.xml # Windows service config
└── target/                 # Build output (generated)
    ├── debug/
    └── release/
```

---

# 🎯 Quick Start Guide

## 1️⃣ Auto Setup (Recommended)

### **Windows PowerShell (Run as Administrator):**
```powershell
# Download and run setup
iwr -useb "https://raw.githubusercontent.com/your-repo/rust-proxy/main/scripts/install-windows.ps1" | iex
```

### **Linux/macOS:**
```bash
# Download and run setup
curl -fsSL "https://raw.githubusercontent.com/your-repo/rust-proxy/main/scripts/install-linux.sh" | bash
```

## 2️⃣ Manual Setup

### **Step 1: Create Project Directory**
```bash
mkdir rust-proxy && cd rust-proxy
```

### **Step 2: Create All Required Files**

#### **📄 Cargo.toml**
```toml
[package]
name = "rust-proxy"
version = "2.0.0"
edition = "2021"
authors = ["Rust Proxy Team <contact@rustproxy.dev>"]
description = "Ultra High Performance Multi-Protocol Proxy Server"
license = "MIT"
repository = "https://github.com/your-repo/rust-proxy"
keywords = ["proxy", "socks5", "http", "performance", "async"]
categories = ["network-programming", "web-programming"]

[dependencies]
tokio = { version = "1.35", features = ["full"] }
tokio-util = { version = "0.7", features = ["io"] }
log = "0.4"
env_logger = "0.10"
rand = "0.8"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
toml = "0.8"
clap = { version = "4.4", features = ["derive", "env"] }
anyhow = "1.0"
thiserror = "1.0"
uuid = { version = "1.6", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }
bytes = "1.5"
futures = "0.3"
async-trait = "0.1"
parking_lot = "0.12"
dashmap = "5.5"
once_cell = "1.19"
crossbeam = "0.8"
num_cpus = "1.16"
rustls = { version = "0.21", optional = true }
webpki-roots = { version = "0.25", optional = true }

[features]
default = ["tls"]
tls = ["rustls", "webpki-roots"]
docker = []

[profile.release]
lto = "fat"
codegen-units = 1
panic = "abort"
strip = "symbols"
opt-level = 3
overflow-checks = false
debug = false

[profile.dev]
opt-level = 1
overflow-checks = true
debug = true

[[bin]]
name = "proxy-server"
path = "src/main.rs"

[build-dependencies]
cc = "1.0"
```

#### **📄 config.toml**
```toml
[server]
host = "0.0.0.0"
port = 28265
max_connections = 10000
connection_timeout = 30
buffer_size = 65536
worker_threads = 0  # 0 = auto detect CPU cores

[dns]
primary = "1.1.1.1:53"
secondary = "1.0.0.1:53"
fallback = ["8.8.8.8:53", "8.8.4.4:53", "208.67.222.222:53"]
timeout = 5

[proxy]
protocols = ["http", "https", "socks5", "socks4"]
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0"
]
rotate_user_agent = true
remove_proxy_headers = true
add_forwarded_headers = false

[logging]
enabled = true
level = "info"  # trace, debug, info, warn, error
file = "proxy.log"
max_size = "100MB"
max_files = 5
console = true

[performance]
tcp_nodelay = true
tcp_keepalive = true
so_reuseaddr = true
backlog = 1024
read_timeout = 30
write_timeout = 30

[security]
block_private_ips = false
allowed_ports = []  # empty = allow all
blocked_ports = [22, 23, 25, 135, 139, 445, 993, 995]
max_request_size = "10MB"
rate_limit = 1000  # requests per minute per IP

[stats]
enabled = true
interval = 60  # seconds
detailed = true
export_metrics = false
metrics_port = 9090
```

#### **📄 .gitignore**
```gitignore
# Rust
target/
Cargo.lock
*.pdb

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db
*.tmp
*.temp

# Logs
*.log
logs/

# Config overrides
config.local.toml
*.env
.env*

# Build artifacts
*.exe
*.dll
*.so
*.dylib
rust-proxy
proxy-server
```

#### **📄 build.rs**
```rust
use std::env;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    
    // Get Git commit hash
    if let Ok(output) = Command::new("git")
        .args(&["rev-parse", "--short", "HEAD"])
        .output() 
    {
        let git_hash = String::from_utf8(output.stdout).unwrap();
        println!("cargo:rustc-env=GIT_HASH={}", git_hash.trim());
    } else {
        println!("cargo:rustc-env=GIT_HASH=unknown");
    }

    // Build timestamp
    let build_time = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    println!("cargo:rustc-env=BUILD_TIME={}", build_time);
    
    // Target triple
    println!("cargo:rustc-env=TARGET={}", env::var("TARGET").unwrap());
    
    // Optimization settings
    if cfg!(not(debug_assertions)) {
        println!("cargo:rustc-link-arg=-s"); // Strip symbols on Unix
    }
}
```

#### **📄 Dockerfile**
```dockerfile
# Multi-stage build for minimal image
FROM rust:1.75-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache \
    build-base \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    git

# Copy source
COPY . .

# Build release binary
ENV RUSTFLAGS="-C target-feature=-crt-static"
RUN cargo build --release --target x86_64-unknown-linux-musl

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add \
    ca-certificates \
    tzdata \
    curl

# Create non-root user
RUN addgroup -g 1000 proxy && \
    adduser -D -s /bin/sh -u 1000 -G proxy proxy

# Copy binary
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/proxy-server /usr/local/bin/
COPY --from=builder /app/config.toml /etc/proxy/

# Set permissions
RUN chmod +x /usr/local/bin/proxy-server && \
    chown -R proxy:proxy /etc/proxy

USER proxy

EXPOSE 28265
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:28265/health || exit 1

CMD ["proxy-server", "--config", "/etc/proxy/config.toml"]
```

#### **📄 docker-compose.yml**
```yaml
version: '3.8'

services:
  rust-proxy:
    build: .
    container_name: rust-proxy-server
    restart: unless-stopped
    ports:
      - "28265:28265"
      - "9090:9090"  # Metrics port
    volumes:
      - ./config.toml:/etc/proxy/config.toml:ro
      - ./logs:/var/log/proxy
    environment:
      - RUST_LOG=info
      - RUST_BACKTRACE=1
    networks:
      - proxy-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:28265/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '2.0'
        reservations:
          memory: 128M
          cpus: '0.5'

networks:
  proxy-network:
    driver: bridge
```

---

# 🛠️ Build Scripts

## **Windows Build Script**

#### **📄 scripts/build-windows.bat**
```batch
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
```

## **Linux Build Script**

#### **📄 scripts/build-linux.sh**
```bash
#!/bin/bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================"
echo -e "🚀 Rust Proxy Server - Linux Builder"
echo -e "========================================${NC}"

# Detect OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$ID
    OS_VERSION=$VERSION_ID
else
    echo -e "${RED}❌ Cannot detect OS version${NC}"
    exit 1
fi

echo -e "${BLUE}📋 Detected OS: $OS $OS_VERSION${NC}"

# Install dependencies based on OS
install_dependencies() {
    echo -e "${YELLOW}📦 Installing build dependencies...${NC}"
    
    case $OS in
        ubuntu|debian)
            sudo apt update
            sudo apt install -y \
                curl \
                build-essential \
                gcc \
                g++ \
                libc6-dev \
                libssl-dev \
                pkg-config \
                cmake \
                git
            ;;
        centos|rhel|rocky|almalinux)
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y \
                openssl-devel \
                cmake \
                git
            ;;
        fedora)
            sudo dnf groupinstall -y "Development Tools"
            sudo dnf install -y \
                openssl-devel \
                cmake \
                git
            ;;
        arch|manjaro)
            sudo pacman -S --needed \
                base-devel \
                openssl \
                cmake \
                git
            ;;
        *)
            echo -e "${RED}❌ Unsupported OS: $OS${NC}"
            echo -e "${YELLOW}Please install build dependencies manually${NC}"
            ;;
    esac
}

# Install Rust if not present
install_rust() {
    if ! command -v cargo &> /dev/null; then
        echo -e "${YELLOW}📥 Installing Rust...${NC}"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile complete
        source ~/.cargo/env
        
        # Add to PATH permanently
        echo 'source ~/.cargo/env' >> ~/.bashrc
        echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
    else
        echo -e "${GREEN}✅ Rust already installed${NC}"
        rustc --version
    fi
}

# Build function
build_project() {
    echo -e "${BLUE}🔨 Building Rust Proxy Server...${NC}"
    
    # Set optimization flags
    export RUSTFLAGS="-C target-cpu=native -C opt-level=3 -C lto=fat"
    
    # Update Rust
    rustup update stable
    
    # Install additional targets
    rustup target add x86_64-unknown-linux-musl
    
    echo -e "${YELLOW}📦 Fetching dependencies...${NC}"
    cargo fetch
    
    echo -e "${YELLOW}🔨 Building release version...${NC}"
    cargo build --release --verbose
    
    # Also build musl version for portability
    echo -e "${YELLOW}🔨 Building static musl version...${NC}"
    if command -v musl-gcc &> /dev/null || [[ $OS == "alpine" ]]; then
        cargo build --release --target x86_64-unknown-linux-musl
    else
        echo -e "${YELLOW}⚠️  Musl not available, skipping static build${NC}"
    fi
}

# Create distribution
create_distribution() {
    echo -e "${BLUE}📦 Creating distribution...${NC}"
    
    mkdir -p dist
    
    # Copy main binary
    cp target/release/proxy-server dist/
    
    # Copy musl binary if exists
    if [[ -f target/x86_64-unknown-linux-musl/release/proxy-server ]]; then
        cp target/x86_64-unknown-linux-musl/release/proxy-server dist/proxy-server-static
    fi
    
    # Copy configs and docs
    cp config.toml dist/
    cp README.md dist/
    
    # Create start script
    cat > dist/start.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
echo "🚀 Starting Rust Proxy Server..."
./proxy-server --config config.toml
EOF
    chmod +x dist/start.sh
    
    # Strip binaries to reduce size
    strip dist/proxy-server 2>/dev/null || true
    if [[ -f dist/proxy-server-static ]]; then
        strip dist/proxy-server-static 2>/dev/null || true
    fi
    
    echo -e "${GREEN}✅ Distribution created in 'dist' folder${NC}"
    
    # Show binary info
    echo -e "${BLUE}📊 Binary Information:${NC}"
    ls -lh dist/proxy-server*
    file dist/proxy-server
    
    if command -v ldd &> /dev/null; then
        echo -e "${BLUE}🔗 Dependencies:${NC}"
        ldd dist/proxy-server || echo "Static binary (no dependencies)"
    fi
}

# Performance test
run_performance_test() {
    echo -e "${BLUE}🧪 Running performance test...${NC}"
    
    if command -v perf &> /dev/null; then
        echo "Performance analysis available with: perf record ./proxy-server"
    fi
    
    echo -e "${GREEN}🎯 To run the proxy server:${NC}"
    echo "   cd dist"
    echo "   ./start.sh"
    echo ""
    echo -e "${GREEN}📊 Monitor performance:${NC}"
    echo "   htop"
    echo "   netstat -tulpn | grep 28265"
    echo "   curl http://localhost:28265/health"
}

# Main execution
main() {
    echo -e "${BLUE}🏁 Starting build process...${NC}"
    
    install_dependencies
    install_rust
    
    # Source cargo environment
    source ~/.cargo/env 2>/dev/null || true
    
    build_project
    
    if [[ $? -eq 0 ]]; then
        create_distribution
        run_performance_test
        echo -e "${GREEN}🎉 Build completed successfully!${NC}"
    else
        echo -e "${RED}❌ Build failed!${NC}"
        exit 1
    fi
}

# Run main function
main "$@"
```

## **Installation Scripts**

#### **📄 scripts/install-windows.ps1**
```powershell
#Requires -RunAsAdministrator

param(
    [string]$InstallPath = "$env:ProgramFiles\RustProxy",
    [switch]$Service,
    [switch]$Desktop,
    [switch]$StartMenu
)

Write-Host "🚀 Rust Proxy Server - Windows Installer" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Error "PowerShell 5.0 or higher required"
    exit 1
}

# Create installation directory
Write-Host "📁 Creating installation directory: $InstallPath" -ForegroundColor Yellow
New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null

try {
    # Download or copy files
    if (Test-Path "dist\proxy-server.exe") {
        Write-Host "📦 Copying from local build..." -ForegroundColor Yellow
        Copy-Item "dist\*" -Destination $InstallPath -Recurse -Force
    } else {
        Write-Host "📥 Downloading latest release..." -ForegroundColor Yellow
        # Add download logic here if hosting binaries
        Write-Error "No local build found. Please run build-windows.bat first."
        exit 1
    }

    # Create Windows service if requested
    if ($Service) {
