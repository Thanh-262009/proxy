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
iwr -useb "https://raw.githubusercontent.com/Thanh-262009/proxy/main/scripts/install-windows.ps1" | iex
```

### **Linux/macOS:**
```bash
# Download and run setup
curl -fsSL "https://raw.githubusercontent.com/Thanh-262009/proxy/main/scripts/install-linux.sh" | bash
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
repository = "https://github.com/Thanh-262009/proxy"
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

# 📋 Additional Configuration Files

## **Linux Systemd Service**

#### **📄 configs/rust-proxy.service**
```ini
[Unit]
Description=Rust High Performance Proxy Server
Documentation=https://github.com/Thanh-262009/proxy
After=network-online.target
Wants=network-online.target
AssertFileIsExecutable=/opt/rust-proxy/proxy-server

[Service]
Type=simple
User=proxyuser
Group=proxyuser
WorkingDirectory=/opt/rust-proxy
ExecStart=/opt/rust-proxy/proxy-server --config /opt/rust-proxy/config.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
RestartPreventExitStatus=23

# Output to journal
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rust-proxy

# Security measures
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/rust-proxy
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true
RemoveIPC=true
PrivateDevices=true

# Capabilities
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Resource limits
LimitNOFILE=1048576
LimitNPROC=1048576
LimitMEMLOCK=64M

[Install]
WantedBy=multi-user.target
```

## **Windows Service Configuration**

#### **📄 configs/windows-service.xml**
```xml
<service>
    <id>RustProxyService</id>
    <name>Rust Proxy Server</name>
    <description>High Performance Multi-Protocol Proxy Server</description>
    <executable>%BASE%\proxy-server.exe</executable>
    <arguments>--config "%BASE%\config.toml"</arguments>
    <workingdirectory>%BASE%</workingdirectory>
    <logmode>rotate</logmode>
    <depend>Tcpip</depend>
    <startmode>Automatic</startmode>
    <delayedAutoStart>false</delayedAutoStart>
    <stopparentprocessfirst>true</stopparentprocessfirst>
    <stoptimeout>15 sec</stoptimeout>
    <waithint>15 sec</waithint>
    <sleeptime>1 sec</sleeptime>
    <interactive>false</interactive>
    
    <onfailure action="restart" delay="5 sec"/>
    <onfailure action="restart" delay="10 sec"/>
    <onfailure action="none"/>
    <resetfailure>1 hour</resetfailure>
</service>
```

## **Nginx Reverse Proxy**

#### **📄 configs/nginx-proxy.conf**
```nginx
upstream rust_proxy {
    server 127.0.0.1:28265 max_fails=3 fail_timeout=30s;
    keepalive 32;
}

server {
    listen 80;
    listen [::]:80;
    server_name proxy.yourdomain.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name proxy.yourdomain.com;

    # SSL Configuration
    ssl_certificate /etc/ssl/certs/proxy.crt;
    ssl_certificate_key /etc/ssl/private/proxy.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    
    # Proxy Configuration
    location / {
        proxy_pass http://rust_proxy;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 30s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
        
        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
        proxy_busy_buffers_size 8k;
        proxy_max_temp_file_size 1024m;
        proxy_temp_file_write_size 8k;
    }
    
    # Health check endpoint
    location /health {
        proxy_pass http://rust_proxy/health;
        access_log off;
    }
    
    # Metrics endpoint (restrict access)
    location /metrics {
        allow 127.0.0.1;
        allow ::1;
        deny all;
        proxy_pass http://rust_proxy/metrics;
    }
}
```

## **Docker Production Compose**

#### **📄 docker-compose.prod.yml**
```yaml
version: '3.8'

services:
  rust-proxy:
    image: rust-proxy:latest
    build:
      context: .
      dockerfile: Dockerfile
      args:
        - BUILD_TYPE=release
    container_name: rust-proxy-prod
    restart: unless-stopped
    
    ports:
      - "28265:28265"
    
    volumes:
      - ./config.prod.toml:/etc/proxy/config.toml:ro
      - ./logs:/var/log/proxy:rw
      - ./ssl:/etc/ssl/proxy:ro
    
    environment:
      - RUST_LOG=info
      - RUST_BACKTRACE=0
      - PROXY_ENV=production
    
    networks:
      - proxy-network
      - monitoring
    
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:28265/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '4.0'
        reservations:
          memory: 256M
          cpus: '1.0'
      replicas: 1
      update_config:
        parallelism: 1
        delay: 10s
        failure_action: rollback
        order: stop-first
      rollback_config:
        parallelism: 1
        delay: 0s
        failure_action: pause
        order: stop-first
    
    labels:
      - "com.datadoghq.ad.check_names=[\"rust_proxy\"]"
      - "com.datadoghq.ad.init_configs=[{}]"
      - "com.datadoghq.ad.instances=[{\"host\":\"%%host%%\",\"port\":28265}]"
    
    security_opt:
      - no-new-privileges:true
    
    read_only: true
    tmpfs:
      - /tmp:size=100M,noexec,nosuid,nodev
      - /var/run:size=10M,noexec,nosuid,nodev
    
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 1048576
        hard: 1048576
      nproc:
        soft: 1048576
        hard: 1048576

  # Monitoring with Prometheus
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--web.enable-lifecycle'
    networks:
      - monitoring
    restart: unless-stopped

  # Visualization with Grafana
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/grafana/dashboards:/etc/grafana/provisioning/dashboards:ro
      - ./monitoring/grafana/datasources:/etc/grafana/provisioning/datasources:ro
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin123
      - GF_USERS_ALLOW_SIGN_UP=false
    networks:
      - monitoring
    restart: unless-stopped
    depends_on:
      - prometheus

networks:
  proxy-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
  monitoring:
    driver: bridge

volumes:
  prometheus_data:
  grafana_data:
```

## **Production Configuration**

#### **📄 config.prod.toml**
```toml
[server]
host = "0.0.0.0"
port = 28265
max_connections = 50000
connection_timeout = 60
buffer_size = 131072  # 128KB for production
worker_threads = 0    # Auto-detect

[dns]
primary = "1.1.1.1:53"
secondary = "1.0.0.1:53"
fallback = ["8.8.8.8:53", "8.8.4.4:53", "208.67.222.222:53", "9.9.9.9:53"]
timeout = 3

[proxy]
protocols = ["http", "https", "socks5", "socks4"]
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0"
]
rotate_user_agent = true
remove_proxy_headers = true
add_forwarded_headers = false
connection_pool_size = 1000
keep_alive_timeout = 300

[logging]
enabled = true
level = "info"
file = "/var/log/proxy/proxy.log"
max_size = "500MB"
max_files = 10
console = false
json_format = true
include_timestamp = true
include_level = true
include_target = true

[performance]
tcp_nodelay = true
tcp_keepalive = true
so_reuseaddr = true
so_reuseport = true
backlog = 4096
read_timeout = 60
write_timeout = 60
connect_timeout = 30
idle_timeout = 300
max_concurrent_streams = 1000

[security]
block_private_ips = false
allowed_ports = []
blocked_ports = [22, 23, 25, 135, 139, 445, 993, 995, 1433, 3389]
max_request_size = "100MB"
rate_limit = 10000
rate_limit_window = 60
enable_ip_whitelist = false
ip_whitelist = []
enable_ip_blacklist = true
ip_blacklist = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]

[stats]
enabled = true
interval = 30
detailed = true
export_metrics = true
metrics_port = 9090
metrics_path = "/metrics"
health_check_port = 28265
health_check_path = "/health"

[ssl]
enabled = false
cert_file = "/etc/ssl/proxy/proxy.crt"
key_file = "/etc/ssl/proxy/proxy.key"
protocols = ["TLSv1.2", "TLSv1.3"]

[cache]
enabled = true
max_size = "1GB"
ttl = 3600
cleanup_interval = 300
```

---

# 🚀 Quick Setup Commands

## **One-Line Install Scripts**

### **Windows (PowerShell as Admin):**
```powershell
iwr -useb "raw.githubusercontent.com/Thanh-262009/proxy/main/install.ps1" | iex
```

### **Linux/macOS:**
```bash
curl -fsSL "raw.githubusercontent.com/Thanh-262009/proxy/main/install.sh" | bash
```

## **Build and Install Commands**

### **Development Setup:**
```bash
# Clone and build
git clone https://github.com/Thanh-262009/proxy.git
cd rust-proxy
chmod +x scripts/build-linux.sh
./scripts/build-linux.sh

# Quick test
./dist/proxy-server --config config.toml --port 28265
```

### **Production Install:**
```bash
# Build for production
./scripts/build-linux.sh
sudo ./scripts/install-linux.sh --path /opt/rust-proxy --service --user --autostart

# Verify installation
sudo systemctl status rust-proxy
curl http://localhost:28265/health
```

### **Docker Deployment:**
```bash
# Build and run
docker-compose -f docker-compose.prod.yml up -d

# Scale up
docker-compose -f docker-compose.prod.yml up -d --scale rust-proxy=3

# Monitor
docker-compose logs -f rust-proxy
```

---

# 🎯 Testing & Verification

## **Proxy Testing:**
```bash
# HTTP proxy test
curl -x http://localhost:28265 http://httpbin.org/ip

# SOCKS5 proxy test
curl --socks5 localhost:28265 http://httpbin.org/ip

# Performance test
ab -n 10000 -c 100 -X localhost:28265 http://httpbin.org/get

# Load test with multiple protocols
./scripts/load-test.sh
```

## **Health Monitoring:**
```bash
# Health check
curl http://localhost:28265/health

# Metrics
curl http://localhost:9090/metrics

# Real-time monitoring
watch -n 1 'curl -s http://localhost:28265/health | jq .'
```

---

# 📊 Performance Benchmarks

**Expected Performance (on modern hardware):**
- **Concurrent Connections:** 50,000+
- **Requests per Second:** 100,000+
- **Latency:** <2ms (local), <50ms (internet)
- **Memory Usage:** <100MB (base), +1KB per connection
- **CPU Usage:** <5% (idle), scaling with load
- **Bandwidth:** Limited only by network interface

**Optimized for:**
- ✅ Gaming (ultra-low latency)
- ✅ 4K Video streaming  
- ✅ Large file downloads
- ✅ High-frequency trading
- ✅ Web scraping at scale
- ✅ Anonymous browsing

Proxy server này được tối ưu để đạt hiệu suất tối đa với độ trễ cực thấp! 🚀

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
        Write-Host "🔧 Installing Windows Service..." -ForegroundColor Yellow
        
        $serviceName = "RustProxy"
        $serviceDisplayName = "Rust Proxy Server"
        $servicePath = "`"$InstallPath\proxy-server.exe`" --config `"$InstallPath\config.toml`""
        
        # Remove existing service
        $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($existingService) {
            Stop-Service -Name $serviceName -Force
            sc.exe delete $serviceName
            Start-Sleep -Seconds 2
        }
        
        # Create new service
        New-Service -Name $serviceName -DisplayName $serviceDisplayName -BinaryPathName $servicePath -StartupType Automatic
        
        Write-Host "✅ Service installed. Use these commands:" -ForegroundColor Green
        Write-Host "   Start: Start-Service -Name $serviceName" -ForegroundColor Cyan
        Write-Host "   Stop:  Stop-Service -Name $serviceName" -ForegroundColor Cyan
        Write-Host "   Status: Get-Service -Name $serviceName" -ForegroundColor Cyan
    }

    # Create desktop shortcut
    if ($Desktop) {
        Write-Host "🖥️  Creating desktop shortcut..." -ForegroundColor Yellow
        
        $WshShell = New-Object -comObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut("$([Environment]::GetFolderPath('Desktop'))\Rust Proxy Server.lnk")
        $Shortcut.TargetPath = "$InstallPath\proxy-server.exe"
        $Shortcut.WorkingDirectory = $InstallPath
        $Shortcut.IconLocation = "$InstallPath\proxy-server.exe,0"
        $Shortcut.Description = "High Performance Rust Proxy Server"
        $Shortcut.Save()
    }

    # Create start menu shortcut
    if ($StartMenu) {
        Write-Host "📋 Creating start menu shortcut..." -ForegroundColor Yellow
        
        $startMenuPath = "$([Environment]::GetFolderPath('CommonPrograms'))\Rust Proxy Server"
        New-Item -ItemType Directory -Path $startMenuPath -Force | Out-Null
        
        $WshShell = New-Object -comObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut("$startMenuPath\Rust Proxy Server.lnk")
        $Shortcut.TargetPath = "$InstallPath\proxy-server.exe"
        $Shortcut.WorkingDirectory = $InstallPath
        $Shortcut.IconLocation = "$InstallPath\proxy-server.exe,0"
        $Shortcut.Save()
        
        # Create uninstaller shortcut
        $Shortcut = $WshShell.CreateShortcut("$startMenuPath\Uninstall.lnk")
        $Shortcut.TargetPath = "powershell.exe"
        $Shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$InstallPath\uninstall.ps1`""
        $Shortcut.WorkingDirectory = $InstallPath
        $Shortcut.Save()
    }

    # Create uninstaller
    $uninstaller = @"
#Requires -RunAsAdministrator
Write-Host "🗑️ Uninstalling Rust Proxy Server..." -ForegroundColor Yellow

# Stop and remove service
try { Stop-Service -Name "RustProxy" -Force -ErrorAction SilentlyContinue } catch {}
try { sc.exe delete "RustProxy" } catch {}

# Remove shortcuts
Remove-Item "$([Environment]::GetFolderPath('Desktop'))\Rust Proxy Server.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item "$([Environment]::GetFolderPath('CommonPrograms'))\Rust Proxy Server" -Recurse -Force -ErrorAction SilentlyContinue

# Remove installation directory
Remove-Item "$InstallPath" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "✅ Uninstall complete!" -ForegroundColor Green
pause
"@
    
    Set-Content -Path "$InstallPath\uninstall.ps1" -Value $uninstaller

    # Add to PATH
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($currentPath -notlike "*$InstallPath*") {
        Write-Host "🔧 Adding to system PATH..." -ForegroundColor Yellow
        [Environment]::SetEnvironmentVariable("Path", "$currentPath;$InstallPath", "Machine")
    }

    # Create firewall rule
    Write-Host "🔥 Configuring Windows Firewall..." -ForegroundColor Yellow
    try {
        New-NetFirewallRule -DisplayName "Rust Proxy Server" -Direction Inbound -Protocol TCP -LocalPort 28265 -Action Allow -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Could not create firewall rule. You may need to allow port 28265 manually."
    }

    Write-Host "✅ Installation completed successfully!" -ForegroundColor Green
    Write-Host "📍 Installation path: $InstallPath" -ForegroundColor Cyan
    Write-Host "🌐 Proxy will run on: http://0.0.0.0:28265" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "🎯 To start the proxy server:" -ForegroundColor Yellow
    Write-Host "   cd `"$InstallPath`"" -ForegroundColor Cyan
    Write-Host "   .\proxy-server.exe" -ForegroundColor Cyan
    
    if ($Service) {
        Write-Host "   OR: Start-Service -Name RustProxy" -ForegroundColor Cyan
    }

} catch {
    Write-Error "Installation failed: $_"
    exit 1
}

pause
```

#### **📄 scripts/install-linux.sh**
```bash
#!/bin/bash
set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default values
INSTALL_PATH="/opt/rust-proxy"
INSTALL_SERVICE=false
CREATE_USER=false
AUTOSTART=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --path)
            INSTALL_PATH="$2"
            shift 2
            ;;
        --service)
            INSTALL_SERVICE=true
            shift
            ;;
        --user)
            CREATE_USER=true
            shift
            ;;
        --autostart)
            AUTOSTART=true
            INSTALL_SERVICE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --path PATH     Installation path (default: /opt/rust-proxy)"
            echo "  --service       Install as systemd service"
            echo "  --user          Create dedicated user"
            echo "  --autostart     Enable autostart (implies --service)"
            echo "  --help          Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}🚀 Rust Proxy Server - Linux Installer${NC}"
echo -e "${BLUE}=====================================${NC}"

# Check if running as root for system-wide installation
if [[ $EUID -ne 0 ]] && [[ "$INSTALL_PATH" == "/opt/"* || "$INSTALL_PATH" == "/usr/"* ]]; then
    echo -e "${RED}❌ Root privileges required for system-wide installation${NC}"
    echo -e "${YELLOW}💡 Run with sudo or choose user installation path${NC}"
    exit 1
fi

# Create installation directory
echo -e "${YELLOW}📁 Creating installation directory: $INSTALL_PATH${NC}"
sudo mkdir -p "$INSTALL_PATH"

# Check for local build
if [[ -f "dist/proxy-server" ]]; then
    echo -e "${YELLOW}📦 Installing from local build...${NC}"
    sudo cp -r dist/* "$INSTALL_PATH/"
elif [[ -f "target/release/proxy-server" ]]; then
    echo -e "${YELLOW}📦 Installing from target directory...${NC}"
    sudo cp target/release/proxy-server "$INSTALL_PATH/"
    sudo cp config.toml "$INSTALL_PATH/"
    sudo cp README.md "$INSTALL_PATH/"
else
    echo -e "${RED}❌ No build found. Please run build-linux.sh first${NC}"
    exit 1
fi

# Make binary executable
sudo chmod +x "$INSTALL_PATH/proxy-server"

# Create dedicated user if requested
if [[ "$CREATE_USER" == true ]]; then
    echo -e "${YELLOW}👤 Creating dedicated user 'proxyuser'...${NC}"
    if ! id "proxyuser" &>/dev/null; then
        sudo useradd --system --home-dir "$INSTALL_PATH" --shell /bin/false --comment "Rust Proxy Service" proxyuser
    fi
    sudo chown -R proxyuser:proxyuser "$INSTALL_PATH"
fi

# Install systemd service
if [[ "$INSTALL_SERVICE" == true ]]; then
    echo -e "${YELLOW}🔧 Installing systemd service...${NC}"
    
    SERVICE_USER="root"
    if [[ "$CREATE_USER" == true ]]; then
        SERVICE_USER="proxyuser"
    fi
    
    sudo tee /etc/systemd/system/rust-proxy.service > /dev/null <<EOF
[Unit]
Description=Rust High Performance Proxy Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_PATH
ExecStart=$INSTALL_PATH/proxy-server --config $INSTALL_PATH/config.toml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$INSTALL_PATH
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Performance settings
LimitNOFILE=1048576
LimitNPROC=1048576

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    
    if [[ "$AUTOSTART" == true ]]; then
        echo -e "${YELLOW}⚡ Enabling autostart...${NC}"
        sudo systemctl enable rust-proxy
        sudo systemctl start rust-proxy
        
        echo -e "${GREEN}✅ Service started and enabled!${NC}"
        echo -e "${BLUE}📊 Service status:${NC}"
        sudo systemctl status rust-proxy --no-pager -l
    else
        echo -e "${GREEN}✅ Service installed!${NC}"
        echo -e "${BLUE}🎯 Control commands:${NC}"
        echo -e "${CYAN}   Start:   sudo systemctl start rust-proxy${NC}"
        echo -e "${CYAN}   Stop:    sudo systemctl stop rust-proxy${NC}"
        echo -e "${CYAN}   Status:  sudo systemctl status rust-proxy${NC}"
        echo -e "${CYAN}   Logs:    sudo journalctl -u rust-proxy -f${NC}"
        echo -e "${CYAN}   Enable:  sudo systemctl enable rust-proxy${NC}"
    fi
fi

# Create command line wrapper
echo -e "${YELLOW}🔗 Creating command line wrapper...${NC}"
sudo tee /usr/local/bin/rust-proxy > /dev/null <<EOF
#!/bin/bash
cd "$INSTALL_PATH"
exec "$INSTALL_PATH/proxy-server" "\$@"
EOF
sudo chmod +x /usr/local/bin/rust-proxy

# Configure firewall if available
if command -v ufw &> /dev/null; then
    echo -e "${YELLOW}🔥 Configuring UFW firewall...${NC}"
    sudo ufw allow 28265/tcp comment "Rust Proxy Server"
elif command -v firewall-cmd &> /dev/null; then
    echo -e "${YELLOW}🔥 Configuring firewalld...${NC}"
    sudo firewall-cmd --permanent --add-port=28265/tcp
    sudo firewall-cmd --reload
fi

# Create uninstaller
echo -e "${YELLOW}🗑️ Creating uninstaller...${NC}"
sudo tee "$INSTALL_PATH/uninstall.sh" > /dev/null <<EOF
#!/bin/bash
set -euo pipefail

echo "🗑️ Uninstalling Rust Proxy Server..."

# Stop and disable service
if systemctl is-active --quiet rust-proxy; then
    sudo systemctl stop rust-proxy
fi
if systemctl is-enabled --quiet rust-proxy; then
    sudo systemctl disable rust-proxy
fi
sudo rm -f /etc/systemd/system/rust-proxy.service
sudo systemctl daemon-reload

# Remove firewall rules
if command -v ufw &> /dev/null; then
    sudo ufw delete allow 28265/tcp || true
elif command -v firewall-cmd &> /dev/null; then
    sudo firewall-cmd --permanent --remove-port=28265/tcp || true
    sudo firewall-cmd --reload || true
fi

# Remove user
if id "proxyuser" &>/dev/null; then
    sudo userdel proxyuser || true
fi

# Remove files
sudo rm -f /usr/local/bin/rust-proxy
sudo rm -rf "$INSTALL_PATH"

echo "✅ Uninstall complete!"
EOF
sudo chmod +x "$INSTALL_PATH/uninstall.sh"

# Set final permissions
if [[ "$CREATE_USER" == true ]]; then
    sudo chown -R proxyuser:proxyuser "$INSTALL_PATH"
else
    sudo chown -R root:root "$INSTALL_PATH"
    sudo chmod 644 "$INSTALL_PATH/config.toml"
fi

echo -e "${GREEN}✅ Installation completed successfully!${NC}"
echo -e "${BLUE}📍 Installation path: $INSTALL_PATH${NC}"
echo -e "${BLUE}🌐 Proxy will run on: http://0.0.0.0:28265${NC}"
echo -e "${BLUE}📋 Configuration file: $INSTALL_PATH/config.toml${NC}"
echo ""
echo -e "${YELLOW}🎯 To start the proxy server:${NC}"
if [[ "$INSTALL_SERVICE" == true ]]; then
    echo -e "${CYAN}   sudo systemctl start rust-proxy${NC}"
else
    echo -e "${CYAN}   cd $INSTALL_PATH${NC}"
    echo -e "${CYAN}   ./proxy-server${NC}"
    echo -e "${CYAN}   # OR from anywhere: rust-proxy${NC}"
fi
echo ""
echo -e "${YELLOW}🔍 Monitor proxy:${NC}"
echo -e "${CYAN}   curl http://localhost:28265/health${NC}"
echo -e "${CYAN}   netstat -tulpn | grep 28265${NC}"
if [[ "$INSTALL_SERVICE" == true ]]; then
    echo -e "${CYAN}   sudo journalctl -u rust-proxy -f${NC}"
fi
echo ""
echo -e "${YELLOW}🗑️ To uninstall:${NC}"
echo -e "${CYAN}   $INSTALL_PATH/uninstall.sh${NC}"
