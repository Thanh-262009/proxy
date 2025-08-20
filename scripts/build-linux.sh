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
