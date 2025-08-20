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
