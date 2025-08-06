#!/bin/bash

# Enhanced Universal Secure Proxy Server v2.0
# Startup và Management Script

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
PROXY_SCRIPT="proxy.py"
CONFIG_FILE="proxy_config.yaml"
REQUIREMENTS_FILE="requirements.txt"
LOG_DIR="logs"
PID_FILE="proxy.pid"

# Banner
print_banner() {
    echo -e "${PURPLE}"
    echo "================================================================================"
    echo "🚀 ENHANCED UNIVERSAL SECURE PROXY SERVER v2.0"
    echo "🛡️  Military-Grade Security | Anti-Detection | High Performance" 
    echo "================================================================================"
    echo -e "${NC}"
}

# Check if script is running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        echo -e "${YELLOW}⚠️  Warning: Running as root. Consider using a non-root user for security.${NC}"
        read -p "Continue anyway? [y/N]: " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Check system requirements
check_requirements() {
    echo -e "${BLUE}🔍 Checking system requirements...${NC}"
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}❌ Python 3 is required but not installed.${NC}"
        exit 1
    fi
    
    python_version=$(python3 --version | cut -d' ' -f2)
    echo -e "${GREEN}✅ Python ${python_version} found${NC}"
    
    # Check pip
    if ! command -v pip3 &> /dev/null; then
        echo -e "${RED}❌ pip3 is required but not installed.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ pip3 found${NC}"
    
    # Check required files
    if [[ ! -f "$PROXY_SCRIPT" ]]; then
        echo -e "${RED}❌ $PROXY_SCRIPT not found${NC}"
        exit 1
    fi
    
    if [[ ! -f "$REQUIREMENTS_FILE" ]]; then
        echo -e "${RED}❌ $REQUIREMENTS_FILE not found${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Required files found${NC}"
}

# Install dependencies
install_dependencies() {
    echo -e "${BLUE}📦 Installing dependencies...${NC}"
    
    # Upgrade pip first
    python3 -m pip install --upgrade pip
    
    # Install requirements
    if python3 -m pip install -r "$REQUIREMENTS_FILE"; then
        echo -e "${GREEN}✅ Dependencies installed successfully${NC}"
    else
        echo -e "${RED}❌ Failed to install dependencies${NC}"
        exit 1
    fi
}

# Setup directories
setup_directories() {
    echo -e "${BLUE}📁 Setting up directories...${NC}"
    
    mkdir -p "$LOG_DIR"
    mkdir -p "backups"
    
    echo -e "${GREEN}✅ Directories created${NC}"
}

# Check if proxy is running
check_running() {
    if [[ -f "$PID_FILE" ]]; then
        PID=$(cat "$PID_FILE")
        if ps -p "$PID" > /dev/null 2>&1; then
            return 0
        else
            rm -f "$PID_FILE"
            return 1
        fi
    fi
    return 1
}

# Start proxy server
start_proxy() {
    echo -e "${BLUE}🚀 Starting Enhanced Proxy Server...${NC}"
    
    if check_running; then
        echo -e "${YELLOW}⚠️  Proxy server is already running (PID: $(cat $PID_FILE))${NC}"
        return 1
    fi
    
    # Parse arguments
    ARGS=""
    PORT=28265
    MAX_CONN=1000
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --port)
                PORT="$2"
                ARGS="$ARGS --port $2"
                shift 2
                ;;
            --max-connections)
                MAX_CONN="$2"
                ARGS="$ARGS --max-connections $2"
                shift 2
                ;;
            --no-encryption)
                ARGS="$ARGS --no-encryption"
                shift
                ;;
            --no-dns-protection)
                ARGS="$ARGS --no-dns-protection"
                shift
                ;;
            --no-anti-detection)
                ARGS="$ARGS --no-anti-detection"
                shift
                ;;
            --performance-mode)
                ARGS="$ARGS --performance-mode"
                shift
                ;;
            --debug)
                ARGS="$ARGS --debug"
                shift
                ;;
            *)
                echo -e "${RED}Unknown argument: $1${NC}"
                exit 1
                ;;
        esac
    done
    
    # Start the proxy server in background
    nohup python3 "$PROXY_SCRIPT" $ARGS > "$LOG_DIR/proxy_startup.log" 2>&1 &
    
    # Save PID
    echo $! > "$PID_FILE"
    
    # Wait a moment and check if it started successfully
    sleep 2
    
    if check_running; then
        echo -e "${GREEN}✅ Proxy server started successfully${NC}"
        echo -e "${CYAN}📡 Server running on port: $PORT${NC}"
        echo -e "${CYAN}🔗 Max connections: $MAX_CONN${NC}"
        echo -e "${CYAN}📋 PID: $(cat $PID_FILE)${NC}"
        echo -e "${CYAN}📝 Logs: $LOG_DIR/proxy_startup.log${NC}"
        return 0
    else
        echo -e "${RED}❌ Failed to start proxy server${NC}"
        echo -e "${YELLOW}Check logs: $LOG_DIR/proxy_startup.log${NC}"
        return 1
    fi
}

# Stop proxy server
stop_proxy() {
    echo -e "${BLUE}🛑 Stopping proxy server...${NC}"
    
    if ! check_running; then
        echo -e "${YELLOW}⚠️  Proxy server is not running${NC}"
        return 1
    fi
    
    PID=$(cat "$PID_FILE")
    
    # Send SIGTERM first
    kill -TERM "$PID" 2>/dev/null
    
    # Wait for graceful shutdown
    for i in {1..10}; do
        if ! ps -p "$PID" > /dev/null 2>&1; then
            rm -f "$PID_FILE"
            echo -e "${GREEN}✅ Proxy server stopped gracefully${NC}"
            return 0
        fi
        sleep 1
    done
    
    # Force kill if still running
    echo -e "${YELLOW}⚠️  Forcing shutdown...${NC}"
    kill -KILL "$PID" 2>/dev/null
    rm -f "$PID_FILE"
    echo -e "${GREEN}✅ Proxy server stopped${NC}"
}

# Restart proxy server
restart_proxy() {
    echo -e "${BLUE}🔄 Restarting proxy server...${NC}"
    stop_proxy
    sleep 2
    start_proxy "$@"
}

# Show proxy status
show_status() {
    echo -e "${BLUE}📊 Proxy Server Status${NC}"
    echo "=================================="
    
    if check_running; then
        PID=$(cat "$PID_FILE")
        echo -e "${GREEN}Status: RUNNING${NC}"
        echo -e "PID: $PID"
        
        # Show process info
        if command -v ps &> /dev/null; then
            echo -e "Process Info:"
            ps -p "$PID" -o pid,ppid,cmd,etime,pcpu,pmem 2>/dev/null || echo "Process info unavailable"
        fi
        
        # Show network connections
        if command -v netstat &> /dev/null; then
            echo -e "\nNetwork Connections:"
            netstat -tulpn 2>/dev/null | grep "$PID" | head -5
        elif command -v ss &> /dev/null; then
            echo -e "\nNetwork Connections:"
            ss -tulpn 2>/dev/null | grep "$PID" | head -5
        fi
        
    else
        echo -e "${RED}Status: STOPPED${NC}"
    fi
    
    # Show recent logs
    if [[ -f "$LOG_DIR/proxy_startup.log" ]]; then
        echo -e "\nRecent Logs:"
        echo "============"
        tail -10 "$LOG_DIR/proxy_startup.log" 2>/dev/null || echo "No logs available"
    fi
}

# Show logs
show_logs() {
    if [[ -f "$LOG_DIR/proxy_startup.log" ]]; then
        echo -e "${BLUE}📝 Showing proxy logs (Press Ctrl+C to exit)${NC}"
        tail -f "$LOG_DIR/proxy_startup.log"
    else
        echo -e "${RED}❌ Log file not found${NC}"
    fi
}

# Performance test
performance_test() {
    echo -e "${BLUE}⚡ Running performance test...${NC}"
    
    if ! check_running; then
        echo -e "${RED}❌ Proxy server is not running${NC}"
        return 1
    fi
    
    # Simple connection test
    PORT=$(grep -o 'port: [0-9]*' "$CONFIG_FILE" 2>/dev/null | cut -d' ' -f2 || echo "28265")
    
    echo "Testing connection to localhost:$PORT..."
    
    if command -v nc &> /dev/null; then
        echo "test" | nc -w 5 localhost "$PORT" && echo -e "${GREEN}✅ Connection test passed${NC}" || echo -e "${RED}❌ Connection test failed${NC}"
    elif command -v telnet &> /dev/null; then
        (echo "test"; sleep 1) | telnet localhost "$PORT" 2>/dev/null && echo -e "${GREEN}✅ Connection test passed${NC}" || echo -e "${RED}❌ Connection test failed${NC}"
    else
        echo -e "${YELLOW}⚠️  nc or telnet not available for testing${NC}"
    fi
}

# Cleanup function
cleanup() {
    echo -e "\n${BLUE}🧹 Cleaning up...${NC}"
    
    # Remove old logs (keep last 5)
    if [[ -d "$LOG_DIR" ]]; then
        find "$LOG_DIR" -name "*.log" -type f -mtime +7 -delete 2>/dev/null || true
    fi
    
    # Remove old backups (keep last 10)
    if [[ -d "backups" ]]; then
        find "backups" -name "*.tar.gz" -type f -mtime +30 -delete 2>/dev/null || true
    fi
    
    echo -e "${GREEN}✅ Cleanup completed${NC}"
}

# Show help
show_help() {
    echo -e "${CYAN}Enhanced Universal Secure Proxy Server v2.0${NC}"
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  start [OPTIONS]     Start the proxy server"
    echo "  stop                Stop the proxy server"
    echo "  restart [OPTIONS]   Restart the proxy server"
    echo "  status              Show server status"
    echo "  logs                Show server logs"
    echo "  test                Run performance test"
    echo "  install             Install dependencies"
    echo "  cleanup             Clean old logs and backups"
    echo "  help                Show this help"
    echo ""
    echo "Start Options:"
    echo "  --port PORT                Set server port (default: 28265)"
    echo "  --max-connections NUM      Set max connections (default: 1000)"
    echo "  --no-encryption           Disable encryption"
    echo "  --no-dns-protection       Disable DNS protection"
    echo "  --no-anti-detection       Disable anti-detection"
    echo "  --performance-mode        Enable performance mode"
    echo "  --debug                   Enable debug logging"
    echo ""
    echo "Examples:"
    echo "  $0 start --port 8080 --max-connections 500"
    echo "  $0 start --performance-mode --debug"
    echo "  $0 restart --no-encryption"
}

# Main function
main() {
    print_banner
    
    case "${1:-help}" in
        start)
            check_root
            check_requirements
            setup_directories
            shift
            start_proxy "$@"
            ;;
        stop)
            stop_proxy
            ;;
        restart)
            check_root
            check_requirements
            setup_directories
            shift
            restart_proxy "$@"
            ;;
        status)
            show_status
            ;;
        logs)
            show_logs
            ;;
        test)
            performance_test
            ;;
        install)
            check_requirements
            install_dependencies
            setup_directories
            ;;
        cleanup)
            cleanup
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            echo -e "${RED}❌ Unknown command: $1${NC}"
            echo -e "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"