# 🚀 Enhanced Universal Secure Proxy Server v2.0

Một proxy server đa giao thức với tính năng bảo mật quân sự, chống phát hiện và hiệu suất cao.

## ✨ Tính Năng Chính

### 🛡️ Bảo Mật Quân Sự
- **Mã hóa đa lớp**: AES-256-GCM + ChaCha20 + Fernet
- **Bảo vệ DNS**: DNS over HTTPS (DoH) và DNS over TLS (DoT)
- **Chống rò rỉ DNS**: Sử dụng DNS server bảo mật
- **Mã hóa end-to-end**: Toàn bộ traffic được mã hóa

### 🥷 Chống Phát Hiện
- **Header spoofing**: Giả mạo header trình duyệt thực
- **Traffic obfuscation**: Làm mờ traffic để tránh DPI
- **IP rotation**: Xoay IP tự động theo thời gian
- **Packet fragmentation**: Phân mảnh gói tin để tránh phát hiện
- **Random timing**: Randomize thời gian gửi gói tin

### ⚡ Hiệu Suất Cao
- **Connection pooling**: Tái sử dụng kết nối để tăng tốc
- **Multi-threading**: Xử lý đồng thời hàng nghìn kết nối
- **Compression**: Nén dữ liệu tự động (gzip, brotli, lz4)
- **Buffer optimization**: Tối ưu hóa buffer size động
- **Rate limiting**: Kiểm soát tốc độ để tránh quá tải

### 🌐 Hỗ Trợ Đa Giao Thức
- **HTTP/HTTPS**: Proxy web thông thường
- **SOCKS4/SOCKS5**: Hỗ trợ đầy đủ SOCKS proxy
- **TCP/UDP**: Proxy cho mọi ứng dụng
- **SSH tunneling**: Tương thích SSH tunnel
- **Custom protocols**: Có thể mở rộng cho giao thức riêng

## 🚀 Cài Đặt Nhanh

### 1. Tải xuống các file
```bash
# Đảm bảo bạn có các file sau:
# - proxy.py (file proxy chính)
# - requirements.txt (dependencies)
# - proxy_config.yaml (cấu hình)  
# - start_proxy.sh (script khởi động)
```

### 2. Cài đặt dependencies
```bash
# Sử dụng script tự động
chmod +x start_proxy.sh
./start_proxy.sh install

# Hoặc cài đặt thủ công
pip3 install -r requirements.txt
```

### 3. Khởi động proxy
```bash
# Khởi động với cấu hình mặc định
./start_proxy.sh start

# Khởi động với cấu hình tùy chỉnh
./start_proxy.sh start --port 8080 --max-connections 500

# Khởi động với chế độ hiệu suất cao
./start_proxy.sh start --performance-mode
```

## 📋 Sử Dụng Chi Tiết

### Các Lệnh Cơ Bản

```bash
# Khởi động proxy server
./start_proxy.sh start

# Dừng proxy server  
./start_proxy.sh stop

# Khởi động lại proxy server
./start_proxy.sh restart

# Xem trạng thái server
./start_proxy.sh status

# Xem logs realtime
./start_proxy.sh logs

# Test hiệu suất
./start_proxy.sh test

# Dọn dẹp logs cũ
./start_proxy.sh cleanup
```

### Tùy Chọn Khởi Động

```bash
# Thay đổi port
./start_proxy.sh start --port 3128

# Tăng số kết nối tối đa
./start_proxy.sh start --max-connections 2000

# Tắt mã hóa (tăng tốc độ)
./start_proxy.sh start --no-encryption

# Tắt bảo vệ DNS
./start_proxy.sh start --no-dns-protection

# Tắt chống phát hiện
./start_proxy.sh start --no-anti-detection

# Chế độ hiệu suất cao
./start_proxy.sh start --performance-mode

# Bật debug mode
./start_proxy.sh start --debug
```

### Khởi Động Thủ Công

```bash
# Khởi động trực tiếp bằng Python
python3 proxy.py --port 28265 --max-connections 1000

# Chạy trong background
nohup python3 proxy.py &

# Với các tùy chọn bảo mật
python3 proxy.py --performance-mode --debug
```

## ⚙️ Cấu Hình

### File cấu hình `proxy_config.yaml`

```yaml
# Server settings
server:
  port: 28265
  max_connections: 2000
  
# Security settings  
security:
  encryption:
    enabled: true
    algorithm: "AES-256-GCM"
  dns_protection:
    enabled: true
    use_doh: true
    
# Anti-detection
anti_detection:
  enabled: true
  header_spoofing:
    enabled: true
  traffic_obfuscation:
    enabled: true
```

### Biến môi trường

```bash
# Đặt port qua biến môi trường
export PROXY_PORT=8080

# Tắt mã hóa
export PROXY_NO_ENCRYPTION=1

# Bật debug mode
export PROXY_DEBUG=1
```

## 🔧 Sử Dụng Với Ứng Dụng

### Cấu hình trình duyệt

**Chrome/Firefox:**
- HTTP Proxy: `127.0.0.1:28265`
- HTTPS Proxy: `127.0.0.1:28265`
- SOCKS5 Proxy: `127.0.0.1:28265`

### Sử dụng với curl

```bash
# HTTP proxy
curl --proxy http://127.0.0.1:28265 https://ipinfo.io

# SOCKS5 proxy
curl --socks5 127.0.0.1:28265 https://ipinfo.io
```

### Sử dụng với Python requests

```python
import requests

proxies = {
    'http': 'http://127.0.0.1:28265',
    'https': 'http://127.0.0.1:28265'
}

response = requests.get('https://ipinfo.io', proxies=proxies)
print(response.text)
```

### Sử dụng với các ứng dụng khác

```bash
# SSH tunnel
ssh -D 28265 user@server

# Telegram Desktop
# Settings -> Advanced -> Connection -> Use custom proxy
# Type: SOCKS5, Server: 127.0.0.1, Port: 28265

# qBittorrent
# Tools -> Options -> Connection -> Proxy Server
# Type: SOCKS5, Server: 127.0.0.1, Port: 28265
```

## 📊 Giám Sát và Thống Kê

### Xem thống kê realtime

```bash
# Xem trạng thái tổng quan
./start_proxy.sh status

# Xem logs realtime
./start_proxy.sh logs

# Test kết nối
./start_proxy.sh test
```

### Log files

```bash
# Main log
tail -f logs/enhanced_proxy_20241206.log

# Startup log  
tail -f logs/proxy_startup.log

# Statistics log
cat logs/stats.json
```

### Giám sát tài nguyên hệ thống

```bash
# Kiểm tra CPU và memory
top -p $(cat proxy.pid)

# Kiểm tra network connections
netstat -tulpn | grep 28265

# Kiểm tra open files
lsof -p $(cat proxy.pid)
```

## 🔒 Bảo Mật và Tối Ưu

### Tăng cường bảo mật

1. **Chạy với user không privileged:**
```bash
# Tạo user riêng cho proxy
sudo useradd -r -s /bin/false proxyuser
sudo chown -R proxyuser:proxyuser /path/to/proxy
sudo -u proxyuser ./start_proxy.sh start
```

2. **Sử dụng firewall:**
```bash
# Chỉ cho phép kết nối từ local
sudo ufw allow from 127.0.0.1 to any port 28265

# Hoặc từ subnet cụ thể
sudo ufw allow from 192.168.1.0/24 to any port 28265
```

3. **Cấu hình SSL/TLS:**
```yaml
# Trong proxy_config.yaml
security:
  ssl:
    enabled: true
    cert_file: "/path/to/cert.pem"
    key_file: "/path/to/key.pem"
```

### Tối ưu hiệu suất

1. **Tăng file descriptor limits:**
```bash
# Tạm thời
ulimit -n 65536

# Vĩnh viễn trong /etc/security/limits.conf
* soft nofile 65536
* hard nofile 65536
```

2. **Tối ưu kernel parameters:**
```bash
# Trong /etc/sysctl.conf
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 30
```

3. **Sử dụng SSD và RAM:**
```bash
# Mount /tmp trên RAM (cho logs tạm)
sudo mount -t tmpfs -o size=1G tmpfs /tmp

# Sử dụng SSD cho logs
mkdir /ssd/proxy_logs
ln -s /ssd/proxy_
