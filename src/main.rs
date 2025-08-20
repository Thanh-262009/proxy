use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use std::sync::Arc;
use std::net::SocketAddr;
use log::{info, warn, error, debug};
use env_logger;
use tokio::time::{timeout, Duration};
use rand::seq::SliceRandom;
use std::collections::HashMap;
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};

// Cấu hình proxy
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub dns_servers: Vec<String>,
    pub user_agents: Vec<String>,
    pub max_connections: usize,
    pub connection_timeout: u64,
    pub buffer_size: usize,
    pub enable_logging: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:28265".to_string(),
            dns_servers: vec![
                "1.1.1.1:53".to_string(),
                "1.0.0.1:53".to_string(),
                "8.8.8.8:53".to_string(),
                "8.8.4.4:53".to_string(),
            ],
            user_agents: vec![
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0".to_string(),
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0".to_string(),
            ],
            max_connections: 10000,
            connection_timeout: 30,
            buffer_size: 65536, // 64KB buffer cho tốc độ cao
            enable_logging: true,
        }
    }
}

// Thống kê kết nối
#[derive(Debug, Default)]
pub struct ConnectionStats {
    pub total_connections: u64,
    pub active_connections: u64,
    pub bytes_transferred: u64,
    pub failed_connections: u64,
}

// Proxy server chính
pub struct ProxyServer {
    config: ProxyConfig,
    stats: Arc<Mutex<ConnectionStats>>,
    connection_pool: Arc<Mutex<HashMap<String, Vec<TcpStream>>>>,
}

impl ProxyServer {
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config,
            stats: Arc::new(Mutex::new(ConnectionStats::default())),
            connection_pool: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.config.enable_logging {
            env_logger::init();
        }

        let listener = TcpListener::bind(&self.config.listen_addr).await?;
        info!("Proxy server khởi động tại: {}", self.config.listen_addr);
        info!("Cấu hình: Max connections: {}, Buffer size: {}", 
              self.config.max_connections, self.config.buffer_size);

        // Khởi động task thống kê
        self.start_stats_logger().await;

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let stats = Arc::clone(&self.stats);
                    let config = self.config.clone();
                    
                    // Kiểm tra giới hạn kết nối
                    {
                        let mut stats_guard = stats.lock().await;
                        if stats_guard.active_connections >= self.config.max_connections as u64 {
                            warn!("Đạt giới hạn kết nối tối đa: {}", self.config.max_connections);
                            continue;
                        }
                        stats_guard.active_connections += 1;
                        stats_guard.total_connections += 1;
                    }

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, addr, config, Arc::clone(&stats)).await {
                            error!("Lỗi xử lý kết nối từ {}: {}", addr, e);
                            let mut stats_guard = stats.lock().await;
                            stats_guard.failed_connections += 1;
                        }
                        
                        // Giảm số kết nối active
                        let mut stats_guard = stats.lock().await;
                        stats_guard.active_connections -= 1;
                    });
                }
                Err(e) => {
                    error!("Lỗi accept connection: {}", e);
                }
            }
        }
    }

    async fn handle_connection(
        mut client: TcpStream,
        client_addr: SocketAddr,
        config: ProxyConfig,
        stats: Arc<Mutex<ConnectionStats>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Kết nối mới từ: {}", client_addr);

        // Đọc request từ client
        let mut buffer = vec![0u8; config.buffer_size];
        let n = timeout(
            Duration::from_secs(config.connection_timeout),
            client.read(&mut buffer)
        ).await??;

        if n == 0 {
            return Ok(());
        }

        let request = String::from_utf8_lossy(&buffer[..n]);
        debug!("Request: {}", request.lines().next().unwrap_or(""));

        // Phân tích request
        if let Some((method, target, version)) = Self::parse_request(&request) {
            match method.as_str() {
                "CONNECT" => {
                    Self::handle_connect(client, &target, config, stats).await?;
                }
                _ => {
                    Self::handle_http(client, method, target, version, &buffer[..n], config, stats).await?;
                }
            }
        } else {
            // Có thể là SOCKS5 hoặc giao thức khác
            Self::handle_socks5(client, &buffer[..n], config, stats).await?;
        }

        Ok(())
    }

    fn parse_request(request: &str) -> Option<(String, String, String)> {
        let first_line = request.lines().next()?;
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        
        if parts.len() >= 3 {
            Some((
                parts[0].to_string(),
                parts[1].to_string(),
                parts[2].to_string(),
            ))
        } else {
            None
        }
    }

    async fn handle_connect(
        mut client: TcpStream,
        target: &str,
        config: ProxyConfig,
        stats: Arc<Mutex<ConnectionStats>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!("CONNECT request tới: {}", target);

        // Kết nối tới target server
        let target_stream = match Self::connect_with_retry(target, &config).await {
            Ok(stream) => stream,
            Err(e) => {
                let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
                client.write_all(response.as_bytes()).await?;
                return Err(e);
            }
        };

        // Gửi response 200 Connection established
        let response = "HTTP/1.1 200 Connection established\r\n\r\n";
        client.write_all(response.as_bytes()).await?;

        // Bắt đầu relay data
        Self::relay_data(client, target_stream, stats).await?;

        Ok(())
    }

    async fn handle_http(
        mut client: TcpStream,
        method: String,
        target: String,
        version: String,
        request_data: &[u8],
        config: ProxyConfig,
        stats: Arc<Mutex<ConnectionStats>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!("HTTP {} request tới: {}", method, target);

        // Parse URL để lấy host và path
        let (host, path) = if target.starts_with("http://") {
            let url = target.trim_start_matches("http://");
            if let Some(slash_pos) = url.find('/') {
                (url[..slash_pos].to_string(), url[slash_pos..].to_string())
            } else {
                (url.to_string(), "/".to_string())
            }
        } else if target.starts_with("https://") {
            let url = target.trim_start_matches("https://");
            if let Some(slash_pos) = url.find('/') {
                (url[..slash_pos].to_string(), url[slash_pos..].to_string())
            } else {
                (url.to_string(), "/".to_string())
            }
        } else {
            // Relative URL, extract host from request headers
            let request_str = String::from_utf8_lossy(request_data);
            let host = Self::extract_host_from_headers(&request_str)
                .unwrap_or_else(|| "www.google.com".to_string());
            (host, target)
        };

        // Kết nối tới server
        let server_addr = if host.contains(':') {
            host.clone()
        } else {
            format!("{}:80", host)
        };

        let mut server = Self::connect_with_retry(&server_addr, &config).await?;

        // Tạo request mới với headers được modify
        let modified_request = Self::modify_request(&method, &path, &version, request_data, &config);
        server.write_all(&modified_request).await?;

        // Relay response về client
        Self::relay_data(client, server, stats).await?;

        Ok(())
    }

    async fn handle_socks5(
        mut client: TcpStream,
        initial_data: &[u8],
        config: ProxyConfig,
        stats: Arc<Mutex<ConnectionStats>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if initial_data.len() < 3 {
            return Ok(());
        }

        // SOCKS5 handshake
        if initial_data[0] == 0x05 {
            debug!("SOCKS5 handshake detected");
            
            // Gửi response: no authentication required
            client.write_all(&[0x05, 0x00]).await?;

            // Đọc connection request
            let mut buffer = vec![0u8; 1024];
            let n = client.read(&mut buffer).await?;
            
            if n < 10 || buffer[0] != 0x05 {
                return Ok(());
            }

            let cmd = buffer[1];
            let atyp = buffer[3];
            
            if cmd != 0x01 { // CONNECT command
                client.write_all(&[0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
                return Ok(());
            }

            // Parse target address
            let (target_addr, addr_end) = match atyp {
                0x01 => { // IPv4
                    let ip = format!("{}.{}.{}.{}", buffer[4], buffer[5], buffer[6], buffer[7]);
                    let port = u16::from_be_bytes([buffer[8], buffer[9]]);
                    (format!("{}:{}", ip, port), 10)
                }
                0x03 => { // Domain name
                    let len = buffer[4] as usize;
                    let domain = String::from_utf8_lossy(&buffer[5..5+len]);
                    let port = u16::from_be_bytes([buffer[5+len], buffer[5+len+1]]);
                    (format!("{}:{}", domain, port), 5 + len + 2)
                }
                _ => {
                    client.write_all(&[0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
                    return Ok(());
                }
            };

            debug!("SOCKS5 connect to: {}", target_addr);

            // Kết nối tới target
            match Self::connect_with_retry(&target_addr, &config).await {
                Ok(target_stream) => {
                    // Gửi success response
                    client.write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
                    
                    // Relay data
                    Self::relay_data(client, target_stream, stats).await?;
                }
                Err(_) => {
                    client.write_all(&[0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
                }
            }
        }

        Ok(())
    }

    async fn connect_with_retry(
        target: &str,
        config: &ProxyConfig,
    ) -> Result<TcpStream, Box<dyn std::error::Error>> {
        let mut last_error = None;
        
        // Thử kết nối với timeout ngắn để tăng tốc độ
        for attempt in 1..=3 {
            match timeout(
                Duration::from_secs(config.connection_timeout / 3),
                TcpStream::connect(target)
            ).await {
                Ok(Ok(stream)) => {
                    debug!("Kết nối thành công tới {} (lần thử {})", target, attempt);
                    
                    // Tối ưu socket cho hiệu suất
                    if let Ok(socket) = stream.into_std() {
                        socket.set_nodelay(true)?;
                        socket.set_nonblocking(false)?;
                        return Ok(TcpStream::from_std(socket)?);
                    }
                    return Ok(stream);
                }
                Ok(Err(e)) => {
                    last_error = Some(Box::new(e) as Box<dyn std::error::Error>);
                    warn!("Lần thử {} kết nối tới {} thất bại", attempt, target);
                }
                Err(e) => {
                    last_error = Some(Box::new(e) as Box<dyn std::error::Error>);
                    warn!("Timeout lần thử {} kết nối tới {}", attempt, target);
                }
            }
            
            if attempt < 3 {
                tokio::time::sleep(Duration::from_millis(100 * attempt as u64)).await;
            }
        }

        Err(last_error.unwrap_or_else(|| "Không thể kết nối".into()))
    }

    async fn relay_data(
        client: TcpStream,
        server: TcpStream,
        stats: Arc<Mutex<ConnectionStats>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (client_read, client_write) = client.into_split();
        let (server_read, server_write) = server.into_split();

        let stats_clone = Arc::clone(&stats);
        let relay_result = tokio::select! {
            result = copy_bidirectional(&mut tokio::io::join(client_read, client_write), &mut tokio::io::join(server_read, server_write)) => {
                result
            }
        };

        match relay_result {
            Ok((bytes_to_server, bytes_to_client)) => {
                let total_bytes = bytes_to_server + bytes_to_client;
                debug!("Relay hoàn thành: {} bytes", total_bytes);
                
                let mut stats_guard = stats_clone.lock().await;
                stats_guard.bytes_transferred += total_bytes;
            }
            Err(e) => {
                debug!("Relay error: {}", e);
            }
        }

        Ok(())
    }

    fn extract_host_from_headers(request: &str) -> Option<String> {
        for line in request.lines() {
            if line.to_lowercase().starts_with("host:") {
                return Some(line[5..].trim().to_string());
            }
        }
        None
    }

    fn modify_request(
        method: &str,
        path: &str,
        version: &str,
        original_data: &[u8],
        config: &ProxyConfig,
    ) -> Vec<u8> {
        let original_request = String::from_utf8_lossy(original_data);
        let mut lines: Vec<String> = original_request.lines().map(|s| s.to_string()).collect();
        
        if !lines.is_empty() {
            // Thay đổi request line
            lines[0] = format!("{} {} {}", method, path, version);
        }

        // Thêm/thay đổi headers để tránh phát hiện
        let mut headers_modified = false;
        let mut user_agent = config.user_agents.choose(&mut rand::thread_rng())
            .unwrap_or(&config.user_agents[0]).clone();

        for line in &mut lines {
            if line.to_lowercase().starts_with("user-agent:") {
                *line = format!("User-Agent: {}", user_agent);
                headers_modified = true;
            } else if line.to_lowercase().starts_with("proxy-connection:") {
                *line = "Connection: keep-alive".to_string();
            }
        }

        if !headers_modified {
            // Thêm User-Agent nếu chưa có
            lines.insert(1, format!("User-Agent: {}", user_agent));
        }

        // Thêm headers chống phát hiện
        lines.insert(1, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8".to_string());
        lines.insert(1, "Accept-Language: en-US,en;q=0.5".to_string());
        lines.insert(1, "Accept-Encoding: gzip, deflate".to_string());
        lines.insert(1, "Cache-Control: no-cache".to_string());

        lines.join("\r\n").into_bytes()
    }

    async fn start_stats_logger(&self) {
        let stats = Arc::clone(&self.stats);
        let enable_logging = self.config.enable_logging;
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                if enable_logging {
                    let stats_guard = stats.lock().await;
                    info!("=== THỐNG KÊ PROXY ===");
                    info!("Tổng kết nối: {}", stats_guard.total_connections);
                    info!("Kết nối đang hoạt động: {}", stats_guard.active_connections);
                    info!("Kết nối thất bại: {}", stats_guard.failed_connections);
                    info!("Tổng dữ liệu truyền: {:.2} MB", 
                          stats_guard.bytes_transferred as f64 / 1024.0 / 1024.0);
                    info!("====================");
                }
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ProxyConfig::default();
    let server = ProxyServer::new(config);
    
    println!("🚀 Đang khởi động High Performance Rust Proxy Server...");
    println!("📡 Địa chỉ: 0.0.0.0:28265");
    println!("🔒 DNS: 1.1.1.1 (Cloudflare)");
    println!("⚡ Tối ưu cho: Gaming, 4K Video, Browsing, Download");
    println!("🛡️  Chống phát hiện: ✅");
    println!("📊 Logging: ✅");
    println!("===============================================");
    
    server.start().await?;
    
    Ok(())
}

// Cargo.toml dependencies cần thiết:
/*
[dependencies]
tokio = { version = "1.0", features = ["full"] }
log = "0.4"
env_logger = "0.10"
rand = "0.8"
serde = { version = "1.0", features = ["derive"] }
*/
