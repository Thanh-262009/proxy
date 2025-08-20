use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use std::sync::Arc;
use std::net::SocketAddr;
use log::{info, warn, error, debug, trace};
use env_logger;
use tokio::time::{timeout, Duration, Instant};
use rand::seq::SliceRandom;
use std::collections::HashMap;
use tokio::sync::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use clap::{Arg, Command};
use anyhow::{Result, Context};
use std::path::Path;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use parking_lot::RwLock as ParkingLot;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

// Build information
const VERSION: &str = env!("CARGO_PKG_VERSION");
const GIT_HASH: &str = env!("GIT_HASH");
const BUILD_TIME: &str = env!("BUILD_TIME");
const TARGET: &str = env!("TARGET");

// Global statistics
static STATS: Lazy<Arc<GlobalStats>> = Lazy::new(|| Arc::new(GlobalStats::new()));

// Configuration structures
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyConfig {
    pub server: ServerConfig,
    pub dns: DnsConfig,
    pub proxy: ProxySettings,
    pub logging: LoggingConfig,
    pub performance: PerformanceConfig,
    pub security: SecurityConfig,
    pub stats: StatsConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub max_connections: usize,
    pub connection_timeout: u64,
    pub buffer_size: usize,
    pub worker_threads: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsConfig {
    pub primary: String,
    pub secondary: String,
    pub fallback: Vec<String>,
    pub timeout: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxySettings {
    pub protocols: Vec<String>,
    pub user_agents: Vec<String>,
    pub rotate_user_agent: bool,
    pub remove_proxy_headers: bool,
    pub add_forwarded_headers: bool,
    #[serde(default = "default_connection_pool_size")]
    pub connection_pool_size: usize,
    #[serde(default = "default_keep_alive_timeout")]
    pub keep_alive_timeout: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    pub enabled: bool,
    pub level: String,
    pub file: Option<String>,
    pub max_size: Option<String>,
    pub max_files: Option<u32>,
    pub console: bool,
    #[serde(default)]
    pub json_format: bool,
    #[serde(default = "default_true")]
    pub include_timestamp: bool,
    #[serde(default = "default_true")]
    pub include_level: bool,
    #[serde(default)]
    pub include_target: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PerformanceConfig {
    pub tcp_nodelay: bool,
    pub tcp_keepalive: bool,
    pub so_reuseaddr: bool,
    #[serde(default)]
    pub so_reuseport: bool,
    pub backlog: u32,
    pub read_timeout: u64,
    pub write_timeout: u64,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout: u64,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout: u64,
    #[serde(default = "default_max_concurrent_streams")]
    pub max_concurrent_streams: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    pub block_private_ips: bool,
    pub allowed_ports: Vec<u16>,
    pub blocked_ports: Vec<u16>,
    pub max_request_size: String,
    pub rate_limit: usize,
    #[serde(default = "default_rate_limit_window")]
    pub rate_limit_window: u64,
    #[serde(default)]
    pub enable_ip_whitelist: bool,
    #[serde(default)]
    pub ip_whitelist: Vec<String>,
    #[serde(default)]
    pub enable_ip_blacklist: bool,
    #[serde(default)]
    pub ip_blacklist: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StatsConfig {
    pub enabled: bool,
    pub interval: u64,
    pub detailed: bool,
    pub export_metrics: bool,
    pub metrics_port: u16,
    #[serde(default = "default_metrics_path")]
    pub metrics_path: String,
    pub health_check_port: u16,
    #[serde(default = "default_health_path")]
    pub health_check_path: String,
}

// Default value functions
fn default_connection_pool_size() -> usize { 1000 }
fn default_keep_alive_timeout() -> u64 { 300 }
fn default_true() -> bool { true }
fn default_connect_timeout() -> u64 { 30 }
fn default_idle_timeout() -> u64 { 300 }
fn default_max_concurrent_streams() -> usize { 1000 }
fn default_rate_limit_window() -> u64 { 60 }
fn default_metrics_path() -> String { "/metrics".to_string() }
fn default_health_path() -> String { "/health".to_string() }

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 28265,
                max_connections: 10000,
                connection_timeout: 30,
                buffer_size: 65536,
                worker_threads: 0,
            },
            dns: DnsConfig {
                primary: "1.1.1.1:53".to_string(),
                secondary: "1.0.0.1:53".to_string(),
                fallback: vec![
                    "8.8.8.8:53".to_string(),
                    "8.8.4.4:53".to_string(),
                    "208.67.222.222:53".to_string(),
                ],
                timeout: 5,
            },
            proxy: ProxySettings {
                protocols: vec![
                    "http".to_string(),
                    "https".to_string(),
                    "socks5".to_string(),
                    "socks4".to_string(),
                ],
                user_agents: vec![
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
                ],
                rotate_user_agent: true,
                remove_proxy_headers: true,
                add_forwarded_headers: false,
                connection_pool_size: 1000,
                keep_alive_timeout: 300,
            },
            logging: LoggingConfig {
                enabled: true,
                level: "info".to_string(),
                file: Some("proxy.log".to_string()),
                max_size: Some("100MB".to_string()),
                max_files: Some(5),
                console: true,
                json_format: false,
                include_timestamp: true,
                include_level: true,
                include_target: false,
            },
            performance: PerformanceConfig {
                tcp_nodelay: true,
                tcp_keepalive: true,
                so_reuseaddr: true,
                so_reuseport: false,
                backlog: 1024,
                read_timeout: 30,
                write_timeout: 30,
                connect_timeout: 30,
                idle_timeout: 300,
                max_concurrent_streams: 1000,
            },
            security: SecurityConfig {
                block_private_ips: false,
                allowed_ports: vec![],
                blocked_ports: vec![22, 23, 25, 135, 139, 445, 993, 995],
                max_request_size: "10MB".to_string(),
                rate_limit: 1000,
                rate_limit_window: 60,
                enable_ip_whitelist: false,
                ip_whitelist: vec![],
                enable_ip_blacklist: false,
                ip_blacklist: vec![],
            },
            stats: StatsConfig {
                enabled: true,
                interval: 60,
                detailed: true,
                export_metrics: false,
                metrics_port: 9090,
                metrics_path: "/metrics".to_string(),
                health_check_port: 28265,
                health_check_path: "/health".to_string(),
            },
        }
    }
}

// Connection statistics
#[derive(Debug, Default, Serialize)]
pub struct ConnectionStats {
    pub total_connections: AtomicU64,
    pub active_connections: AtomicUsize,
    pub bytes_transferred: AtomicU64,
    pub failed_connections: AtomicU64,
    pub requests_per_protocol: DashMap<String, u64>,
    pub avg_response_time: AtomicU64,
    pub peak_connections: AtomicUsize,
    pub uptime_start: DateTime<Utc>,
}

#[derive(Debug)]
pub struct GlobalStats {
    pub connections: ConnectionStats,
    pub rate_limiter: DashMap<SocketAddr, (Instant, usize)>,
    pub connection_pool: DashMap<String, Vec<Arc<Mutex<Option<TcpStream>>>>>,
}

impl GlobalStats {
    pub fn new() -> Self {
        Self {
            connections: ConnectionStats {
                uptime_start: Utc::now(),
                ..Default::default()
            },
            rate_limiter: DashMap::new(),
            connection_pool: DashMap::new(),
        }
    }

    pub fn increment_connections(&self, protocol: &str) {
        self.connections.total_connections.fetch_add(1, Ordering::Relaxed);
        let current = self.connections.active_connections.fetch_add(1, Ordering::Relaxed) + 1;
        
        // Update peak connections
        loop {
            let peak = self.connections.peak_connections.load(Ordering::Relaxed);
            if current <= peak {
                break;
            }
            if self.connections.peak_connections.compare_exchange_weak(
                peak, current, Ordering::Relaxed, Ordering::Relaxed
            ).is_ok() {
                break;
            }
        }
        
        *self.connections.requests_per_protocol.entry(protocol.to_string()).or_insert(0) += 1;
    }

    pub fn decrement_connections(&self) {
        self.connections.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn add_bytes_transferred(&self, bytes: u64) {
        self.connections.bytes_transferred.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn increment_failed(&self) {
        self.connections.failed_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn check_rate_limit(&self, addr: SocketAddr, limit: usize, window: Duration) -> bool {
        let now = Instant::now();
        
        match self.rate_limiter.entry(addr) {
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                let (last_reset, count) = entry.get_mut();
                
                if now.duration_since(*last_reset) > window {
                    *last_reset = now;
                    *count = 1;
                    true
                } else if *count < limit {
                    *count += 1;
                    true
                } else {
                    false
                }
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert((now, 1));
                true
            }
        }
    }
}

// Connection session
#[derive(Debug)]
pub struct ConnectionSession {
    pub id: Uuid,
    pub client_addr: SocketAddr,
    pub start_time: Instant,
    pub protocol: String,
    pub target: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl ConnectionSession {
    pub fn new(client_addr: SocketAddr, protocol: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            client_addr,
            start_time: Instant::now(),
            protocol,
            target: None,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
}

// Main proxy server
pub struct ProxyServer {
    config: Arc<ProxyConfig>,
    stats: Arc<GlobalStats>,
}

impl ProxyServer {
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config: Arc::new(config),
            stats: STATS.clone(),
        }
    }

    pub async fn start(&self) -> Result<()> {
        self.setup_logging().context("Failed to setup logging")?;
        
        info!("🚀 Starting Rust High Performance Proxy Server");
        info!("📋 Version: {} ({})", VERSION, GIT_HASH);
        info!("🏗️  Built: {} for {}", BUILD_TIME, TARGET);
        info!("📡 Listening on: {}:{}", self.config.server.host, self.config.server.port);
        info!("⚡ Max connections: {}", self.config.server.max_connections);
        info!("💾 Buffer size: {} bytes", self.config.server.buffer_size);
        
        // Set up Tokio runtime with optimal settings
        let worker_threads = if self.config.server.worker_threads == 0 {
            num_cpus::get()
        } else {
            self.config.server.worker_threads
        };
        
        info!("🧵 Worker threads: {}", worker_threads);
        
        // Start metrics server if enabled
        if self.config.stats.export_metrics {
            self.start_metrics_server().await?;
        }
        
        // Start health check server
        self.start_health_server().await?;
        
        // Start statistics logger
        if self.config.stats.enabled {
            self.start_stats_logger().await;
        }
        
        // Create TCP listener with optimal settings
        let listener = TcpListener::bind(format!("{}:{}", 
            self.config.server.host, 
            self.config.server.port
        )).await.context("Failed to bind to address")?;
        
        info!("✅ Proxy server started successfully");
        info!("🎯 Ready to accept connections...");
        
        // Main accept loop
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    // Check rate limiting
                    if !self.stats.check_rate_limit(
                        addr,
                        self.config.security.rate_limit,
                        Duration::from_secs(self.config.security.rate_limit_window),
                    ) {
                        warn!("⚠️  Rate limit exceeded for {}", addr);
                        continue;
                    }
                    
                    // Check connection limit
                    let active = self.stats.connections.active_connections.load(Ordering::Relaxed);
                    if active >= self.config.server.max_connections {
                        warn!("⚠️  Connection limit reached: {}/{}", active, self.config.server.max_connections);
                        continue;
                    }
                    
                    // Handle connection
                    let config = Arc::clone(&self.config);
                    let stats = Arc::clone(&self.stats);
                    
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, addr, config, stats).await {
                            error!("❌ Connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("❌ Failed to accept connection: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    fn setup_logging(&self) -> Result<()> {
        if !self.config.logging.enabled {
            return Ok(());
        }

        let mut builder = env_logger::Builder::new();
        
        // Set log level
        let level = match self.config.logging.level.as_str() {
            "trace" => log::LevelFilter::Trace,
            "debug" => log::LevelFilter::Debug,
            "info" => log::LevelFilter::Info,
            "warn" => log::LevelFilter::Warn,
            "error" => log::LevelFilter::Error,
            _ => log::LevelFilter::Info,
        };
        
        builder.filter_level(level);
        
        if self.config.logging.console {
            builder.format_timestamp_secs();
        }
        
        builder.init();
        
        Ok(())
    }

    async fn start_metrics_server(&self) -> Result<()> {
        let port = self.config.stats.metrics_port;
        let path = self.config.stats.metrics_path.clone();
        let stats = Arc::clone(&self.stats);
        
        tokio::spawn(async move {
            let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await.unwrap();
            info!("📊 Metrics server started on port {}", port);
            
            loop {
                if let Ok((mut stream, _)) = listener.accept().await {
                    let response = Self::generate_metrics(&stats).await;
                    let http_response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                        response.len(),
                        response
                    );
                    let _ = stream.write_all(http_response.as_bytes()).await;
                }
            }
        });
        
        Ok(())
    }

    async fn start_health_server(&self) -> Result<()> {
        let port = self.config.stats.health_check_port;
        let path = self.config.stats.health_check_path.clone();
        let stats = Arc::clone(&self.stats);
        
        tokio::spawn(async move {
            let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await.unwrap();
            debug!("💚 Health check server started on port {}", port);
            
            loop {
                if let Ok((mut stream, _)) = listener.accept().await {
                    let health_status = Self::generate_health_status(&stats).await;
                    let http_response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        health_status.len(),
                        health_status
                    );
                    let _ = stream.write_all(http_response.as_bytes()).await;
                }
            }
        });
        
        Ok(())
    }

    async fn start_stats_logger(&self) {
        let stats = Arc::clone(&self.stats);
        let interval = self.config.stats.interval;
        let detailed = self.config.stats.detailed;
        
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(Duration::from_secs(interval));
            
            loop {
                interval_timer.tick().await;
                
                let total = stats.connections.total_connections.load(Ordering::Relaxed);
                let active = stats.connections.active_connections.load(Ordering::Relaxed);
                let failed = stats.connections.failed_connections.load(Ordering::Relaxed);
                let bytes = stats.connections.bytes_transferred.load(Ordering::Relaxed);
                let peak = stats.connections.peak_connections.load(Ordering::Relaxed);
                
                info!("📊 === PROXY STATISTICS ===");
                info!("📈 Total connections: {}", total);
                info!("⚡ Active connections: {}", active);
                info!("🔝 Peak connections: {}", peak);
                info!("❌ Failed connections: {}", failed);
                info!("💾 Bytes transferred: {:.2} MB", bytes as f64 / 1024.0 / 1024.0);
                info!("⏱️  Uptime: {:.1} hours", 
                      stats.connections.uptime_start.elapsed().unwrap().as_secs() as f64 / 3600.0);
                
                if detailed {
                    info!("🌐 Protocol breakdown:");
                    for entry in stats.connections.requests_per_protocol.iter() {
                        info!("   {}: {} requests", entry.key(), entry.value());
                    }
                }
                
                info!("========================");
            }
        });
    }

    async fn handle_connection(
        stream: TcpStream,
        client_addr: SocketAddr,
        config: Arc<ProxyConfig>,
        stats: Arc<GlobalStats>,
    ) -> Result<()> {
        // Optimize socket settings
        if let Ok(socket) = stream.into_std() {
            socket.set_nodelay(config.performance.tcp_nodelay).ok();
            let stream = TcpStream::from_std(socket)?;
            
            let session = ConnectionSession::new(client_addr, "unknown".to_string());
            debug!("🔗 New connection {} from {}", session.id, client_addr);
            
            // Try to detect protocol and handle accordingly
            if let Err(e) = Self::handle_connection_inner(stream, session, config, stats).await {
                error!("❌ Connection handling error: {}", e);
            }
        }
        
        Ok(())
    }

    async fn handle_connection_inner(
        mut client: TcpStream,
        mut session: ConnectionSession,
        config: Arc<ProxyConfig>,
        stats: Arc<GlobalStats>,
    ) -> Result<()> {
        stats.increment_connections("detecting");
        
        // Read initial data to detect protocol
        let mut buffer = vec![0u8; config.server.buffer_size];
        let n = timeout(
            Duration::from_secs(config.server.connection_timeout),
            client.read(&mut buffer)
        ).await??;

        if n == 0 {
            stats.decrement_connections();
            return Ok(());
        }

        // Protocol detection
        if Self::is_http_request(&buffer[..n]) {
            session.protocol = "http".to_string();
            Self::handle_http(client, session, &buffer[..n], config, stats).await?;
        } else if Self::is_socks5_request(&buffer[..n]) {
            session.protocol = "socks5".to_string();
            Self::handle_socks5(client, session, &buffer[..n], config, stats).await?;
        } else if Self::is_socks4_request(&buffer[..n]) {
            session.protocol = "socks4".to_string();
            Self::handle_socks4(client, session, &buffer[..n], config, stats).await?;
        } else {
            // Try to handle as raw TCP tunnel
            session.protocol = "tcp".to_string();
            Self::handle_tcp_tunnel(client, session, &buffer[..n], config, stats).await?;
        }

        stats.decrement_connections();
        Ok(())
    }

    fn is_http_request(data: &[u8]) -> bool {
        let request = String::from_utf8_lossy(data);
        let first_line = request.lines().next().unwrap_or("");
        
        first_line.starts_with("GET ") || 
        first_line.starts_with("POST ") ||
        first_line.starts_with("PUT ") ||
        first_line.starts_with("DELETE ") ||
        first_line.starts_with("HEAD ") ||
        first_line.starts_with("OPTIONS ") ||
        first_line.starts_with("PATCH ") ||
        first_line.starts_with("CONNECT ")
    }

    fn is_socks5_request(data: &[u8]) -> bool {
        data.len() >= 3 && data[0] == 0x05
    }

    fn is_socks4_request(data: &[u8]) -> bool {
        data.len() >= 8 && data[0] == 0x04
    }

    async fn handle_http(
        mut client: TcpStream,
        mut session: ConnectionSession,
        initial_data: &[u8],
        config: Arc<ProxyConfig>,
        stats: Arc<GlobalStats>,
    ) -> Result<()> {
        let request = String::from_utf8_lossy(initial_data);
        let first_line = request.lines().next().unwrap_or("");
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        
        if parts.len() < 3 {
            return Err(anyhow::anyhow!("Invalid HTTP request"));
        }

        let method = parts[0];
        let target = parts[1];
        let version = parts[2];

        debug!("🌐 HTTP {} request to: {}", method, target);
        session.target = Some(target.to_string());

        match method {
            "CONNECT" => {
                Self::handle_http_connect(client, session, target, config, stats).await
            }
            _ => {
                client.write_all(&[0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
                return Err(anyhow::anyhow!("Unsupported address type: {}", atyp));
            }
        };

        debug!("🎯 SOCKS5 connect to: {}", target_addr);

        // Connect to target
        match Self::connect_with_retry(&target_addr, &config).await {
            Ok(target_stream) => {
                // Send success response
                client.write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
                
                // Start data relay
                Self::relay_data(client, target_stream, session, stats).await
            }
            Err(e) => {
                error!("❌ SOCKS5 connection failed: {}", e);
                client.write_all(&[0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
                Err(e)
            }
        }
    }

    async fn handle_socks4(
        mut client: TcpStream,
        session: ConnectionSession,
        initial_data: &[u8],
        config: Arc<ProxyConfig>,
        stats: Arc<GlobalStats>,
    ) -> Result<()> {
        debug!("🧦 SOCKS4 request from: {}", session.client_addr);

        if initial_data.len() < 8 {
            return Err(anyhow::anyhow!("Invalid SOCKS4 request length"));
        }

        let cmd = initial_data[1];
        if cmd != 0x01 {
            // Send rejection response
            client.write_all(&[0x00, 0x5B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
            return Err(anyhow::anyhow!("Unsupported SOCKS4 command: {}", cmd));
        }

        let port = u16::from_be_bytes([initial_data[2], initial_data[3]]);
        let ip = format!("{}.{}.{}.{}", 
            initial_data[4], initial_data[5], initial_data[6], initial_data[7]);
        let target_addr = format!("{}:{}", ip, port);

        debug!("🎯 SOCKS4 connect to: {}", target_addr);

        match Self::connect_with_retry(&target_addr, &config).await {
            Ok(target_stream) => {
                // Send success response
                client.write_all(&[0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
                
                // Start data relay
                Self::relay_data(client, target_stream, session, stats).await
            }
            Err(e) => {
                error!("❌ SOCKS4 connection failed: {}", e);
                client.write_all(&[0x00, 0x5B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
                Err(e)
            }
        }
    }

    async fn handle_tcp_tunnel(
        client: TcpStream,
        session: ConnectionSession,
        initial_data: &[u8],
        config: Arc<ProxyConfig>,
        stats: Arc<GlobalStats>,
    ) -> Result<()> {
        debug!("🔧 Raw TCP tunnel from: {}", session.client_addr);
        
        // For raw TCP, we need to determine the target from configuration or headers
        // This is a simplified implementation - in practice you'd need more logic
        let target_addr = "127.0.0.1:80"; // Default target
        
        match Self::connect_with_retry(target_addr, &config).await {
            Ok(mut target_stream) => {
                // Forward the initial data
                target_stream.write_all(initial_data).await?;
                
                // Start bidirectional relay
                Self::relay_data(client, target_stream, session, stats).await
            }
            Err(e) => {
                error!("❌ TCP tunnel connection failed: {}", e);
                Err(e)
            }
        }
    }

    async fn connect_with_retry(target: &str, config: &ProxyConfig) -> Result<TcpStream> {
        let mut last_error = None;
        
        for attempt in 1..=3 {
            match timeout(
                Duration::from_secs(config.performance.connect_timeout),
                TcpStream::connect(target)
            ).await {
                Ok(Ok(stream)) => {
                    trace!("✅ Connected to {} (attempt {})", target, attempt);
                    
                    // Optimize socket
                    if let Ok(socket) = stream.into_std() {
                        socket.set_nodelay(config.performance.tcp_nodelay).ok();
                        return Ok(TcpStream::from_std(socket)?);
                    }
                    return Ok(stream);
                }
                Ok(Err(e)) => {
                    last_error = Some(anyhow::anyhow!(e));
                    warn!("⚠️  Connection attempt {} to {} failed", attempt, target);
                }
                Err(e) => {
                    last_error = Some(anyhow::anyhow!(e));
                    warn!("⏰ Connection attempt {} to {} timed out", attempt, target);
                }
            }
            
            if attempt < 3 {
                tokio::time::sleep(Duration::from_millis(100 * attempt as u64)).await;
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Connection failed after retries")))
    }

    async fn relay_data(
        client: TcpStream,
        server: TcpStream,
        session: ConnectionSession,
        stats: Arc<GlobalStats>,
    ) -> Result<()> {
        let session_id = session.id;
        let start_time = session.start_time;
        
        debug!("🔄 Starting data relay for session {}", session_id);

        let result = tokio::select! {
            result = copy_bidirectional(&mut &client, &mut &server) => result,
            _ = tokio::time::sleep(Duration::from_secs(300)) => {
                warn!("⏰ Connection timeout for session {}", session_id);
                return Ok(());
            }
        };

        match result {
            Ok((bytes_to_server, bytes_to_client)) => {
                let total_bytes = bytes_to_server + bytes_to_client;
                let duration = start_time.elapsed();
                
                debug!("✅ Session {} completed: {} bytes in {:.2}s", 
                       session_id, total_bytes, duration.as_secs_f64());
                
                stats.add_bytes_transferred(total_bytes);
                
                // Update average response time
                let avg_time = stats.connections.avg_response_time.load(Ordering::Relaxed);
                let new_avg = if avg_time == 0 {
                    duration.as_millis() as u64
                } else {
                    (avg_time + duration.as_millis() as u64) / 2
                };
                stats.connections.avg_response_time.store(new_avg, Ordering::Relaxed);
            }
            Err(e) => {
                debug!("⚠️  Session {} relay error: {}", session_id, e);
                stats.increment_failed();
            }
        }

        Ok(())
    }

    fn parse_http_url(target: &str, request_data: &[u8]) -> Result<(String, String)> {
        if target.starts_with("http://") {
            let url = target.trim_start_matches("http://");
            if let Some(slash_pos) = url.find('/') {
                Ok((url[..slash_pos].to_string(), url[slash_pos..].to_string()))
            } else {
                Ok((url.to_string(), "/".to_string()))
            }
        } else if target.starts_with("https://") {
            let url = target.trim_start_matches("https://");
            if let Some(slash_pos) = url.find('/') {
                Ok((url[..slash_pos].to_string(), url[slash_pos..].to_string()))
            } else {
                Ok((url.to_string(), "/".to_string()))
            }
        } else {
            // Extract host from headers
            let request_str = String::from_utf8_lossy(request_data);
            let host = Self::extract_host_header(&request_str)
                .unwrap_or_else(|| "example.com".to_string());
            Ok((host, target.to_string()))
        }
    }

    fn extract_host_header(request: &str) -> Option<String> {
        for line in request.lines() {
            if line.to_lowercase().starts_with("host:") {
                return Some(line[5..].trim().to_string());
            }
        }
        None
    }

    fn create_http_request(
        method: &str,
        path: &str,
        version: &str,
        original_data: &[u8],
        config: &ProxyConfig,
    ) -> Vec<u8> {
        let original_request = String::from_utf8_lossy(original_data);
        let mut lines: Vec<String> = original_request.lines().map(|s| s.to_string()).collect();
        
        if !lines.is_empty() {
            lines[0] = format!("{} {} {}", method, path, version);
        }

        // Anti-detection modifications
        let mut user_agent_modified = false;
        
        for line in &mut lines {
            let lower_line = line.to_lowercase();
            
            if lower_line.starts_with("user-agent:") && config.proxy.rotate_user_agent {
                if let Some(ua) = config.proxy.user_agents.choose(&mut rand::thread_rng()) {
                    *line = format!("User-Agent: {}", ua);
                    user_agent_modified = true;
                }
            } else if config.proxy.remove_proxy_headers && 
                     (lower_line.starts_with("proxy-connection:") || 
                      lower_line.starts_with("proxy-authorization:")) {
                *line = String::new(); // Remove proxy headers
            }
        }

        // Add User-Agent if not present
        if !user_agent_modified && config.proxy.rotate_user_agent {
            if let Some(ua) = config.proxy.user_agents.choose(&mut rand::thread_rng()) {
                lines.insert(1, format!("User-Agent: {}", ua));
            }
        }

        // Add anti-detection headers
        if !lines.iter().any(|l| l.to_lowercase().starts_with("accept:")) {
            lines.insert(1, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8".to_string());
        }
        if !lines.iter().any(|l| l.to_lowercase().starts_with("accept-language:")) {
            lines.insert(1, "Accept-Language: en-US,en;q=0.9".to_string());
        }
        if !lines.iter().any(|l| l.to_lowercase().starts_with("accept-encoding:")) {
            lines.insert(1, "Accept-Encoding: gzip, deflate, br".to_string());
        }

        // Remove empty lines and rejoin
        lines.retain(|line| !line.is_empty());
        lines.join("\r\n").into_bytes()
    }

    async fn generate_metrics(stats: &GlobalStats) -> String {
        let total = stats.connections.total_connections.load(Ordering::Relaxed);
        let active = stats.connections.active_connections.load(Ordering::Relaxed);
        let failed = stats.connections.failed_connections.load(Ordering::Relaxed);
        let bytes = stats.connections.bytes_transferred.load(Ordering::Relaxed);
        let peak = stats.connections.peak_connections.load(Ordering::Relaxed);
        let avg_time = stats.connections.avg_response_time.load(Ordering::Relaxed);
        let uptime = stats.connections.uptime_start.elapsed().unwrap().as_secs();

        let mut metrics = format!(
            "# HELP proxy_connections_total Total number of connections\n\
             # TYPE proxy_connections_total counter\n\
             proxy_connections_total {}\n\
             \n\
             # HELP proxy_connections_active Currently active connections\n\
             # TYPE proxy_connections_active gauge\n\
             proxy_connections_active {}\n\
             \n\
             # HELP proxy_connections_failed Total failed connections\n\
             # TYPE proxy_connections_failed counter\n\
             proxy_connections_failed {}\n\
             \n\
             # HELP proxy_bytes_transferred_total Total bytes transferred\n\
             # TYPE proxy_bytes_transferred_total counter\n\
             proxy_bytes_transferred_total {}\n\
             \n\
             # HELP proxy_connections_peak Peak concurrent connections\n\
             # TYPE proxy_connections_peak gauge\n\
             proxy_connections_peak {}\n\
             \n\
             # HELP proxy_response_time_avg Average response time in milliseconds\n\
             # TYPE proxy_response_time_avg gauge\n\
             proxy_response_time_avg {}\n\
             \n\
             # HELP proxy_uptime_seconds Proxy uptime in seconds\n\
             # TYPE proxy_uptime_seconds counter\n\
             proxy_uptime_seconds {}\n\
             \n",
            total, active, failed, bytes, peak, avg_time, uptime
        );

        // Add per-protocol metrics
        for entry in stats.connections.requests_per_protocol.iter() {
            metrics.push_str(&format!(
                "# HELP proxy_requests_by_protocol_total Total requests by protocol\n\
                 # TYPE proxy_requests_by_protocol_total counter\n\
                 proxy_requests_by_protocol_total{{protocol=\"{}\"}} {}\n\
                 \n",
                entry.key(), entry.value()
            ));
        }

        metrics
    }

    async fn generate_health_status(stats: &GlobalStats) -> String {
        let total = stats.connections.total_connections.load(Ordering::Relaxed);
        let active = stats.connections.active_connections.load(Ordering::Relaxed);
        let failed = stats.connections.failed_connections.load(Ordering::Relaxed);
        let uptime = stats.connections.uptime_start.elapsed().unwrap().as_secs();
        
        let health_status = serde_json::json!({
            "status": "healthy",
            "version": VERSION,
            "build": {
                "git_hash": GIT_HASH,
                "build_time": BUILD_TIME,
                "target": TARGET
            },
            "uptime_seconds": uptime,
            "connections": {
                "total": total,
                "active": active,
                "failed": failed,
                "peak": stats.connections.peak_connections.load(Ordering::Relaxed)
            },
            "bytes_transferred": stats.connections.bytes_transferred.load(Ordering::Relaxed),
            "avg_response_time_ms": stats.connections.avg_response_time.load(Ordering::Relaxed),
            "timestamp": Utc::now().to_rfc3339()
        });

        serde_json::to_string_pretty(&health_status).unwrap_or_else(|_| "{}".to_string())
    }
}

// Configuration loading
fn load_config(config_path: &str) -> Result<ProxyConfig> {
    if Path::new(config_path).exists() {
        let config_str = std::fs::read_to_string(config_path)
            .context("Failed to read config file")?;
        let config: ProxyConfig = toml::from_str(&config_str)
            .context("Failed to parse config file")?;
        info!("📋 Loaded configuration from: {}", config_path);
        Ok(config)
    } else {
        warn!("⚠️  Config file not found: {}, using defaults", config_path);
        Ok(ProxyConfig::default())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let matches = Command::new("Rust High Performance Proxy Server")
        .version(VERSION)
        .author("Rust Proxy Team")
        .about("Ultra-fast multi-protocol proxy server with anti-detection")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
                .default_value("config.toml")
        )
        .arg(
            Arg::new("host")
                .long("host")
                .value_name("HOST")
                .help("Host to bind to")
                .default_value("0.0.0.0")
        )
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .value_name("PORT")
                .help("Port to bind to")
                .default_value("28265")
        )
        .arg(
            Arg::new("workers")
                .short('w')
                .long("workers")
                .value_name("WORKERS")
                .help("Number of worker threads (0 = auto)")
                .default_value("0")
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(clap::ArgAction::Count)
                .help("Increase verbosity (-v, -vv, -vvv)")
        )
        .arg(
            Arg::new("quiet")
                .short('q')
                .long("quiet")
                .help("Suppress output")
                .action(clap::ArgAction::SetTrue)
        )
        .get_matches();

    // Load configuration
    let config_path = matches.get_one::<String>("config").unwrap();
    let mut config = load_config(config_path)?;

    // Override with command line arguments
    if let Some(host) = matches.get_one::<String>("host") {
        config.server.host = host.clone();
    }
    if let Some(port) = matches.get_one::<String>("port") {
        config.server.port = port.parse().context("Invalid port number")?;
    }
    if let Some(workers) = matches.get_one::<String>("workers") {
        config.server.worker_threads = workers.parse().context("Invalid worker count")?;
    }

    // Handle verbosity
    if matches.get_flag("quiet") {
        config.logging.enabled = false;
    } else {
        let verbosity = matches.get_count("verbose");
        config.logging.level = match verbosity {
            0 => "info".to_string(),
            1 => "debug".to_string(),
            2 => "trace".to_string(),
            _ => "trace".to_string(),
        };
    }

    // Print banner
    if config.logging.enabled {
        println!("\n🚀 ==========================================");
        println!("🚀  RUST HIGH PERFORMANCE PROXY SERVER");
        println!("🚀 ==========================================");
        println!("📋 Version: {} ({})", VERSION, GIT_HASH);
        println!("🏗️  Built: {} for {}", BUILD_TIME, TARGET);
        println!("📡 Address: {}:{}", config.server.host, config.server.port);
        println!("⚡ Features: HTTP/HTTPS/SOCKS4/SOCKS5");
        println!("🛡️  Anti-Detection: ✅");
        println!("🔒 DNS: {} (Secure)", config.dns.primary);
        println!("💾 Buffer: {} KB", config.server.buffer_size / 1024);
        println!("🔄 Max Connections: {}", config.server.max_connections);
        println!("🚀 ==========================================\n");
    }

    // Create and start proxy server
    let server = ProxyServer::new(config);
    
    // Handle graceful shutdown
    let server_handle = tokio::spawn(async move {
        if let Err(e) = server.start().await {
            error!("❌ Server error: {}", e);
            std::process::exit(1);
        }
    });

    // Wait for Ctrl+C
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("🛑 Received shutdown signal, gracefully stopping...");
        }
        _ = server_handle => {
            info!("🏁 Server task completed");
        }
    }

    info!("👋 Proxy server stopped");
    Ok(())
}
                Self::handle_http_request(client, session, method, target, version, initial_data, config, stats).await
            }
        }
    }

    async fn handle_http_connect(
        mut client: TcpStream,
        session: ConnectionSession,
        target: &str,
        config: Arc<ProxyConfig>,
        stats: Arc<GlobalStats>,
    ) -> Result<()> {
        debug!("🔗 CONNECT tunnel to: {}", target);
        
        // Connect to target server
        let target_stream = Self::connect_with_retry(target, &config).await
            .context("Failed to connect to target")?;

        // Send 200 Connection established
        let response = "HTTP/1.1 200 Connection established\r\n\r\n";
        client.write_all(response.as_bytes()).await?;

        // Start bidirectional data relay
        Self::relay_data(client, target_stream, session, stats).await
    }

    async fn handle_http_request(
        mut client: TcpStream,
        session: ConnectionSession,
        method: &str,
        target: &str,
        version: &str,
        request_data: &[u8],
        config: Arc<ProxyConfig>,
        stats: Arc<GlobalStats>,
    ) -> Result<()> {
        // Parse URL and create modified request
        let (host, path) = Self::parse_http_url(target, request_data)?;
        
        let server_addr = if host.contains(':') {
            host.clone()
        } else {
            format!("{}:80", host)
        };

        debug!("🌐 HTTP {} to {}:{}", method, host, path);

        // Connect to target server
        let mut server = Self::connect_with_retry(&server_addr, &config).await?;

        // Create and send modified request
        let modified_request = Self::create_http_request(method, &path, version, request_data, &config);
        server.write_all(&modified_request).await?;

        // Relay response back to client
        Self::relay_data(client, server, session, stats).await
    }

    async fn handle_socks5(
        mut client: TcpStream,
        session: ConnectionSession,
        initial_data: &[u8],
        config: Arc<ProxyConfig>,
        stats: Arc<GlobalStats>,
    ) -> Result<()> {
        debug!("🧦 SOCKS5 handshake from: {}", session.client_addr);

        // SOCKS5 authentication negotiation
        client.write_all(&[0x05, 0x00]).await?; // No authentication required

        // Read connection request
        let mut buffer = vec![0u8; 1024];
        let n = client.read(&mut buffer).await?;
        
        if n < 10 || buffer[0] != 0x05 {
            return Err(anyhow::anyhow!("Invalid SOCKS5 request"));
        }

        let cmd = buffer[1];
        let atyp = buffer[3];
        
        if cmd != 0x01 { // CONNECT command
            client.write_all(&[0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
            return Err(anyhow::anyhow!("Unsupported SOCKS5 command: {}", cmd));
        }

        // Parse target address
        let target_addr = match atyp {
            0x01 => { // IPv4
                let ip = format!("{}.{}.{}.{}", buffer[4], buffer[5], buffer[6], buffer[7]);
                let port = u16::from_be_bytes([buffer[8], buffer[9]]);
                format!("{}:{}", ip, port)
            }
            0x03 => { // Domain name
                let len = buffer[4] as usize;
                if n < 5 + len + 2 {
                    return Err(anyhow::anyhow!("Invalid domain name length"));
                }
                let domain = String::from_utf8_lossy(&buffer[5..5+len]);
                let port = u16::from_be_bytes([buffer[5+len], buffer[5+len+1]]);
                format!("{}:{}", domain, port)
            }
            _ => {
