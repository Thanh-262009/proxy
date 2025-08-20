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
