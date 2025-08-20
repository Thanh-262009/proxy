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
