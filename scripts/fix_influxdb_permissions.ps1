# Fix InfluxDB Permissions Script for Windows
# This script resolves the "Access is denied" error for InfluxDB data files

Write-Host "Fixing InfluxDB Permissions..." -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# Get current user
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Write-Host "Current user: $currentUser" -ForegroundColor Yellow

# Define InfluxDB data directory
$influxDataDir = "$env:USERPROFILE\.influxdbv2"
Write-Host "InfluxDB data directory: $influxDataDir" -ForegroundColor Yellow

# Check if directory exists
if (Test-Path $influxDataDir) {
    Write-Host "InfluxDB data directory found" -ForegroundColor Green
} else {
    Write-Host "InfluxDB data directory not found. Creating..." -ForegroundColor Red
    New-Item -ItemType Directory -Path $influxDataDir -Force | Out-Null
}

# Function to grant full control to current user
function Grant-FullControl {
    param([string]$Path)
    
    try {
        # Get current ACL
        $acl = Get-Acl $Path
        
        # Create access rule for current user with full control
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $currentUser, 
            "FullControl", 
            "ContainerInherit,ObjectInherit", 
            "None", 
            "Allow"
        )
        
        # Add the rule
        $acl.SetAccessRule($accessRule)
        
        # Apply the new ACL
        Set-Acl -Path $Path -AclObject $acl
        
        Write-Host "Granted full control to $currentUser on $Path" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Failed to set permissions on $Path : $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Grant permissions to the main directory
Write-Host "Setting permissions on InfluxDB data directory..." -ForegroundColor Yellow
Grant-FullControl -Path $influxDataDir

# Grant permissions to all subdirectories and files
Write-Host "Setting permissions on all subdirectories and files..." -ForegroundColor Yellow
Get-ChildItem -Path $influxDataDir -Recurse | ForEach-Object {
    Grant-FullControl -Path $_.FullName
}

# Stop InfluxDB service if running
Write-Host "Stopping InfluxDB service..." -ForegroundColor Yellow
try {
    $influxService = Get-Service -Name "InfluxDB" -ErrorAction SilentlyContinue
    if ($influxService -and $influxService.Status -eq "Running") {
        Stop-Service -Name "InfluxDB" -Force
        Write-Host "InfluxDB service stopped" -ForegroundColor Green
        Start-Sleep -Seconds 3
    } else {
        Write-Host "InfluxDB service not running or not found" -ForegroundColor Yellow
    }
} catch {
    Write-Host "Could not stop InfluxDB service: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Start InfluxDB service
Write-Host "Starting InfluxDB service..." -ForegroundColor Yellow
try {
    Start-Service -Name "InfluxDB" -ErrorAction SilentlyContinue
    Write-Host "InfluxDB service started" -ForegroundColor Green
} catch {
    Write-Host "Could not start InfluxDB service: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "You may need to start InfluxDB manually" -ForegroundColor Yellow
}

# Alternative: Run InfluxDB as current user
Write-Host "Alternative: Running InfluxDB as current user..." -ForegroundColor Yellow
Write-Host "If the service approach doesn't work, you can run InfluxDB directly:" -ForegroundColor Cyan
Write-Host "1. Open Command Prompt as Administrator" -ForegroundColor White
Write-Host "2. Navigate to InfluxDB installation directory" -ForegroundColor White
Write-Host "3. Run: influxd.exe --config influxdb.conf" -ForegroundColor White

# Check if InfluxDB is accessible
Write-Host "Testing InfluxDB connection..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8086/health" -TimeoutSec 5 -ErrorAction SilentlyContinue
    if ($response.StatusCode -eq 200) {
        Write-Host "InfluxDB is accessible at http://localhost:8086" -ForegroundColor Green
    } else {
        Write-Host "InfluxDB responded with status: $($response.StatusCode)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "InfluxDB is not accessible: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Try restarting InfluxDB manually" -ForegroundColor Cyan
}

Write-Host "=================================" -ForegroundColor Cyan
Write-Host "Permission fix completed!" -ForegroundColor Green
Write-Host "If issues persist, try running this script as Administrator" -ForegroundColor Yellow 