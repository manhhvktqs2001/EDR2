# Cleanup Test Data Script for EDR System
# Usage: .\cleanup_test_data.ps1

Write-Host "Cleaning up test data from Redis and InfluxDB..." -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan

# Cleanup Redis test data
Write-Host "Cleaning Redis test data..." -ForegroundColor Yellow

# Get all keys
$keys = redis-cli -h localhost -p 6379 KEYS "*"
Write-Host "Current Redis keys: $($keys -join ', ')" -ForegroundColor Gray

# Delete test keys (keep only real agent data)
$testKeys = @(
    "threat:hash:abc123",
    "test:agent:status", 
    "session:user123"
)

foreach ($key in $testKeys) {
    $exists = redis-cli -h localhost -p 6379 EXISTS $key
    if ($exists -eq 1) {
        $result = redis-cli -h localhost -p 6379 DEL $key
        Write-Host "Deleted key: $key (result: $result)" -ForegroundColor Green
    } else {
        Write-Host "Key not found: $key" -ForegroundColor Yellow
    }
}

# Show remaining keys
$remainingKeys = redis-cli -h localhost -p 6379 KEYS "*"
Write-Host "Remaining Redis keys: $($remainingKeys -join ', ')" -ForegroundColor Green

# Cleanup InfluxDB test data
Write-Host "Cleaning InfluxDB test data..." -ForegroundColor Yellow

# Note: InfluxDB cleanup requires proper authentication
# For now, we'll just show the current data structure
Write-Host "InfluxDB cleanup requires proper authentication token." -ForegroundColor Red
Write-Host "Please use InfluxDB Dashboard to manually delete test data." -ForegroundColor Yellow
Write-Host "Or update the script with proper authentication token." -ForegroundColor Yellow

Write-Host "Cleanup completed!" -ForegroundColor Green 