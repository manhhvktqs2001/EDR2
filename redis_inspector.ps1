# Redis Inspector Script for EDR System
# Usage: .\redis_inspector.ps1

param(
    [string]$RedisHost = "localhost",
    [int]$RedisPort = 6379,
    [string]$Action = "info"
)

function Test-RedisConnection {
    try {
        $result = redis-cli -h $RedisHost -p $RedisPort ping
        if ($result -eq "PONG") {
            Write-Host "Redis connection successful" -ForegroundColor Green
            return $true
        }
    }
    catch {
        Write-Host "Redis connection failed" -ForegroundColor Red
        return $false
    }
}

function Get-RedisInfo {
    Write-Host "Redis Information:" -ForegroundColor Cyan
    redis-cli -h $RedisHost -p $RedisPort INFO | Select-String -Pattern "^(redis_version|connected_clients|used_memory|total_commands_processed|keyspace_hits|keyspace_misses)" | ForEach-Object {
        Write-Host "  $_" -ForegroundColor Yellow
    }
}

function Get-RedisKeys {
    Write-Host "Redis Keys:" -ForegroundColor Cyan
    $keys = redis-cli -h $RedisHost -p $RedisPort KEYS "*"
    if ($keys) {
        foreach ($key in $keys) {
            $value = redis-cli -h $RedisHost -p $RedisPort GET $key
            $ttl = redis-cli -h $RedisHost -p $RedisPort TTL $key
            Write-Host "  Key: $key" -ForegroundColor Green
            Write-Host "    Value: $value" -ForegroundColor White
            Write-Host "    TTL: $ttl seconds" -ForegroundColor Gray
            Write-Host ""
        }
    } else {
        Write-Host "  No keys found" -ForegroundColor Yellow
    }
}

function Get-AgentStatus {
    Write-Host "Agent Status:" -ForegroundColor Cyan
    $agentKeys = redis-cli -h $RedisHost -p $RedisPort KEYS "agent:*"
    if ($agentKeys) {
        foreach ($key in $agentKeys) {
            $status = redis-cli -h $RedisHost -p $RedisPort GET $key
            $agentId = $key.Replace("agent:", "")
            Write-Host "  Agent: $agentId -> $status" -ForegroundColor Green
        }
    } else {
        Write-Host "  No agent status found" -ForegroundColor Yellow
    }
}

function Get-ThreatIntelligence {
    Write-Host "Threat Intelligence:" -ForegroundColor Cyan
    $threatKeys = redis-cli -h $RedisHost -p $RedisPort KEYS "threat:*"
    if ($threatKeys) {
        foreach ($key in $threatKeys) {
            $info = redis-cli -h $RedisHost -p $RedisPort GET $key
            Write-Host "  $key -> $info" -ForegroundColor Red
        }
    } else {
        Write-Host "  No threat intelligence found" -ForegroundColor Yellow
    }
}

function Get-SessionInfo {
    Write-Host "Session Information:" -ForegroundColor Cyan
    $sessionKeys = redis-cli -h $RedisHost -p $RedisPort KEYS "session:*"
    if ($sessionKeys) {
        foreach ($key in $sessionKeys) {
            $session = redis-cli -h $RedisHost -p $RedisPort GET $key
            Write-Host "  $key -> $session" -ForegroundColor Blue
        }
    } else {
        Write-Host "  No session information found" -ForegroundColor Yellow
    }
}

function Get-WebSocketConnections {
    Write-Host "WebSocket Connections:" -ForegroundColor Cyan
    $wsKey = "websocket:connections"
    $connections = redis-cli -h $RedisHost -p $RedisPort SMEMBERS $wsKey
    if ($connections) {
        foreach ($conn in $connections) {
            Write-Host "  Connection: $conn" -ForegroundColor Magenta
        }
    } else {
        Write-Host "  No WebSocket connections found" -ForegroundColor Yellow
    }
}

# Main execution
Write-Host "Redis Inspector for EDR System" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

if (Test-RedisConnection) {
    switch ($Action.ToLower()) {
        "info" {
            Get-RedisInfo
            Get-RedisKeys
        }
        "agents" {
            Get-AgentStatus
        }
        "threats" {
            Get-ThreatIntelligence
        }
        "sessions" {
            Get-SessionInfo
        }
        "websocket" {
            Get-WebSocketConnections
        }
        "all" {
            Get-RedisInfo
            Get-RedisKeys
            Get-AgentStatus
            Get-ThreatIntelligence
            Get-SessionInfo
            Get-WebSocketConnections
        }
        default {
            Write-Host "Usage: .\redis_inspector.ps1 -Action [info|agents|threats|sessions|websocket|all]" -ForegroundColor Yellow
        }
    }
} 