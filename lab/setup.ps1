
# ============================================================
# setup.ps1 — Threat Hunting Training Lab Setup
# ============================================================
# HOW TO RUN:
# Right-click this file and select "Run with PowerShell"
# OR open PowerShell and type: .\setup.ps1
# ============================================================
 
# Keep window open on ANY error so you can read it
$ErrorActionPreference = "Continue"
trap {
    Write-Host ""
    Write-Host "ERROR: $_" -ForegroundColor Red
    Write-Host ""
    Read-Host "Press Enter to close"
    exit 1
}
 
function Pause-AndExit {
    Write-Host ""
    Read-Host "Press Enter to close"
    exit 1
}
 
Clear-Host
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Threat Hunting Training Lab — Setup" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
 
# ── Step 1: Check Docker ──────────────────────────────────
Write-Host "[1/5] Checking Docker Desktop..." -ForegroundColor Yellow
 
$dockerCheck = Get-Command docker -ErrorAction SilentlyContinue
if (-not $dockerCheck) {
    Write-Host ""
    Write-Host "  ERROR: Docker not found." -ForegroundColor Red
    Write-Host ""
    Write-Host "  Please install Docker Desktop first:" -ForegroundColor White
    Write-Host "  https://www.docker.com/products/docker-desktop/" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  After installing, restart your computer then run this script again." -ForegroundColor White
    Pause-AndExit
}
 
Write-Host "      Docker found." -ForegroundColor Green
 
# Check Docker is actually running
$dockerRunning = docker info 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "  ERROR: Docker Desktop is installed but not running." -ForegroundColor Red
    Write-Host ""
    Write-Host "  Please:" -ForegroundColor White
    Write-Host "  1. Open Docker Desktop from your Start menu" -ForegroundColor White
    Write-Host "  2. Wait for it to say 'Engine running' at the bottom" -ForegroundColor White
    Write-Host "  3. Run this script again" -ForegroundColor White
    Pause-AndExit
}
 
Write-Host "      Docker is running." -ForegroundColor Green
 
# ── Step 2: Set working directory ────────────────────────
Write-Host "[2/5] Setting working directory..." -ForegroundColor Yellow
 
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptDir) {
    $scriptDir = Get-Location
}
Set-Location $scriptDir
Write-Host "      Working in: $scriptDir" -ForegroundColor Green
 
# ── Step 3: Check RAM ─────────────────────────────────────
Write-Host "[3/5] Checking available RAM..." -ForegroundColor Yellow
 
$totalRAM = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB
$totalRAM = [math]::Round($totalRAM, 1)
Write-Host "      Found: ${totalRAM}GB RAM" -ForegroundColor Green
 
if ($totalRAM -lt 7) {
    Write-Host "      WARNING: Less than 8GB RAM detected. Wazuh may run slowly." -ForegroundColor Red
    $cont = Read-Host "      Continue anyway? (y/n)"
    if ($cont -ne "y") { Pause-AndExit }
}
 
# ── Step 4: Create a simple docker-compose ───────────────
Write-Host "[4/5] Writing simplified Wazuh configuration..." -ForegroundColor Yellow
 
# Use the official Wazuh single-node deployment (much simpler than custom certs)
$composeContent = @"
version: '3.8'
services:
  wazuh:
    image: wazuh/wazuh-odfe:4.3.10
    container_name: wazuh-training
    restart: always
    ports:
      - "443:443"
      - "1514:1514"
      - "1515:1515"
      - "55000:55000"
    environment:
      - ELASTICSEARCH_URL=https://elasticsearch:9200
      - ELASTIC_USERNAME=admin
      - ELASTIC_PASSWORD=SecretPassword
    volumes:
      - wazuh-data:/var/ossec/data
      - wazuh-logs:/var/ossec/logs
    healthcheck:
      test: ["CMD", "curl", "-f", "-k", "https://localhost/app/wazuh"]
      interval: 30s
      timeout: 10s
      retries: 10
 
  elasticsearch:
    image: amazon/opendistro-for-elasticsearch:1.13.3
    container_name: wazuh-elasticsearch
    restart: always
    environment:
      - discovery.type=single-node
      - opendistro_security.ssl.http.enabled=false
      - ELASTIC_PASSWORD=SecretPassword
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - elasticsearch-data:/usr/share/elasticsearch/data
 
  kibana:
    image: wazuh/wazuh-kibana-odfe:4.3.10
    container_name: wazuh-kibana
    restart: always
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_URL=https://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=admin
      - ELASTICSEARCH_PASSWORD=SecretPassword
    depends_on:
      - elasticsearch
      - wazuh
 
  log-injector:
    image: python:3.11-slim
    container_name: log-injector
    volumes:
      - ./inject-logs.py:/inject-logs.py
    environment:
      - INDEXER_URL=http://elasticsearch:9200
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=SecretPassword
    command: >
      sh -c "pip install requests urllib3 --quiet &&
             sleep 90 &&
             python /inject-logs.py"
    depends_on:
      - elasticsearch
 
volumes:
  wazuh-data:
  wazuh-logs:
  elasticsearch-data:
"@
 
$composeContent | Out-File -FilePath ".\docker-compose-simple.yml" -Encoding UTF8
Write-Host "      Configuration written." -ForegroundColor Green
 
# ── Step 5: Start containers ──────────────────────────────
Write-Host "[5/5] Starting Wazuh containers..." -ForegroundColor Yellow
Write-Host "      This will take 5-10 minutes on first run." -ForegroundColor Gray
Write-Host "      Docker is downloading Wazuh images (~3GB total)." -ForegroundColor Gray
Write-Host "      DO NOT close this window." -ForegroundColor Yellow
Write-Host ""
 
docker-compose -f docker-compose-simple.yml up -d
 
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "  ERROR: docker-compose failed to start." -ForegroundColor Red
    Write-Host "  Make sure Docker Desktop is fully running and try again." -ForegroundColor White
    Pause-AndExit
}
 
Write-Host ""
Write-Host "  Containers are starting. Waiting for Wazuh to be ready..." -ForegroundColor Gray
Write-Host "  This takes about 3-5 minutes. Please wait." -ForegroundColor Gray
Write-Host ""
 
$maxWait = 300
$waited = 0
$ready = $false
 
while ($waited -lt $maxWait) {
    Start-Sleep -Seconds 15
    $waited += 15
    Write-Host "  Waiting... ($waited seconds elapsed)" -ForegroundColor Gray
 
    try {
        $response = Invoke-WebRequest -Uri "https://localhost" -SkipCertificateCheck -TimeoutSec 5 -UseBasicParsing 2>$null
        if ($response.StatusCode -eq 200) {
            $ready = $true
            break
        }
    } catch { }
}
 
Write-Host ""
 
if ($ready) {
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "  LAB IS READY" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Wazuh Dashboard : https://localhost" -ForegroundColor White
    Write-Host "  Username        : admin" -ForegroundColor White
    Write-Host "  Password        : SecretPassword" -ForegroundColor White
    Write-Host ""
    Write-Host "  Get your training IoC values:" -ForegroundColor Yellow
    Write-Host "  docker logs log-injector" -ForegroundColor Cyan
    Write-Host ""
    Start-Process "https://localhost"
} else {
    Write-Host "  Wazuh is still starting up." -ForegroundColor Yellow
    Write-Host "  Try opening https://localhost in your browser in a few minutes." -ForegroundColor White
    Write-Host ""
    Write-Host "  Username : admin" -ForegroundColor White
    Write-Host "  Password : SecretPassword" -ForegroundColor White
}
 
Write-Host ""
Write-Host "  To stop the lab when finished:" -ForegroundColor Yellow
Write-Host "  docker-compose -f docker-compose-simple.yml down" -ForegroundColor Cyan
Write-Host ""
Read-Host "Press Enter to close this window"
