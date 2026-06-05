
# ============================================================
# setup.ps1 — Threat Hunting Training Lab Setup
# Run this script as Administrator in PowerShell
# ============================================================
# This script will:
#   1. Check that Docker Desktop is installed and running
#   2. Pull the Wazuh Docker images
#   3. Generate SSL certificates for the Wazuh stack
#   4. Start all containers
#   5. Inject randomized training log data
#   6. Open the Wazuh Dashboard in your browser
# ============================================================
 
$ErrorActionPreference = "Stop"
 
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Threat Hunting Training Lab — Setup" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
 
# ── Step 1: Check Docker is installed ────────────────────
Write-Host "[1/6] Checking Docker Desktop..." -ForegroundColor Yellow
 
try {
    $dockerVersion = docker --version 2>&1
    Write-Host "      Found: $dockerVersion" -ForegroundColor Green
} catch {
    Write-Host ""
    Write-Host "  ERROR: Docker Desktop is not installed or not in PATH." -ForegroundColor Red
    Write-Host ""
    Write-Host "  Please install Docker Desktop first:" -ForegroundColor White
    Write-Host "  https://www.docker.com/products/docker-desktop/" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  After installing, restart your computer, then run this" -ForegroundColor White
    Write-Host "  script again." -ForegroundColor White
    Write-Host ""
    Read-Host "  Press Enter to exit"
    exit 1
}
 
# ── Step 2: Check Docker is running ──────────────────────
Write-Host "[2/6] Checking Docker is running..." -ForegroundColor Yellow
 
try {
    docker info 2>&1 | Out-Null
    Write-Host "      Docker is running." -ForegroundColor Green
} catch {
    Write-Host ""
    Write-Host "  ERROR: Docker Desktop is installed but not running." -ForegroundColor Red
    Write-Host ""
    Write-Host "  Please:" -ForegroundColor White
    Write-Host "  1. Open Docker Desktop from your Start menu" -ForegroundColor White
    Write-Host "  2. Wait for it to say 'Docker Desktop is running'" -ForegroundColor White
    Write-Host "  3. Run this script again" -ForegroundColor White
    Write-Host ""
    Read-Host "  Press Enter to exit"
    exit 1
}
 
# ── Step 3: Check memory ─────────────────────────────────
Write-Host "[3/6] Checking available RAM..." -ForegroundColor Yellow
 
$totalRAM = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB
$totalRAM = [math]::Round($totalRAM, 1)
 
if ($totalRAM -lt 7) {
    Write-Host ""
    Write-Host "  WARNING: You have ${totalRAM}GB RAM. Wazuh needs at least 8GB." -ForegroundColor Red
    Write-Host "  The lab may run slowly or fail to start." -ForegroundColor Red
    Write-Host ""
    $continue = Read-Host "  Continue anyway? (y/n)"
    if ($continue -ne "y") { exit 1 }
} else {
    Write-Host "      Found ${totalRAM}GB RAM — sufficient." -ForegroundColor Green
}
 
# ── Step 4: Navigate to lab directory ────────────────────
Write-Host "[4/6] Setting up lab directory..." -ForegroundColor Yellow
 
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir
Write-Host "      Working directory: $scriptDir" -ForegroundColor Green
 
# ── Step 5: Generate SSL certificates ────────────────────
Write-Host "[5/6] Generating SSL certificates for Wazuh..." -ForegroundColor Yellow
 
# Pull the cert generator image and run it
Write-Host "      Pulling Wazuh cert generator (this may take a few minutes)..." -ForegroundColor Gray
 
docker pull wazuh/wazuh-certs-generator:0.0.2 2>&1 | Out-Null
 
# Create config directory
New-Item -ItemType Directory -Force -Path ".\config\wazuh_indexer_ssl_certs" | Out-Null
 
# Write cert config
$certConfig = @"
nodes:
  indexer:
    - name: wazuh.indexer
      ip: wazuh.indexer
  server:
    - name: wazuh.manager
      ip: wazuh.manager
  dashboard:
    - name: wazuh.dashboard
      ip: wazuh.dashboard
"@
$certConfig | Out-File -FilePath ".\config\certs.yml" -Encoding UTF8
 
# Generate certs
docker run --rm `
    -v "${scriptDir}/config/wazuh_indexer_ssl_certs:/certificates" `
    -v "${scriptDir}/config/certs.yml:/config/certs.yml" `
    wazuh/wazuh-certs-generator:0.0.2 2>&1 | Out-Null
 
Write-Host "      SSL certificates generated." -ForegroundColor Green
 
# ── Step 6: Write Wazuh config files ─────────────────────
Write-Host "      Writing Wazuh configuration files..." -ForegroundColor Gray
 
# Indexer config
New-Item -ItemType Directory -Force -Path ".\config\wazuh_indexer" | Out-Null
@"
network.host: "0.0.0.0"
node.name: "wazuh.indexer"
cluster.initial_cluster_manager_nodes:
- "wazuh.indexer"
cluster.name: "wazuh-cluster"
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer
plugins.security.ssl.http.pemcert_filepath: certs/wazuh.indexer.pem
plugins.security.ssl.http.pemkey_filepath: certs/wazuh.indexer.key
plugins.security.ssl.http.pemtrustedcas_filepath: certs/root-ca.pem
plugins.security.ssl.transport.pemcert_filepath: certs/wazuh.indexer.pem
plugins.security.ssl.transport.pemkey_filepath: certs/wazuh.indexer.key
plugins.security.ssl.transport.pemtrustedcas_filepath: certs/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false
plugins.security.authcz.admin_dn:
- "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.check_snapshot_restore_write_privilege: true
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.nodes_dn:
- "CN=wazuh.indexer,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.restapi.roles_enabled:
- "all_access"
- "security_rest_api_access"
plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices: [".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opendistro-notifications-*", ".opendistro-notebooks", ".opensearch-observability", ".opendistro-asff-results*", ".opendistro-ism-*", ".opendistro-rollup-jobs", ".opensearch-sap-log-types*", ".opensearch-sap-detectors*", ".opensearch-sap-detectors-findings-*"]
compatibility.override_main_response_version: true
"@ | Out-File -FilePath ".\config\wazuh_indexer\wazuh.indexer.yml" -Encoding UTF8
 
# Internal users (hashed password for 'SecretPassword')
@"
_meta:
  type: "internalusers"
  config_version: 2
admin:
  hash: "`$2y`$12`$K/SpwjtB.wOHJ/Nc0.kEueFGMf1FApTW0zSgN2LVXeRhcB29DQBkC"
  reserved: true
  backend_roles:
  - "admin"
  description: "Admin user"
kibanaserver:
  hash: "`$2a`$12`$4AcgAt3xwOWadA5s5blL6ev39OXDNhmOesEoo33eZtrq2N0YrU3H."
  reserved: true
  description: "OpenSearch Dashboards user"
"@ | Out-File -FilePath ".\config\wazuh_indexer\internal_users.yml" -Encoding UTF8
 
# Dashboard config
New-Item -ItemType Directory -Force -Path ".\config\wazuh_dashboard" | Out-Null
@"
server.host: 0.0.0.0
server.port: 5601
opensearch.hosts: https://wazuh.indexer:9200
opensearch.ssl.verificationMode: certificate
opensearch.requestHeadersWhitelist: ["securitytenant","Authorization"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
server.ssl.enabled: true
server.ssl.key: "/usr/share/wazuh-dashboard/certs/wazuh-dashboard-key.pem"
server.ssl.certificate: "/usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem"
opensearch.ssl.certificateAuthorities: ["/usr/share/wazuh-dashboard/certs/root-ca.pem"]
uiSettings.overrides.defaultRoute: /app/wazuh
"@ | Out-File -FilePath ".\config\wazuh_dashboard\opensearch_dashboards.yml" -Encoding UTF8
 
@"
hosts:
  - default:
      url: https://wazuh.manager
      port: 55000
      username: wazuh-wui
      password: "MyS3cr37P450r.*-"
      run_as: false
"@ | Out-File -FilePath ".\config\wazuh_dashboard\wazuh.yml" -Encoding UTF8
 
# Manager config
New-Item -ItemType Directory -Force -Path ".\config\wazuh_cluster" | Out-Null
@"
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>smtp.example.wazuh.com</smtp_server>
    <email_from>wazuh@example.wazuh.com</email_from>
    <email_to>recipient@example.wazuh.com</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <agents_disconnection_time>1m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
  </global>
  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>
  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>
</ossec_config>
"@ | Out-File -FilePath ".\config\wazuh_cluster\wazuh_manager.conf" -Encoding UTF8
 
Write-Host "      Configuration files written." -ForegroundColor Green
 
# ── Step 7: Start containers ──────────────────────────────
Write-Host "[6/6] Starting Wazuh containers..." -ForegroundColor Yellow
Write-Host "      This will take 3-5 minutes on first run." -ForegroundColor Gray
Write-Host "      Docker is downloading Wazuh images (~2GB total)." -ForegroundColor Gray
Write-Host ""
 
docker-compose up -d 2>&1
 
Write-Host ""
Write-Host "      Containers started. Waiting for Wazuh to initialize..." -ForegroundColor Gray
 
# Wait for dashboard to be ready
$maxWait = 180
$waited  = 0
Write-Host "      Checking dashboard health (up to ${maxWait}s)..." -ForegroundColor Gray
 
while ($waited -lt $maxWait) {
    try {
        $response = Invoke-WebRequest -Uri "https://localhost" -SkipCertificateCheck -TimeoutSec 5 -UseBasicParsing 2>&1
        if ($response.StatusCode -eq 200) {
            Write-Host "      Wazuh Dashboard is ready!" -ForegroundColor Green
            break
        }
    } catch { }
    Start-Sleep -Seconds 10
    $waited += 10
    Write-Host "      Still waiting... ($waited/${maxWait}s)" -ForegroundColor Gray
}
 
# ── Done ──────────────────────────────────────────────────
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  LAB IS READY" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Wazuh Dashboard : https://localhost" -ForegroundColor White
Write-Host "  Username        : admin" -ForegroundColor White
Write-Host "  Password        : SecretPassword" -ForegroundColor White
Write-Host ""
Write-Host "  Training events have been injected." -ForegroundColor White
Write-Host "  Check the console output of the log-injector" -ForegroundColor White
Write-Host "  container for this session's IoC values:" -ForegroundColor White
Write-Host ""
Write-Host "  docker logs log-injector" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Opening dashboard in browser..." -ForegroundColor Gray
 
Start-Sleep -Seconds 2
Start-Process "https://localhost"
 
Write-Host ""
Write-Host "  To stop the lab when finished:" -ForegroundColor Yellow
Write-Host "  docker-compose down" -ForegroundColor Cyan
Write-Host ""
Read-Host "  Press Enter to close this window"
 
