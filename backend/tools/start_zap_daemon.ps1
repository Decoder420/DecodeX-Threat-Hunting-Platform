# Start OWASP ZAP in daemon mode for the Threat Hunting Platform web scanner.
# Usage: powershell -ExecutionPolicy Bypass -File .\start_zap_daemon.ps1

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$ZapHome = Join-Path $Root "zap\ZAP_2.17.0"
$ZapBat = Join-Path $ZapHome "zap.bat"
$KeyFile = Join-Path $Root "zap_api_key.txt"
$Log = Join-Path $Root "zap\zap-daemon.log"
$Port = 8080
$HostAddr = "127.0.0.1"

if (-not (Test-Path $ZapBat)) {
  throw "ZAP not found at $ZapBat. Extract ZAP_2.17.0 Crossplatform zip under tools\zap first."
}

if (-not (Test-Path $KeyFile)) {
  $key = -join ((1..32) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) })
  Set-Content -Path $KeyFile -Value $key -NoNewline
} else {
  $key = (Get-Content $KeyFile -Raw).Trim()
}

$existing = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($existing) {
  Write-Host "Port $Port already in use (PID $($existing.OwningProcess | Select-Object -First 1)). Checking ZAP API..."
} else {
  $args = @(
    "-daemon",
    "-host", $HostAddr,
    "-port", "$Port",
    "-config", "api.key=$key",
    "-config", "api.addrs.addr.name=.*",
    "-config", "api.addrs.addr.regex=true"
  )
  Write-Host "Starting ZAP daemon on http://${HostAddr}:$Port ..."
  Start-Process -FilePath $ZapBat -ArgumentList $args -WorkingDirectory $ZapHome -WindowStyle Hidden `
    -RedirectStandardOutput $Log -RedirectStandardError "$Log.err" | Out-Null
}

$ready = $false
for ($i = 0; $i -lt 60; $i++) {
  try {
    $uri = "http://${HostAddr}:$Port/JSON/core/view/version/?apikey=$key"
    $r = Invoke-RestMethod -Uri $uri -TimeoutSec 3
    if ($r.version) {
      Write-Host "ZAP READY version=$($r.version)"
      $ready = $true
      break
    }
  } catch {
    Start-Sleep -Seconds 2
  }
}

if (-not $ready) {
  throw "ZAP did not become ready on port $Port. Check $Log"
}

Write-Host ""
Write-Host "Set in backend/.env:"
Write-Host "  ZAP_ENABLED=true"
Write-Host "  ZAP_URL=http://${HostAddr}:$Port"
Write-Host "  ZAP_API_KEY=$key"
Write-Host "Then restart the Flask backend."
