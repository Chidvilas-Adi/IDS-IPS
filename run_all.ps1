$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

if (-not (Test-Path ".env")) {
    throw ".env is missing. Copy .env.example to .env and configure it first."
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator to enable packet capture and firewall actions."
}

$env:POSTGRES_HOST = "localhost"
$env:DATABASE_URL = ""
$env:MONGO_HOST = "localhost"
$env:REDIS_HOST = "localhost"
$env:API_PORT = "1234"

Write-Host "Starting PostgreSQL, MongoDB, and Redis..."
docker compose up -d --wait postgres mongodb redis
if ($LASTEXITCODE -ne 0) {
    throw "Database services failed. Inspect them with: docker compose logs postgres mongodb redis"
}

Write-Host "Applying the PostgreSQL schema and migrations..."
docker compose run --rm schema
if ($LASTEXITCODE -ne 0) {
    throw "PostgreSQL schema application failed."
}

docker compose up -d --no-deps --wait api
if ($LASTEXITCODE -ne 0) {
    throw "API failed to start. Inspect it with: docker compose logs api"
}

Write-Host "Building and starting the React dashboard and HTTPS gateway..."
docker compose up -d --build --wait gui nginx
if ($LASTEXITCODE -ne 0) {
    throw "Dashboard or gateway failed to start. Inspect them with: docker compose logs gui nginx"
}

if (-not (Test-Path "$projectRoot\engine\.venv\Scripts\python.exe")) {
    py -3 -m venv "$projectRoot\engine\.venv"
    if ($LASTEXITCODE -ne 0) {
        throw "Python 3 is required to create engine\.venv."
    }
}

$bridgePython = "$projectRoot\engine\.venv\Scripts\python.exe"
& $bridgePython -m pip install -r "$projectRoot\engine\requirements-bridge.txt"
if ($LASTEXITCODE -ne 0) {
    throw "Could not install packet-adapter requirements."
}

$bridge = Start-Process -FilePath $bridgePython -ArgumentList "-u pure_db_socket_bridge.py" -WorkingDirectory "$projectRoot\engine" -PassThru
Start-Process "https://localhost:8443"

Write-Host "API container: idsips_api"
Write-Host "Packet adapter PID: $($bridge.Id)"
Write-Host "Dashboard: https://localhost:8443"
