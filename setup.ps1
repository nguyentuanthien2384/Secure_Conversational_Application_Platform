# =====================================================================
# setup.ps1 - Cai dat & chay du an bang 1 lenh (Windows PowerShell)
#   powershell -ExecutionPolicy Bypass -File setup.ps1
#   powershell -ExecutionPolicy Bypass -File setup.ps1 -Test
#   powershell -ExecutionPolicy Bypass -File setup.ps1 -NoRun
# =====================================================================
param(
    [switch]$Test,
    [switch]$NoRun
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

function Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "  [OK] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  [!] $m"  -ForegroundColor Yellow }
function Die($m)  { Write-Host "  [X] $m"  -ForegroundColor Red; exit 1 }

# ---------- 1. Python ----------
Step "1/5 Kiem tra Python"
if (Get-Command python -ErrorAction SilentlyContinue) {
    Ok ((python --version) -join "")
} else {
    Warn "Chua co Python - uv se tu tai Python 3.12 rieng cho du an."
}

# ---------- 2. uv ----------
Step "2/5 Kiem tra uv (trinh quan ly package)"
$env:Path = "$env:USERPROFILE\.local\bin;$env:Path"
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Warn "Chua co uv - dang cai (can Internet)..."
    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
    $env:Path = "$env:USERPROFILE\.local\bin;$env:Path"
}
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Die "Khong cai duoc uv. Xem https://docs.astral.sh/uv/getting-started/installation/"
}
Ok ((uv --version) -join "")

# ---------- 3. .env ----------
Step "3/5 Kiem tra cau hinh .env"
if (Test-Path ".env") {
    Ok ".env da ton tai - giu nguyen"
} else {
    Copy-Item ".env.example" ".env"
    Warn "Da tao .env - dang sinh secrets ngau nhien..."
    $bytes1 = New-Object byte[] 48
    $bytes2 = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes1); $rng.GetBytes($bytes2)
    $appSecret = [Convert]::ToBase64String($bytes1).Replace('+','-').Replace('/','_').TrimEnd('=')
    $masterKey = [Convert]::ToBase64String($bytes2).Replace('+','-').Replace('/','_')
    $lines = Get-Content ".env"
    $out = foreach ($line in $lines) {
        if     ($line -like "APP_SECRET_KEY=*")        { "APP_SECRET_KEY=$appSecret" }
        elseif ($line -like "MASTER_ENCRYPTION_KEY=*") { "MASTER_ENCRYPTION_KEY=$masterKey" }
        elseif ($line -like "SEED_DEMO_DATA=*")        { "SEED_DEMO_DATA=true" }
        else                                           { $line }
    }
    if (-not ($out -like "SEED_DEMO_DATA=*")) { $out += "SEED_DEMO_DATA=true" }
    $out | Set-Content ".env" -Encoding UTF8
    Ok "Da sinh APP_SECRET_KEY va MASTER_ENCRYPTION_KEY"
}

# ---------- 4. Dependency ----------
Step "4/5 Cai dependency (uv sync --group dev)"
uv sync --group dev
if ($LASTEXITCODE -ne 0) { Die "uv sync that bai - kiem tra ket noi Internet" }
Ok "Moi truong ao .venv da san sang"

# ---------- 5. Test ----------
if ($Test) {
    Step "5/5 Kiem thu va quet bao mat"
    uv run pytest --cov=src.app --cov-report=term-missing
    uv run ruff check src/app tests scripts/migrate_database.py
    uv run bandit -q -r src/app -ll -ii
} else {
    Step "5/5 Bo qua test (them -Test neu muon chay)"
}

Write-Host ""
Write-Host "========================================================" -ForegroundColor Green
Write-Host " CAI DAT XONG" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
Write-Host "  Giao dien web : http://127.0.0.1:8000"
Write-Host "  Swagger API   : http://127.0.0.1:8000/docs"
Write-Host "  SPA tinh      : http://127.0.0.1:8000/spa"
Write-Host ""
Write-Host "  Tai khoan demo (mat khau chung: Phenikaa-Vault#2026-Lab)"
Write-Host "    demo.user  - user"
Write-Host "    demo.mod   - moderator"
Write-Host "    demo.boss  - admin"
Write-Host "  Admin bootstrap: xem BOOTSTRAP_ADMIN_* trong file .env"
Write-Host ""

if (-not $NoRun) {
    Step "Dang khoi dong server... (Ctrl+C de dung)"
    uv run python run_app.py
} else {
    Write-Host "  Chay server bang: uv run python run_app.py"
}
