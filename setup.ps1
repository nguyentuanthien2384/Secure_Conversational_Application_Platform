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

# ---------- 3. Dependency ----------
Step "3/5 Cai dependency (uv sync --group dev)"
uv sync --group dev
if ($LASTEXITCODE -ne 0) { Die "uv sync that bai - kiem tra ket noi Internet" }
Ok "Moi truong ao .venv da san sang"

# ---------- 4. Private local storage ----------
Step "4/5 Kiem tra cau hinh va kho luu tru private"
uv run python -m scripts.local_storage init
if ($LASTEXITCODE -ne 0) { Die "Khong the tao cau hinh an toan - xem huong dan o tren" }
Ok "Cau hinh local san sang; secrets khong di qua tham so lenh"

# ---------- 5. Test ----------
if ($Test) {
    Step "5/5 Kiem thu va quet bao mat"
    uv run pytest --cov=src.app --cov-report=term-missing
    if ($LASTEXITCODE -ne 0) { Die "Kiem thu that bai" }
    uv run ruff check src tests scripts
    if ($LASTEXITCODE -ne 0) { Die "Ruff bao loi" }
    uv run bandit -q -r src/app -ll -ii
    if ($LASTEXITCODE -ne 0) { Die "Bandit bao canh bao" }
} else {
    Step "5/5 Bo qua test (them -Test neu muon chay)"
}

Write-Host ""
Write-Host "========================================================" -ForegroundColor Green
Write-Host " CAI DAT XONG" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
Write-Host "  Giao dien web : http://127.0.0.1:8000"
Write-Host "  Swagger API   : http://127.0.0.1:8000/docs"
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
