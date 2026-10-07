# =====================================================================
# deploy/deploy.ps1 - Deploy SCAP demo len VPS bang Docker (Windows PowerShell)
# Build image tren may nay, chuyen len VPS qua SSH, chay docker compose tren VPS.
#
#   .\deploy\deploy.ps1 setup-server -Server root@IP_VPS   # 1 lan: Docker, user deploy, UFW
#   .\deploy\deploy.ps1 configure -Domain demo.ten-mien.vn -Email ban@ten-mien.vn
#   .\deploy\deploy.ps1 configure -EdgeMode shared-proxy   # VPS da co app khac giu 80/443
#   .\deploy\deploy.ps1 deploy -Server deploy@IP_VPS       # moi lan cap nhat code
#   .\deploy\deploy.ps1 deploy -Server deploy@IP_VPS -SkipBuild   # chi doi cau hinh
#   .\deploy\deploy.ps1 admin  -Server deploy@IP_VPS       # tao tai khoan quan tri
#   .\deploy\deploy.ps1 status -Server deploy@IP_VPS
#   .\deploy\deploy.ps1 logs   -Server deploy@IP_VPS [-Follow]
#   .\deploy\deploy.ps1 backup -Server deploy@IP_VPS       # sao luu DB, tai ve backups\vps
#
# Dat $env:SCAP_VPS = "deploy@IP_VPS" de khong phai go -Server moi lan, va
# $env:SCAP_VPS_PORT = "2018" neu VPS dung cong SSH khac 22 (VPS 123HOST: 2018).
# Neu PowerShell chan script: powershell -ExecutionPolicy Bypass -File deploy\deploy.ps1 ...
# Chi tiet: docs/VPS_DEMO_DEPLOYMENT.md
# =====================================================================
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("setup-server", "configure", "deploy", "admin", "status", "logs", "backup")]
    [string]$Action,
    [string]$Server = $env:SCAP_VPS,
    [int]$Port = $(if ($env:SCAP_VPS_PORT) { [int]$env:SCAP_VPS_PORT } else { 22 }),
    [string]$Domain,
    [string]$Email,
    [ValidateSet("direct", "shared-proxy")]
    [string]$EdgeMode,
    [string]$DeployUser = "deploy",
    [string]$AdminUser = "operator",
    [string]$Platform = "linux/amd64",
    [switch]$SkipBuild,
    [switch]$Follow
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$OutDir = Join-Path $PSScriptRoot "out"
$EnvFile = Join-Path $PSScriptRoot ".env.vps"
$Python = Join-Path $Root ".venv\Scripts\python.exe"
# Build chi can app; tren VPS, vps-compose.sh tu them overlay theo SCAP_EDGE_MODE.
$ComposeArgs = @("compose", "--env-file", "deploy/.env.vps", "-p", "scap-vps-demo",
                 "-f", "docker-compose.yml", "-f", "docker-compose.vps-demo.yml")
$RemoteCompose = "bash scap-vps/vps-compose.sh"
$SshArgs = @("-p", "$Port")
# Script van hanh dat o ~/scap-vps; cau hinh di trong goi tar.
$RemoteScripts = @("deploy/remote-deploy.sh", "deploy/vps-compose.sh", "deploy/backup.sh", "deploy/restore.sh")
$BundleFiles = @("docker-compose.yml", "docker-compose.vps-demo.yml", "docker-compose.shared-proxy.yml",
                 "Caddyfile", "Caddyfile.shared-proxy", "deploy/shared-proxy-site.caddy", "scripts", "src")
# Image nen duoc ghim theo digest; tag phai khop docs/VPS_DEMO_DEPLOYMENT.md.
$BaseImages = [ordered]@{
    BASE_IMAGE     = "python:3.12-slim"
    POSTGRES_IMAGE = "postgres:17-alpine"
    REDIS_IMAGE    = "redis:7.4-alpine"
    CADDY_IMAGE    = "caddy:2.10-alpine"
}

function Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "  [OK] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  [!] $m" -ForegroundColor Yellow }
function Die($m)  { throw $m }

function Invoke-Checked([string]$File, [string[]]$Arguments, [string]$Failure) {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { Die "$Failure (ma loi $LASTEXITCODE)" }
}

# Windows PowerShell bien stderr cua lenh ngoai thanh loi khi redirect; tam tat Stop.
function Get-Output([string]$File, [string[]]$Arguments) {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $text = & $File @Arguments 2>$null
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $saved
    }
    if ($code -ne 0) { return $null }
    return ($text -join "`n").Trim()
}

# Chi doc cac gia tri cong khai (domain, ten image); khong in bi mat.
function Get-Setting([string]$Name) {
    $match = Select-String -Path $EnvFile -Pattern "^$Name=(.*)$" | Select-Object -First 1
    if ($match) { return $match.Matches[0].Groups[1].Value }
    return ""
}

function Assert-Server {
    if (-not $Server) { Die "Thieu -Server (vi du: -Server deploy@103.1.2.3) hoac bien SCAP_VPS." }
    if ($Server -notmatch '^([a-z_][a-z0-9_-]*@)?[A-Za-z0-9][A-Za-z0-9.-]*$') {
        Die "-Server phai co dang user@IP hoac user@ten-mien."
    }
}

function Assert-Python {
    if (-not (Test-Path $Python)) { Die "Chua co .venv - chay setup.ps1 truoc." }
}

function Assert-Docker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Die "Chua cai Docker Desktop." }
    $os = Get-Output docker @("info", "--format", "{{.OSType}}")
    if ($null -eq $os) { Die "Docker Desktop chua chay - mo Docker Desktop, doi bieu tuong xanh roi chay lai." }
    if ($os -ne "linux") { Die "Docker Desktop dang o Windows containers - chuyen sang Linux containers." }
}

# File chay tren Linux ma co CRLF se hong (bash, init script cua Postgres).
function Assert-LineEndings([string[]]$Paths) {
    foreach ($path in $Paths) {
        if ([IO.File]::ReadAllBytes((Join-Path $Root $path)) -contains 13) {
            Die "$path co xuong dong CRLF. Chay: git add --renormalize . ; git checkout -- $path"
        }
    }
}

function Compress-Gzip([string]$Source, [string]$Target) {
    $reader = [IO.File]::OpenRead($Source)
    try {
        $writer = [IO.File]::Create($Target)
        try {
            $gzip = New-Object IO.Compression.GZipStream($writer, [IO.Compression.CompressionLevel]::Optimal)
            try { $reader.CopyTo($gzip) } finally { $gzip.Dispose() }
        } finally { $writer.Dispose() }
    } finally { $reader.Dispose() }
}

Push-Location $Root
try {
    switch ($Action) {
        "setup-server" {
            Assert-Server
            Assert-LineEndings @("deploy/server-setup.sh")
            $key = Join-Path $HOME ".ssh\id_ed25519"
            if (-not (Test-Path "$key.pub")) {
                Step "Tao SSH key moi: $key"
                Warn "Nhan Enter 2 lan (khong dat passphrase) de cac lan deploy sau khong hoi lai."
                New-Item -ItemType Directory -Force (Split-Path $key) | Out-Null
                Invoke-Checked ssh-keygen @("-t", "ed25519", "-f", $key, "-C", "scap-deploy") "Khong tao duoc SSH key"
            }
            New-Item -ItemType Directory -Force $OutDir | Out-Null
            Copy-Item "$key.pub" (Join-Path $OutDir "scap-deploy-key.pub") -Force

            Step "Tai script cai dat len $Server (nhap mat khau VPS neu duoc hoi)"
            Invoke-Checked scp @("-P", "$Port", "deploy/server-setup.sh", "deploy/out/scap-deploy-key.pub", "${Server}:") "Khong upload duoc len VPS"

            Step "Cai Docker, tai khoan $DeployUser, swap, UFW tren VPS (mat vai phut)"
            $remote = 'if [ $(id -u) -eq 0 ]; then S=; else S=sudo; fi; $S bash server-setup.sh --deploy-user {0} --authorized-key scap-deploy-key.pub; rc=$?; rm -f server-setup.sh scap-deploy-key.pub; exit $rc' -f $DeployUser
            Invoke-Checked ssh ($SshArgs + @("-t", $Server, $remote)) "Cai dat VPS that bai"

            $target = "$DeployUser@" + $Server.Split("@")[-1]
            Step "Kiem tra dang nhap bang key: $target"
            Invoke-Checked ssh ($SshArgs + @("-o", "BatchMode=yes", $target, "docker compose version")) "Chua dang nhap duoc bang key (key co passphrase? hay thu: ssh $target)"
            Ok "VPS san sang. Tu gio dung: -Server $target"
            Write-Host "  Goi y: `$env:SCAP_VPS = `"$target`""
        }

        "configure" {
            Assert-Python
            Assert-Docker
            $cli = @("-m", "scripts.prepare_vps", "configure", "--project", ".")
            if ($Domain) { $cli += @("--domain", $Domain.ToLowerInvariant()) }
            if ($Email) { $cli += @("--email", $Email) }
            if ($EdgeMode) { $cli += @("--edge-mode", $EdgeMode) }

            Step "Ghim digest SHA-256 cho image nen (lay tu Docker Hub)"
            foreach ($name in $BaseImages.Keys) {
                $ref = $BaseImages[$name]
                $json = Get-Output docker @("buildx", "imagetools", "inspect", $ref, "--format", "{{json .Manifest}}")
                if (-not $json) { Die "Khong lay duoc digest cua $ref - kiem tra Internet." }
                $digest = ($json | ConvertFrom-Json).digest
                if ($digest -notmatch '^sha256:[0-9a-f]{64}$') { Die "Digest khong hop le cho $ref." }
                Ok "$name = $ref@$digest"
                $cli += @("--image", "$name=$ref@$digest")
            }

            Step "Cap nhat deploy/.env.vps (khoa bi mat giu nguyen)"
            Invoke-Checked $Python $cli "Cap nhat cau hinh that bai"
            & $Python -m scripts.prepare_vps check --project .
            if ($LASTEXITCODE -ne 0) { Die "Cau hinh van con thieu - xem danh sach o tren." }
            $publicDomain = Get-Setting "PUBLIC_DOMAIN"
            Ok "Cau hinh hop le cho https://$publicDomain (che do bien: $(Get-Setting 'SCAP_EDGE_MODE'))"
            Write-Host "  Nho tao ban ghi DNS A: $publicDomain -> IP cua VPS truoc khi deploy."
        }

        "deploy" {
            Assert-Server
            Assert-Python
            if (-not $SkipBuild) { Assert-Docker }
            Assert-LineEndings ($RemoteScripts + @("Caddyfile", "Caddyfile.shared-proxy",
                                  "docker-compose.yml", "docker-compose.vps-demo.yml",
                                  "docker-compose.shared-proxy.yml", "deploy/shared-proxy-site.caddy",
                                  "scripts/init_db_roles.sh", "scripts/db_least_privilege.sql"))

            Step "Kiem tra deploy/.env.vps"
            & $Python -m scripts.prepare_vps check --project .
            if ($LASTEXITCODE -ne 0) { Die "Chua du cau hinh - chay: .\deploy\deploy.ps1 configure -Domain ... -Email ..." }

            New-Item -ItemType Directory -Force $OutDir | Out-Null
            $uploads = $RemoteScripts + @("deploy/out/scap-deploy.tar")
            if (-not $SkipBuild) {
                Step "Build image ung dung cho $Platform"
                $savedPlatform = $env:DOCKER_DEFAULT_PLATFORM
                $env:DOCKER_DEFAULT_PLATFORM = $Platform
                try {
                    Invoke-Checked docker ($ComposeArgs + @("build", "app")) "Build image that bai"
                } finally {
                    $env:DOCKER_DEFAULT_PLATFORM = $savedPlatform
                }
                $image = Get-Setting "SCAP_APP_IMAGE"
                Step "Xuat va nen image $image"
                $tar = Join-Path $OutDir "scap-image.tar"
                Invoke-Checked docker @("image", "save", "-o", $tar, $image) "Khong xuat duoc image"
                Compress-Gzip $tar (Join-Path $OutDir "scap-image.tar.gz")
                Remove-Item $tar
                $uploads += "deploy/out/scap-image.tar.gz"
            }

            Step "Dong goi cau hinh Compose/Caddy/scripts"
            $tarExe = Join-Path $env:SystemRoot "System32\tar.exe"
            Invoke-Checked $tarExe (@("-cf", "deploy/out/scap-deploy.tar", "--exclude=__pycache__", "--exclude=*.pyc") +
                                    $BundleFiles) "Khong dong goi duoc cau hinh"

            Step "Upload len $Server"
            Invoke-Checked ssh ($SshArgs + @($Server, "install -d -m 700 scap-vps scap-vps/deploy")) "Khong ket noi duoc VPS"
            Invoke-Checked scp (@("-P", "$Port") + $uploads + @("${Server}:scap-vps/")) "Upload that bai"
            Invoke-Checked scp @("-P", "$Port", "deploy/.env.vps", "${Server}:scap-vps/deploy/.env.vps") "Upload cau hinh that bai"

            Step "Khoi dong tren VPS"
            Invoke-Checked ssh ($SshArgs + @($Server, "bash scap-vps/remote-deploy.sh")) "Deploy tren VPS that bai"
            Remove-Item -Force (Join-Path $OutDir "scap-*.tar*")
            Ok "Deploy xong: https://$(Get-Setting 'PUBLIC_DOMAIN')"
        }

        "admin" {
            Assert-Server
            if ($AdminUser -notmatch '^[A-Za-z0-9_.-]{3,64}$') { Die "Ten admin chi gom chu, so, . _ - (3-64 ky tu)." }
            Step "Tao tai khoan quan tri '$AdminUser' (mat khau 15-128 ky tu, nhap 2 lan, khong hien thi)"
            $remote = "$RemoteCompose run --rm --no-deps app /app/.venv/bin/python scripts/create_admin.py --username $AdminUser"
            Invoke-Checked ssh ($SshArgs + @("-t", $Server, $remote)) "Tao admin that bai"
            Ok "Da tao '$AdminUser'. Dang nhap roi bat MFA cho tai khoan nay."
        }

        "status" {
            Assert-Server
            Invoke-Checked ssh ($SshArgs + @($Server, "$RemoteCompose ps && docker stats --no-stream && free -m && df -h /")) "Khong lay duoc trang thai"
        }

        "logs" {
            Assert-Server
            $remote = "$RemoteCompose logs --tail 150"
            if ($Follow) { $remote += " --follow" }
            & ssh ($SshArgs + @("-t", $Server, $remote))
        }

        "backup" {
            Assert-Server
            Step "Sao luu PostgreSQL tren VPS"
            Invoke-Checked ssh ($SshArgs + @($Server, "bash scap-vps/backup.sh")) "Sao luu that bai"
            $latest = Get-Output ssh ($SshArgs + @($Server, "ls -1d scap-vps/backups/20*Z | tail -n 1"))
            if ($latest -notmatch '^scap-vps/backups/[0-9TZ]+$') { Die "Khong tim thay ban sao luu vua tao." }
            $localDir = Join-Path $Root "backups\vps"
            New-Item -ItemType Directory -Force $localDir | Out-Null
            Step "Tai $latest ve backups\vps (ban sao ngoai VPS)"
            Invoke-Checked scp @("-P", "$Port", "-r", "${Server}:$latest", "backups/vps/") "Tai ban sao luu that bai"
            Ok "Da luu backups\vps\$(Split-Path $latest -Leaf). Giu kem deploy\.env.vps de khoi phuc duoc."
        }
    }
} catch {
    Write-Host "  [X] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
} finally {
    Pop-Location
}
