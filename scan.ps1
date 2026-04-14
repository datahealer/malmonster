# Malware IOC Scanner — supply-chain/npm loader family
# Based on real incident: blockchain-fetched stage-2 node payload
# Safe: read-only, no network, no destructive actions
# Supports: Windows (PowerShell 5.1+ / PowerShell 7+)
# Usage: powershell -ExecutionPolicy Bypass -File scan.ps1 [-CodeDir C:\path\to\projects]

param(
    [string]$CodeDir = $env:USERPROFILE
)

# ── Colours ────────────────────────────────────────────────────────────────────
function Write-Alert  { param($msg) Write-Host "[ALERT] $msg" -ForegroundColor Red;    $script:Hits++ }
function Write-Warn   { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow; $script:Warns++ }
function Write-Ok     { param($msg) Write-Host "[OK]    $msg" -ForegroundColor Green }
function Write-Info   { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-Hdr    { param($msg) Write-Host "`n━━━ $msg ━━━" -ForegroundColor White }

$script:Hits  = 0
$script:Warns = 0

Write-Host "Malware IOC Scanner — $(Get-Date)" -ForegroundColor White
Write-Host "Running as: $env:USERNAME on $env:COMPUTERNAME"
Write-Host "Scanning code under: $CodeDir"

# ── 1. Suspicious Node Processes ──────────────────────────────────────────────
Write-Hdr "1. Suspicious Node Processes (inline eval)"

$nodeProcs = Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue
if (-not $nodeProcs) {
    Write-Ok "No node.exe processes running"
} else {
    foreach ($proc in $nodeProcs) {
        $cmd = $proc.CommandLine
        $pid_ = $proc.ProcessId
        $ppid = $proc.ParentProcessId
        $parent = (Get-CimInstance Win32_Process -Filter "ProcessId = $ppid" -ErrorAction SilentlyContinue).CommandLine

        # Get process start time
        $started = $proc.CreationDate

        # Inline eval: node -e "..."
        if ($cmd -match 'node\s+-e\s') {
            Write-Alert "Suspicious 'node -e' inline process found:"
            Write-Host "    PID     : $pid_"
            Write-Host "    Started : $started"
            Write-Host "    Command : $($cmd.Substring(0, [Math]::Min(120, $cmd.Length)))..."
            Write-Host "    Parent  : PPID $ppid -> $($parent -replace "`n",' ')" -ForegroundColor Red
        } else {
            Write-Info "node.exe PID $pid_ (started $started)"
            Write-Host "    Command : $($cmd.Substring(0, [Math]::Min(100, $cmd.Length)))"
            Write-Host "    Parent  : PPID $ppid -> $parent"
        }
    }
}

# ── 2. Node Process Working Directories ───────────────────────────────────────
Write-Hdr "2. Node Process Working Directories"

$nodeProcs2 = Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue
if ($nodeProcs2) {
    foreach ($proc in $nodeProcs2) {
        $pid_ = $proc.ProcessId
        # Get working directory via the process handle
        try {
            $handle = [System.Diagnostics.Process]::GetProcessById($pid_)
            $cwd = $handle.MainModule.FileName  # fallback — exe path
            # More reliable: WMI doesn't expose cwd directly; use handle path as indicator
        } catch { $cwd = "(access denied or process exited)" }

        $marker = if ($proc.CommandLine -match 'node\s+-e') { " [ALERT: inline eval]" } else { "" }
        Write-Host "    PID $pid_$marker"
        Write-Host "    Started : $($proc.CreationDate)"
        Write-Host "    Command : $($proc.CommandLine.Substring(0, [Math]::Min(100,$proc.CommandLine.Length)))"
        Write-Host ""
    }
} else {
    Write-Ok "No node.exe processes found"
}

# ── 3. Open Network Connections from Node ─────────────────────────────────────
Write-Hdr "3. Open Network Connections from Node"

$nodePids = (Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue).ProcessId
if ($nodePids) {
    $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
        $nodePids -contains $_.OwningProcess -and $_.State -eq 'Established'
    }
    $outbound = $conns | Where-Object {
        $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0)'
    }
    $listen = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
        $nodePids -contains $_.OwningProcess -and $_.State -eq 'Listen'
    }

    if ($outbound) {
        Write-Alert "Outbound node connections (potential exfiltration):"
        foreach ($c in $outbound) {
            $line = "    PID $($c.OwningProcess) -> $($c.RemoteAddress):$($c.RemotePort)"
            # Highlight MongoDB (27017) and suspicious HTTPS (443) connections
            if ($c.RemotePort -eq 27017 -or $c.RemotePort -eq 443) {
                Write-Host "  !! $line" -ForegroundColor Red
            } else {
                Write-Host $line
            }
        }
    } else {
        Write-Ok "No suspicious outbound node connections"
    }
    if ($listen) {
        Write-Info "Node LISTEN ports (dev servers, likely fine):"
        foreach ($c in $listen) {
            Write-Host "    PID $($c.OwningProcess) LISTEN :$($c.LocalPort)"
        }
    }
} else {
    Write-Ok "No node.exe processes — skipping network check"
}

# ── 4. Malware Blockchain C2 Domains ──────────────────────────────────────────
Write-Hdr "4. Malware Blockchain C2 Domains (live connection check)"

$malwareDomains = @(
    "api.trongrid.io",
    "fullnode.mainnet.aptoslabs.com",
    "bsc-dataseed.binance.org",
    "bsc-rpc.publicnode.com"
)

# Resolve each domain to IPs, then check active connections
foreach ($domain in $malwareDomains) {
    try {
        $ips = [System.Net.Dns]::GetHostAddresses($domain) | Select-Object -ExpandProperty IPAddressToString
        $hit = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
            $ips -contains $_.RemoteAddress -and $_.State -eq 'Established'
        }
        if ($hit) {
            Write-Alert "LIVE connection to malware C2 domain: $domain"
            foreach ($c in $hit) {
                Write-Host "    PID $($c.OwningProcess) -> $($c.RemoteAddress):$($c.RemotePort)" -ForegroundColor Red
            }
        } else {
            Write-Ok "No live connection to $domain"
        }
    } catch {
        Write-Info "Could not resolve $domain (offline or DNS blocked — that's OK)"
    }
}

# ── 5. Persistence Mechanisms ─────────────────────────────────────────────────
Write-Hdr "5. Persistence Mechanisms"

# 5a. Scheduled Tasks referencing node/npm
Write-Info "Checking Scheduled Tasks for node/npm references..."
$suspTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.Actions | Where-Object {
        ($_.Execute -match 'node|npm|npx') -or ($_.Arguments -match 'node\s+-e|atob|eval')
    }
}
if ($suspTasks) {
    foreach ($t in $suspTasks) {
        Write-Alert "Suspicious Scheduled Task: $($t.TaskPath)$($t.TaskName)"
        $t.Actions | ForEach-Object { Write-Host "    Execute : $($_.Execute) $($_.Arguments)" -ForegroundColor Red }
    }
} else {
    Write-Ok "No suspicious scheduled tasks found"
}

# 5b. Run/RunOnce registry keys
Write-Info "Checking registry Run keys for node/npm entries..."
$runKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($key in $runKeys) {
    if (Test-Path $key) {
        $vals = Get-ItemProperty $key -ErrorAction SilentlyContinue
        $vals.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            if ($_.Value -match 'node|npm|npx|atob|eval') {
                Write-Alert "Suspicious Run key in $key`:"
                Write-Host "    $($_.Name) = $($_.Value)" -ForegroundColor Red
            }
        }
    }
}
Write-Ok "Registry Run keys scanned"

# 5c. Startup folder
Write-Info "Checking startup folders..."
$startupDirs = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($dir in $startupDirs) {
    if (Test-Path $dir) {
        $items = Get-ChildItem $dir -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            $content = Get-Content $item.FullName -ErrorAction SilentlyContinue -Raw
            if ($content -match 'node|npm|atob|eval') {
                Write-Alert "Suspicious startup item: $($item.FullName)"
            } else {
                Write-Info "  Startup: $($item.Name)"
            }
        }
    }
}

# ── 6. Shell Startup File Tampering ───────────────────────────────────────────
Write-Hdr "6. Shell Profile Tampering (PowerShell)"

$profileFiles = @(
    $PROFILE.CurrentUserCurrentHost,
    $PROFILE.CurrentUserAllHosts,
    $PROFILE.AllUsersCurrentHost,
    $PROFILE.AllUsersAllHosts
)
foreach ($f in $profileFiles) {
    if ($f -and (Test-Path $f)) {
        $content = Get-Content $f -ErrorAction SilentlyContinue -Raw
        if ($content -match 'Invoke-Expression|iex\s|node\s+-e|atob|[Cc]onvert[Ff]rom[Bb]ase64') {
            Write-Alert "Suspicious content in PowerShell profile: $f"
            Select-String -Path $f -Pattern 'Invoke-Expression|iex\s|node\s+-e|atob|ConvertFromBase64' |
                ForEach-Object { Write-Host "    Line $($_.LineNumber): $($_.Line.Trim())" -ForegroundColor Red }
        } else {
            $age = (Get-Date) - (Get-Item $f).LastWriteTime
            if ($age.TotalDays -le 30) {
                Write-Warn "$f modified $([int]$age.TotalDays) days ago — review if unexpected"
            } else {
                Write-Ok "$f clean (modified $([int]$age.TotalDays) days ago)"
            }
        }
    }
}

# ── 7. Sensitive Credentials (exposure check) ─────────────────────────────────
Write-Hdr "7. Sensitive Credentials (exposure check)"

$sensitiveFiles = @(
    "$env:USERPROFILE\.ssh\id_rsa",
    "$env:USERPROFILE\.ssh\id_ed25519",
    "$env:USERPROFILE\.ssh\id_ecdsa",
    "$env:USERPROFILE\.aws\credentials",
    "$env:USERPROFILE\.npmrc",
    "$env:USERPROFILE\.gitconfig",
    "$env:USERPROFILE\.netrc",
    "$env:USERPROFILE\.docker\config.json"
)
$foundSensitive = $false
foreach ($f in $sensitiveFiles) {
    if (Test-Path $f) {
        $mtime = (Get-Item $f).LastWriteTime.ToString("yyyy-MM-dd")
        Write-Warn "Exposed: $f (modified $mtime) — rotate credentials from a clean machine"
        $foundSensitive = $true
    }
}
if (-not $foundSensitive) { Write-Ok "No common credential files found" }

# ── 8. Config & Source Files with Injected Eval/Atob ─────────────────────────
Write-Hdr "8. Config & Source Files with Injected Eval/Atob"
Write-Info "Scanning $CodeDir for malware injection patterns..."

$malwarePattern = 'eval\s*\(.*atob\(|atob\s*\(|child_process.*spawn|global\[.r.\]\s*=\s*require'
$configPatterns = @('next.config.*','vite.config.*','webpack.config.*','*.config.js','*.config.ts','*.config.mjs')

foreach ($pat in $configPatterns) {
    Get-ChildItem -Path $CodeDir -Filter $pat -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\(node_modules|\.git)\\' } |
        ForEach-Object {
            $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -match $malwarePattern) {
                Write-Alert "INFECTED config: $($_.FullName)"
                Select-String -Path $_.FullName -Pattern $malwarePattern |
                    Select-Object -First 3 |
                    ForEach-Object { Write-Host "    Line $($_.LineNumber): $($_.Line.Trim())" -ForegroundColor Red }
            }
        }
}

# Scan all JS/TS source files outside node_modules
$infectedSrc = Get-ChildItem -Path $CodeDir -Include '*.js','*.ts','*.mjs' -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\(node_modules|\.git)\\' } |
    Where-Object {
        $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
        $content -match $malwarePattern
    }

if ($infectedSrc) {
    foreach ($src in $infectedSrc) {
        Write-Alert "Malware pattern in source: $($src.FullName)"
        Select-String -Path $src.FullName -Pattern $malwarePattern |
            Select-Object -First 2 |
            ForEach-Object { Write-Host "    Line $($_.LineNumber): $($_.Line.Trim())" -ForegroundColor Red }
    }
} else {
    Write-Ok "No injected eval/atob found in source files"
}

# ── 9. Package.json Lifecycle Scripts ─────────────────────────────────────────
Write-Hdr "9. Package.json Lifecycle Scripts (postinstall/preinstall vectors)"

$legitimateScripts = 'husky|prisma|electron-builder|node scripts/|npm run|patch-package|is-ci'

Get-ChildItem -Path $CodeDir -Filter 'package.json' -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\(node_modules|\.git)\\' } |
    ForEach-Object {
        $lines = Select-String -Path $_.FullName -Pattern '"(postinstall|preinstall|prepare|predev|prebuild)"' -ErrorAction SilentlyContinue
        foreach ($line in $lines) {
            if ($line.Line -notmatch $legitimateScripts) {
                Write-Alert "Suspicious lifecycle script in $($_.FullName):"
                Write-Host "    $($line.Line.Trim())" -ForegroundColor Red
            }
        }
    }

# ── 10. Infected npm Packages in node_modules ────────────────────────────────
Write-Hdr "10. Infected npm Packages in node_modules"
Write-Info "Scanning node_modules for malware signatures (may take a moment)..."

$nmSignatures = @(
    'global\["r"\]=require',
    'bsc-dataseed\.binance\.org',
    'api\.trongrid\.io',
    'fullnode\.mainnet\.aptoslabs\.com',
    'jso\$ft\$giden\$String'
)
$nmPattern = $nmSignatures -join '|'

$nmHits = Get-ChildItem -Path $CodeDir -Filter '*.js' -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\node_modules\\' } |
    Where-Object {
        $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
        $content -match $nmPattern
    } | Select-Object -First 20

if ($nmHits) {
    Write-Alert "INFECTED npm package(s) found:"
    foreach ($f in $nmHits) {
        # Extract package name from path
        $pkg = ($f.FullName -replace '.*\\node_modules\\','') -replace '\\.*',''
        Write-Host "    Package : $pkg" -ForegroundColor Red
        Write-Host "    File    : $($f.FullName)"
    }
} else {
    Write-Ok "No known malware signatures found in node_modules"
}

# ── 11. Unexpected Files in AppData ──────────────────────────────────────────
Write-Hdr "11. Unexpected Files in AppData (dropped malware check)"

$suspAppData = Get-ChildItem -Path $env:APPDATA -Filter '*.js' -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\(npm|Code|electron|Discord|Slack)\\' } |
    Select-Object -First 20

if ($suspAppData) {
    Write-Warn "Unexpected .js files in AppData — review:"
    foreach ($f in $suspAppData) {
        Write-Host "    $($f.FullName)  (modified: $($f.LastWriteTime.ToString('yyyy-MM-dd')))"
    }
} else {
    Write-Ok "No unexpected .js files in AppData"
}

# ── 12. PIDs to Kill ──────────────────────────────────────────────────────────
Write-Hdr "12. PIDs to Kill (if any alerts above)"

$evilProcs = Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match 'node\s+-e\s' }

if ($evilProcs) {
    Write-Alert "Suspicious node -e PIDs to kill:"
    $pidList = $evilProcs.ProcessId -join ','
    Write-Host ""
    Write-Host "    Stop-Process -Id $pidList -Force" -ForegroundColor Red
    Write-Host "    # or in cmd.exe:" -ForegroundColor Gray
    foreach ($p in $evilProcs.ProcessId) { Write-Host "    taskkill /PID $p /F" -ForegroundColor Red }
    Write-Host ""
    foreach ($proc in $evilProcs) {
        Write-Host "    PID $($proc.ProcessId) — started $($proc.CreationDate)"
        # Find and flag the parent too (nodemon/npm that would restart it)
        $parent = Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.ParentProcessId)" -ErrorAction SilentlyContinue
        if ($parent -and $parent.Name -match 'node|npm') {
            Write-Host "    └─ also kill parent PPID $($proc.ParentProcessId) ($($parent.Name)) to prevent restart" -ForegroundColor Yellow
            Write-Host "       taskkill /PID $($proc.ParentProcessId) /F" -ForegroundColor Yellow
        }
    }
} else {
    Write-Ok "No suspicious node -e PIDs found"
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Hdr "Summary"
Write-Host ""
if ($script:Hits -gt 0) {
    Write-Host "  ALERTS  : $($script:Hits) compromise indicator(s) found — act immediately" -ForegroundColor Red
} else {
    Write-Host "  ALERTS  : 0 — no hard indicators found" -ForegroundColor Green
}
if ($script:Warns -gt 0) {
    Write-Host "  WARNINGS: $($script:Warns) item(s) need manual review" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Remediation checklist:" -ForegroundColor White
Write-Host "  [ ] 1. Disconnect from network to stop exfiltration"
Write-Host "  [ ] 2. Kill suspicious node -e processes (commands listed above)"
Write-Host "  [ ] 3. Kill parent nodemon/npm process to prevent restart"
Write-Host "  [ ] 4. From a CLEAN machine — rotate:"
Write-Host "         ~/.aws/credentials  (AWS keys)"
Write-Host "         ~/.ssh/             (SSH keys — generate new keypair)"
Write-Host "         ~/.npmrc            (npm token)"
Write-Host "         ~/.docker/config.json (Docker token)"
Write-Host "         GitHub tokens, .env files in all projects"
Write-Host "  [ ] 5. Delete node_modules\ in affected project, do NOT re-install yet"
Write-Host "  [ ] 6. Identify infected package: diff package-lock.json vs known-clean commit"
Write-Host "  [ ] 7. Check all project .env files were not read/exfiltrated"
Write-Host "  [ ] 8. If in doubt: back up clean files, wipe, reinstall Windows"
Write-Host ""
