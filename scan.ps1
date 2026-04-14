# Malware IOC Scanner - supply-chain/npm loader family
# Based on real incident: blockchain-fetched stage-2 node payload
# Safe: read-only, no network, no destructive actions
# Supports: Windows (PowerShell 5.1+ / PowerShell 7+)
#
# Usage (from PowerShell prompt):
#   Set-ExecutionPolicy -Scope Process Bypass; .\scan.ps1
#   Set-ExecutionPolicy -Scope Process Bypass; .\scan.ps1 -CodeDir C:\path\to\projects
#
# Usage (from cmd.exe):
#   powershell -ExecutionPolicy Bypass -File scan.ps1
#   powershell -ExecutionPolicy Bypass -File scan.ps1 -CodeDir C:\path\to\projects

param(
    [string]$CodeDir = $env:USERPROFILE
)

# ------ Colours ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
function Write-Alert { param($msg) Write-Host "[ALERT] $msg" -ForegroundColor Red;    $script:Hits++ }
function Write-Warn  { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow; $script:Warns++ }
function Write-Ok    { param($msg) Write-Host "[OK]    $msg" -ForegroundColor Green }
function Write-Info  { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-Hdr   { param($msg) Write-Host "`n=== $msg ===" -ForegroundColor White }

$script:Hits  = 0
$script:Warns = 0

Write-Host "Malware IOC Scanner - $(Get-Date)" -ForegroundColor White
Write-Host "Running as: $env:USERNAME on $env:COMPUTERNAME"
Write-Host "Scanning code under: $CodeDir"

# ------ 1. Suspicious Node Processes ---------------------------------------------------------------------------------------------------------------------------------------
Write-Hdr "1. Suspicious Node Processes (inline eval)"

$nodeProcs = Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue
if (-not $nodeProcs) {
    Write-Ok "No node.exe processes running"
} else {
    foreach ($proc in $nodeProcs) {
        $cmd     = $proc.CommandLine
        $pid_    = $proc.ProcessId
        $ppid    = $proc.ParentProcessId
        $started = $proc.CreationDate
        $parent  = (Get-CimInstance Win32_Process -Filter "ProcessId = $ppid" -ErrorAction SilentlyContinue).CommandLine

        if ($cmd -match 'node\s+-e\s') {
            Write-Alert "Suspicious 'node -e' inline process found:"
            Write-Host "    PID     : $pid_" -ForegroundColor Red
            Write-Host "    Started : $started" -ForegroundColor Red
            Write-Host "    Command : $($cmd.Substring(0, [Math]::Min(120, $cmd.Length)))..." -ForegroundColor Red
            Write-Host "    Parent  : PPID $ppid -> $($parent -replace [char]10,' ')" -ForegroundColor Red
        } else {
            Write-Info "node.exe PID $pid_ (started $started)"
            Write-Host "    Command : $($cmd.Substring(0, [Math]::Min(100, $cmd.Length)))"
            Write-Host "    Parent  : PPID $ppid -> $parent"
        }
    }
}

# ------ 2. Node Process Working Directories ------------------------------------------------------------------------------------------------------------------
Write-Hdr "2. Node Process Working Directories"

$nodeProcs2 = Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue
if ($nodeProcs2) {
    foreach ($proc in $nodeProcs2) {
        $pid_ = $proc.ProcessId
        $cwd  = "(not available - run as admin for full access)"
        try {
            $h   = [System.Diagnostics.Process]::GetProcessById($pid_)
            $cwd = Split-Path $h.MainModule.FileName
        } catch {}

        $marker = if ($proc.CommandLine -match 'node\s+-e') { " [ALERT: inline eval]" } else { "" }
        Write-Host "    PID $pid_$marker"
        Write-Host "    Started : $($proc.CreationDate)"
        Write-Host "    Exe dir : $cwd"
        $cmdPreview = $proc.CommandLine
        if ($cmdPreview.Length -gt 100) { $cmdPreview = $cmdPreview.Substring(0,100) + "..." }
        Write-Host "    Command : $cmdPreview"
        Write-Host ""
    }
} else {
    Write-Ok "No node.exe processes found"
}

# ------ 3. Open Network Connections from Node ------------------------------------------------------------------------------------------------------------
Write-Hdr "3. Open Network Connections from Node"

$nodePids = (Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue).ProcessId
if ($nodePids) {
    $allConns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
        $nodePids -contains $_.OwningProcess
    }
    $outbound = $allConns | Where-Object {
        $_.State -eq 'Established' -and
        $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0)'
    }
    $listening = $allConns | Where-Object { $_.State -eq 'Listen' }

    if ($outbound) {
        Write-Alert "Outbound node connections (potential exfiltration):"
        foreach ($c in $outbound) {
            $line = "    PID $($c.OwningProcess) -> $($c.RemoteAddress):$($c.RemotePort)"
            if ($c.RemotePort -eq 27017 -or $c.RemotePort -eq 443) {
                Write-Host "  !! $line (SUSPICIOUS PORT)" -ForegroundColor Red
            } else {
                Write-Host $line
            }
        }
    } else {
        Write-Ok "No suspicious outbound node connections"
    }
    if ($listening) {
        Write-Info "Node LISTEN ports (dev servers, likely fine):"
        foreach ($c in $listening) {
            Write-Host "    PID $($c.OwningProcess) listening on :$($c.LocalPort)"
        }
    }
} else {
    Write-Ok "No node.exe processes - skipping network check"
}

# ------ 4. Malware Blockchain C2 Domains ---------------------------------------------------------------------------------------------------------------------------
Write-Hdr "4. Malware Blockchain C2 Domains (live connection check)"

$malwareDomains = @(
    "api.trongrid.io"
    "fullnode.mainnet.aptoslabs.com"
    "bsc-dataseed.binance.org"
    "bsc-rpc.publicnode.com"
)

foreach ($domain in $malwareDomains) {
    try {
        $ips = [System.Net.Dns]::GetHostAddresses($domain) |
               Select-Object -ExpandProperty IPAddressToString
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
        Write-Info "Could not resolve $domain (offline or DNS blocked - OK)"
    }
}

# ------ 5. Persistence Mechanisms ---------------------------------------------------------------------------------------------------------------------------------------------------
Write-Hdr "5. Persistence Mechanisms"

# 5a. Scheduled Tasks
Write-Info "Checking Scheduled Tasks for node/npm references..."
$suspTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $task = $_
    $task.Actions | Where-Object {
        ($_.Execute -match 'node|npm|npx') -or
        ($_.Arguments -match 'node\s+-e|atob|eval')
    }
}
if ($suspTasks) {
    foreach ($t in $suspTasks) {
        Write-Alert "Suspicious Scheduled Task: $($t.TaskPath)$($t.TaskName)"
        $t.Actions | ForEach-Object {
            Write-Host "    Execute   : $($_.Execute)" -ForegroundColor Red
            Write-Host "    Arguments : $($_.Arguments)" -ForegroundColor Red
        }
    }
} else {
    Write-Ok "No suspicious scheduled tasks found"
}

# 5b. Registry Run/RunOnce keys
Write-Info "Checking registry Run keys..."
$runKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
$foundRunKey = $false
foreach ($key in $runKeys) {
    if (Test-Path $key) {
        $vals = Get-ItemProperty $key -ErrorAction SilentlyContinue
        $vals.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            if ($_.Value -match 'node|npm|npx|atob|eval') {
                Write-Alert "Suspicious Run key in ${key}:"
                Write-Host "    $($_.Name) = $($_.Value)" -ForegroundColor Red
                $foundRunKey = $true
            }
        }
    }
}
if (-not $foundRunKey) { Write-Ok "Registry Run keys clean" }

# 5c. Startup folders
Write-Info "Checking startup folders..."
$startupDirs = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($dir in $startupDirs) {
    if (Test-Path $dir) {
        $items = Get-ChildItem $dir -ErrorAction SilentlyContinue
        if ($items) {
            foreach ($item in $items) {
                $content = Get-Content $item.FullName -ErrorAction SilentlyContinue -Raw
                if ($content -match 'node|npm|atob|eval') {
                    Write-Alert "Suspicious startup item: $($item.FullName)"
                } else {
                    Write-Info "  Startup item (looks ok): $($item.Name)"
                }
            }
        } else {
            Write-Ok "Startup folder empty: $dir"
        }
    }
}

# ------ 6. PowerShell Profile Tampering ------------------------------------------------------------------------------------------------------------------------------
Write-Hdr "6. PowerShell Profile Tampering"

$profileFiles = @(
    $PROFILE.CurrentUserCurrentHost
    $PROFILE.CurrentUserAllHosts
    $PROFILE.AllUsersCurrentHost
    $PROFILE.AllUsersAllHosts
)
$checkedProfiles = 0
foreach ($f in $profileFiles) {
    if ($f -and (Test-Path $f)) {
        $checkedProfiles++
        $content = Get-Content $f -ErrorAction SilentlyContinue -Raw
        if ($content -match 'Invoke-Expression|iex\s|node\s+-e|atob|ConvertFromBase64') {
            Write-Alert "Suspicious content in PowerShell profile: $f"
            Select-String -Path $f -Pattern 'Invoke-Expression|iex\s|node\s+-e|atob|ConvertFromBase64' |
                ForEach-Object { Write-Host "    Line $($_.LineNumber): $($_.Line.Trim())" -ForegroundColor Red }
        } else {
            $ageDays = [int]((Get-Date) - (Get-Item $f).LastWriteTime).TotalDays
            if ($ageDays -le 30) {
                Write-Warn "$f modified $ageDays days ago - review if unexpected"
            } else {
                Write-Ok "$f clean (modified $ageDays days ago)"
            }
        }
    }
}
if ($checkedProfiles -eq 0) { Write-Ok "No PowerShell profile files found" }

# ------ 7. Sensitive Credentials (exposure check) ------------------------------------------------------------------------------------------------
Write-Hdr "7. Sensitive Credentials (exposure check)"

$sensitiveFiles = @(
    "$env:USERPROFILE\.ssh\id_rsa"
    "$env:USERPROFILE\.ssh\id_ed25519"
    "$env:USERPROFILE\.ssh\id_ecdsa"
    "$env:USERPROFILE\.aws\credentials"
    "$env:USERPROFILE\.npmrc"
    "$env:USERPROFILE\.gitconfig"
    "$env:USERPROFILE\.netrc"
    "$env:USERPROFILE\.docker\config.json"
)
$foundSensitive = $false
foreach ($f in $sensitiveFiles) {
    if (Test-Path $f) {
        $mtime = (Get-Item $f).LastWriteTime.ToString("yyyy-MM-dd")
        Write-Warn "Exposed: $f (modified $mtime) - rotate from a clean machine"
        $foundSensitive = $true
    }
}
if (-not $foundSensitive) { Write-Ok "No common credential files found" }

# ------ 8. Config & Source Files with Injected Eval/Atob ---------------------------------------------------------------------------
Write-Hdr "8. Config and Source Files with Injected Eval/Atob"
Write-Info "Scanning $CodeDir for malware injection patterns..."

$malwarePattern = 'eval\s*\(.*atob\(|atob\s*\(|child_process.*spawn|global\[.r.\]\s*=\s*require'
$configPatterns = @(
    'next.config.*'
    'vite.config.*'
    'webpack.config.*'
    '*.config.js'
    '*.config.ts'
    '*.config.mjs'
)

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

$infectedSrc = Get-ChildItem -Path $CodeDir -Include '*.js','*.ts','*.mjs' -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\(node_modules|\.git)\\' } |
    Where-Object {
        $c = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
        $c -match $malwarePattern
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

# ------ 9. Package.json Lifecycle Scripts ------------------------------------------------------------------------------------------------------------------------
Write-Hdr "9. Package.json Lifecycle Scripts"

$legitimateScripts = 'husky|prisma|electron-builder|node scripts/|npm run|patch-package|is-ci'
$foundSuspScript   = $false

Get-ChildItem -Path $CodeDir -Filter 'package.json' -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\(node_modules|\.git)\\' } |
    ForEach-Object {
        $matches_ = Select-String -Path $_.FullName `
            -Pattern '"(postinstall|preinstall|prepare|predev|prebuild)"' `
            -ErrorAction SilentlyContinue
        foreach ($line in $matches_) {
            if ($line.Line -notmatch $legitimateScripts) {
                Write-Alert "Suspicious lifecycle script in $($_.FullName):"
                Write-Host "    $($line.Line.Trim())" -ForegroundColor Red
                $foundSuspScript = $true
            }
        }
    }
if (-not $foundSuspScript) { Write-Ok "No suspicious lifecycle scripts found" }

# ------ 10. Infected npm Packages in node_modules ------------------------------------------------------------------------------------------------
Write-Hdr "10. Infected npm Packages in node_modules"
Write-Info "Scanning node_modules for malware signatures (may take a moment)..."

$nmPattern = 'global\[\"r\"\]=require|bsc-dataseed\.binance\.org|api\.trongrid\.io|fullnode\.mainnet\.aptoslabs\.com|jso\$ft\$giden\$String'

$nmHits = Get-ChildItem -Path $CodeDir -Filter '*.js' -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\node_modules\\' } |
    Where-Object {
        $c = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
        $c -match $nmPattern
    } | Select-Object -First 20

if ($nmHits) {
    Write-Alert "INFECTED npm package(s) found:"
    foreach ($f in $nmHits) {
        $pkg = ($f.FullName -replace '.*\\node_modules\\','') -replace '\\.*',''
        Write-Host "    Package : $pkg" -ForegroundColor Red
        Write-Host "    File    : $($f.FullName)"
    }
} else {
    Write-Ok "No known malware signatures found in node_modules"
}

# ------ 11. Unexpected JS Files in AppData ---------------------------------------------------------------------------------------------------------------------
Write-Hdr "11. Unexpected Files in AppData (dropped malware check)"

$suspAppData = Get-ChildItem -Path $env:APPDATA -Filter '*.js' -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\(npm|Code|electron|Discord|Slack)\\' } |
    Select-Object -First 20

if ($suspAppData) {
    Write-Warn "Unexpected .js files in AppData - review:"
    foreach ($f in $suspAppData) {
        Write-Host "    $($f.FullName)  (modified: $($f.LastWriteTime.ToString('yyyy-MM-dd')))"
    }
} else {
    Write-Ok "No unexpected .js files in AppData"
}

# ------ 12. Kill Commands ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Write-Hdr "12. Processes to Kill (if any alerts above)"

$evilProcs = Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match 'node\s+-e\s' }

if ($evilProcs) {
    Write-Alert "Suspicious node -e processes found. Run these commands to kill them:"
    Write-Host ""
    foreach ($proc in $evilProcs) {
        $pid_ = $proc.ProcessId
        Write-Host "    Stop-Process -Id $pid_ -Force" -ForegroundColor Red
        Write-Host "    # or from cmd.exe:  taskkill /PID $pid_ /F" -ForegroundColor Gray
        Write-Host ""

        $parentProc = Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.ParentProcessId)" -ErrorAction SilentlyContinue
        if ($parentProc -and $parentProc.Name -match 'node|npm') {
            Write-Host "    Also kill parent (prevents restart):" -ForegroundColor Yellow
            Write-Host "    Stop-Process -Id $($proc.ParentProcessId) -Force" -ForegroundColor Yellow
            Write-Host "    # or from cmd.exe:  taskkill /PID $($proc.ParentProcessId) /F" -ForegroundColor Gray
            Write-Host ""
        }
    }
} else {
    Write-Ok "No suspicious node -e processes found"
}

# ------ Summary ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Write-Hdr "Summary"
Write-Host ""
if ($script:Hits -gt 0) {
    Write-Host "  ALERTS   : $($script:Hits) compromise indicator(s) found - act immediately" -ForegroundColor Red
} else {
    Write-Host "  ALERTS   : 0 - no hard indicators found" -ForegroundColor Green
}
if ($script:Warns -gt 0) {
    Write-Host "  WARNINGS : $($script:Warns) item(s) need manual review" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Remediation checklist:" -ForegroundColor White
Write-Host "  [ ] 1. Disconnect from network to stop exfiltration"
Write-Host "  [ ] 2. Kill suspicious node -e processes (commands listed above)"
Write-Host "  [ ] 3. Kill parent nodemon/npm process to prevent restart"
Write-Host "  [ ] 4. From a CLEAN machine - rotate:"
Write-Host "         ~/.aws/credentials     (AWS keys)"
Write-Host "         ~/.ssh/                (SSH keys - generate a new keypair)"
Write-Host "         ~/.npmrc               (npm token)"
Write-Host "         ~/.docker/config.json  (Docker token)"
Write-Host "         GitHub tokens, .env files in all projects"
Write-Host "  [ ] 5. Delete node_modules\ in affected project, do NOT re-install yet"
Write-Host "  [ ] 6. Identify infected package: diff package-lock.json vs known-clean commit"
Write-Host "  [ ] 7. Check all .env files were not read/exfiltrated"
Write-Host "  [ ] 8. If in doubt: back up clean files, wipe, reinstall Windows"
Write-Host ""
