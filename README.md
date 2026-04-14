# Malware IOC Scanner

Detects and removes a supply-chain malware family that injects a blockchain-fetched stage-2 Node.js payload into npm projects.

Built from a real incident. Safe to run — scan-only by default, destructive actions require explicit flags and prompt before each step.

---

## Background

An attacker injected this into a `next.config.js`:

```js
eval(global['_V']='5-42'; + atob('Z2xvYmFsW...'))
```

The obfuscated payload:
1. Makes outbound HTTPS requests to fetch a second-stage payload stored in **blockchain transaction data** (Tron, Aptos, BSC)
2. Decrypts it with an XOR routine
3. Runs it with `eval()`
4. Spawns a detached background `node -e` process (`child_process.spawn(..., { detached: true, stdio: 'ignore' })`) that survives after your app stops

The second-stage payload can read `~/.ssh`, `~/.aws`, `.env` files, database credentials, and any file your user account can access — and exfiltrate them to an attacker-controlled server.

---

## What the scanner checks

| # | Check |
|---|-------|
| 1 | `node -e` inline eval processes |
| 2 | Working directory and parent chain of all node processes |
| 3 | Outbound network connections from node (flags MongoDB :27017 and :443) |
| 4 | Live connections to known malware C2 domains (Tron, Aptos, BSC endpoints) |
| 5 | Persistence — LaunchAgents (macOS) / Scheduled Tasks + Registry (Windows) |
| 6 | Shell startup file tampering (`.zshrc`, `.bashrc`, etc.) / PowerShell profiles |
| 7 | Crontab entries |
| 8 | Sensitive credential files that may have been read (`~/.aws`, `~/.ssh`, etc.) |
| 9 | Injected `eval`/`atob` patterns in config and source files |
| 10 | Suspicious `postinstall`/`preinstall` lifecycle scripts in `package.json` |
| 11 | Known malware signatures inside `node_modules` |
| 12 | Unexpected hidden files in home root |
| 13 | Remediation — kill processes and/or delete infected files |

---

## Files

| File | Platform | Run with |
|------|----------|----------|
| `scan.sh` | macOS | `bash scan.sh` |
| `scan.ps1` | Windows | `powershell -ExecutionPolicy Bypass -File scan.ps1` |

---

## Usage

### macOS

```bash
# Scan only — read-only, no changes made
bash scan.sh

# Scan + kill malicious processes
bash scan.sh --kill

# Scan + kill processes + delete infected files (node_modules, LaunchAgents)
bash scan.sh --kill --purge

# Override the project root (default is ~/)
bash scan.sh --code-dir /path/to/your/projects
bash scan.sh --kill --code-dir /path/to/your/projects
```

### Windows (PowerShell)

```powershell
# Scan only
powershell -ExecutionPolicy Bypass -File scan.ps1

# Override project root
powershell -ExecutionPolicy Bypass -File scan.ps1 -CodeDir C:\path\to\projects
```

> The Windows script is scan-only. Process killing on Windows: open Task Manager, find `node.exe` processes, and end them — or run `taskkill /PID <pid> /F` in an admin command prompt.

---

## Modes (macOS)

| Mode | Kills `node -e` process | Kills nodemon/npm parent | Deletes `node_modules/` | Removes LaunchAgent plists |
|------|:---:|:---:|:---:|:---:|
| _(no flags)_ | — | — | — | — |
| `--kill` | ✓ | ✓ | — | — |
| `--kill --purge` | ✓ | ✓ | ✓ | ✓ |

Every destructive step prompts for confirmation before executing. Saying no to any step skips it and continues.

When run without `--purge`, the script still shows exactly which files it *would* delete — so you can review them before committing.

---

## Output colours

| Colour | Meaning |
|--------|---------|
| 🔴 `[ALERT]` | Confirmed indicator of compromise — act immediately |
| 🟡 `[WARN]` | Needs manual review |
| 🟢 `[OK]` | Clean |
| 🔵 `[INFO]` | Informational |
| 🟣 `[KILLED]` / `[PURGED]` | Action taken |

---

## Remediation checklist

If alerts are found:

- [ ] **Turn off WiFi** immediately to stop active exfiltration
- [ ] **Kill malicious processes** — re-run with `--kill` or do it manually
- [ ] **Kill the parent** (nodemon/npm) so the malware doesn't restart
- [ ] From a **clean, separate machine** — rotate all credentials that were accessible:
  - AWS keys (`~/.aws/credentials`)
  - SSH keys (`~/.ssh/`) — generate a new keypair
  - npm token (`~/.npmrc`)
  - Docker token (`~/.docker/config.json`)
  - GitHub personal access tokens
  - All `.env` files across your projects
  - Any database passwords, API keys the project could access
- [ ] **Delete `node_modules/`** in the infected project — do NOT re-install until you've identified the infected package
- [ ] **Identify the infected package** — diff `package-lock.json` against a known-clean commit in git
- [ ] **Audit other projects** on the same machine — the malware may have read or modified them
- [ ] If the machine handled sensitive data: **wipe and reinstall the OS**, restore only known-clean files

---

## Known malware signatures

These strings in source files or network connections are definitive indicators:

```
global["r"]=require          # stage-1 loader bootstrap
api.trongrid.io              # blockchain C2 — Tron
fullnode.mainnet.aptoslabs.com  # blockchain C2 — Aptos
bsc-dataseed.binance.org     # blockchain C2 — BSC
bsc-rpc.publicnode.com       # blockchain C2 — BSC fallback
jso$ft$giden$String          # obfuscation marker in stage-2
global['_V']='5-             # version marker in detached process
atob(...)  inside eval(...)  # stage-1 loader pattern
child_process.spawn(..., { detached: true, stdio: 'ignore' })
```

---

## What this malware cannot do automatically

- Break out of your macOS/Windows user permissions
- Gain root/admin access (unless a privilege-escalation payload was also delivered)
- Instantly infect other projects (it requires actively searching and writing to them)

But because it executes arbitrary second-stage code fetched from the internet, **assume any secret accessible during the infected run is compromised**.

---

## Limitations

- The scanner detects the malware **while it is running or present in source files**. If the machine was infected, cleaned (rebooted), and you're checking retroactively, process-based checks will show clean — focus on sections 9, 11, and credential rotation.
- `node_modules` scanning can be slow on large projects with many dependencies.
- The Windows script does not have `--kill`/`--purge` flags — use Task Manager or `taskkill` manually.
