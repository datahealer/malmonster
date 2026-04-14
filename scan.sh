#!/usr/bin/env bash
# Malware IOC Scanner — supply-chain/npm loader family
# Based on real incident: blockchain-fetched stage-2 node payload
# Platform: macOS
# Usage:
#   bash scan.sh                        # scan only, no changes
#   bash scan.sh --kill                 # scan + kill malicious processes
#   bash scan.sh --kill --purge         # scan + kill processes + delete infected files
#   bash scan.sh --code-dir /path       # override project root

RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BOLD='\033[1m'
RST='\033[0m'

HITS=0
WARNS=0
OPT_KILL=0    # --kill  : kill malicious node processes
OPT_PURGE=0   # --purge : also delete infected node_modules & LaunchAgents (requires --kill)

flag()  { echo -e "${RED}[ALERT]${RST} $1"; ((HITS++)); }
warn()  { echo -e "${YEL}[WARN] ${RST} $1"; ((WARNS++)); }
ok()    { echo -e "${GRN}[OK]   ${RST} $1"; }
info()  { echo -e "${CYN}[INFO] ${RST} $1"; }
hdr()   { echo -e "\n${BOLD}━━━ $1 ━━━${RST}"; }
killed(){ echo -e "\033[0;35m[KILLED]${RST} $1"; }
purged(){ echo -e "\033[0;35m[PURGED]${RST} $1"; }

# Parse arguments
CODE_DIR="$HOME"
for arg in "$@"; do
  case "$arg" in
    --kill)       OPT_KILL=1 ;;
    --purge)      OPT_PURGE=1; OPT_KILL=1 ;;  # --purge implies --kill
    --code-dir)   shift; CODE_DIR="$1" ;;
    --code-dir=*) CODE_DIR="${arg#*=}" ;;
  esac
done

# Warn clearly about what mode we're in
if [[ $OPT_PURGE -eq 1 ]]; then
  echo -e "${RED}${BOLD}MODE: KILL + PURGE — will kill processes AND delete infected files${RST}"
  echo -e "${YEL}You will be prompted before each destructive action.${RST}"
elif [[ $OPT_KILL -eq 1 ]]; then
  echo -e "${YEL}${BOLD}MODE: KILL — will kill malicious processes (no file deletion)${RST}"
  echo -e "${YEL}You will be prompted before each kill.${RST}"
else
  echo -e "${GRN}${BOLD}MODE: SCAN ONLY — read-only, no changes made${RST}"
fi

# Shared confirm helper — prompts user, returns 0 for yes, 1 for no
confirm() {
  local prompt="$1"
  echo -en "${YEL}  --> $prompt [y/N] ${RST}"
  read -r ans
  [[ "$ans" =~ ^[Yy]$ ]]
}

# Tracked lists — populated during scan, acted on at the end
EVIL_PIDS=()          # node -e PIDs
EVIL_PARENT_PIDS=()   # nodemon/npm parents of evil PIDs
INFECTED_NM_DIRS=()   # node_modules/ dirs containing malware
INFECTED_PLISTS=()    # malicious LaunchAgent plist paths

echo -e "${BOLD}Malware IOC Scanner — $(date)${RST}"
echo "Running as: $(whoami) on $(hostname)"
echo "Scanning code under: $CODE_DIR"

# ──────────────────────────────────────────────
hdr "1. Suspicious Node Processes (inline eval)"
# node -e with inline code — classic detached malware spawn pattern
NODE_E_PROCS=$(ps aux | grep -E 'node\s+-e' | grep -v grep)
if [[ -n "$NODE_E_PROCS" ]]; then
  flag "Suspicious 'node -e' inline processes found:"
  while read -r line; do
    PID=$(echo "$line" | awk '{print $2}')
    PPID=$(ps -o ppid= -p "$PID" 2>/dev/null | tr -d ' ')
    PARENT_CMD=$(ps -o command= -p "$PPID" 2>/dev/null)
    echo "    PID $PID: $(echo "$line" | awk '{print $11, $12, $13}')..."
    echo "    └─ spawned by PPID $PPID: $(echo "$PARENT_CMD" | cut -c1-80)"
    # Track for remediation
    EVIL_PIDS+=("$PID")
    if echo "$PARENT_CMD" | grep -qiE 'nodemon|npm|yarn'; then
      EVIL_PARENT_PIDS+=("$PPID")
    fi
  done <<< "$NODE_E_PROCS"
else
  ok "No 'node -e' inline processes running"
fi

# Detached node processes (no controlling terminal — stdio: ignore)
DETACHED=$(ps axo pid,ppid,tt,command | awk '$3 == "??" && /node/' | grep -v grep)
if [[ -n "$DETACHED" ]]; then
  warn "Detached node processes (no tty) — review manually:"
  echo "$DETACHED" | while read -r line; do echo "    $line"; done
else
  ok "No detached node processes detected"
fi

# ──────────────────────────────────────────────
hdr "2. Node Process Working Directories & Parent Chain"
info "All node processes with working directories:"
for PID in $(pgrep -x node 2>/dev/null); do
  CMD=$(ps -o command= -p "$PID" 2>/dev/null | cut -c1-80)
  CWD=$(lsof -p "$PID" 2>/dev/null | awk '$4=="cwd" {print $NF}')
  PPID=$(ps -o ppid= -p "$PID" 2>/dev/null | tr -d ' ')
  PARENT=$(ps -o command= -p "$PPID" 2>/dev/null | cut -c1-60)
  STARTED=$(ps -o lstart= -p "$PID" 2>/dev/null)
  IS_DETACHED=$(ps axo pid,tt | awk -v p="$PID" '$1==p {print $2}')
  MARKER=""
  echo "$CMD" | grep -qE 'node\s+-e' && MARKER=" ${RED}[ALERT: inline eval]${RST}"
  [[ "$IS_DETACHED" == "??" ]] && MARKER="$MARKER ${YEL}[detached]${RST}"
  echo -e "    PID $PID$MARKER"
  echo    "    ├─ started : $STARTED"
  echo    "    ├─ cwd     : $CWD"
  echo    "    ├─ command : $CMD"
  echo    "    └─ parent  : PPID $PPID → $PARENT"
  echo ""
done

# ──────────────────────────────────────────────
hdr "3. Open Network Connections from Node"
NODE_NET=$(lsof -i -P 2>/dev/null | grep node | grep -v grep)
if [[ -n "$NODE_NET" ]]; then
  OUTBOUND=$(echo "$NODE_NET" | grep -v 'LISTEN\|localhost\|127\.0\.0\|::1')
  LISTEN=$(echo "$NODE_NET" | grep 'LISTEN')
  if [[ -n "$OUTBOUND" ]]; then
    flag "Outbound node connections (potential exfiltration):"
    echo "$OUTBOUND" | while read -r line; do
      echo "$line" | grep -qE ':27017|:443' && PREFIX="${RED}  !!${RST}" || PREFIX="    "
      echo -e "$PREFIX $line"
    done
  else
    ok "No suspicious outbound node connections"
  fi
  if [[ -n "$LISTEN" ]]; then
    info "Node LISTEN ports (dev servers, likely fine):"
    echo "$LISTEN" | while read -r line; do echo "    $line"; done
  fi
else
  ok "No open network connections from node"
fi

# ──────────────────────────────────────────────
hdr "4. Malware Blockchain C2 Domains (live connection check)"
DOMAINS=(
  "api.trongrid.io"
  "fullnode.mainnet.aptoslabs.com"
  "bsc-dataseed.binance.org"
  "bsc-rpc.publicnode.com"
)
for domain in "${DOMAINS[@]}"; do
  CONN=$(lsof -i 2>/dev/null | grep -i "$domain" | grep -v grep)
  if [[ -n "$CONN" ]]; then
    flag "LIVE connection to malware C2 domain: $domain"
    echo "$CONN" | while read -r line; do echo "    $line"; done
  else
    ok "No live connection to $domain"
  fi
done

# ──────────────────────────────────────────────
hdr "5. Persistence — LaunchAgents"
# Only scan user LaunchAgents — system ones are noisy false positives
USER_AGENT_DIR="$HOME/Library/LaunchAgents"
if [[ -d "$USER_AGENT_DIR" ]]; then
  TOTAL=$(find "$USER_AGENT_DIR" -name "*.plist" 2>/dev/null | wc -l | tr -d ' ')
  info "User LaunchAgents: $TOTAL plists"
  while read -r plist; do
    if grep -qiE '\bnode\b|\bnpm\b|\bnpx\b|eval\(|atob\(|base64' "$plist" 2>/dev/null; then
      flag "Suspicious user LaunchAgent: $plist"
      grep -iE '\bnode\b|\bnpm\b|\bnpx\b|eval\(|atob\(|base64' "$plist" | head -5 | while read -r l; do echo "    $l"; done
      INFECTED_PLISTS+=("$plist")
    else
      info "  $plist"
    fi
  done < <(find "$USER_AGENT_DIR" -name "*.plist" 2>/dev/null)
else
  ok "No user LaunchAgents directory"
fi
for dir in "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
  if [[ -d "$dir" ]]; then
    COUNT=$(find "$dir" -name "*.plist" 2>/dev/null | wc -l | tr -d ' ')
    info "System $dir: $COUNT plists (not auto-scanned — review manually if suspicious)"
  fi
done

# ──────────────────────────────────────────────
hdr "6. Shell Startup File Tampering"
SHELL_FILES=(
  "$HOME/.zshrc"
  "$HOME/.bashrc"
  "$HOME/.bash_profile"
  "$HOME/.profile"
  "$HOME/.zprofile"
  "$HOME/.zshenv"
)
for f in "${SHELL_FILES[@]}"; do
  if [[ -f "$f" ]]; then
    MATCHES=$(grep -nE 'eval\s*\(|atob\(|base64|node\s+-e|curl.*(bash|sh)|wget.*(bash|sh)' "$f" 2>/dev/null)
    if [[ -n "$MATCHES" ]]; then
      flag "Suspicious content in $f:"
      echo "$MATCHES" | while read -r line; do echo "    $line"; done
    else
      MTIME_EPOCH=$(stat -f "%m" "$f" 2>/dev/null)
      NOW_EPOCH=$(date +%s)
      AGE_DAYS=$(( (NOW_EPOCH - MTIME_EPOCH) / 86400 ))
      MTIME=$(date -r "$MTIME_EPOCH" +%Y-%m-%d 2>/dev/null || echo "unknown")
      if [[ $AGE_DAYS -le 30 ]]; then
        warn "$f modified $AGE_DAYS days ago ($MTIME) — review if unexpected"
      else
        ok "$f clean (last modified $MTIME)"
      fi
    fi
  fi
done

# ──────────────────────────────────────────────
hdr "7. Crontab Entries"
CRON=$(crontab -l 2>/dev/null)
if [[ -n "$CRON" ]]; then
  warn "User crontab entries found — review:"
  echo "$CRON" | while read -r line; do echo "    $line"; done
else
  ok "No user crontab entries"
fi

# ──────────────────────────────────────────────
hdr "8. Sensitive Credentials (exposure check)"
SENSITIVE=(
  "$HOME/.ssh/id_rsa"
  "$HOME/.ssh/id_ed25519"
  "$HOME/.ssh/id_ecdsa"
  "$HOME/.aws/credentials"
  "$HOME/.npmrc"
  "$HOME/.gitconfig"
  "$HOME/.netrc"
  "$HOME/.docker/config.json"
)
FOUND_SENSITIVE=0
for f in "${SENSITIVE[@]}"; do
  if [[ -f "$f" ]]; then
    MTIME=$(date -r "$(stat -f "%m" "$f")" +%Y-%m-%d 2>/dev/null || echo "unknown")
    warn "Exposed: $f (modified $MTIME) — rotate credentials from a clean machine"
    FOUND_SENSITIVE=1
  fi
done
[[ $FOUND_SENSITIVE -eq 0 ]] && ok "No common credential files found"

# ──────────────────────────────────────────────
hdr "9. Config & Source Files with Injected Eval/Atob"
info "Scanning $CODE_DIR for malware injection patterns..."
MALWARE_PATTERN='eval\s*\(.*atob\(|atob\s*\(|child_process.*spawn.*detach|global\[.r.\]\s*=\s*require'

find "$CODE_DIR" \
  -not \( -path '*/.git/*' -o -path '*/node_modules/*' \) \
  -type f \( -name "next.config.*" -o -name "vite.config.*" -o -name "webpack.config.*" \
             -o -name "*.config.js" -o -name "*.config.ts" -o -name "*.config.mjs" \) \
  2>/dev/null | while read -r cfg; do
    if grep -qE "$MALWARE_PATTERN" "$cfg" 2>/dev/null; then
      flag "INFECTED config: $cfg"
      grep -nE "$MALWARE_PATTERN" "$cfg" | head -3 | while read -r l; do echo "    $l"; done
    fi
  done

INFECTED_SRC=$(grep -rlE "$MALWARE_PATTERN" "$CODE_DIR" \
  --include="*.js" --include="*.ts" --include="*.mjs" \
  --exclude-dir=node_modules --exclude-dir=.git \
  2>/dev/null)
if [[ -n "$INFECTED_SRC" ]]; then
  echo "$INFECTED_SRC" | while read -r src; do
    flag "Malware pattern in source: $src"
    grep -nE "$MALWARE_PATTERN" "$src" | head -2 | while read -r l; do echo "    $l"; done
  done
else
  ok "No injected eval/atob found in source files"
fi

# ──────────────────────────────────────────────
hdr "10. Package.json Lifecycle Scripts (postinstall/preinstall vectors)"
find "$CODE_DIR" \
  -not \( -path '*/.git/*' -o -path '*/node_modules/*' \) \
  -name "package.json" \
  2>/dev/null | while read -r pkg; do
    SUSPICIOUS_SCRIPTS=$(grep -E '"(postinstall|preinstall|prepare|predev|prebuild)"' "$pkg" 2>/dev/null | \
      grep -vE 'husky|prisma|electron-builder|node scripts/|npm run|patch-package|is-ci')
    if [[ -n "$SUSPICIOUS_SCRIPTS" ]]; then
      flag "Suspicious lifecycle script in $pkg:"
      echo "$SUSPICIOUS_SCRIPTS" | while read -r l; do echo "    $l"; done
    fi
  done

# ──────────────────────────────────────────────
hdr "11. Infected npm Packages in node_modules"
info "Scanning node_modules for malware signatures (this may take a moment)..."
NM_HITS=$(grep -rl \
  --include="*.js" \
  -e 'global\["r"\]=require' \
  -e 'global\[.r.\]=require' \
  -e 'bsc-dataseed\.binance\.org' \
  -e 'api\.trongrid\.io' \
  -e 'fullnode\.mainnet\.aptoslabs\.com' \
  -e 'jso\$ft\$giden\$String' \
  "$CODE_DIR" 2>/dev/null | grep node_modules | head -20)

if [[ -n "$NM_HITS" ]]; then
  flag "INFECTED npm package(s) found:"
  while read -r f; do
    PKG=$(echo "$f" | grep -oE 'node_modules/(@[^/]+/[^/]+|[^/]+)' | head -1 | sed 's|node_modules/||')
    echo "    Package: $PKG"
    echo "    File:    $f"
    # Track the node_modules/ directory root for purge
    NM_DIR=$(echo "$f" | grep -oE '^.*/node_modules' | head -1)
    # Avoid duplicates
    [[ -n "$NM_DIR" ]] && [[ ! " ${INFECTED_NM_DIRS[*]} " =~ " $NM_DIR " ]] && INFECTED_NM_DIRS+=("$NM_DIR")
  done <<< "$NM_HITS"
else
  ok "No known malware signatures found in node_modules"
fi

# ──────────────────────────────────────────────
hdr "12. Unexpected Hidden Files in Home Root"
HIDDEN=$(find "$HOME" -maxdepth 1 -name ".*" -type f 2>/dev/null | \
  grep -vE '\.(zshrc|bashrc|bash_profile|zprofile|zshenv|profile|gitconfig|gitignore|npmrc|DS_Store|CFUserTextEncoding|localized|vimrc|viminfo|lesshst|wget-hsts|python_history|node_repl_history|zsh_history|bash_history|bash_sessions|config|aws|ssh|Trash|docker)')
if [[ -n "$HIDDEN" ]]; then
  warn "Unexpected hidden files in home root:"
  echo "$HIDDEN" | while read -r f; do
    MTIME=$(date -r "$(stat -f "%m" "$f")" +%Y-%m-%d 2>/dev/null || echo "unknown")
    echo "    $f  (modified: $MTIME)"
  done
else
  ok "No unexpected hidden files in home root"
fi

# ──────────────────────────────────────────────
hdr "13. Remediation"

# ── KILL ──────────────────────────────────────────────────────────────────────
if [[ ${#EVIL_PIDS[@]} -eq 0 ]]; then
  ok "No malicious processes to kill"
elif [[ $OPT_KILL -eq 0 ]]; then
  echo -e "${YEL}  Malicious PIDs found but --kill not set. To kill them, re-run with:${RST}"
  echo -e "    ${BOLD}bash scan.sh --kill${RST}"
  echo -e "  PIDs: ${EVIL_PIDS[*]}"
  [[ ${#EVIL_PARENT_PIDS[@]} -gt 0 ]] && \
    echo -e "  Parent PIDs (nodemon/npm): ${EVIL_PARENT_PIDS[*]}"
else
  echo -e "${BOLD}Processes to kill:${RST}"
  for pid in "${EVIL_PIDS[@]}"; do
    CWD=$(lsof -p "$pid" 2>/dev/null | awk '$4=="cwd" {print $NF}')
    echo -e "    ${RED}PID $pid${RST} — cwd: $CWD"
  done
  for pid in "${EVIL_PARENT_PIDS[@]}"; do
    echo -e "    ${YEL}PID $pid${RST} — parent (nodemon/npm, will restart malware if left alive)"
  done
  echo ""
  if confirm "Kill all ${#EVIL_PIDS[@]} malicious process(es) (and ${#EVIL_PARENT_PIDS[@]} parent(s))?"; then
    for pid in "${EVIL_PIDS[@]}"; do
      if kill -9 "$pid" 2>/dev/null; then
        killed "PID $pid"
      else
        warn "Could not kill PID $pid (already exited?)"
      fi
    done
    for pid in "${EVIL_PARENT_PIDS[@]}"; do
      if kill -9 "$pid" 2>/dev/null; then
        killed "Parent PID $pid"
      else
        warn "Could not kill parent PID $pid (already exited?)"
      fi
    done
  else
    info "Skipped killing processes"
  fi
fi

# ── PURGE ─────────────────────────────────────────────────────────────────────
if [[ $OPT_PURGE -eq 0 ]]; then
  # Just report what --purge would delete
  if [[ ${#INFECTED_NM_DIRS[@]} -gt 0 ]] || [[ ${#INFECTED_PLISTS[@]} -gt 0 ]]; then
    echo ""
    echo -e "${YEL}  --purge not set. To also delete infected files, re-run with:${RST}"
    echo -e "    ${BOLD}bash scan.sh --kill --purge${RST}"
    [[ ${#INFECTED_NM_DIRS[@]} -gt 0 ]] && \
      echo "  Would delete node_modules/:" && \
      printf "    %s\n" "${INFECTED_NM_DIRS[@]}"
    [[ ${#INFECTED_PLISTS[@]} -gt 0 ]] && \
      echo "  Would unload + delete LaunchAgents:" && \
      printf "    %s\n" "${INFECTED_PLISTS[@]}"
  fi
else
  # Delete infected node_modules dirs
  if [[ ${#INFECTED_NM_DIRS[@]} -eq 0 ]]; then
    ok "No infected node_modules directories to delete"
  else
    echo ""
    echo -e "${BOLD}Infected node_modules to delete:${RST}"
    printf "    %s\n" "${INFECTED_NM_DIRS[@]}"
    echo ""
    if confirm "Delete ${#INFECTED_NM_DIRS[@]} node_modules director(y/ies)? (irreversible — re-run npm install after)"; then
      for dir in "${INFECTED_NM_DIRS[@]}"; do
        rm -rf "$dir" && purged "$dir" || warn "Failed to delete $dir"
      done
    else
      info "Skipped deleting node_modules"
    fi
  fi

  # Unload + delete infected LaunchAgent plists
  if [[ ${#INFECTED_PLISTS[@]} -eq 0 ]]; then
    ok "No infected LaunchAgents to remove"
  else
    echo ""
    echo -e "${BOLD}Infected LaunchAgents to unload and delete:${RST}"
    printf "    %s\n" "${INFECTED_PLISTS[@]}"
    echo ""
    if confirm "Unload and delete ${#INFECTED_PLISTS[@]} LaunchAgent plist(s)?"; then
      for plist in "${INFECTED_PLISTS[@]}"; do
        launchctl unload "$plist" 2>/dev/null && info "Unloaded: $plist"
        rm -f "$plist" && purged "$plist" || warn "Failed to delete $plist"
      done
    else
      info "Skipped removing LaunchAgents"
    fi
  fi
fi

# ──────────────────────────────────────────────
hdr "Summary"
echo ""
if [[ $HITS -gt 0 ]]; then
  echo -e "${RED}${BOLD}  ALERTS : $HITS compromise indicator(s) found — act immediately${RST}"
else
  echo -e "${GRN}${BOLD}  ALERTS : 0 — no hard indicators found${RST}"
fi
if [[ $WARNS -gt 0 ]]; then
  echo -e "${YEL}${BOLD}  WARNINGS: $WARNS item(s) need manual review${RST}"
fi

echo ""
echo -e "${BOLD}Remediation checklist:${RST}"
echo "  [ ] 1. Turn off WiFi immediately to stop exfiltration"
echo "  [ ] 2. Kill suspicious node -e processes (PIDs listed above)"
echo "  [ ] 3. Kill parent nodemon/npm process to prevent restart"
echo "  [ ] 4. From a CLEAN machine — rotate:"
echo "         ~/.aws/credentials  (AWS keys)"
echo "         ~/.ssh/             (SSH keys — generate new keypair)"
echo "         ~/.npmrc            (npm token)"
echo "         ~/.docker/config.json (Docker token)"
echo "         GitHub tokens, .env files in all projects"
echo "  [ ] 5. Delete node_modules/ in affected project, do NOT re-install yet"
echo "  [ ] 6. Identify infected package: diff package-lock.json vs known-clean commit"
echo "  [ ] 7. Check all project .env files were not read/exfiltrated"
echo "  [ ] 8. If in doubt: back up clean files, wipe, reinstall macOS"
echo ""
