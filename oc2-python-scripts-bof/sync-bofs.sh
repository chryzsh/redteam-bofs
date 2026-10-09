#!/usr/bin/env bash
#
# sync-bofs.sh - Pull, build, and sync external BOF binaries into OC2 script directories.
#
# Usage: ./oc2-python-scripts-bof/sync-bofs.sh [--no-pull] [--no-build] [project ...]
#
# Options:
#   --no-pull   Skip git pull (use current submodule state)
#   --no-build  Skip compilation (copy existing .o files only)
#
# If project names are given, only those projects are synced.
# Otherwise all projects are synced.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXTERNAL="$REPO_ROOT/external"
OC2_DIR="$REPO_ROOT/oc2-python-scripts-bof"

DO_PULL=true
DO_BUILD=true
PROJECTS=()

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-pull)  DO_PULL=false; shift ;;
        --no-build) DO_BUILD=false; shift ;;
        *)          PROJECTS+=("$1"); shift ;;
    esac
done

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1"; }

copy_bof() {
    local src="$1" dst="$2"
    if [[ -f "$src" ]]; then
        mkdir -p "$(dirname "$dst")"
        cp "$src" "$dst"
        return 0
    fi
    return 1
}

# Check submodules are initialized
if [[ ! -f "$REPO_ROOT/.gitmodules" ]]; then
    err "No .gitmodules found. Run: git submodule update --init"
    exit 1
fi

should_sync() {
    local name="$1"
    if [[ ${#PROJECTS[@]} -eq 0 ]]; then
        return 0
    fi
    for p in "${PROJECTS[@]}"; do
        [[ "$p" == "$name" ]] && return 0
    done
    return 1
}

pull_submodule() {
    local path="$1" name="$2"
    if [[ ! -d "$path/.git" && ! -f "$path/.git" ]]; then
        warn "$name not initialized. Running git submodule update --init..."
        git -C "$REPO_ROOT" submodule update --init "$path"
    fi
    if $DO_PULL; then
        log "Pulling latest $name..."
        git -C "$path" pull origin "$(git -C "$path" rev-parse --abbrev-ref HEAD)" --ff-only 2>/dev/null || \
            warn "Could not fast-forward $name (detached HEAD or diverged). Using current state."
    fi
}

SYNCED=0
FAILED=0
count_sync() { SYNCED=$((SYNCED + 1)); }
count_fail() { FAILED=$((FAILED + 1)); }

# ============================================
# cookie-monster
# ============================================
if should_sync "cookie-monster"; then
    log "--- cookie-monster ---"
    pull_submodule "$EXTERNAL/cookie-monster" "cookie-monster"

    if $DO_BUILD; then
        log "Building cookie-monster..."
        if ! make -C "$EXTERNAL/cookie-monster" all 2>&1 | tail -3; then
            warn "cookie-monster build failed. Will try to copy existing .o files."
        fi
    fi

    DST="$OC2_DIR/cookie-monster"
    if copy_bof "$EXTERNAL/cookie-monster/cookie-monster-bof.x64.o" "$DST/cookie-monster-bof.x64.o" && \
       copy_bof "$EXTERNAL/cookie-monster/cookie-monster-bof.x86.o" "$DST/cookie-monster-bof.x86.o"; then
        ok "cookie-monster synced"; count_sync
    else
        err "cookie-monster .o files not found"; count_fail
    fi
fi

# ============================================
# LNKgenerator-BOF
#
# Upstream Makefile hardcodes the mingw compilers without honoring CFLAGS, and
# modern gcc rejects the IShellLinkW** -> void** cast in CoCreateInstance with
# -Wincompatible-pointer-types. Inject a PATH shim that adds the warning
# downgrade for both x64 and x86 builds.
# ============================================
if should_sync "LNKgenerator-BOF"; then
    log "--- LNKgenerator-BOF ---"
    pull_submodule "$EXTERNAL/LNKgenerator-BOF" "LNKgenerator-BOF"

    if $DO_BUILD; then
        log "Building LNKgenerator-BOF..."
        SHIM_DIR="$EXTERNAL/LNKgenerator-BOF/.shim"
        mkdir -p "$SHIM_DIR"
        for arch in x86_64 i686; do
            SHIM_CC="$SHIM_DIR/${arch}-w64-mingw32-gcc"
            cat > "$SHIM_CC" <<SHIM
#!/usr/bin/env bash
exec /usr/bin/${arch}-w64-mingw32-gcc -Wno-incompatible-pointer-types "\$@"
SHIM
            chmod +x "$SHIM_CC"
        done
        if ! PATH="$SHIM_DIR:$PATH" make -C "$EXTERNAL/LNKgenerator-BOF" all 2>&1 | tail -3; then
            warn "LNKgenerator-BOF build failed. Will try to copy existing .o files."
        fi
    fi

    DST="$OC2_DIR/LNKgenerator-BOF"
    if copy_bof "$EXTERNAL/LNKgenerator-BOF/LNKgenerator-BOF.x64.o" "$DST/LNKgenerator-BOF.x64.o" && \
       copy_bof "$EXTERNAL/LNKgenerator-BOF/LNKgenerator-BOF.x86.o" "$DST/LNKgenerator-BOF.x86.o"; then
        ok "LNKgenerator-BOF synced"; count_sync
    else
        err "LNKgenerator-BOF .o files not found"; count_fail
    fi
fi

# ============================================
# Kerbeus-BOF (deployed standalone — see AGENTS.md "Deployment")
#
# Upstream ships its own kerbeus_oc2_bof.s1.py with a hardcoded
# BASE_DIR="/shared/bofs/Kerbeus-BOF/_bin", so the project must be deployed
# to /opt/oc2/shared/bofs/Kerbeus-BOF/ on the teamserver, not nested under
# custom/. Build only — binaries stay in external/Kerbeus-BOF/_bin/ and are
# rsynced from there directly by deploy-to-oc2.sh -t ''.
# ============================================
if should_sync "Kerbeus-BOF"; then
    log "--- Kerbeus-BOF ---"
    pull_submodule "$EXTERNAL/Kerbeus-BOF" "Kerbeus-BOF"

    if $DO_BUILD; then
        log "Building Kerbeus-BOF..."
        # Upstream Makefile hardcodes `x86_64-w64-mingw32-gcc` without honoring
        # CFLAGS, and the source uses `typedef int bool;` which conflicts with
        # the C23 default in modern gcc. Inject a PATH shim that pins -std=c11.
        SHIM_DIR="$EXTERNAL/Kerbeus-BOF/.shim"
        SHIM_CC="$SHIM_DIR/x86_64-w64-mingw32-gcc"
        mkdir -p "$SHIM_DIR"
        cat > "$SHIM_CC" <<'SHIM'
#!/usr/bin/env bash
exec /usr/bin/x86_64-w64-mingw32-gcc -std=c11 "$@"
SHIM
        chmod +x "$SHIM_CC"
        if ! PATH="$SHIM_DIR:$PATH" make -C "$EXTERNAL/Kerbeus-BOF" 2>&1 | tail -3; then
            warn "Kerbeus-BOF build failed."
        fi
    fi

    KERB_OK=true
    for bof in asktgt asktgs renew s4u cross_s4u ptt purge klist triage dump describe hash kerberoasting asreproasting tgtdeleg changepw; do
        if [[ ! -f "$EXTERNAL/Kerbeus-BOF/_bin/${bof}.x64.o" ]]; then
            warn "Kerbeus-BOF: ${bof}.x64.o missing in external/Kerbeus-BOF/_bin/"
            KERB_OK=false
        fi
    done
    if $KERB_OK; then
        ok "Kerbeus-BOF built (deploy with: deploy-to-oc2.sh -t '' <host> external/Kerbeus-BOF)"
    else
        warn "Kerbeus-BOF partially built"
    fi
    count_sync
fi

# ============================================
# SQL-BOF (deployed standalone — see AGENTS.md "Deployment")
#
# Upstream ships its own sql_bof.s1.py with a hardcoded
# BASE_DIR="/shared/bofs/SQL-BOF/SQL", so the project must be deployed to
# /opt/oc2/shared/bofs/SQL-BOF/ on the teamserver. Build only — binaries
# stay in external/SQL-BOF/SQL/<bof>/ and are rsynced from there directly.
# ============================================
if should_sync "SQL-BOF"; then
    log "--- SQL-BOF ---"
    pull_submodule "$EXTERNAL/SQL-BOF" "SQL-BOF"

    if $DO_BUILD; then
        log "Building SQL-BOF..."
        if ! (cd "$EXTERNAL/SQL-BOF" && bash make_all.sh 2>&1 | tail -5); then
            warn "SQL-BOF build failed."
        fi
    fi

    SQL_OK=true
    for bof in whoami info query xpcmd links impersonate columns rows tables databases users search smb 1434udp agentcmd agentstatus checkrpc clr olecmd adsi togglemodule; do
        SRC_DIR="$EXTERNAL/SQL-BOF/SQL/${bof}"
        if [[ ! -d "$SRC_DIR" ]]; then
            warn "SQL-BOF: ${bof} directory not found"
            SQL_OK=false
        fi
    done
    if $SQL_OK; then
        ok "SQL-BOF built (deploy with: deploy-to-oc2.sh -t '' <host> external/SQL-BOF)"
    else
        warn "SQL-BOF partially built"
    fi
    count_sync
fi

# ============================================
# OperatorsKit (cross-compiled with mingw, x64 only)
# ============================================
if should_sync "OperatorsKit"; then
    log "--- OperatorsKit ---"
    pull_submodule "$EXTERNAL/OperatorsKit" "OperatorsKit"

    DST="$OC2_DIR/OperatorsKit"
    OPS_OK=true
    MINGW_CC="x86_64-w64-mingw32-gcc"
    MINGW_FLAGS="-c -Os -Wno-incompatible-pointer-types -Wno-int-conversion"

    # addtaskscheduler
    SRC="$EXTERNAL/OperatorsKit/KIT/AddTaskScheduler"
    if $DO_BUILD; then
        log "Building addtaskscheduler..."
        if $MINGW_CC $MINGW_FLAGS -o "$DST/addtaskscheduler.x64.o" "$SRC/addtaskscheduler.c" -I "$SRC" 2>&1 | tail -3; then
            x86_64-w64-mingw32-strip --strip-unneeded "$DST/addtaskscheduler.x64.o" 2>/dev/null
        else
            warn "addtaskscheduler build failed"
            OPS_OK=false
        fi
    else
        # Fallback: copy upstream MSVC-compiled .o if available
        if [[ -f "$SRC/addtaskscheduler.o" ]]; then
            cp "$SRC/addtaskscheduler.o" "$DST/addtaskscheduler.x64.o"
        else
            warn "OperatorsKit: addtaskscheduler.o not found"; OPS_OK=false
        fi
    fi

    # credprompt - has upstream bugs preventing mingw cross-compile,
    # copy the pre-built MSVC .o from the repo
    SRC="$EXTERNAL/OperatorsKit/KIT/CredPrompt"
    if [[ -f "$SRC/credprompt.o" ]]; then
        cp "$SRC/credprompt.o" "$DST/credprompt.x64.o"
    else
        warn "OperatorsKit: credprompt.o not found"; OPS_OK=false
    fi

    if $OPS_OK; then
        ok "OperatorsKit synced"; count_sync
    else
        err "OperatorsKit build/sync failed"; count_fail
    fi
fi

# ============================================
# PrivKit
# ============================================
if should_sync "PrivKit"; then
    log "--- PrivKit ---"
    pull_submodule "$EXTERNAL/PrivKit" "PrivKit"

    if $DO_BUILD; then
        log "Building PrivKit..."
        if ! (cd "$EXTERNAL/PrivKit" && bash make_all.sh 2>&1 | tail -5); then
            warn "PrivKit build failed. Will try to copy existing .o files."
        fi
    fi

    PRIV_OK=true
    PRIV_DST_DIR="$OC2_DIR/PrivKit"
    mkdir -p "$PRIV_DST_DIR"
    for check in AlwaysInstallElevatedCheck AutoLogonCheck CredentialManagerCheck HijackablePathCheck \
                 ModifiableAutorunCheck ModifiableSVCCheck TokenPrivilegesCheck UnquotedSVCPathCheck \
                 PowerShellHistoryCheck UACStatusCheck; do
        FOUND=false
        for o in "$EXTERNAL/PrivKit/${check}/${check}.x64.o" "$EXTERNAL/PrivKit/${check}/${check}.x86.o"; do
            if [[ -f "$o" ]]; then
                cp "$o" "$PRIV_DST_DIR/"
                FOUND=true
            fi
        done
        if ! $FOUND; then
            warn "PrivKit: ${check} .o files not found"
            PRIV_OK=false
        fi
    done
    if $PRIV_OK; then
        ok "PrivKit synced"
    else
        warn "PrivKit partially synced"
    fi
    count_sync
fi

echo ""
log "Sync complete: ${SYNCED} projects synced, ${FAILED} failed."
