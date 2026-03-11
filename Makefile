# ────────────────────────────────────────────────
# PLAGUE-V PoC — Makefile (M1–M3 + Netscan + Orchestrator)
# ────────────────────────────────────────────────
# Directory layout:
#   src/     — source files
#   build/   — intermediate object files
#   bin/     — final binaries
#   config/  — IOA maps and target configs
#
# Override lib60870 path:
#   make LIB60870_HOME=/path/to/lib60870-C
# ────────────────────────────────────────────────

LIB60870_HOME ?= /opt/lib60870/lib60870-C

CC       = gcc
CFLAGS   = -std=gnu99 -g -Wall -Wextra
INCLUDES = -I$(LIB60870_HOME)/src/inc/api \
           -I$(LIB60870_HOME)/src/hal/inc \
           -Isrc
LIB_NAME = $(LIB60870_HOME)/build/liblib60870.a
LDLIBS   = -lpthread

# ─── Directory layout ───
SRCDIR   = src
BUILDDIR = build
BINDIR   = bin

.PHONY: all clean dirs run run-multi run-recon run-netscan run-orchestrator

all: dirs $(BINDIR)/plague_v_poc $(BINDIR)/plague_v_multi $(BINDIR)/plague_v_recon \
     $(BINDIR)/plague_v_netscan $(BINDIR)/plague_v_orchestrator

dirs:
	@mkdir -p $(BUILDDIR) $(BINDIR) $(BINDIR)/config

# ════════════════════════════════════════════════
#  Milestone 1: Single-IOA PoC
# ════════════════════════════════════════════════
$(BINDIR)/plague_v_poc: $(SRCDIR)/plague_v_poc.c $(LIB_NAME) | dirs
	$(CC) $(CFLAGS) -o $@ $< $(INCLUDES) $(LIB_NAME) $(LDLIBS)
	@echo "[+] Built $@"

# ════════════════════════════════════════════════
#  Milestone 2: Multi-IOA Attack
# ════════════════════════════════════════════════
$(BINDIR)/plague_v_multi: $(BUILDDIR)/plague_v_multi.o $(BUILDDIR)/ioa_parser.o $(LIB_NAME) | dirs
	$(CC) $(CFLAGS) -o $@ $(BUILDDIR)/plague_v_multi.o $(BUILDDIR)/ioa_parser.o $(LIB_NAME) $(LDLIBS)
	@echo "[+] Built $@"

$(BUILDDIR)/plague_v_multi.o: $(SRCDIR)/plague_v_multi.c $(SRCDIR)/ioa_parser.h | dirs
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BUILDDIR)/ioa_parser.o: $(SRCDIR)/ioa_parser.c $(SRCDIR)/ioa_parser.h | dirs
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# ════════════════════════════════════════════════
#  Milestone 3: Reconnaissance
# ════════════════════════════════════════════════
$(BINDIR)/plague_v_recon: $(BUILDDIR)/plague_v_recon.o $(LIB_NAME) | dirs
	$(CC) $(CFLAGS) -o $@ $(BUILDDIR)/plague_v_recon.o $(LIB_NAME) $(LDLIBS)
	@echo "[+] Built $@"

$(BUILDDIR)/plague_v_recon.o: $(SRCDIR)/plague_v_recon.c $(SRCDIR)/plague_v_recon.h | dirs
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# ════════════════════════════════════════════════
#  Netscan: Active Scanner + Passive Sniffer
# ════════════════════════════════════════════════
$(BINDIR)/plague_v_netscan: $(BUILDDIR)/plague_v_netscan.o $(BUILDDIR)/netscan_types.o | dirs
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS) -lpcap
	@echo "[+] Built $@"

$(BUILDDIR)/plague_v_netscan.o: $(SRCDIR)/plague_v_netscan.c $(SRCDIR)/netscan_types.h | dirs
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BUILDDIR)/netscan_types.o: $(SRCDIR)/netscan_types.c $(SRCDIR)/netscan_types.h | dirs
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# ════════════════════════════════════════════════
#  Orchestrator: Kill Chain Automation
# ════════════════════════════════════════════════
$(BINDIR)/plague_v_orchestrator: $(BUILDDIR)/plague_v_orchestrator.o $(BUILDDIR)/netscan_types.o | dirs
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)
	@echo "[+] Built $@"

$(BUILDDIR)/plague_v_orchestrator.o: $(SRCDIR)/plague_v_orchestrator.c $(SRCDIR)/netscan_types.h | dirs
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# ════════════════════════════════════════════════
#  Run targets (from bin/)
# ════════════════════════════════════════════════
run: $(BINDIR)/plague_v_poc
	cd $(BINDIR) && ./plague_v_poc

run-multi: $(BINDIR)/plague_v_multi
	cd $(BINDIR) && ./plague_v_multi

run-recon: $(BINDIR)/plague_v_recon
	cd $(BINDIR) && ./plague_v_recon

run-netscan: $(BINDIR)/plague_v_netscan
	cd $(BINDIR) && ./plague_v_netscan --help

run-orchestrator: $(BINDIR)/plague_v_orchestrator
	cd $(BINDIR) && ./plague_v_orchestrator --help

# ─── Recon → Attack pipeline (legacy) ───
pipeline: $(BINDIR)/plague_v_recon $(BINDIR)/plague_v_multi
	@echo "[*] Phase 1: Reconnaissance"
	cd $(BINDIR) && ./plague_v_recon $(TARGET) $(PORT) config/discovered_ioa_map.txt
	@echo ""
	@echo "[*] Phase 2: Attack with discovered IOAs"
	cd $(BINDIR) && ./plague_v_multi $(TARGET) $(PORT) config/discovered_ioa_map.txt

# ─── Full automated pipeline (new) ───
full-pipeline: $(BINDIR)/plague_v_orchestrator $(BINDIR)/plague_v_netscan \
               $(BINDIR)/plague_v_recon $(BINDIR)/plague_v_multi
	cd $(BINDIR) && ./plague_v_orchestrator --range $(RANGE) --interface $(IFACE)

clean:
	rm -f $(BUILDDIR)/*.o
	rm -f $(BINDIR)/plague_v_poc $(BINDIR)/plague_v_multi $(BINDIR)/plague_v_recon
	rm -f $(BINDIR)/plague_v_netscan $(BINDIR)/plague_v_orchestrator
	@echo "[+] Cleaned"
