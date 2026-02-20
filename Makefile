LIB60870_HOME ?= /opt/lib60870/lib60870-C

CC       = gcc
CFLAGS   = -std=gnu99 -g -Wall -Wextra
INCLUDES = -I$(LIB60870_HOME)/src/inc/api \
           -I$(LIB60870_HOME)/src/hal/inc
LIB_NAME = $(LIB60870_HOME)/build/src/liblib60870.a
LDLIBS   = -lpthread

SRC_DIR    = src
BUILD_DIR  = build
BIN_DIR    = bin
SCRIPT_DIR = scripts

BIN_POC   = $(BIN_DIR)/plague_v_poc
BIN_MULTI = $(BIN_DIR)/plague_v_multi
BIN_RECON = $(BIN_DIR)/plague_v_recon

OBJS = \
  $(BUILD_DIR)/plague_v_poc.o \
  $(BUILD_DIR)/plague_v_multi.o \
  $(BUILD_DIR)/plague_v_recon.o \
  $(BUILD_DIR)/ioa_parser.o

# ─── Targets ───
.PHONY: all clean pipeline dirs

all: dirs $(BIN_POC) $(BIN_MULTI) $(BIN_RECON)

dirs:
	@mkdir -p $(BUILD_DIR) $(BIN_DIR)

# ─── Milestone 1: Single-command PoC ───
$(BIN_POC): $(BUILD_DIR)/plague_v_poc.o $(LIB_NAME)
	$(CC) $(CFLAGS) -o $@ $< $(INCLUDES) $(LIB_NAME) $(LDLIBS)
	@echo "[+] Built plague_v_poc -> $@"

$(BUILD_DIR)/plague_v_poc.o: $(SRC_DIR)/plague_v_poc.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# ─── Milestone 2: Multi-IOA attack ───
$(BIN_MULTI): $(BUILD_DIR)/plague_v_multi.o $(BUILD_DIR)/ioa_parser.o $(LIB_NAME)
	$(CC) $(CFLAGS) -o $@ $(BUILD_DIR)/plague_v_multi.o $(BUILD_DIR)/ioa_parser.o \
		$(LIB_NAME) $(LDLIBS)
	@echo "[+] Built plague_v_multi -> $@"

$(BUILD_DIR)/plague_v_multi.o: $(SRC_DIR)/plague_v_multi.c $(SRC_DIR)/ioa_parser.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BUILD_DIR)/ioa_parser.o: $(SRC_DIR)/ioa_parser.c $(SRC_DIR)/ioa_parser.h
	$(CC) $(CFLAGS) -c $< -o $@

# ─── Milestone 3: Reconnaissance ───
$(BIN_RECON): $(BUILD_DIR)/plague_v_recon.o $(LIB_NAME)
	$(CC) $(CFLAGS) -o $@ $(BUILD_DIR)/plague_v_recon.o $(LIB_NAME) $(LDLIBS)
	@echo "[+] Built plague_v_recon -> $@"

$(BUILD_DIR)/plague_v_recon.o: $(SRC_DIR)/plague_v_recon.c $(SRC_DIR)/plague_v_recon.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# ─── Automated recon → attack pipeline ───
pipeline: all
	@echo "[*] Running recon → attack pipeline..."
	@cd $(SCRIPT_DIR) && ./test_recon.sh

# ─── Cleanup ───
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
	@echo "[+] Cleaned ($(BUILD_DIR) and $(BIN_DIR) removed)"
