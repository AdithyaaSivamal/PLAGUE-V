# PLAGUE‑V

Proof‑of‑concept implementation of **Industroyer (2016)** IEC‑104 payload logic against a `lib60870-C` basic server.

PLAGUE‑V provides a small, self‑contained C framework for:

- Sending IEC‑104 control commands to specific IOAs (M1)
- Executing multi‑IOA breaker operations from a target list (M2)
- Discovering IOAs via General Interrogation, Industroyer‑style (M3)

It is intended for **off‑line research and education** in controlled lab environments, not for use against real infrastructure.

> ⚠️ **Disclaimer**  
> PLAGUE‑V is for authorized security research and training only. Do not use it on networks or systems you do not own or have explicit permission to test.

---

## Features

- C implementation using the **lib60870‑C** IEC‑104 stack
- Three milestones mirroring Industroyer’s IEC‑104 behavior:
  - **M1** – Single `C_SC_NA_1` command to one IOA
  - **M2** – Multi‑IOA attack using a configurable target map
  - **M3** – Automated IOA discovery using `C_IC_NA_1` (General Interrogation)
- Simple test scripts for running end‑to‑end scenarios
- Clean project layout (`src/`, `build/`, `bin/`, `config/`, `scripts/`)

---

## Repository Layout

```text
plague-v/
├── Makefile           # build rules (uses lib60870-C)
├── src/               # C sources and headers
├── bin/               # compiled binaries (created by make)
├── build/             # object files and intermediates
├── config/            # IOA map examples
├── scripts/           # test_* scripts
└── docs/              # documentation (PLAGUE-V Lite, etc.)
```

---

## Build

Prerequisites:

- Linux toolchain (`gcc`, `make`)
- [`lib60870-C`](https://lib60870.com/) built and installed  
  (default path in the Makefile: `/opt/lib60870/lib60870-C`)

Build all milestones:

```bash
git clone https://github.com/<your-username>/plague-v.git
cd plague-v

# Adjust LIB60870_HOME in Makefile if needed, then:
make
```

Binaries will be placed in `bin/`:

- `bin/plague_v_poc`
- `bin/plague_v_multi`
- `bin/plague_v_recon`

Clean:

```bash
make clean
```

---

## Configuration

The framework uses simple text files to define IOA targets and to store discovered IOAs.

```text
config/
├── target_ioa_map.example.txt     # example IOAs and labels for M2
└── discovered_ioa_map.example.txt # example output format from M3
```

Typical workflow:

1. Copy example files to live configs:
   ```bash
   cp config/target_ioa_map.example.txt config/target_ioa_map.txt
   cp config/discovered_ioa_map.example.txt config/discovered_ioa_map.txt
   ```
2. Edit `target_ioa_map.txt` to match your lab server’s IOAs (e.g., 5000–5007).

---

## Usage

### Start the IEC‑104 Test Server

Run the `lib60870-C` `simple_server` (or your own IEC‑104 lab server) on an isolated network:

```bash
# Example (adjust to your lib60870-C build):
./simple_server 10.10.10.10 2404
```

### Milestone 1 – Single Command (M1)

Send a single `C_SC_NA_1` command to a configured IOA:

```bash
./bin/plague_v_poc
```

Expected behavior:

- Connects to the IEC‑104 server.
- Activates data transfer.
- Issues one ON/OFF command to the configured IOA (e.g., 5000).

### Milestone 2 – Multi‑IOA Attack (M2)

Iterate through a configured list of breaker IOAs:

```bash
./bin/plague_v_multi
```

Reads `config/target_ioa_map.txt` and sends commands to each IOA entry in sequence.

### Milestone 3 – Automated Recon (M3)

Use General Interrogation to discover IOAs:

```bash
./bin/plague_v_recon
```

Behavior:

- Sends `C_IC_NA_1` to the server.
- Parses monitoring responses.
- Writes discovered IOAs and basic metadata into `config/discovered_ioa_map.txt`.

### Test Scripts

Convenience wrappers live in `scripts/`:

```bash
cd scripts

./test_sequence.sh   # run typical M1/M2/M3 sequence
./test_multi.sh      # focus on multi-IOA behavior
./test_recon.sh      # recon + follow-up actions
```

---

## Documentation

A concise, engineer‑focused **PLAGUE‑V Lite Technical Design Document** is being written using the ANTLabs LaTeX template and will be added under `docs/` soon.

Planned docs (WIP):

- `docs/plaguev-lite/main.tex` – PLAGUE‑V Lite TDD (primary reference)
- Sections:
  - Overview & Threat Background (Industroyer 2016 IEC‑104)
  - Architecture & Data Structures
  - IEC‑104 protocol notes used by PLAGUE‑V
  - M1/M2/M3 internals
  - Extending PLAGUE‑V

Once added, this README will link directly to the compiled PDF.

---

## Screenshots & Diagrams (placeholders)

> Replace the placeholders below with actual images/figures once you have them.

- **Figure 1 – High‑level topology**  
  `docs/media/topology.png`  
  _Attacker host running PLAGUE‑V → isolated IEC‑104 server → breaker IOAs._

- **Figure 2 – Industroyer vs PLAGUE‑V mapping**  
  `docs/media/industroyer_mapping.png`  
  _Table/diagram mapping Industroyer IEC‑104 behavior to M1/M2/M3._

- **Figure 3 – Example PLAGUE‑V run**  
  `docs/media/run_example.png`  
  _Terminal screenshot showing M3 discovery followed by M2 attack._

You can reference these in the LaTeX docs and link them from this README once they exist.

---

## Related Reading

A few useful references for context around IEC‑104, Industroyer, and the building blocks used here:

- **Sandworm / Industroyer**
  - ESET – “Win32/Industroyer: A new threat for industrial control systems”
  - ESET – “INDUSTROYER2: Industroyer reloaded”
  - MITRE ATT&CK for ICS – entries related to Industroyer and Sandworm

- **IEC‑60870‑5‑104**
  - Official IEC‑104 standard (paywalled, but summarized in many ICS security blogs)
  - Various IEC‑104 protocol primers from ICS‑security vendors

- **lib60870‑C**
  - Project site and documentation: <https://lib60870.com/>
  - Git repo and examples (`simple_server`, etc.)

---

## Status and Scope

PLAGUE‑V is:

- A **proof‑of‑concept IEC‑104 payload emulator** inspired by Industroyer (2016)
- Focused on:
  - General Interrogation–based IOA reconnaissance
  - Config‑driven multi‑IOA control
  - Clean, reproducible lab environments

PLAGUE‑V is **not**:

- A full recreation of the entire Industroyer toolchain
- A wiper, loader, lateral‑movement framework, or multi‑protocol ICS implant
- Intended for use on production power systems

---

## License

> TODO: Add a license (e.g., MIT, BSD‑3‑Clause).  
> Until then, treat this repository as “all rights reserved” by default.
