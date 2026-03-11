/*
 * netscan_types.c
 *
 * Shared data structure operations for plague_v_netscan
 */

#include "netscan_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define INITIAL_CAPACITY 32

/* Protocol name lookup */
const char*
protocol_name(OTProtocol proto)
{
    switch (proto) {
    case PROTO_IEC104:   return "IEC 104";
    case PROTO_IEC61850: return "IEC 61850";
    case PROTO_OPC_UA:   return "OPC UA";
    case PROTO_MODBUS:   return "Modbus";
    default:             return "Unknown";
    }
}

/* Type ID → name (command-direction only) */
const char*
typeid_to_name(uint8_t tid)
{
    switch (tid) {
    case 45: return "C_SC_NA_1";    /* Single Command */
    case 46: return "C_DC_NA_1";    /* Double Command */
    case 47: return "C_RC_NA_1";    /* Regulating Step */
    case 48: return "C_SE_NA_1";    /* Set Point Normalized */
    case 49: return "C_SE_NB_1";    /* Set Point Scaled */
    case 50: return "C_SE_NC_1";    /* Set Point Short Float */
    case 51: return "C_BO_NA_1";    /* Bitstring 32-bit */
    case 58: return "C_SC_TA_1";    /* Single Command w/ Time */
    case 59: return "C_DC_TA_1";    /* Double Command w/ Time */
    case 60: return "C_RC_TA_1";    /* Regulating Step w/ Time */
    case 61: return "C_SE_TA_1";    /* Set Point Normalized w/ Time */
    case 62: return "C_SE_TB_1";    /* Set Point Scaled w/ Time */
    case 63: return "C_SE_TC_1";    /* Set Point Short Float w/ Time */
    case 64: return "C_BO_TA_1";    /* Bitstring 32-bit w/ Time */
    case 100: return "C_IC_NA_1";   /* Interrogation Command */
    case 101: return "C_CI_NA_1";   /* Counter Interrogation */
    case 102: return "C_RD_NA_1";   /* Read Command */
    case 103: return "C_CS_NA_1";   /* Clock Sync */
    default: return "UNKNOWN";
    }
}

/* ─── Is this a command-direction Type ID? (45-69) ─── */
bool
is_command_typeid(uint8_t tid)
{
    return (tid >= 45 && tid <= 69);
}

/* ════════════════════════════════════════════════════
 *  ScanResults
 * ════════════════════════════════════════════════════ */

void
scan_results_init(ScanResults *sr)
{
    sr->entries  = malloc(sizeof(ScanTarget) * INITIAL_CAPACITY);
    sr->count    = 0;
    sr->capacity = (sr->entries != NULL) ? INITIAL_CAPACITY : 0;
}

int
scan_results_add(ScanResults *sr, ScanTarget target)
{
    if (sr->count >= sr->capacity) {
        int new_cap = sr->capacity * 2;
        ScanTarget *tmp = realloc(sr->entries, sizeof(ScanTarget) * new_cap);
        if (!tmp) return -1;
        sr->entries  = tmp;
        sr->capacity = new_cap;
    }
    sr->entries[sr->count++] = target;
    return 0;
}

void
scan_results_free(ScanResults *sr)
{
    free(sr->entries);
    sr->entries  = NULL;
    sr->count    = 0;
    sr->capacity = 0;
}

void
scan_results_print(const ScanResults *sr)
{
    printf("╔════════════════════╦═══════╦══════════╦═══════════╦══════════╦══════════╗\n");
    printf("║       IP           ║ Port  ║  IEC-104 ║ IEC 61850 ║  OPC UA  ║ RTT (ms) ║\n");
    printf("╠════════════════════╬═══════╬══════════╬═══════════╬══════════╬══════════╣\n");

    for (int i = 0; i < sr->count; i++) {
        const ScanTarget *t = &sr->entries[i];
        printf("║ %-18s ║ %-5d ║   %s    ║    %s     ║   %s    ║ %7.1f  ║\n",
               t->ip, t->port,
               t->is_iec104  ? "✓" : "✗",
               t->is_iec61850 ? "✓" : "✗",
               t->is_opc_ua   ? "✓" : "✗",
               t->response_time_ms);
    }

    printf("╚════════════════════╩═══════╩══════════╩═══════════╩══════════╩══════════╝\n");
}

int
scan_results_write(const ScanResults *sr, const char *filepath)
{
    FILE *f = fopen(filepath, "w");
    if (!f) return -1;

    time_t now = time(NULL);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(f, "# PLAGUE-V Netscan Results\n");
    fprintf(f, "# Generated: %s\n", timebuf);
    fprintf(f, "# Format: IP  Port  IEC104  IEC61850  OPC_UA  RTT_ms\n\n");

    for (int i = 0; i < sr->count; i++) {
        const ScanTarget *t = &sr->entries[i];
        fprintf(f, "%s  %d  %d  %d  %d  %.1f\n",
                t->ip, t->port,
                t->is_iec104, t->is_iec61850, t->is_opc_ua,
                t->response_time_ms);
    }

    fclose(f);
    return 0;
}

/* ════════════════════════════════════════════════════
 *  SniffResults
 * ════════════════════════════════════════════════════ */

void
sniff_results_init(SniffResults *sr)
{
    sr->entries  = malloc(sizeof(SniffedCommand) * INITIAL_CAPACITY);
    sr->count    = 0;
    sr->capacity = (sr->entries != NULL) ? INITIAL_CAPACITY : 0;
}

int
sniff_results_add(SniffResults *sr, SniffedCommand cmd)
{
    /* Deduplication: merge if same dst + ca + ioa + type_id */
    for (int i = 0; i < sr->count; i++) {
        SniffedCommand *e = &sr->entries[i];
        if (strcmp(e->dst_ip, cmd.dst_ip) == 0 &&
            e->ca == cmd.ca &&
            e->ioa == cmd.ioa &&
            e->type_id == cmd.type_id) {
            e->observation_count++;
            e->state = cmd.state;   /* Update to latest observed state */
            return 0;
        }
    }

    /* New entry */
    if (sr->count >= sr->capacity) {
        int new_cap = sr->capacity * 2;
        SniffedCommand *tmp = realloc(sr->entries, sizeof(SniffedCommand) * new_cap);
        if (!tmp) return -1;
        sr->entries  = tmp;
        sr->capacity = new_cap;
    }

    cmd.observation_count = 1;
    sr->entries[sr->count++] = cmd;
    return 0;
}

void
sniff_results_free(SniffResults *sr)
{
    free(sr->entries);
    sr->entries  = NULL;
    sr->count    = 0;
    sr->capacity = 0;
}

void
sniff_results_print(const SniffResults *sr)
{
    if (sr->count == 0) {
        printf("[*] No command traffic captured\n");
        return;
    }

    printf("╔════════════════════╦════════════════════╦═══════╦═══════╦══════════════╦═══════╦══════╗\n");
    printf("║    Source IP       ║   Destination IP   ║  CA   ║  IOA  ║   Type ID    ║ State ║ Seen ║\n");
    printf("╠════════════════════╬════════════════════╬═══════╬═══════╬══════════════╬═══════╬══════╣\n");

    for (int i = 0; i < sr->count; i++) {
        const SniffedCommand *c = &sr->entries[i];
        printf("║ %-18s ║ %-18s ║ %-5d ║ %-5d ║ %-12s ║  %s  ║  %-3d ║\n",
               c->src_ip, c->dst_ip, c->ca, c->ioa,
               typeid_to_name(c->type_id),
               c->state ? "ON " : "OFF",
               c->observation_count);
    }

    printf("╚════════════════════╩════════════════════╩═══════╩═══════╩══════════════╩═══════╩══════╝\n");
}

int
sniff_results_write_config(const SniffResults *sr, const char *filepath)
{
    FILE *f = fopen(filepath, "a");   /* Append — may follow scan results */
    if (!f) return -1;

    time_t now = time(NULL);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(f, "\n# Sniffed command IOAs (passive reconnaissance)\n");
    fprintf(f, "# Captured: %s\n", timebuf);
    fprintf(f, "# Format: IOA  Name  TargetState\n\n");

    int written = 0;
    for (int i = 0; i < sr->count; i++) {
        const SniffedCommand *c = &sr->entries[i];

        /* Only write command-direction Type IDs */
        if (!is_command_typeid(c->type_id))
            continue;

        fprintf(f, "%u  SNIFF_%s_IOA_%u  %s\n",
                c->ioa,
                typeid_to_name(c->type_id),
                c->ioa,
                c->state ? "ON" : "OFF");
        written++;
    }

    fclose(f);
    return written;
}
