/*
 * plague_v_recon.c — IEC-104 Reconnaissance Module (Milestone 3)
 *
 * Sends a General Interrogation (C_IC_NA_1) to an IEC-104 server,
 * collects all response IOAs, and outputs a discovery report plus
 * a config file compatible with plague_v_multi.c.
 *
 * Build: make plague_v_recon
 * Usage: ./plague_v_recon [target_ip] [port] [output_file]
 *   Defaults: 10.10.10.10  2404  config/discovered_ioa_map.txt
 */

#include "cs104_connection.h"
#include "hal_thread.h"
#include "hal_time.h"
#include "plague_v_recon.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Configuration defaults */
#define DEFAULT_IP       "10.10.10.10"
#define DEFAULT_PORT     2404
#define DEFAULT_OUTPUT   "config/discovered_ioa_map.txt"
#define DEFAULT_CA       1
#define DEFAULT_OA       3
#define GI_TIMEOUT_MS    5000    /* Wait for GI responses */
#define INITIAL_CAPACITY 32

/* Globals */
static IOAInventory g_inventory;
static volatile bool g_gi_confirmed = false;
static volatile bool g_gi_terminated = false;
static bool g_debug = false;

/* ----------------------------
 *  Inventory implementation
 * ---------------------------*/

void
inventory_init(IOAInventory *inv)
{
    inv->entries = (DiscoveredIOA *)malloc(INITIAL_CAPACITY * sizeof(DiscoveredIOA));
    inv->count = 0;
    inv->capacity = (inv->entries != NULL) ? INITIAL_CAPACITY : 0;
}

int
inventory_add(IOAInventory *inv, DiscoveredIOA entry)
{
    /* Check for duplicate IOA */
    for (int i = 0; i < inv->count; i++) {
        if (inv->entries[i].ioa == entry.ioa)
            return 0;  /* Skip if already exists */
    }

    /* Grow if needed */
    if (inv->count >= inv->capacity) {
        int new_cap = inv->capacity * 2;
        DiscoveredIOA *new_buf = (DiscoveredIOA *)
            realloc(inv->entries, (size_t)new_cap * sizeof(DiscoveredIOA));
        if (!new_buf) {
            fprintf(stderr, "[!] realloc failed for inventory\n");
            return -1;
        }
        inv->entries = new_buf;
        inv->capacity = new_cap;
    }

    inv->entries[inv->count++] = entry;
    return 1;
}

void
inventory_free(IOAInventory *inv)
{
    free(inv->entries);
    inv->entries = NULL;
    inv->count = 0;
    inv->capacity = 0;
}

const char*
typeid_name(uint8_t tid)
{
    switch (tid) {
    case 1:   return "M_SP_NA_1 (Single-Point)";
    case 3:   return "M_DP_NA_1 (Double-Point)";
    case 7:   return "M_BO_NA_1 (Bitstring32)";
    case 9:   return "M_ME_NA_1 (Normalized)";
    case 11:  return "M_ME_NB_1 (Scaled)";
    case 13:  return "M_ME_NC_1 (Short Float)";
    case 30:  return "M_SP_TB_1 (SP + Time)";
    case 31:  return "M_DP_TB_1 (DP + Time)";
    case 34:  return "M_ME_TD_1 (Norm + Time)";
    case 35:  return "M_ME_TE_1 (Scaled + Time)";
    case 36:  return "M_ME_TF_1 (Short + Time)";
    case 100: return "C_IC_NA_1 (Interrogation)";
    default:  return "Unknown";
    }
}

const char*
category_name(IOACategory cat)
{
    switch (cat) {
    case IOA_CAT_SINGLE_POINT:    return "Single-Point";
    case IOA_CAT_DOUBLE_POINT:    return "Double-Point";
    case IOA_CAT_BITSTRING:       return "Bitstring";
    case IOA_CAT_MEASURED_NORM:   return "Measured (Norm)";
    case IOA_CAT_MEASURED_SCALED: return "Measured (Scaled)";
    case IOA_CAT_MEASURED_SHORT:  return "Measured (Float)";
    case IOA_CAT_OTHER:           return "Other";
    default:                      return "?";
    }
}

void
inventory_print_table(const IOAInventory *inv)
{
    printf("╔═══════╦══════════════════════════════╦═══════╦═════════╗\n");
    printf("║  IOA  ║         Type ID              ║ State ║  Value  ║\n");
    printf("╠═══════╬══════════════════════════════╬═══════╬═════════╣\n");

    for (int i = 0; i < inv->count; i++) {
        const DiscoveredIOA *e = &inv->entries[i];
        char state_str[8] = "  -  ";
        char value_str[12] = "   -   ";

        if (e->is_digital) {
            snprintf(state_str, sizeof(state_str), " %s ",
                     e->digital_state ? " ON" : "OFF");
        }

        if (!e->is_digital && e->category != IOA_CAT_BITSTRING) {
            snprintf(value_str, sizeof(value_str), "%7.1f", e->analog_value);
        }
        else if (e->category == IOA_CAT_BITSTRING) {
            snprintf(value_str, sizeof(value_str), "0x%04X",
                     (unsigned)e->bitstring);
        }

        printf("║ %-5u ║ %-28s ║ %-5s ║ %-7s ║\n",
               e->ioa, typeid_name(e->type_id), state_str, value_str);
    }

    printf("╚═══════╩══════════════════════════════╩═══════╩═════════╝\n");
}

void
inventory_print_summary(const IOAInventory *inv)
{
    int counts[7] = {0};
    for (int i = 0; i < inv->count; i++)
        counts[inv->entries[i].category]++;

    printf("  %-20s : %d\n", "Single-Point (dig)", counts[IOA_CAT_SINGLE_POINT]);
    printf("  %-20s : %d\n", "Double-Point (dig)", counts[IOA_CAT_DOUBLE_POINT]);
    printf("  %-20s : %d\n", "Bitstring",          counts[IOA_CAT_BITSTRING]);
    printf("  %-20s : %d\n", "Measured Normalized", counts[IOA_CAT_MEASURED_NORM]);
    printf("  %-20s : %d\n", "Measured Scaled",     counts[IOA_CAT_MEASURED_SCALED]);
    printf("  %-20s : %d\n", "Measured Float",      counts[IOA_CAT_MEASURED_SHORT]);
    if (counts[IOA_CAT_OTHER] > 0)
        printf("  %-20s : %d\n", "Other",           counts[IOA_CAT_OTHER]);
}

int
inventory_write_config(const IOAInventory *inv,
                       const char *filepath,
                       const char *target_ip, int target_port)
{
    FILE *fp = fopen(filepath, "w");
    if (!fp) {
        fprintf(stderr, "[!] Cannot write to: %s\n", filepath);
        return -1;
    }

    /* Header with timestamp */
    time_t now = time(NULL);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(fp, "# Auto-discovered IOAs from %s:%d on %s\n", target_ip, target_port, timebuf);
    fprintf(fp, "# Format: IOA  Name  TargetState\n");
    fprintf(fp, "# Total: %d IOAs discovered\n\n", inv->count);

    for (int i = 0; i < inv->count; i++) {
        const DiscoveredIOA *e = &inv->entries[i];

        /* Generate a descriptive name */
        const char *prefix;
        switch (e->category) {
        case IOA_CAT_SINGLE_POINT:    prefix = "SP"; break;
        case IOA_CAT_DOUBLE_POINT:    prefix = "DP"; break;
        case IOA_CAT_BITSTRING:       prefix = "BS"; break;
        case IOA_CAT_MEASURED_NORM:   prefix = "MN"; break;
        case IOA_CAT_MEASURED_SCALED: prefix = "MS"; break;
        case IOA_CAT_MEASURED_SHORT:  prefix = "MF"; break;
        default:                      prefix = "UK"; break;
        }

        /* State for config: digital points get ON/OFF, analog default to OFF */
        const char *state_str;
        if (e->is_digital)
            state_str = e->digital_state ? "ON" : "OFF";
        else
            state_str = "OFF";

        fprintf(fp, "%-6u %s_IOA_%u  %s\n", e->ioa, prefix, e->ioa, state_str);
    }

    fclose(fp);
    return 0;
}

/* ═══════════════════════════════════════════
 *  Callbacks
 * ═══════════════════════════════════════════ */

static void
rawMessageHandler(void* parameter, uint8_t* msg, int msgSize, bool sent)
{
    (void)parameter;
    if (!g_debug)
        return;
    printf("  %s ", sent ? ">>>" : "<<<");
    for (int i = 0; i < msgSize; i++)
        printf("%02x ", msg[i]);
    printf("\n");
}

static void
connectionHandler(void* parameter, CS104_Connection connection,
                  CS104_ConnectionEvent event)
{
    (void)parameter;
    (void)connection;
    switch (event) {
    case CS104_CONNECTION_OPENED:
        printf("[+] TCP connected\n");
        break;
    case CS104_CONNECTION_CLOSED:
        printf("[*] Connection closed\n");
        break;
    case CS104_CONNECTION_FAILED:
        printf("[!] Connection FAILED\n");
        break;
    case CS104_CONNECTION_STARTDT_CON_RECEIVED:
        printf("[+] STARTDT_CON received — data transfer ACTIVE\n");
        break;
    case CS104_CONNECTION_STOPDT_CON_RECEIVED:
        printf("[+] STOPDT_CON received\n");
        break;
    }
}

/* Process each information object in the ASDU */
static void
process_single_point(CS101_ASDU asdu, int num_elements)
{
    for (int i = 0; i < num_elements; i++) {
        InformationObject io = CS101_ASDU_getElement(asdu, i);
        if (!io) continue;

        SinglePointInformation spi = (SinglePointInformation)io;
        DiscoveredIOA entry = {0};
        entry.ioa = (uint32_t)InformationObject_getObjectAddress(io);
        entry.type_id = CS101_ASDU_getTypeID(asdu);
        entry.category = IOA_CAT_SINGLE_POINT;
        entry.is_digital = true;
        entry.digital_state = SinglePointInformation_getValue(spi);
        inventory_add(&g_inventory, entry);

        InformationObject_destroy(io);
    }
}

static void
process_double_point(CS101_ASDU asdu, int num_elements)
{
    for (int i = 0; i < num_elements; i++) {
        InformationObject io = CS101_ASDU_getElement(asdu, i);
        if (!io) continue;

        DoublePointInformation dpi = (DoublePointInformation)io;
        DoublePointValue dpv = DoublePointInformation_getValue(dpi);

        DiscoveredIOA entry = {0};
        entry.ioa = (uint32_t)InformationObject_getObjectAddress(io);
        entry.type_id = CS101_ASDU_getTypeID(asdu);
        entry.category = IOA_CAT_DOUBLE_POINT;
        entry.is_digital = true;
        entry.digital_state = (dpv == IEC60870_DOUBLE_POINT_ON);
        inventory_add(&g_inventory, entry);

        InformationObject_destroy(io);
    }
}

static void
process_bitstring(CS101_ASDU asdu, int num_elements)
{
    for (int i = 0; i < num_elements; i++) {
        InformationObject io = CS101_ASDU_getElement(asdu, i);
        if (!io) continue;

        BitString32 bs = (BitString32)io;
        DiscoveredIOA entry = {0};
        entry.ioa = (uint32_t)InformationObject_getObjectAddress(io);
        entry.type_id = CS101_ASDU_getTypeID(asdu);
        entry.category = IOA_CAT_BITSTRING;
        entry.is_digital = false;
        entry.bitstring = BitString32_getValue(bs);
        inventory_add(&g_inventory, entry);

        InformationObject_destroy(io);
    }
}

static void
process_measured_normalized(CS101_ASDU asdu, int num_elements)
{
    for (int i = 0; i < num_elements; i++) {
        InformationObject io = CS101_ASDU_getElement(asdu, i);
        if (!io) continue;

        MeasuredValueNormalized mvn = (MeasuredValueNormalized)io;
        DiscoveredIOA entry = {0};
        entry.ioa = (uint32_t)InformationObject_getObjectAddress(io);
        entry.type_id = CS101_ASDU_getTypeID(asdu);
        entry.category = IOA_CAT_MEASURED_NORM;
        entry.is_digital = false;
        entry.analog_value = MeasuredValueNormalized_getValue(mvn);
        inventory_add(&g_inventory, entry);

        InformationObject_destroy(io);
    }
}

static void
process_measured_scaled(CS101_ASDU asdu, int num_elements)
{
    for (int i = 0; i < num_elements; i++) {
        InformationObject io = CS101_ASDU_getElement(asdu, i);
        if (!io) continue;

        MeasuredValueScaled mvs = (MeasuredValueScaled)io;
        DiscoveredIOA entry = {0};
        entry.ioa = (uint32_t)InformationObject_getObjectAddress(io);
        entry.type_id = CS101_ASDU_getTypeID(asdu);
        entry.category = IOA_CAT_MEASURED_SCALED;
        entry.is_digital = false;
        entry.analog_value = (float)MeasuredValueScaled_getValue(mvs);
        inventory_add(&g_inventory, entry);

        InformationObject_destroy(io);
    }
}

static void
process_measured_short(CS101_ASDU asdu, int num_elements)
{
    for (int i = 0; i < num_elements; i++) {
        InformationObject io = CS101_ASDU_getElement(asdu, i);
        if (!io) continue;

        MeasuredValueShort mvf = (MeasuredValueShort)io;
        DiscoveredIOA entry = {0};
        entry.ioa = (uint32_t)InformationObject_getObjectAddress(io);
        entry.type_id = CS101_ASDU_getTypeID(asdu);
        entry.category = IOA_CAT_MEASURED_SHORT;
        entry.is_digital = false;
        entry.analog_value = MeasuredValueShort_getValue(mvf);
        inventory_add(&g_inventory, entry);

        InformationObject_destroy(io);
    }
}

static void
process_generic(CS101_ASDU asdu, int num_elements)
{
    for (int i = 0; i < num_elements; i++) {
        InformationObject io = CS101_ASDU_getElement(asdu, i);
        if (!io) continue;

        DiscoveredIOA entry = {0};
        entry.ioa = (uint32_t)InformationObject_getObjectAddress(io);
        entry.type_id = CS101_ASDU_getTypeID(asdu);
        entry.category = IOA_CAT_OTHER;
        entry.is_digital = false;
        inventory_add(&g_inventory, entry);

        InformationObject_destroy(io);
    }
}

/* ─── Main ASDU handler ─── */
static bool
asduReceivedHandler(void* parameter, int address, CS101_ASDU asdu)
{
    (void)parameter;
    (void)address;

    TypeID tid = CS101_ASDU_getTypeID(asdu);
    CS101_CauseOfTransmission cot = CS101_ASDU_getCOT(asdu);
    int num = CS101_ASDU_getNumberOfElements(asdu);

    /* Handle GI confirmation/termination */
    if (tid == C_IC_NA_1) {
        if (cot == CS101_COT_ACTIVATION_CON) {
            bool neg = CS101_ASDU_isNegative(asdu);
            if (neg) {
                printf("[!] Interrogation REJECTED (negative ACT_CON)\n");
            }
            else {
                printf("[+] Interrogation accepted (ACT_CON)\n");
                g_gi_confirmed = true;
            }
        }
        else if (cot == CS101_COT_ACTIVATION_TERMINATION) {
            printf("[+] Interrogation complete (ACT_TERM)\n");
            g_gi_terminated = true;
        }
        return true;
    }

    /* Only collect data from GI responses (COT=20) or spontaneous/periodic */
    if (cot != CS101_COT_INTERROGATED_BY_STATION &&
        cot != CS101_COT_SPONTANEOUS &&
        cot != CS101_COT_PERIODIC) {
        return true;
    }

    /* Dispatch by Type ID */
    switch (tid) {
    case M_SP_NA_1:  /* 1 */
    case M_SP_TB_1:  /* 30 */
        process_single_point(asdu, num);
        break;
    case M_DP_NA_1:  /* 3 */
    case M_DP_TB_1:  /* 31 */
        process_double_point(asdu, num);
        break;
    case M_BO_NA_1:  /* 7 */
    case M_BO_TB_1:  /* 33 */
        process_bitstring(asdu, num);
        break;
    case M_ME_NA_1:  /* 9 */
    case M_ME_TD_1:  /* 34 */
        process_measured_normalized(asdu, num);
        break;
    case M_ME_NB_1:  /* 11 */
    case M_ME_TE_1:  /* 35 */
        process_measured_scaled(asdu, num);
        break;
    case M_ME_NC_1:  /* 13 */
    case M_ME_TF_1:  /* 36 */
        process_measured_short(asdu, num);
        break;
    default:
        process_generic(asdu, num);
        break;
    }

    return true;
}

/* ----------------------------*
 *            Main             *
 * --------------------------- */
int
main(int argc, char** argv)
{
    const char* ip     = DEFAULT_IP;
    int         port   = DEFAULT_PORT;
    const char* output = DEFAULT_OUTPUT;

    if (argc > 1) ip     = argv[1];
    if (argc > 2) port   = atoi(argv[2]);
    if (argc > 3) output = argv[3];

    /* Check for --debug flag anywhere in args */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--debug") == 0) {
            g_debug = true;
            printf("[*] Debug mode: raw hex dump enabled\n");
        }
    }

    printf("╔══════════════════════════════════════════╗\n");
    printf("║   PLAGUE-V — IEC-104 Reconnaissance     ║\n");
    printf("╚══════════════════════════════════════════╝\n");
    printf("[*] Target : %s:%d\n", ip, port);
    printf("[*] Output : %s\n", output);
    printf("[*] CA=%d  OA=%d\n\n", DEFAULT_CA, DEFAULT_OA);

    /* Step 1: Initialize inventory */
    inventory_init(&g_inventory);
    if (g_inventory.entries == NULL) {
        fprintf(stderr, "[!] Failed to allocate IOA inventory\n");
        return 1;
    }

    /* Step 2: Create connection */
    CS104_Connection con = CS104_Connection_create(ip, port);
    if (con == NULL) {
        fprintf(stderr, "[!] Failed to create connection object\n");
        inventory_free(&g_inventory);
        return 1;
    }

    /* Step 3: Configure */
    CS101_AppLayerParameters alParams = CS104_Connection_getAppLayerParameters(con);
    alParams->originatorAddress = DEFAULT_OA;

    CS104_APCIParameters apciParams = CS104_Connection_getAPCIParameters(con);
    apciParams->t0 = 5;

    /* Step 4: Register callbacks */
    CS104_Connection_setConnectionHandler(con, connectionHandler, NULL);
    CS104_Connection_setASDUReceivedHandler(con, asduReceivedHandler, NULL);
    CS104_Connection_setRawMessageHandler(con, rawMessageHandler, NULL);

    /* Step 5: Connect */
    printf("[*] Connecting to %s:%d ...\n", ip, port);
    if (!CS104_Connection_connect(con)) {
        fprintf(stderr, "[!] TCP connection failed (timeout after %ds)\n",
                apciParams->t0);
        CS104_Connection_destroy(con);
        inventory_free(&g_inventory);
        return 1;
    }

    /* Step 6: Activate */
    printf("[>] Sending STARTDT_ACT ...\n");
    CS104_Connection_sendStartDT(con);
    Thread_sleep(500);

    /* Step 7: Send General Interrogation */
    printf("[>] Sending C_IC_NA_1 (General Interrogation, QOI=20) ...\n");

    bool gi_sent = CS104_Connection_sendInterrogationCommand(
        con, CS101_COT_ACTIVATION, DEFAULT_CA, IEC60870_QOI_STATION);

    if (!gi_sent) {
        fprintf(stderr, "[!] Failed to send interrogation command\n");
        CS104_Connection_destroy(con);
        inventory_free(&g_inventory);
        return 1;
    }
    printf("[+] Interrogation command sent\n");

    /* Step 8: Collect responses */
    printf("[*] Collecting responses (%dms timeout) ...\n", GI_TIMEOUT_MS);

    /* Wait for GI termination or timeout */
    int waited = 0;
    while (!g_gi_terminated && waited < GI_TIMEOUT_MS) {
        Thread_sleep(100);
        waited += 100;
    }

    if (g_gi_terminated) {
        printf("[+] Server signaled interrogation complete\n");
    }
    else {
        printf("[*] Timeout reached — proceeding with collected data\n");
    }

    /* Step 9: Display results */
    printf("\n[+] Discovered %d IOAs:\n\n", g_inventory.count);

    if (g_inventory.count > 0) {
        inventory_print_table(&g_inventory);

        printf("\n[*] Summary by type:\n");
        inventory_print_summary(&g_inventory);
    }
    else {
        printf("    (no IOAs found — server may not support GI)\n");
    }

    /* Step 10: Write config file */
    if (g_inventory.count > 0) {
        printf("\n[*] Writing config to %s ...\n", output);
        if (inventory_write_config(&g_inventory, output, ip, port) == 0) {
            printf("[+] Saved %d IOAs to %s\n", g_inventory.count, output);
        }
        else {
            fprintf(stderr, "[!] Failed to write config file\n");
        }
    }

    /* Step 11: Cleanup */
    printf("\n[*] Disconnecting ...\n");
    CS104_Connection_destroy(con);
    inventory_free(&g_inventory);
    printf("[✓] Reconnaissance complete\n");

    return 0;
}
