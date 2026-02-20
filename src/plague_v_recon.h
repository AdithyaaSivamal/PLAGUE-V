/*
 * plague_v_recon.h — IOA discovery storage structures
 *
 * Dynamic array of discovered IOA entries populated during
 * General Interrogation response processing.
 */

#ifndef PLAGUE_V_RECON_H
#define PLAGUE_V_RECON_H

#include <stdint.h>
#include <stdbool.h>

/* IOA category (for grouping) */
typedef enum {
    IOA_CAT_SINGLE_POINT,       /* M_SP_NA_1 (1) */
    IOA_CAT_DOUBLE_POINT,       /* M_DP_NA_1 (3) */
    IOA_CAT_BITSTRING,          /* M_BO_NA_1 (7) */
    IOA_CAT_MEASURED_NORM,      /* M_ME_NA_1 (9) */
    IOA_CAT_MEASURED_SCALED,    /* M_ME_NB_1 (11) */
    IOA_CAT_MEASURED_SHORT,     /* M_ME_NC_1 (13) */
    IOA_CAT_OTHER               /* Anything else */
} IOACategory;

/* Single discovered IOA entry */
typedef struct {
    uint32_t    ioa;
    uint8_t     type_id;        /* Raw IEC-104 Type ID */
    IOACategory category;
    bool        is_digital;     /* true = has ON/OFF state */
    bool        digital_state;  /* ON=true, OFF=false (only if is_digital) */
    float       analog_value;   /* Analog reading (only if !is_digital) */
    uint32_t    bitstring;      /* Raw bitstring (only for M_BO_NA_1) */
} DiscoveredIOA;

/* Dynamic array of discovered IOAs */
typedef struct {
    DiscoveredIOA *entries;
    int count;
    int capacity;
} IOAInventory;

/* Initialize an empty inventory */
void inventory_init(IOAInventory *inv);

/* Add a discovered IOA (grows array as needed) */
int inventory_add(IOAInventory *inv, DiscoveredIOA entry);

/* Free the inventory */
void inventory_free(IOAInventory *inv);

/* Print formatted discovery table to stdout */
void inventory_print_table(const IOAInventory *inv);

/* Print category summary (counts by type) */
void inventory_print_summary(const IOAInventory *inv);

/* Write discovered IOAs to config file (plague_v_multi format) */
int inventory_write_config(const IOAInventory *inv,
                           const char *filepath,
                           const char *target_ip, int target_port);

/* Get human-readable name for a Type ID */
const char* typeid_name(uint8_t tid);

/* Get category string */
const char* category_name(IOACategory cat);

#endif /* PLAGUE_V_RECON_H */
