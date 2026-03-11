/*
 * netscan_types.h 
 *
 * Shared data structures for plague_v_netscan
 *
 * Defines target and sniffed-command types used by the network scanner, passive sniffer, and orchestrator.
 */

#ifndef NETSCAN_TYPES_H
#define NETSCAN_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

/* Protocol identifiers */
typedef enum {
    PROTO_IEC104,
    PROTO_IEC61850,
    PROTO_OPC_UA,
    PROTO_MODBUS,
    PROTO_UNKNOWN
} OTProtocol;

/* Default ports */
#define PORT_IEC104     2404
#define PORT_IEC61850   102
#define PORT_GOOSE      8102
#define PORT_OPC_UA     4840
#define PORT_MODBUS     502

/* Active scan result */
#define IP_STR_MAX 46   /* IPv4 or IPv6 string */

typedef struct {
    char        ip[IP_STR_MAX];
    uint16_t    port;
    bool        is_iec104;          /* STARTDT handshake confirmed */
    bool        is_iec61850;        /* Port 102 open (skeleton) */
    bool        is_opc_ua;          /* Port 4840 open (skeleton) */
    double      response_time_ms;   /* TCP connect round-trip */
} ScanTarget;

typedef struct {
    ScanTarget *entries;
    int         count;
    int         capacity;
} ScanResults;

/* Passive sniff result */
typedef struct {
    char        src_ip[IP_STR_MAX]; /* Who sent the command (SCADA master) */
    char        dst_ip[IP_STR_MAX]; /* Who received it (RTU) */
    uint16_t    dst_port;
    OTProtocol  protocol;
    uint8_t     type_id;            /* IEC-104 Type ID (e.g. 45 = C_SC_NA_1) */
    uint8_t     cot;                /* Cause of Transmission */
    uint16_t    ca;                 /* Common Address */
    uint32_t    ioa;                /* Information Object Address */
    uint8_t     state;              /* Command state (ON/OFF) */
    int         observation_count;  /* How many times this exact cmd was seen */
} SniffedCommand;

typedef struct {
    SniffedCommand *entries;
    int             count;
    int             capacity;
} SniffResults;

/* ScanResults functions */
void scan_results_init(ScanResults *sr);
int  scan_results_add(ScanResults *sr, ScanTarget target);
void scan_results_free(ScanResults *sr);
void scan_results_print(const ScanResults *sr);
int  scan_results_write(const ScanResults *sr, const char *filepath);

/* SniffResults functions */
void sniff_results_init(SniffResults *sr);

/**
 * Add or merge a sniffed command. If an entry with the same
 * dst_ip + ca + ioa + type_id already exists, increment its
 * observation_count instead of creating a duplicate.
 */
int  sniff_results_add(SniffResults *sr, SniffedCommand cmd);
void sniff_results_free(SniffResults *sr);
void sniff_results_print(const SniffResults *sr);

/**
 * Write sniffed commands as an ioa_parser-compatible config file.
 * Only includes command-direction Type IDs (45-69).
 */
int  sniff_results_write_config(const SniffResults *sr,
                                const char *filepath);

/* extra functions */
const char* protocol_name(OTProtocol proto);
const char* typeid_to_name(uint8_t tid);
bool        is_command_typeid(uint8_t tid);

#endif /* NETSCAN_TYPES_H */
