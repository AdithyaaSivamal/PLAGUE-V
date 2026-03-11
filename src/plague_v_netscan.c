/*
 * plague_v_netscan.c (Network Scanner and Passive Sniffer)
 *
 * Phase 1 (Active):  TCP port scan + STARTDT handshake to discover
 *                    IEC-104 servers on a network.
 * Phase 2 (Passive): libpcap-based sniffing to capture command-direction
 *                    ASDUs and identify controllable IOAs.
 *
 * Usage: ./plague_v_netscan --scan 10.10.10.0/24 --sniff eth0 --output config/netscan_targets.txt
 */

#include "netscan_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>


#define DEFAULT_PORT          2404
#define DEFAULT_SNIFF_DUR     300
#define DEFAULT_OUTPUT        "config/netscan_targets.txt"
#define CONNECT_TIMEOUT_SEC   2
#define HANDSHAKE_TIMEOUT_SEC 3
#define PCAP_SNAP_LEN         65535
#define PCAP_PROMISC          1

/* IEC-104 STARTDT frames */
static const uint8_t STARTDT_ACT[] = { 0x68, 0x04, 0x07, 0x00, 0x00, 0x00 };
static const uint8_t STARTDT_CON[] = { 0x68, 0x04, 0x0b, 0x00, 0x00, 0x00 };

/* Global state for signal handling */
static volatile sig_atomic_t g_stop_sniff = 0;

static void
sigint_handler(int sig)
{
    (void)sig;
    g_stop_sniff = 1;
}

/* ────────────────────────────────────────────────────
 *  CIDR Parsing
 * ──────────────────────────────────────────────────── */

typedef struct {
    uint32_t start;     /* Network order start IP */
    uint32_t end;       /* Network order end IP */
    int      count;     /* Number of hosts */
} CIDRRange;

static int
parse_cidr(const char *cidr, CIDRRange *range)
{
    char ip_str[IP_STR_MAX];
    int prefix = 32;

    /* Split on '/' */
    const char *slash = strchr(cidr, '/');
    if (slash) {
        size_t ip_len = (size_t)(slash - cidr);
        if (ip_len >= IP_STR_MAX) return -1;
        memcpy(ip_str, cidr, ip_len);
        ip_str[ip_len] = '\0';
        prefix = atoi(slash + 1);
        if (prefix < 0 || prefix > 32) return -1;
    } else {
        strncpy(ip_str, cidr, IP_STR_MAX - 1);
        ip_str[IP_STR_MAX - 1] = '\0';
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) return -1;

    uint32_t ip_host = ntohl(addr.s_addr);
    uint32_t mask = (prefix == 0) ? 0 : (~0U << (32 - prefix));
    uint32_t network = ip_host & mask;
    uint32_t broadcast = network | ~mask;

    if (prefix >= 31) {
        /* /31 or /32: just the single host(s) */
        range->start = htonl(network);
        range->end   = htonl(broadcast);
        range->count = broadcast - network + 1;
    } else {
        /* Skip network and broadcast addresses */
        range->start = htonl(network + 1);
        range->end   = htonl(broadcast - 1);
        range->count = broadcast - network - 1;
    }

    return 0;
}

static void
ip_from_u32(uint32_t net_order, char *buf, size_t buflen)
{
    struct in_addr a;
    a.s_addr = net_order;
    inet_ntop(AF_INET, &a, buf, buflen);
}

static uint32_t
next_ip(uint32_t net_order)
{
    return htonl(ntohl(net_order) + 1);
}

/* ────────────────────────────────────────────────────
 *  Active Scan: TCP Connect + STARTDT Handshake
 * ──────────────────────────────────────────────────── */

static bool
tcp_connect_with_timeout(const char *ip, uint16_t port, int timeout_sec,
                         int *out_sock, double *rtt_ms)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    inet_pton(AF_INET, ip, &sa.sin_addr);

    /* Set connect timeout via SO_SNDTIMEO */
    struct timeval tv = { .tv_sec = timeout_sec, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct timespec t_start, t_end;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    int ret = connect(sock, (struct sockaddr *)&sa, sizeof(sa));

    clock_gettime(CLOCK_MONOTONIC, &t_end);

    *rtt_ms = (t_end.tv_sec - t_start.tv_sec) * 1000.0 +
              (t_end.tv_nsec - t_start.tv_nsec) / 1e6;

    if (ret != 0) {
        close(sock);
        return false;
    }

    *out_sock = sock;
    return true;
}

static bool
iec104_startdt_handshake(int sock)
{
    /* Send STARTDT_ACT */
    if (send(sock, STARTDT_ACT, sizeof(STARTDT_ACT), 0) != sizeof(STARTDT_ACT))
        return false;

    /* Wait for STARTDT_CON */
    uint8_t buf[6];
    ssize_t n = recv(sock, buf, sizeof(buf), 0);
    if (n != 6) return false;

    return (memcmp(buf, STARTDT_CON, sizeof(STARTDT_CON)) == 0);
}

static ScanTarget
scan_host(const char *ip, uint16_t port)
{
    ScanTarget target;
    memset(&target, 0, sizeof(target));
    strncpy(target.ip, ip, IP_STR_MAX - 1);
    target.port = port;

    int sock = -1;
    double rtt = 0;

    if (!tcp_connect_with_timeout(ip, port, CONNECT_TIMEOUT_SEC, &sock, &rtt)) {
        target.response_time_ms = rtt;
        return target;
    }

    target.response_time_ms = rtt;

    /* Attempt IEC-104 STARTDT handshake */
    target.is_iec104 = iec104_startdt_handshake(sock);
    close(sock);

    return target;
}

static int
run_active_scan(const char *cidr, uint16_t port, ScanResults *results)
{
    CIDRRange range;
    if (parse_cidr(cidr, &range) != 0) {
        fprintf(stderr, "[!] Invalid CIDR notation: %s\n", cidr);
        return -1;
    }

    printf("[*] Scanning %s (port %d, %d hosts) ...\n", cidr, port, range.count);

    int confirmed = 0;
    uint32_t current = range.start;

    for (int i = 0; i < range.count; i++) {
        char ip_str[IP_STR_MAX];
        ip_from_u32(current, ip_str, sizeof(ip_str));

        ScanTarget target = scan_host(ip_str, port);

        if (target.is_iec104) {
            printf("[+] %s:%d — IEC-104 server confirmed (%.1fms)\n",
                   ip_str, port, target.response_time_ms);
            confirmed++;
        } else if (target.response_time_ms > 0 &&
                   target.response_time_ms < (CONNECT_TIMEOUT_SEC * 1000)) {
            printf("[-] %s:%d — port open but NOT IEC-104 (%.1fms)\n",
                   ip_str, port, target.response_time_ms);
        }
        /* Silently skip unreachable hosts */

        scan_results_add(results, target);
        current = next_ip(current);
    }

    printf("[*] Scan complete: %d IEC-104 server(s) found\n\n", confirmed);
    return confirmed;
}

/* ────────────────────────────────────────────────────
 *  Skeleton Protocol Hooks
 * ──────────────────────────────────────────────────── */

/**
 * IEC 61850 MMS/GOOSE detection stub.
 * In a full implementation, this would parse MMS (ISO 8327/8823)
 * or GOOSE (ethertype 0x88B8) frames to extract:
 *   - Logical node references
 *   - GOOSE dataset members
 *   - MMS named variables (control block references)
 */
static void
sniff_iec61850(const uint8_t *payload, int len,
               const char *src_ip, const char *dst_ip, uint16_t dst_port)
{
    (void)payload;
    (void)len;

    /* TODO: Parse MMS INITREQ/INITRSP for association detection */
    /* TODO: Parse GOOSE ethertype 0x88B8 frames for dataset enumeration */
    printf("[*] IEC 61850 traffic detected: %s → %s:%d (%d bytes) "
           "[parsing not implemented]\n",
           src_ip, dst_ip, dst_port, len);
}

/**
 * OPC UA detection stub.
 * In a full implementation, this would parse:
 *   - OPC UA "Hello" message (msg type "HEL")
 *   - GetEndpoints response to discover server capabilities
 *   - Browse responses to enumerate OPC node IDs
 */
static void
sniff_opc_ua(const uint8_t *payload, int len,
             const char *src_ip, const char *dst_ip, uint16_t dst_port)
{
    (void)payload;
    (void)len;

    /* TODO: Parse OPC UA binary protocol header (msg type at offset 0-2) */
    /* TODO: Extract endpoint URLs from GetEndpointsResponse */
    printf("[*] OPC UA traffic detected: %s → %s:%d (%d bytes) "
           "[parsing not implemented]\n",
           src_ip, dst_ip, dst_port, len);
}

/**
 * Modbus TCP detection stub.
 * In a full implementation, this would parse MBAP header and
 * extract function codes, unit IDs, and register addresses.
 */
static void
sniff_modbus(const uint8_t *payload, int len,
             const char *src_ip, const char *dst_ip, uint16_t dst_port)
{
    (void)payload;
    (void)len;

    /* TODO: Parse MBAP header (transaction ID, protocol ID, length, unit ID) */
    /* TODO: Extract function code and register addresses */
    printf("[*] Modbus TCP traffic detected: %s → %s:%d (%d bytes) "
           "[parsing not implemented]\n",
           src_ip, dst_ip, dst_port, len);
}

/* ────────────────────────────────────────────────────
 *  Passive Sniff: libpcap IEC-104 Command Extraction
 * ──────────────────────────────────────────────────── */

/* Context passed to pcap callback */
typedef struct {
    SniffResults *results;
    int           pkt_count;
    int           cmd_count;
} SniffContext;

static void
pcap_callback(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
    SniffContext *ctx = (SniffContext *)user;
    ctx->pkt_count++;

    /* Need at least Ethernet + IP + TCP headers */
    if (hdr->caplen < (14 + 20 + 20)) return;

    /* Parse Ethernet */
    uint16_t ethertype = ntohs(*(uint16_t *)(pkt + 12));
    if (ethertype != ETHERTYPE_IP) return;

    /* Parse IP header */
    const struct ip *iph = (const struct ip *)(pkt + 14);
    int ip_hdr_len = iph->ip_hl * 4;
    if (iph->ip_p != IPPROTO_TCP) return;

    char src_ip[IP_STR_MAX], dst_ip[IP_STR_MAX];
    inet_ntop(AF_INET, &iph->ip_src, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &iph->ip_dst, dst_ip, sizeof(dst_ip));

    /* Parse TCP header */
    const struct tcphdr *tcph = (const struct tcphdr *)(pkt + 14 + ip_hdr_len);
    int tcp_hdr_len = tcph->th_off * 4;
    uint16_t src_port = ntohs(tcph->th_sport);
    uint16_t dst_port = ntohs(tcph->th_dport);

    /* Calculate TCP payload offset and length */
    int payload_offset = 14 + ip_hdr_len + tcp_hdr_len;
    int payload_len = (int)hdr->caplen - payload_offset;
    if (payload_len < 6) return;  /* Need at least APCI (6 bytes) */

    const uint8_t *payload = pkt + payload_offset;

    /* Protocol routing by destination port */

    if (dst_port == PORT_IEC61850 || dst_port == PORT_GOOSE ||
        src_port == PORT_IEC61850 || src_port == PORT_GOOSE) {
        sniff_iec61850(payload, payload_len, src_ip, dst_ip, dst_port);
        return;
    }

    if (dst_port == PORT_OPC_UA || src_port == PORT_OPC_UA) {
        sniff_opc_ua(payload, payload_len, src_ip, dst_ip, dst_port);
        return;
    }

    if (dst_port == PORT_MODBUS || src_port == PORT_MODBUS) {
        sniff_modbus(payload, payload_len, src_ip, dst_ip, dst_port);
        return;
    }

    /* ── IEC-104 parsing ── */

    /* Validate IEC-104 start byte */
    if (payload[0] != 0x68) return;

    uint8_t frame_len = payload[1];
    if (payload_len < frame_len + 2) return;

    /* Check for I-frame (bit 0 of first control byte == 0) */
    if (payload[2] & 0x01) return;  /* S-frame or U-frame, skip */

    /* Need at least APCI (4 ctrl) + ASDU header (6 min) = 10 bytes after start */
    if (frame_len < 10) return;

    /* Parse ASDU header (starts at offset 6) */
    uint8_t type_id = payload[6];
    /* uint8_t vsq     = payload[7]; */
    uint8_t cot     = payload[8] & 0x3F;  /* Lower 6 bits */
    /* uint8_t oa      = payload[9]; */       /* Originator address */
    uint16_t ca     = payload[10] | (payload[11] << 8);

    /* Parse IOA (3 bytes, little-endian, starts at offset 12) */
    uint32_t ioa = 0;
    if (frame_len >= 13) {
        ioa = payload[12] | (payload[13] << 8) | (payload[14] << 16);
    }

    /* Only record command-direction Type IDs */
    if (!is_command_typeid(type_id)) return;

    /* Extract state for single/double commands */
    uint8_t state = 0;
    if (frame_len >= 14 && (type_id == 45 || type_id == 58)) {
        state = payload[15] & 0x01;  /* SCO bit 0 */
    }

    SniffedCommand cmd;
    memset(&cmd, 0, sizeof(cmd));
    strncpy(cmd.src_ip, src_ip, IP_STR_MAX - 1);
    strncpy(cmd.dst_ip, dst_ip, IP_STR_MAX - 1);
    cmd.dst_port = dst_port;
    cmd.protocol = PROTO_IEC104;
    cmd.type_id  = type_id;
    cmd.cot      = cot;
    cmd.ca       = ca;
    cmd.ioa      = ioa;
    cmd.state    = state;

    sniff_results_add(ctx->results, cmd);
    ctx->cmd_count++;

    printf("[+] Command captured: %s → %s  %s  CA=%d  IOA=%d  %s\n",
           src_ip, dst_ip, typeid_to_name(type_id),
           ca, ioa, state ? "ON" : "OFF");
}

static int
run_passive_sniff(const char *interface, int duration_sec, SniffResults *results)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Build BPF filter for all OT protocol ports */
    char filter_expr[256];
    snprintf(filter_expr, sizeof(filter_expr),
             "tcp port %d or tcp port %d or tcp port %d or tcp port %d or tcp port %d",
             PORT_IEC104, PORT_IEC61850, PORT_GOOSE, PORT_OPC_UA, PORT_MODBUS);

    pcap_t *handle = pcap_open_live(interface, PCAP_SNAP_LEN, PCAP_PROMISC,
                                    100 /* 100ms read timeout */, errbuf);
    if (!handle) {
        fprintf(stderr, "[!] pcap_open_live(%s) failed: %s\n", interface, errbuf);
        fprintf(stderr, "    Hint: run with sudo or set CAP_NET_RAW\n");
        return -1;
    }

    /* Set non-blocking mode — critical for Docker/container environments
     * where pcap_dispatch can block indefinitely despite read timeout */
    if (pcap_setnonblock(handle, 1, errbuf) == -1) {
        fprintf(stderr, "[!] pcap_setnonblock failed: %s\n", errbuf);
        pcap_close(handle);
        return -1;
    }

    /* Compile and apply BPF filter */
    struct bpf_program bpf;
    if (pcap_compile(handle, &bpf, filter_expr, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "[!] BPF compile failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }
    if (pcap_setfilter(handle, &bpf) == -1) {
        fprintf(stderr, "[!] BPF setfilter failed: %s\n", pcap_geterr(handle));
        pcap_freecode(&bpf);
        pcap_close(handle);
        return -1;
    }
    pcap_freecode(&bpf);

    printf("[*] Sniffing on %s for %ds (filter: %s) ...\n",
           interface, duration_sec, filter_expr);
    printf("[*] Press Ctrl-C to stop early\n\n");

    /* Install signal handler for clean stop */
    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    SniffContext ctx = { .results = results, .pkt_count = 0, .cmd_count = 0 };

    time_t start_time = time(NULL);
    time_t last_tick  = start_time;

    while (!g_stop_sniff) {
        /* Check duration */
        time_t now = time(NULL);
        if (now - start_time >= duration_sec) break;

        /* Progress tick every second */
        if (now != last_tick) {
            int remaining = duration_sec - (int)(now - start_time);
            printf("\r[*] Sniffing... %ds remaining, %d cmd(s) captured   ",
                   remaining, ctx.cmd_count);
            fflush(stdout);
            last_tick = now;
        }

        /* Non-blocking dispatch — returns immediately if no packets */
        pcap_dispatch(handle, 10, pcap_callback, (u_char *)&ctx);

        /* Sleep 200ms to avoid busy-waiting */
        usleep(200000);
    }

    pcap_close(handle);

    printf("\r[*] Sniff complete: %d packets processed, %d commands captured       \n\n",
           ctx.pkt_count, ctx.cmd_count);

    return ctx.cmd_count;
}

/* ────────────────────────────────────────────────────
 *  CLI + Main
 * ──────────────────────────────────────────────────── */

static void
print_usage(const char *prog)
{
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  --scan <cidr>           Active scan (e.g. 10.10.10.0/24)\n");
    printf("  --port <port>           Target port (default: %d)\n", DEFAULT_PORT);
    printf("  --sniff <interface>     Passive sniff (e.g. eth0)\n");
    printf("  --sniff-duration <sec>  Sniff duration in seconds (default: %d)\n", DEFAULT_SNIFF_DUR);
    printf("  --output <path>         Config output path (default: %s)\n", DEFAULT_OUTPUT);
    printf("  --scan-only             Run active scan only (skip sniffing)\n");
    printf("  --sniff-only            Run passive sniff only (skip scanning)\n");
    printf("  --help                  Show this help\n");
    printf("\nExamples:\n");
    printf("  %s --scan 10.10.10.0/24 --sniff eth0\n", prog);
    printf("  %s --scan 10.10.10.10/32 --scan-only\n", prog);
    printf("  %s --sniff eth0 --sniff-duration 60\n", prog);
}

int
main(int argc, char **argv)
{
    const char *scan_cidr    = NULL;
    const char *sniff_iface  = NULL;
    const char *output_path  = DEFAULT_OUTPUT;
    uint16_t    port         = DEFAULT_PORT;
    int         sniff_dur    = DEFAULT_SNIFF_DUR;
    bool        scan_only    = false;
    bool        sniff_only   = false;

    static struct option long_opts[] = {
        { "scan",           required_argument, NULL, 's' },
        { "port",           required_argument, NULL, 'p' },
        { "sniff",          required_argument, NULL, 'n' },
        { "sniff-duration", required_argument, NULL, 'd' },
        { "output",         required_argument, NULL, 'o' },
        { "scan-only",      no_argument,       NULL, 'S' },
        { "sniff-only",     no_argument,       NULL, 'N' },
        { "help",           no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "s:p:n:d:o:SNh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 's': scan_cidr   = optarg; break;
        case 'p': port        = (uint16_t)atoi(optarg); break;
        case 'n': sniff_iface = optarg; break;
        case 'd': sniff_dur   = atoi(optarg); break;
        case 'o': output_path = optarg; break;
        case 'S': scan_only   = true; break;
        case 'N': sniff_only  = true; break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Validate: need at least one mode */
    if (!scan_cidr && !sniff_iface) {
        fprintf(stderr, "[!] Must specify --scan <cidr> and/or --sniff <interface>\n\n");
        print_usage(argv[0]);
        return 1;
    }

    printf("╔══════════════════════════════════════════╗\n");
    printf("║   PLAGUE-V — Network Reconnaissance      ║\n");
    printf("╚══════════════════════════════════════════╝\n");

    if (scan_cidr)   printf("[*] Scan range : %s (port %d)\n", scan_cidr, port);
    if (sniff_iface) printf("[*] Sniff iface: %s (%ds)\n", sniff_iface, sniff_dur);
    printf("[*] Output     : %s\n\n", output_path);

    ScanResults  scan_results;
    SniffResults sniff_results;
    scan_results_init(&scan_results);
    sniff_results_init(&sniff_results);

    int exit_code = 0;

    /* Phase 1: Active Scan */
    if (scan_cidr && !sniff_only) {
        int found = run_active_scan(scan_cidr, port, &scan_results);
        if (found > 0) {
            scan_results_print(&scan_results);
            printf("\n");
        } else if (found == 0) {
            printf("[*] No IEC-104 servers found in %s\n\n", scan_cidr);
        } else {
            exit_code = 2;
        }
    }

    /* Phase 2: Passive Sniff */
    if (sniff_iface && !scan_only) {
        int cmds = run_passive_sniff(sniff_iface, sniff_dur, &sniff_results);
        if (cmds > 0) {
            sniff_results_print(&sniff_results);
            printf("\n");
        } else if (cmds == 0) {
            printf("[*] No command traffic captured during sniff period\n\n");
        } else {
            exit_code = 2;
        }
    }

    /* Write output config */
    if (exit_code == 0) {
        printf("[*] Writing results to %s ...\n", output_path);

        /* Write scan results first */
        int iec104_count = 0;
        for (int i = 0; i < scan_results.count; i++) {
            if (scan_results.entries[i].is_iec104)
                iec104_count++;
        }

        if (iec104_count > 0) {
            scan_results_write(&scan_results, output_path);
            printf("[+] Wrote %d scan target(s)\n", iec104_count);
        }

        /* Append sniffed command IOAs */
        if (sniff_results.count > 0) {
            int written = sniff_results_write_config(&sniff_results, output_path);
            printf("[+] Wrote %d sniffed command IOA(s)\n", written);
        }

        if (iec104_count == 0 && sniff_results.count == 0) {
            printf("[*] No targets to write\n");
            exit_code = 1;
        }
    }

    
    printf("\n╔══════════════════════════════════════════╗\n");
    printf("║          RECONNAISSANCE SUMMARY          ║\n");
    printf("╠══════════════════════════════════════════╣\n");

    int iec104_servers = 0;
    for (int i = 0; i < scan_results.count; i++) {
        if (scan_results.entries[i].is_iec104)
            iec104_servers++;
    }

    printf("║  Hosts scanned     : %-19d ║\n", scan_results.count);
    printf("║  IEC-104 servers   : %-19d ║\n", iec104_servers);
    printf("║  Commands sniffed  : %-19d ║\n", sniff_results.count);
    printf("║  Output file       : %-19s ║\n",
           exit_code == 0 ? output_path : "(none)");
    printf("╚══════════════════════════════════════════╝\n");

    /* ── Cleanup ── */
    scan_results_free(&scan_results);
    sniff_results_free(&sniff_results);

    return exit_code;
}
