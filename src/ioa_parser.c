/*
 * ioa_parser.c — IOA target map parser implementation
 *
 * Reads a config file line-by-line, skipping comments and blank lines,
 * and builds a linked list of IOATarget nodes.
 */

#include "ioa_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define LINE_BUF_SIZE 256
#define IOA_MAX       16777215   /* 24-bit max (3-byte IOA) */

/* Helper funcion to check if a line is blank or comment */
static int
is_skip_line(const char *line)
{
    while (*line) {
        if (*line == '#')
            return 1;          
        if (!isspace((unsigned char)*line))
            return 0;          
        line++;
    }
    return 1;            
}

/* Load IOA map from config file */
IOATarget*
load_ioa_map(const char *config_path)
{
    FILE *fp = fopen(config_path, "r");
    if (!fp) {
        fprintf(stderr, "[!] Config file not found: %s\n", config_path);
        return NULL;
    }

    IOATarget *head = NULL;
    IOATarget *tail = NULL;
    char line[LINE_BUF_SIZE];
    int line_num = 0;
    int count = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        if (is_skip_line(line))
            continue;

        /* Parse for: IOA  Name  State */
        unsigned int ioa_val = 0;
        char name_buf[IOA_NAME_MAX];
        char state_buf[16];

        int matched = sscanf(line, "%u %63s %15s", &ioa_val, name_buf, state_buf);

        if (matched < 3) {
            fprintf(stderr, "[!] Line %d: malformed entry "
                    "(expected: IOA Name State): %s", line_num, line);
            continue;
        }

        /* Validate IOA range */
        if (ioa_val > IOA_MAX) {
            fprintf(stderr, "[!] Line %d: IOA %u exceeds 24-bit max (%d)\n",
                    line_num, ioa_val, IOA_MAX);
            continue;
        }

        /* Parse state string */
        uint8_t state;
        if (strcasecmp(state_buf, "OFF") == 0) {
            state = 0;
        }
        else if (strcasecmp(state_buf, "ON") == 0) {
            state = 1;
        }
        else {
            fprintf(stderr, "[!] Warning: unknown state '%s' on line %d, "
                    "defaulting to OFF\n", state_buf, line_num);
            state = 0;
        }

        /* Allocate node */
        IOATarget *node = (IOATarget *)malloc(sizeof(IOATarget));
        if (!node) {
            fprintf(stderr, "[!] malloc failed at line %d\n", line_num);
            fclose(fp);
            free_ioa_map(head);
            return NULL;
        }

        node->ioa = (uint32_t)ioa_val;
        strncpy(node->name, name_buf, IOA_NAME_MAX - 1);
        node->name[IOA_NAME_MAX - 1] = '\0';
        node->target_state = state;
        node->next = NULL;

        /* Append to list (preserves config file order) */
        if (tail) {
            tail->next = node;
            tail = node;
        }
        else {
            head = tail = node;
        }
        count++;
    }

    fclose(fp);

    if (count == 0) {
        fprintf(stderr, "[!] Config file contains no valid IOA entries: %s\n",
                config_path);
        return NULL;
    }

    return head;
}

/* Cleanup */
void
free_ioa_map(IOATarget *head)
{
    IOATarget *current = head;
    while (current) {
        IOATarget *next = current->next;
        free(current);
        current = next;
    }
}

/* Count nodes */
int
get_ioa_count(IOATarget *head)
{
    int count = 0;
    const IOATarget *current = head;
    while (current) {
        count++;
        current = current->next;
    }
    return count;
}

/* Print formatted table */
void
print_ioa_map(IOATarget *head)
{
    const IOATarget *current = head;
    while (current) {
        printf("  %-6u %-24s → %s\n",
               current->ioa,
               current->name,
               current->target_state ? "ON" : "OFF");
        current = current->next;
    }
}
