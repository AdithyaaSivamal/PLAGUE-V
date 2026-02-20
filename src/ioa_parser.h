/*
 * ioa_parser.h — IOA target map parser
 *
 * Parses a config file of IOA targets into a linked list.
 * Each line: IOA  Name  State (OFF/ON)
 */

#ifndef IOA_PARSER_H
#define IOA_PARSER_H

#include <stdint.h>

#define IOA_NAME_MAX 64

typedef struct IOATarget {
    uint32_t ioa;                   /* Information Object Address */
    char     name[IOA_NAME_MAX];    /* Human-readable label */
    uint8_t  target_state;          /* 0 = OFF (open), 1 = ON (close) */
    struct IOATarget *next;         /* Linked list pointer */
} IOATarget;

/**
 * Parse config file into a linked list of IOA targets.
 * Returns head pointer, or NULL on error (file not found, empty, etc.).
 */
IOATarget* load_ioa_map(const char *config_path);

/* Free the entire linked list. */
void free_ioa_map(IOATarget *head);

/*  Count the number of IOA targets in the list. */
int get_ioa_count(IOATarget *head);

/* Print the loaded IOA map in a formatted table (for debugging). */
void print_ioa_map(IOATarget *head);

#endif
