#ifndef MRSH_FINGERPRINT_LIST_H
#define MRSH_FINGERPRINT_LIST_H

#include <stddef.h>
#include <stdio.h>

#include "fingerprint.h"

#ifndef MRSH_FINGERPRINT_LIST_TYPE_DEFINED
#define MRSH_FINGERPRINT_LIST_TYPE_DEFINED
typedef struct FINGERPRINT_LIST FINGERPRINT_LIST;
#endif

struct FINGERPRINT_LIST {
    FINGERPRINT *list;
    FINGERPRINT *last_element;
    size_t size;
};

typedef struct {
    char **filename;
    double *score;
    size_t length;
} MATCH_RESULT;

FINGERPRINT_LIST *init_empty_fingerprintList(void);
FINGERPRINT_LIST *init_fingerprintList_for_ListFile(const char *filename);
int fingerprintList_destroy(FINGERPRINT_LIST *fpl);

int add_new_fingerprint(FINGERPRINT_LIST *fpl, FINGERPRINT *fp);

/* These calls preflight both candidate and Bloom-filter work budgets and emit
 * no partial output when either budget would be exceeded. */
int all_against_all_comparsion(const FINGERPRINT_LIST *fpl);
int fingerprint_list_comparsion(const FINGERPRINT_LIST *fpl1,
                                const FINGERPRINT_LIST *fpl2);
int fingerprint_against_list_comparison(const FINGERPRINT_LIST *fpl,
                                        const FINGERPRINT *fp);

int print_fingerprintList(const FINGERPRINT_LIST *fpl);

/* Parse one canonical digest string. The caller owns *out on success. */
int fingerprint_parse(const char *digest, FINGERPRINT **out);

/* Parse a list without taking ownership of handle. */
int read_fingerprint_file(FINGERPRINT_LIST *fpl, FILE *handle);

#endif /* MRSH_FINGERPRINT_LIST_H */
