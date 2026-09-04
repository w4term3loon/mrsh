#ifndef MRSH_FINGERPRINT_H
#define MRSH_FINGERPRINT_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "bloomfilter.h"

#ifndef MRSH_FINGERPRINT_TYPE_DEFINED
#define MRSH_FINGERPRINT_TYPE_DEFINED
typedef struct FINGERPRINT FINGERPRINT;
#endif

struct FINGERPRINT {
    BLOOMFILTER *bf_list;
    BLOOMFILTER *bf_list_last_element;
    struct FINGERPRINT *next;

    /* Number of filters after the first (kept for digest compatibility). */
    uint32_t amount_of_BF;

    char *file_name;
    uint64_t filesize;
};

FINGERPRINT *init_empty_fingerprint(void);
/* Takes ownership of handle and closes it on every return path. */
FINGERPRINT *init_fingerprint_for_file(FILE *handle, const char *filename);
FINGERPRINT *fingerprint_clone(const FINGERPRINT *source);
int fingerprint_destroy(FINGERPRINT *fp);

int fingerprint_set_name(FINGERPRINT *fp, const char *name);
int fingerprint_set_name_n(FINGERPRINT *fp, const char *name, size_t length);
size_t fingerprint_filter_count(const FINGERPRINT *fp);
/* Return the Bloom-filter pair count, or MRSH_ERR_RANGE when it exceeds the
 * public per-operation work budget. */
int fingerprint_comparison_work(const FINGERPRINT *fingerprint1,
                                const FINGERPRINT *fingerprint2,
                                uint64_t *work_out);

int fingerprint_compare(const FINGERPRINT *fingerprint1,
                        const FINGERPRINT *fingerprint2);
int bloom_max_score(const BLOOMFILTER *bf, const FINGERPRINT *fingerprint);
int add_hash_to_fingerprint(FINGERPRINT *fp, uint64 hash_value);
int add_new_bloomfilter(FINGERPRINT *fp, BLOOMFILTER *bf);
double compute_e_min(uint32_t blocks_in_bf1, uint32_t blocks_in_bf2);

int fingerprint_fprint(FILE *stream, const FINGERPRINT *fp);
int print_fingerprint(const FINGERPRINT *fp);

#endif /* MRSH_FINGERPRINT_H */
