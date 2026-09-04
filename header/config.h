/* Core MRSH configuration and shared types. */
#ifndef MRSH_CONFIG_H
#define MRSH_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

#define ROLLING_WINDOW          7U
#define BLOCK_SIZE              160U
#define BLOCK_SIZE_MAX          50000U
#define MAX_FILTER              65535U
#define SHIFTOPS                11U
#define MASK                    UINT64_C(0x7FF)
#define FILTERSIZE              256U
#define SUBHASHES               5U
#define BLOOMFILTERBITSIZE      (FILTERSIZE * 8U)
#define MAXBLOCKS               160U
#define MINBLOCKS               8U
#define SKIPPED_BYTES           (BLOCK_SIZE / 4U)
#define MAX_BLOOM_ARR           MAX_FILTER
#define PROBABILITY             0.99951172

/* Maximum encoded name length plus its terminating NUL byte. */
#define FINGERPRINT_NAME_MAX    65536U

/* Public CPU budgets for one comparison operation. */
#define MRSH_MAX_COMPARISON_CANDIDATES UINT64_C(1000000)
#define MRSH_MAX_BLOOM_COMPARISON_WORK UINT64_C(1000000)
#ifndef MRSH_MAX_COMPARISON_OUTPUT_BYTES
#define MRSH_MAX_COMPARISON_OUTPUT_BYTES (256U * 1024U * 1024U)
#endif
#define FINGERPRINT_LIST_MAX_ENTRIES 100000U
#define FINGERPRINT_LIST_MAX_BYTES (256U * 1024U * 1024U)
#define MRSH_DIRECTORY_MAX_DEPTH   256U
#define MRSH_TRAVERSAL_MAX_ENTRIES FINGERPRINT_LIST_MAX_ENTRIES
#define MRSH_TRAVERSAL_MAX_PATH_BYTES FINGERPRINT_LIST_MAX_BYTES

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

/* Compatibility aliases used by the original implementation. */
typedef uint64_t uint64;
typedef unsigned char uchar;
typedef uint32_t uint32;

typedef enum {
    MRSH_OK = 0,
    MRSH_ERR_INVALID = -1,
    MRSH_ERR_NOMEM = -2,
    MRSH_ERR_IO = -3,
    MRSH_ERR_FORMAT = -4,
    MRSH_ERR_RANGE = -5
} MRSH_STATUS;

typedef struct {
    bool compare;
    bool file_comparison;
    bool print;
    bool gen_compare;
    bool compareLists;
    bool helpmessage;
    bool recursive;
    bool path_list_compare;
    int threshold;
} MODES;

extern MODES *mode;

#endif /* MRSH_CONFIG_H */
