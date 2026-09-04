#ifndef MRSH_GLUE_H
#define MRSH_GLUE_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#define MRSH_GLUE_API __declspec(dllexport)
#elif defined(__GNUC__) || defined(__clang__)
#define MRSH_GLUE_API __attribute__((visibility("default")))
#else
#define MRSH_GLUE_API
#endif

/* Python and other foreign-function callers treat these types as opaque. */
#ifndef MRSH_FINGERPRINT_TYPE_DEFINED
#define MRSH_FINGERPRINT_TYPE_DEFINED
typedef struct FINGERPRINT FINGERPRINT;
#endif
#ifndef MRSH_FINGERPRINT_LIST_TYPE_DEFINED
#define MRSH_FINGERPRINT_LIST_TYPE_DEFINED
typedef struct FINGERPRINT_LIST FINGERPRINT_LIST;
#endif
typedef struct compare_list compare_list_t;

MRSH_GLUE_API int mrsh_abi_version(void);
MRSH_GLUE_API const char *mrsh_error_string(int error);

MRSH_GLUE_API size_t fp_name_capacity(void);
MRSH_GLUE_API size_t fp_max_digest_size(void);
MRSH_GLUE_API size_t fpl_max_digest_size(void);
MRSH_GLUE_API size_t fpl_max_entries(void);
MRSH_GLUE_API size_t scan_max_entries(void);
MRSH_GLUE_API size_t scan_max_path_bytes(void);
MRSH_GLUE_API unsigned int scan_max_depth(void);

MRSH_GLUE_API FINGERPRINT *fp_init(void);
MRSH_GLUE_API void fp_destroy(FINGERPRINT *fp);
MRSH_GLUE_API int fp_add_file(FINGERPRINT *fp, const char *filename,
                              const char *label);
/* descriptor is borrowed and its seek position is not changed. */
MRSH_GLUE_API int fp_add_fd(FINGERPRINT *fp, int descriptor,
                            const char *label);
MRSH_GLUE_API FINGERPRINT *fp_init_file(const char *filename,
                                        const char *label);
MRSH_GLUE_API int fp_hash_bytes(FINGERPRINT *fp,
                                const unsigned char *bytes, size_t size);
MRSH_GLUE_API int fp_add_bytes(FINGERPRINT *fp,
                               const unsigned char *bytes, size_t size,
                               const char *label);
MRSH_GLUE_API FINGERPRINT *fp_init_bytes(const unsigned char *bytes,
                                         size_t size, const char *label);
MRSH_GLUE_API int fp_metadata(const FINGERPRINT *fp, const char **name,
                              uint64_t *size, uint32_t *filter_count);
MRSH_GLUE_API FINGERPRINT *fp_clone(const FINGERPRINT *source);
MRSH_GLUE_API char *fp_str(const FINGERPRINT *fp);
MRSH_GLUE_API int fp_parse(const char *digest, FINGERPRINT **out);
MRSH_GLUE_API FINGERPRINT *parse_fingerprint_string(const char *digest);
MRSH_GLUE_API int fp_compare(const FINGERPRINT *fp1,
                             const FINGERPRINT *fp2);

MRSH_GLUE_API FINGERPRINT_LIST *fpl_init(void);
MRSH_GLUE_API void fpl_destroy(FINGERPRINT_LIST *fpl);
MRSH_GLUE_API size_t fpl_size(const FINGERPRINT_LIST *fpl);
MRSH_GLUE_API FINGERPRINT_LIST *fpl_clone(const FINGERPRINT_LIST *source);
MRSH_GLUE_API int fpl_add_path_ex(FINGERPRINT_LIST *fpl,
                                  const char *filename, const char *label,
                                  int recursive);
MRSH_GLUE_API int fpl_add_path(FINGERPRINT_LIST *fpl,
                               const char *filename, const char *label);
MRSH_GLUE_API int fpl_add_path_no_follow(FINGERPRINT_LIST *fpl,
                                         const char *filename,
                                         const char *label);
/* descriptor is borrowed and its seek position is not changed. */
MRSH_GLUE_API int fpl_add_fd(FINGERPRINT_LIST *fpl, int descriptor,
                             const char *label);
MRSH_GLUE_API int fpl_add_bytes(FINGERPRINT_LIST *fpl,
                                const unsigned char *bytes, size_t size,
                                const char *label);
MRSH_GLUE_API char *fpl_str(const FINGERPRINT_LIST *fpl);
MRSH_GLUE_API int fpl_parse(const char *digest, FINGERPRINT_LIST **out);

MRSH_GLUE_API void cl_free(compare_list_t *cl);
MRSH_GLUE_API compare_list_t *cl_fpl_all(const FINGERPRINT_LIST *fpl,
                                         unsigned int threshold);
MRSH_GLUE_API compare_list_t *cl_fpl_vs_fpl(
    const FINGERPRINT_LIST *fpl1, const FINGERPRINT_LIST *fpl2,
    unsigned int threshold);
MRSH_GLUE_API compare_list_t *cl_fp_vs_fpl(const FINGERPRINT *target,
                                           const FINGERPRINT_LIST *fpl,
                                           unsigned int threshold);
MRSH_GLUE_API size_t cl_size(const compare_list_t *cl);
MRSH_GLUE_API int cl_get(const compare_list_t *cl, size_t index,
                         const char **name1, const char **name2,
                         uint8_t *score);

MRSH_GLUE_API void str_free(char *str);
MRSH_GLUE_API int str_compare(const char *digest1, const char *digest2);

#endif /* MRSH_GLUE_H */
