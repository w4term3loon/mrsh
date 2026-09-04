/*
 * Python-facing ABI for MRSH-v2.
 *
 * Keep this interface deliberately small and opaque: callers own pointers
 * returned by fp_init/fp_parse/fp_clone and fpl_init/fpl_parse/fpl_clone, but
 * they must not depend on the layout of the native structures.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mrsh_glue.h"
#include "config.h"
#include "fingerprintList.h"
#include "hashing.h"
#include "helper.h"
#include "traversal.h"

/* The command-line program provides its own mode object. The shared library
 * uses static storage so loading it cannot fail due to this compatibility
 * global. */
static MODES mode_storage;
MODES *mode = &mode_storage;

enum {
  MRSH_GLUE_ABI_VERSION = 2,
  MRSH_MAX_COMPARISON_RESULTS = 1000000
};

#define MRSH_MAX_COMPARISON_BYTES ((size_t)256U * 1024U * 1024U)

#define MRSH_MAX_DIGEST_LENGTH                                                \
  ((size_t)FINGERPRINT_NAME_MAX + 64U +                                      \
   (size_t)MAX_FILTER * FILTERSIZE * 2U)

typedef struct {
  char *name1;
  char *name2;
  uint8_t score;
} compare_t;

struct compare_list {
  compare_t *list;
  size_t size;
  size_t capacity;
  size_t name_bytes;
};

static int checked_add_size(size_t a, size_t b, size_t *out) {
  if (!out || a > SIZE_MAX - b)
    return MRSH_ERR_RANGE;
  *out = a + b;
  return MRSH_OK;
}

static int checked_mul_size(size_t a, size_t b, size_t *out) {
  if (!out || (a != 0 && b > SIZE_MAX / a))
    return MRSH_ERR_RANGE;
  *out = a * b;
  return MRSH_OK;
}

static int valid_name(const char *name) {
  size_t len;
  size_t index;

  if (!name)
    return MRSH_ERR_INVALID;
  len = strnlen(name, FINGERPRINT_NAME_MAX);
  if (len >= FINGERPRINT_NAME_MAX)
    return MRSH_ERR_RANGE;
  for (index = 0; index < len; ++index) {
    unsigned char byte = (unsigned char)name[index];
    if (byte < 0x20U || byte == 0x7fU)
      return MRSH_ERR_FORMAT;
  }
  return MRSH_OK;
}

static int duplicate_borrowed_descriptor(int descriptor) {
  int duplicate;

#ifdef F_DUPFD_CLOEXEC
  do {
    duplicate = fcntl(descriptor, F_DUPFD_CLOEXEC, 0);
  } while (duplicate < 0 && errno == EINTR);
#else
  do {
    duplicate = dup(descriptor);
  } while (duplicate < 0 && errno == EINTR);
  if (duplicate >= 0) {
    int flags;
    do {
      flags = fcntl(duplicate, F_GETFD);
    } while (flags < 0 && errno == EINTR);
    if (flags < 0 || fcntl(duplicate, F_SETFD, flags | FD_CLOEXEC) < 0) {
      (void)close(duplicate);
      duplicate = -1;
    }
  }
#endif
  return duplicate;
}

static int fingerprint_is_pristine(const FINGERPRINT *fp) {
  if (!fp || !fp->bf_list || fp->bf_list_last_element != fp->bf_list || fp->next ||
      fp->amount_of_BF != 0 || fp->bf_list->next || fp->bf_list->amount_of_blocks != 0)
    return 0;

  for (size_t i = 0; i < FILTERSIZE; ++i) {
    if (fp->bf_list->array[i] != 0)
      return 0;
  }
  return 1;
}

static int fingerprint_is_valid(const FINGERPRINT *fp) {
  const BLOOMFILTER *bf;
  size_t count = 0;

  if (!fp || !fp->bf_list || !fp->bf_list_last_element || !fp->file_name)
    return 0;
  if (fp->amount_of_BF >= MAX_FILTER)
    return 0;
  if (strnlen(fp->file_name, FINGERPRINT_NAME_MAX) >= FINGERPRINT_NAME_MAX)
    return 0;

  for (bf = fp->bf_list; bf; bf = (const BLOOMFILTER *)bf->next) {
    if (++count > (size_t)fp->amount_of_BF + 1)
      return 0;
    if (bf->amount_of_blocks > MAXBLOCKS)
      return 0;
    if (!bf->next && bf != fp->bf_list_last_element)
      return 0;
  }
  return count == (size_t)fp->amount_of_BF + 1;
}

static int append_fingerprint(FINGERPRINT_LIST *fpl, FINGERPRINT *fp) {
  if (!fpl || !fp || fp->next)
    return MRSH_ERR_INVALID;
  if (fpl->size >= (size_t)FINGERPRINT_LIST_MAX_ENTRIES)
    return MRSH_ERR_RANGE;

  if (!fpl->list)
    fpl->list = fp;
  else
    fpl->last_element->next = fp;
  fpl->last_element = fp;
  ++fpl->size;
  return MRSH_OK;
}

int mrsh_abi_version(void) { return MRSH_GLUE_ABI_VERSION; }

const char *mrsh_error_string(int error) {
  switch (error) {
  case MRSH_OK:
    return "success";
  case MRSH_ERR_INVALID:
    return "invalid argument or object state";
  case MRSH_ERR_NOMEM:
    return "out of memory";
  case MRSH_ERR_IO:
    return "I/O error";
  case MRSH_ERR_FORMAT:
    return "invalid fingerprint format";
  case MRSH_ERR_RANGE:
    return "value out of range";
  default:
    return "unknown MRSH error";
  }
}

size_t fp_name_capacity(void) { return FINGERPRINT_NAME_MAX; }

size_t fp_max_digest_size(void) { return MRSH_MAX_DIGEST_LENGTH; }

size_t fpl_max_digest_size(void) { return FINGERPRINT_LIST_MAX_BYTES; }

size_t fpl_max_entries(void) { return FINGERPRINT_LIST_MAX_ENTRIES; }

size_t scan_max_entries(void) { return MRSH_TRAVERSAL_MAX_ENTRIES; }

size_t scan_max_path_bytes(void) { return MRSH_TRAVERSAL_MAX_PATH_BYTES; }

unsigned int scan_max_depth(void) { return MRSH_DIRECTORY_MAX_DEPTH; }

FINGERPRINT *fp_init(void) {
  FINGERPRINT *fp = init_empty_fingerprint();
  if (fp)
    fp->next = NULL;
  return fp;
}

void fp_destroy(FINGERPRINT *fp) {
  if (fp)
    fingerprint_destroy(fp);
}

static int fp_add_file_impl(FINGERPRINT *fp, const char *filename,
                            const char *label,
                            const struct stat *expected,
                            int follow_final_symlink) {
  const char *stored_name;
  FILE *file;
  int result;
  int close_result;

  if (!fp || !filename || !fingerprint_is_pristine(fp))
    return MRSH_ERR_INVALID;
  stored_name = label ? label : filename;
  result = valid_name(stored_name);
  if (result != MRSH_OK)
    return result;

  if (expected && follow_final_symlink)
    result = open_regular_file_follow_checked(filename, expected, &file);
  else if (expected)
    result = open_regular_file_checked(filename, expected, &file);
  else
    result = open_regular_file(filename, &file);
  if (result != MRSH_OK)
    return result;
  result = hashFileToFingerprint(fp, file);
  close_result = fclose(file);
  if (result != MRSH_OK)
    return result;
  if (close_result != 0)
    return MRSH_ERR_IO;
  return fingerprint_set_name(fp, stored_name);
}

int fp_add_file(FINGERPRINT *fp, const char *filename, const char *label) {
  return fp_add_file_impl(fp, filename, label, NULL, 0);
}

int fp_add_fd(FINGERPRINT *fp, int descriptor, const char *label) {
  int duplicate;
  int close_result;
  int result;

  if (!fp || descriptor < 0 || !fingerprint_is_pristine(fp))
    return MRSH_ERR_INVALID;
  if (!label)
    label = "n/a";
  result = valid_name(label);
  if (result != MRSH_OK)
    return result;
  duplicate = duplicate_borrowed_descriptor(descriptor);
  if (duplicate < 0)
    return MRSH_ERR_IO;
  result = hashFileDescriptorToFingerprint(fp, duplicate);
  close_result = close(duplicate);
  if (result != MRSH_OK)
    return result;
  if (close_result != 0)
    return MRSH_ERR_IO;
  return fingerprint_set_name(fp, label);
}

FINGERPRINT *fp_init_file(const char *filename, const char *label) {
  FINGERPRINT *fp = fp_init();
  if (!fp)
    return NULL;
  if (fp_add_file(fp, filename, label) != MRSH_OK) {
    fp_destroy(fp);
    return NULL;
  }
  return fp;
}

int fp_hash_bytes(FINGERPRINT *fp, const unsigned char *bytes, size_t size) {
  if (!fp || (size != 0 && !bytes))
    return MRSH_ERR_INVALID;
  return hashPacketBuffer(fp, bytes, size);
}

int fp_add_bytes(FINGERPRINT *fp, const unsigned char *bytes, size_t size,
                 const char *label) {
  int result;

  if (!fp || !fingerprint_is_pristine(fp) || (size != 0 && !bytes))
    return MRSH_ERR_INVALID;
  if (!label)
    label = "n/a";
  result = valid_name(label);
  if (result != MRSH_OK)
    return result;

  fp->filesize = (uint64_t)size;
  result = fp_hash_bytes(fp, bytes, size);
  if (result != MRSH_OK)
    return result;
  return fingerprint_set_name(fp, label);
}

FINGERPRINT *fp_init_bytes(const unsigned char *bytes, size_t size, const char *label) {
  FINGERPRINT *fp = fp_init();
  if (!fp)
    return NULL;
  if (fp_add_bytes(fp, bytes, size, label) != MRSH_OK) {
    fp_destroy(fp);
    return NULL;
  }
  return fp;
}

int fp_metadata(const FINGERPRINT *fp, const char **name, uint64_t *size,
                uint32_t *filter_count) {
  if (!fingerprint_is_valid(fp) || !name || !size || !filter_count)
    return MRSH_ERR_INVALID;
  *name = fp->file_name;
  *size = fp->filesize;
  *filter_count = fp->amount_of_BF + 1;
  return MRSH_OK;
}

FINGERPRINT *fp_clone(const FINGERPRINT *source) {
  if (!fingerprint_is_valid(source))
    return NULL;
  return fingerprint_clone(source);
}

char *fp_str(const FINGERPRINT *fp) {
  const BLOOMFILTER *bf;
  size_t hex_len;
  size_t total_len;
  int header_len;
  char *result;
  size_t pos;

  if (!fingerprint_is_valid(fp))
    return NULL;
  header_len = snprintf(NULL, 0, "%s:%" PRIu64 ":%u:%u:", fp->file_name,
                        fp->filesize,
                        fp->amount_of_BF + 1,
                        fp->bf_list_last_element->amount_of_blocks);
  if (header_len < 0 || checked_mul_size((size_t)fp->amount_of_BF + 1,
                                         (size_t)FILTERSIZE * 2, &hex_len) != MRSH_OK ||
      checked_add_size((size_t)header_len, hex_len, &total_len) != MRSH_OK ||
      total_len == SIZE_MAX)
    return NULL;

  result = malloc(total_len + 1);
  if (!result)
    return NULL;
  if (snprintf(result, total_len + 1, "%s:%" PRIu64 ":%u:%u:", fp->file_name,
               fp->filesize,
               fp->amount_of_BF + 1,
               fp->bf_list_last_element->amount_of_blocks) != header_len) {
    free(result);
    return NULL;
  }
  pos = (size_t)header_len;
  for (bf = fp->bf_list; bf; bf = (const BLOOMFILTER *)bf->next) {
    static const char digits[] = "0123456789ABCDEF";
    for (size_t i = 0; i < FILTERSIZE; ++i) {
      result[pos++] = digits[bf->array[i] >> 4];
      result[pos++] = digits[bf->array[i] & 0x0f];
    }
  }
  result[pos] = '\0';
  return result;
}

FINGERPRINT_LIST *fpl_init(void) { return init_empty_fingerprintList(); }

void fpl_destroy(FINGERPRINT_LIST *fpl) {
  if (fpl)
    fingerprintList_destroy(fpl);
}

size_t fpl_size(const FINGERPRINT_LIST *fpl) { return fpl ? fpl->size : 0; }

FINGERPRINT_LIST *fpl_clone(const FINGERPRINT_LIST *source) {
  FINGERPRINT_LIST *copy;
  FINGERPRINT *fp_copy;

  if (!source)
    return NULL;
  copy = fpl_init();
  if (!copy)
    return NULL;
  for (const FINGERPRINT *fp = source->list; fp; fp = fp->next) {
    fp_copy = fp_clone(fp);
    if (!fp_copy || append_fingerprint(copy, fp_copy) != MRSH_OK) {
      fp_destroy(fp_copy);
      fpl_destroy(copy);
      return NULL;
    }
  }
  return copy;
}

static int join_component(const char *prefix, const char *name, char **out) {
  size_t prefix_len;
  size_t name_len;
  size_t size;
  int separator;

  if (!prefix || !name || !out)
    return MRSH_ERR_INVALID;
  prefix_len = strlen(prefix);
  name_len = strlen(name);
  separator = prefix_len != 0 && prefix[prefix_len - 1] != '/';
  if (checked_add_size(prefix_len, (size_t)separator, &size) != MRSH_OK ||
      checked_add_size(size, name_len, &size) != MRSH_OK || size == SIZE_MAX)
    return MRSH_ERR_RANGE;
  *out = malloc(size + 1);
  if (!*out)
    return MRSH_ERR_NOMEM;
  memcpy(*out, prefix, prefix_len);
  if (separator)
    (*out)[prefix_len++] = '/';
  memcpy(*out + prefix_len, name, name_len + 1);
  return MRSH_OK;
}

typedef struct {
  FINGERPRINT_LIST *list;
  const char *label_prefix;
} directory_add_context_t;

static int add_visited_file(int descriptor, const char *relative_path,
                            void *opaque_context) {
  directory_add_context_t *context = opaque_context;
  FINGERPRINT *fp;
  char *label = NULL;
  int result;

  if (!context || !context->list || !relative_path)
    return MRSH_ERR_INVALID;
  result = join_component(context->label_prefix, relative_path, &label);
  if (result != MRSH_OK)
    return result;
  result = valid_name(label);
  if (result != MRSH_OK) {
    free(label);
    return result;
  }
  fp = fp_init();
  if (!fp) {
    free(label);
    return MRSH_ERR_NOMEM;
  }
  result = fp_add_fd(fp, descriptor, label);
  if (result == MRSH_OK)
    result = append_fingerprint(context->list, fp);
  if (result != MRSH_OK)
    fp_destroy(fp);
  free(label);
  return result;
}

int fpl_add_path_ex(FINGERPRINT_LIST *fpl, const char *filename,
                    const char *label, int recursive) {
  struct stat st;
  FINGERPRINT_LIST *staged;
  int follow_symlink = 0;
  int result;

  if (!fpl || !filename)
    return MRSH_ERR_INVALID;
  if (label) {
    result = valid_name(label);
    if (result != MRSH_OK)
      return result;
  }
  if (lstat(filename, &st) != 0)
    return MRSH_ERR_IO;
  if (S_ISLNK(st.st_mode)) {
    follow_symlink = 1;
    if (stat(filename, &st) != 0)
      return MRSH_ERR_IO;
    if (!S_ISREG(st.st_mode))
      return MRSH_ERR_INVALID;
  }
  staged = fpl_init();
  if (!staged)
    return MRSH_ERR_NOMEM;

  if (S_ISREG(st.st_mode)) {
    FINGERPRINT *fp = fp_init();
    if (!fp)
      result = MRSH_ERR_NOMEM;
    else {
      result = fp_add_file_impl(fp, filename, label, &st, follow_symlink);
      if (result == MRSH_OK)
        result = append_fingerprint(staged, fp);
      if (result != MRSH_OK)
        fp_destroy(fp);
    }
  } else if (S_ISDIR(st.st_mode)) {
    directory_add_context_t context = {staged, label ? label : ""};
    result = visit_regular_files(filename, &st, recursive != 0,
                                 add_visited_file, &context);
  } else {
    result = MRSH_ERR_INVALID;
  }

  if (result == MRSH_OK && staged->size) {
    if (fpl->size > (size_t)FINGERPRINT_LIST_MAX_ENTRIES ||
        staged->size > (size_t)FINGERPRINT_LIST_MAX_ENTRIES - fpl->size)
      result = MRSH_ERR_RANGE;
    else {
      if (!fpl->list)
        fpl->list = staged->list;
      else
        fpl->last_element->next = staged->list;
      fpl->last_element = staged->last_element;
      fpl->size += staged->size;
      staged->list = NULL;
      staged->last_element = NULL;
      staged->size = 0;
    }
  }
  fpl_destroy(staged);
  return result;
}

int fpl_add_path(FINGERPRINT_LIST *fpl, const char *filename, const char *label) {
  return fpl_add_path_ex(fpl, filename, label, mode && mode->recursive);
}

int fpl_add_path_no_follow(FINGERPRINT_LIST *fpl, const char *filename,
                           const char *label) {
  struct stat st;
  FINGERPRINT *fp;
  int result;

  if (!fpl || !filename)
    return MRSH_ERR_INVALID;
  if (label) {
    result = valid_name(label);
    if (result != MRSH_OK)
      return result;
  }
  if (lstat(filename, &st) != 0)
    return MRSH_ERR_IO;
  if (!S_ISREG(st.st_mode))
    return MRSH_ERR_INVALID;
  fp = fp_init();
  if (!fp)
    return MRSH_ERR_NOMEM;
  result = fp_add_file_impl(fp, filename, label, &st, 0);
  if (result == MRSH_OK)
    result = append_fingerprint(fpl, fp);
  if (result != MRSH_OK)
    fp_destroy(fp);
  return result;
}

int fpl_add_fd(FINGERPRINT_LIST *fpl, int descriptor, const char *label) {
  FINGERPRINT *fp;
  int result;

  if (!fpl || descriptor < 0)
    return MRSH_ERR_INVALID;
  fp = fp_init();
  if (!fp)
    return MRSH_ERR_NOMEM;
  result = fp_add_fd(fp, descriptor, label);
  if (result == MRSH_OK)
    result = append_fingerprint(fpl, fp);
  if (result != MRSH_OK)
    fp_destroy(fp);
  return result;
}

int fpl_add_bytes(FINGERPRINT_LIST *fpl, const unsigned char *bytes, size_t size,
                  const char *label) {
  FINGERPRINT *fp;
  int result;

  if (!fpl)
    return MRSH_ERR_INVALID;
  fp = fp_init();
  if (!fp)
    return MRSH_ERR_NOMEM;
  result = fp_add_bytes(fp, bytes, size, label);
  if (result == MRSH_OK)
    result = append_fingerprint(fpl, fp);
  if (result != MRSH_OK)
    fp_destroy(fp);
  return result;
}

char *fpl_str(const FINGERPRINT_LIST *fpl) {
  char *result;
  size_t used = 0;
  size_t capacity = 1;
  size_t entries = 0;

  if (!fpl)
    return NULL;
  result = malloc(1);
  if (!result)
    return NULL;
  result[0] = '\0';

  for (const FINGERPRINT *fp = fpl->list; fp; fp = fp->next) {
    char *digest;
    size_t digest_len;
    size_t needed;
    char *grown;
    if (entries >= (size_t)FINGERPRINT_LIST_MAX_ENTRIES) {
      free(result);
      return NULL;
    }
    digest = fp_str(fp);
    if (!digest) {
      free(result);
      return NULL;
    }
    digest_len = strlen(digest);
    if (checked_add_size(used, used ? 1 : 0, &needed) != MRSH_OK ||
        checked_add_size(needed, digest_len, &needed) != MRSH_OK ||
        needed > (size_t)FINGERPRINT_LIST_MAX_BYTES || needed == SIZE_MAX) {
      free(digest);
      free(result);
      return NULL;
    }
    if (needed + 1 > capacity) {
      size_t new_capacity = capacity;
      while (new_capacity < needed + 1) {
        if (new_capacity > ((size_t)FINGERPRINT_LIST_MAX_BYTES + 1U) / 2U) {
          new_capacity = needed + 1;
          break;
        }
        new_capacity *= 2U;
      }
      grown = realloc(result, new_capacity);
      if (!grown) {
        free(digest);
        free(result);
        return NULL;
      }
      result = grown;
      capacity = new_capacity;
    }
    if (used)
      result[used++] = '\n';
    memcpy(result + used, digest, digest_len + 1);
    used += digest_len;
    ++entries;
    free(digest);
  }
  return result;
}

void str_free(char *str) { free(str); }

static int parse_fingerprint_span(const char *digest, size_t length,
                                  FINGERPRINT **out) {
  char *terminated;
  int result;

  if (!digest || !out)
    return MRSH_ERR_INVALID;
  if (length > MRSH_MAX_DIGEST_LENGTH || length == SIZE_MAX)
    return MRSH_ERR_RANGE;
  terminated = malloc(length + 1U);
  if (!terminated)
    return MRSH_ERR_NOMEM;
  memcpy(terminated, digest, length);
  terminated[length] = '\0';
  result = fingerprint_parse(terminated, out);
  free(terminated);
  return result;
}

int fp_parse(const char *digest, FINGERPRINT **out) {
  return fingerprint_parse(digest, out);
}

FINGERPRINT *parse_fingerprint_string(const char *digest) {
  FINGERPRINT *fp = NULL;
  if (fp_parse(digest, &fp) != MRSH_OK)
    return NULL;
  return fp;
}

int fpl_parse(const char *digest, FINGERPRINT_LIST **out) {
  FINGERPRINT_LIST *fpl;
  const char *cursor;
  const char *end;
  size_t digest_len;

  if (!digest || !out)
    return MRSH_ERR_INVALID;
  *out = NULL;
  digest_len = strnlen(digest, (size_t)FINGERPRINT_LIST_MAX_BYTES + 1U);
  if (digest_len > (size_t)FINGERPRINT_LIST_MAX_BYTES)
    return MRSH_ERR_RANGE;
  fpl = fpl_init();
  if (!fpl)
    return MRSH_ERR_NOMEM;
  if (!*digest) {
    *out = fpl;
    return MRSH_OK;
  }

  cursor = digest;
  end = digest + digest_len;
  while (cursor < end) {
    const char *newline;
    const char *line_end;
    size_t line_len;
    FINGERPRINT *fp = NULL;
    int result;
    newline = memchr(cursor, '\n', (size_t)(end - cursor));
    line_end = newline ? newline : end;
    line_len = (size_t)(line_end - cursor);
    if (line_len > MRSH_MAX_DIGEST_LENGTH) {
      fpl_destroy(fpl);
      return MRSH_ERR_RANGE;
    }
    if (!line_len || memchr(cursor, '\r', line_len)) {
      fpl_destroy(fpl);
      return MRSH_ERR_FORMAT;
    }
    result = parse_fingerprint_span(cursor, line_len, &fp);
    if (result != MRSH_OK || append_fingerprint(fpl, fp) != MRSH_OK) {
      fp_destroy(fp);
      fpl_destroy(fpl);
      return result != MRSH_OK ? result : MRSH_ERR_RANGE;
    }
    if (!newline)
      break;
    cursor = newline + 1;
  }
  *out = fpl;
  return MRSH_OK;
}

int fp_compare(const FINGERPRINT *fp1, const FINGERPRINT *fp2) {
  int score;
  if (!fingerprint_is_valid(fp1) || !fingerprint_is_valid(fp2))
    return MRSH_ERR_INVALID;
  score = fingerprint_compare(fp1, fp2);
  if (score < 0)
    return score;
  return score <= 100 ? score : MRSH_ERR_FORMAT;
}

static int account_comparison_work(const FINGERPRINT *first,
                                   const FINGERPRINT *second,
                                   uint64_t *candidate_count,
                                   uint64_t *bloom_work) {
  uint64_t pair_work;
  int result;

  if (!candidate_count || !bloom_work)
    return MRSH_ERR_INVALID;
  if (*candidate_count >= MRSH_MAX_COMPARISON_CANDIDATES)
    return MRSH_ERR_RANGE;
  result = fingerprint_comparison_work(first, second, &pair_work);
  if (result != MRSH_OK)
    return result;
  if (pair_work > MRSH_MAX_BLOOM_COMPARISON_WORK ||
      *bloom_work > MRSH_MAX_BLOOM_COMPARISON_WORK - pair_work)
    return MRSH_ERR_RANGE;
  ++*candidate_count;
  *bloom_work += pair_work;
  return MRSH_OK;
}

static compare_list_t *compare_list_new(void) {
  compare_list_t *cl = calloc(1, sizeof(*cl));
  return cl;
}

void cl_free(compare_list_t *cl) {
  if (!cl)
    return;
  for (size_t i = 0; i < cl->size; ++i) {
    free(cl->list[i].name1);
    free(cl->list[i].name2);
  }
  free(cl->list);
  free(cl);
}

static int compare_list_add(compare_list_t *cl, const char *name1,
                            const char *name2, int score) {
  compare_t *entry;
  size_t name1_len;
  size_t name2_len;
  size_t added_name_bytes;
  size_t total_name_bytes;

  if (!cl || !name1 || !name2 || score < 0 || score > 100)
    return MRSH_ERR_INVALID;
  if (cl->size >= MRSH_MAX_COMPARISON_RESULTS)
    return MRSH_ERR_RANGE;
  name1_len = strnlen(name1, FINGERPRINT_NAME_MAX);
  name2_len = strnlen(name2, FINGERPRINT_NAME_MAX);
  if (name1_len >= FINGERPRINT_NAME_MAX || name2_len >= FINGERPRINT_NAME_MAX ||
      checked_add_size(name1_len, name2_len, &added_name_bytes) != MRSH_OK ||
      checked_add_size(added_name_bytes, 2U, &added_name_bytes) != MRSH_OK ||
      checked_add_size(cl->name_bytes, added_name_bytes, &total_name_bytes) != MRSH_OK ||
      total_name_bytes > MRSH_MAX_COMPARISON_BYTES)
    return MRSH_ERR_RANGE;

  if (cl->size == cl->capacity) {
    size_t new_capacity = cl->capacity ? cl->capacity * 2U : 16U;
    compare_t *grown;
    if (new_capacity < cl->capacity ||
        new_capacity > MRSH_MAX_COMPARISON_RESULTS)
      new_capacity = MRSH_MAX_COMPARISON_RESULTS;
    if (new_capacity <= cl->capacity ||
        new_capacity > SIZE_MAX / sizeof(*cl->list))
      return MRSH_ERR_RANGE;
    grown = realloc(cl->list, new_capacity * sizeof(*cl->list));
    if (!grown)
      return MRSH_ERR_NOMEM;
    cl->list = grown;
    cl->capacity = new_capacity;
  }

  entry = &cl->list[cl->size];
  entry->name1 = strdup(name1);
  entry->name2 = strdup(name2);
  if (!entry->name1 || !entry->name2) {
    free(entry->name1);
    free(entry->name2);
    entry->name1 = NULL;
    entry->name2 = NULL;
    return MRSH_ERR_NOMEM;
  }
  entry->score = (uint8_t)score;
  cl->name_bytes = total_name_bytes;
  ++cl->size;
  return MRSH_OK;
}

compare_list_t *cl_fpl_all(const FINGERPRINT_LIST *fpl, unsigned int threshold) {
  compare_list_t *cl;
  uint64_t candidate_count = 0;
  uint64_t bloom_work = 0;
  if (!fpl || threshold > 100)
    return NULL;
  for (const FINGERPRINT *fp1 = fpl->list; fp1; fp1 = fp1->next) {
    for (const FINGERPRINT *fp2 = fp1->next; fp2; fp2 = fp2->next) {
      if (account_comparison_work(fp1, fp2, &candidate_count,
                                  &bloom_work) != MRSH_OK)
        return NULL;
    }
  }
  cl = compare_list_new();
  if (!cl)
    return NULL;

  for (const FINGERPRINT *fp1 = fpl->list; fp1; fp1 = fp1->next) {
    for (const FINGERPRINT *fp2 = fp1->next; fp2; fp2 = fp2->next) {
      int score = fp_compare(fp1, fp2);
      if (score < 0 || ((unsigned int)score >= threshold &&
                        compare_list_add(cl, fp1->file_name, fp2->file_name, score) != MRSH_OK)) {
        cl_free(cl);
        return NULL;
      }
    }
  }
  return cl;
}

compare_list_t *cl_fpl_vs_fpl(const FINGERPRINT_LIST *fpl1,
                              const FINGERPRINT_LIST *fpl2,
                              unsigned int threshold) {
  compare_list_t *cl;
  uint64_t candidate_count = 0;
  uint64_t bloom_work = 0;
  if (!fpl1 || !fpl2 || threshold > 100)
    return NULL;
  for (const FINGERPRINT *fp1 = fpl1->list; fp1; fp1 = fp1->next) {
    for (const FINGERPRINT *fp2 = fpl2->list; fp2; fp2 = fp2->next) {
      if (account_comparison_work(fp1, fp2, &candidate_count,
                                  &bloom_work) != MRSH_OK)
        return NULL;
    }
  }
  cl = compare_list_new();
  if (!cl)
    return NULL;
  for (const FINGERPRINT *fp1 = fpl1->list; fp1; fp1 = fp1->next) {
    for (const FINGERPRINT *fp2 = fpl2->list; fp2; fp2 = fp2->next) {
      int score = fp_compare(fp1, fp2);
      if (score < 0 || ((unsigned int)score >= threshold &&
                        compare_list_add(cl, fp1->file_name, fp2->file_name, score) != MRSH_OK)) {
        cl_free(cl);
        return NULL;
      }
    }
  }
  return cl;
}

compare_list_t *cl_fp_vs_fpl(const FINGERPRINT *target,
                             const FINGERPRINT_LIST *fpl,
                             unsigned int threshold) {
  compare_list_t *cl;
  uint64_t candidate_count = 0;
  uint64_t bloom_work = 0;
  if (!target || !fpl || threshold > 100)
    return NULL;
  for (const FINGERPRINT *fp = fpl->list; fp; fp = fp->next) {
    if (account_comparison_work(target, fp, &candidate_count,
                                &bloom_work) != MRSH_OK)
      return NULL;
  }
  cl = compare_list_new();
  if (!cl)
    return NULL;
  for (const FINGERPRINT *fp = fpl->list; fp; fp = fp->next) {
    int score = fp_compare(target, fp);
    if (score < 0 || ((unsigned int)score >= threshold &&
                      compare_list_add(cl, target->file_name, fp->file_name, score) != MRSH_OK)) {
      cl_free(cl);
      return NULL;
    }
  }
  return cl;
}

size_t cl_size(const compare_list_t *cl) { return cl ? cl->size : 0; }

int cl_get(const compare_list_t *cl, size_t index, const char **name1,
           const char **name2, uint8_t *score) {
  if (!cl || index >= cl->size || !name1 || !name2 || !score)
    return MRSH_ERR_INVALID;
  *name1 = cl->list[index].name1;
  *name2 = cl->list[index].name2;
  *score = cl->list[index].score;
  return MRSH_OK;
}

int str_compare(const char *digest1, const char *digest2) {
  FINGERPRINT *fp1 = NULL;
  FINGERPRINT *fp2 = NULL;
  int result;

  result = fp_parse(digest1, &fp1);
  if (result != MRSH_OK)
    return result;
  result = fp_parse(digest2, &fp2);
  if (result == MRSH_OK)
    result = fp_compare(fp1, fp2);
  fp_destroy(fp1);
  fp_destroy(fp2);
  return result;
}
