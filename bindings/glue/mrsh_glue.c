/*
 * Partially copied from the original source.
 * Author: Frank Breitinger
 * Created on 28. April 2013, 19:15
 * Modified by w4term3loon.
 */

#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// missing from fingerprintList.h
#include <stdio.h>

#include "config.h"
#include "fingerprintList.h"
#include "hashing.h"
#include "helper.h"
#include "util.h"

MODES *mode;

/**
 * @brief Initialize global mode configuration structure
 * @note Called automatically at program startup via __attribute__((constructor))
 */
__attribute__((constructor)) void
init_modes(void) {
  mode = (MODES *)malloc(sizeof(MODES));
  mode->compare = false;
  mode->gen_compare = false;
  mode->compareLists = false;
  mode->file_comparison = false;
  mode->helpmessage = false;
  mode->print = false;
  mode->threshold = 0;
  mode->recursive = false;
  mode->path_list_compare = false;
}

/**
 * @brief Clean up global mode configuration structure
 * @note Called automatically at program exit via __attribute__((destructor))
 */
__attribute__((destructor)) void
destroy_modes(void) {
  free((void *)mode);
  mode = NULL;
}

// missing from helper.h
bool
is_file(const char *path);
bool
is_dir(const char *path);

/**
 * @brief Initialize an empty fingerprint structure
 * @return Pointer to newly allocated empty fingerprint, or NULL on error
 */
FINGERPRINT *
fp_init(void) {
  return init_empty_fingerprint();
}

/**
 * @brief Destroy and free a fingerprint structure
 * @param fp Fingerprint to destroy
 */
void
fp_destroy(FINGERPRINT *fp) {
  fingerprint_destroy(fp);
}

/**
 * @brief Add a file to an existing fingerprint by hashing its contents
 * @param fp Fingerprint structure to populate
 * @param filename Path to file to hash
 * @param label Optional label to use instead of filename (can be NULL)
 * @return 0 on success, -1 on error
 * @note Only processes regular files, not directories
 */
int
fp_add_file(FINGERPRINT *fp, char *filename, const char *label) {
  if (is_dir(filename)) {
    return -1;
  } else if (is_file(filename)) {
    FILE *file = getFileHandle(filename);
    fp->filesize = find_file_size(file);

    if (!label) {
      strcpy(fp->file_name, filename);
    } else {
      strcpy(fp->file_name, label);
    }

    hashFileToFingerprint(fp, file);
    fclose(file);
    return 0;
  }
  return -1;
}

/**
 * @brief Create a new fingerprint from a file
 * @param filename Path to file to hash
 * @param label Optional label to use instead of filename (can be NULL)
 * @return Pointer to newly created fingerprint, or NULL on error
 */
FINGERPRINT *
fp_init_file(char *filename, const char *label) {
  FINGERPRINT *fp = init_empty_fingerprint();
  fp_add_file(fp, filename, label);
  return fp;
}

/**
 * @brief Hash raw bytes into a fingerprint using rolling hash algorithm
 * @param fingerprint Fingerprint structure to populate with hash values
 * @param byte_buffer Raw bytes to hash
 * @param bytes_size Size of byte buffer
 * @return 1 on success
 * @note Uses rolling hash with FNV-64 for block boundaries
 */
int
fp_hash_bytes(FINGERPRINT *fingerprint, unsigned char *byte_buffer, unsigned long bytes_size) {
  short first = 1;

  unsigned int last_block_index = 0;
  uint64 rValue, hashvalue = 0;

  // we need these arrays for the extended rollhash function
  uchar window[ROLLING_WINDOW] = {0};
  uint32 rhData[4] = {0};

  for (unsigned int i = 0; i < bytes_size; i++) {

    // rValue = djb2x(byte_buffer[i],window,i);
    rValue = roll_hashx(byte_buffer[i], window, rhData);

    if (rValue % BLOCK_SIZE == BLOCK_SIZE - 1) // || chunk_index >= BLOCK_SIZE_MAX)
    {

#ifdef network
      if (first == 1) {
        first = 0;
        last_block_index = i + 1;
        if (i + SKIPPED_BYTES < bytes_read)
          i += SKIPPED_BYTES;
        continue;
      }
#endif

      hashvalue = fnv64Bit(byte_buffer, last_block_index, i); //,current_index, FNV1_64_INIT);
      add_hash_to_fingerprint(fingerprint, hashvalue);        // printf("%i %llu \n", i, hashvalue);

      last_block_index = i + 1;

      if (i + SKIPPED_BYTES < bytes_size)
        i += SKIPPED_BYTES;
    }
  }

#ifndef network
  hashvalue = fnv64Bit(byte_buffer, last_block_index, bytes_size - 1);
  add_hash_to_fingerprint(fingerprint, hashvalue);
#endif

  return 1;
}

/**
 * @brief Add raw bytes to an existing fingerprint
 * @param fp Fingerprint structure to populate
 * @param byte_buffer Raw bytes to hash
 * @param bytes_size Size of byte buffer
 * @param label Label to assign to this fingerprint
 * @return 0 on success
 */
int
fp_add_bytes(FINGERPRINT *fp, unsigned char *byte_buffer, unsigned long bytes_size,
             const char *label) {
  strcpy(fp->file_name, label);
  fp->filesize = bytes_size;

  fp_hash_bytes(fp, byte_buffer, bytes_size);
  return 0;
}

/**
 * @brief Create a new fingerprint from raw bytes
 * @param byte_buffer Raw bytes to hash
 * @param bytes_size Size of byte buffer
 * @param label Label to assign to this fingerprint
 * @return Pointer to newly created fingerprint
 */
FINGERPRINT *
fp_init_bytes(unsigned char *byte_buffer, unsigned long bytes_size, const char *label) {
  FINGERPRINT *fp = init_empty_fingerprint();
  fp_add_bytes(fp, byte_buffer, bytes_size, label);
  return fp;
}

/**
 * @brief Convert a fingerprint to its string representation
 * @param fp Fingerprint to convert
 * @return Allocated string containing fingerprint data in hex format, or NULL on error
 * @note Format: "filename:filesize:bf_count:blocks:HEXDATA"
 * @note Caller must free returned string with str_free()
 */
char *
fp_str(FINGERPRINT *fp) {
  if (!fp) {
    return NULL;
  }

  int j;
  BLOOMFILTER *bf = fp->bf_list;

  size_t metadata_len = strlen(fp->file_name) + 64;         // generous space for numbers
  size_t hex_len = (fp->amount_of_BF + 1) * FILTERSIZE * 2; // 2 hex chars per byte
  size_t total_len = metadata_len + hex_len + 10;           // +10 for newlines and safety

  char *result = malloc(total_len);
  if (!result) {
    return NULL;
  }

  // metadata
  int pos = snprintf(result, total_len, "%s:%d:%d:%d:", fp->file_name, fp->filesize,
                     fp->amount_of_BF + 1, fp->bf_list_last_element->amount_of_blocks);
  if (pos < 0 || pos >= total_len) {
    free(result);
    return NULL;
  }

  // add BFs
  while (bf != NULL && pos < total_len - 2) {
    for (j = 0; j < FILTERSIZE && pos < total_len - 2; j++) {
      int written = snprintf(result + pos, total_len - pos, "%02X", bf->array[j]);
      if (written != 2) { // sanity check
        free(result);
        return NULL;
      }
      pos += 2;
    }
    bf = bf->next;
  }

  // null terminate
  if (pos < total_len) {
    result[pos] = '\0';
  }

  return result;
}

/**
 * @brief Initialize an empty fingerprint list
 * @return Pointer to newly allocated empty fingerprint list
 */
FINGERPRINT_LIST *
fpl_init(void) {
  return init_empty_fingerprintList();
}

/**
 * @brief Destroy and free a fingerprint list and all its fingerprints
 * @param fpl Fingerprint list to destroy
 */
void
fpl_destroy(FINGERPRINT_LIST *fpl) {
  fingerprintList_destroy(fpl);
}

/**
 * @brief Add all files from a path (file or directory) to fingerprint list
 * @param fpl Fingerprint list to add to
 * @param filename Path to file or directory
 * @param label Optional label prefix for entries (can be NULL)
 * @note If filename is a directory, recursively processes all files within
 * @note Respects global mode->recursive setting for subdirectory traversal
 */
void
fpl_add_path(FINGERPRINT_LIST *fpl, char *filename, const char *label) {
  DIR *dir;
  struct dirent *ent;
  const int max_path_length = 1024;

  char *cur_dir = (char *)malloc(max_path_length);
  getcwd(cur_dir, max_path_length);

  // in case of a dir
  if (is_dir(filename)) {
    dir = opendir(filename);
    chdir(filename);

    // run through all files of the dir
    while ((ent = readdir(dir)) != NULL) {

      // if we found a file, generate hash value and add it
      if (is_file(ent->d_name)) {
        FILE *file = getFileHandle(ent->d_name);
        FINGERPRINT *fp = init_fingerprint_for_file(file, ent->d_name);
        add_new_fingerprint(fpl, fp);
      }

      // when we found a dir and recursive mode is on, go deeper
      else if (is_dir(ent->d_name) && mode->recursive) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
          continue;
        fpl_add_path(fpl, ent->d_name, label);
      }
    }
    chdir(cur_dir);
    closedir(dir);
  }

  // in case we we have only a file
  else if (is_file(filename)) {
    FILE *file = getFileHandle(filename);
    FINGERPRINT *fp = fp_init_file(filename, label);
    add_new_fingerprint(fpl, fp);
  }

  free(cur_dir);
  return;
}

/**
 * @brief Add raw bytes as a fingerprint to the list
 * @param fpl Fingerprint list to add to
 * @param byte_buffer Raw bytes to hash
 * @param bytes_size Size of byte buffer
 * @param label Label to assign to this fingerprint entry
 */
void
fpl_add_bytes(FINGERPRINT_LIST *fpl, unsigned char *byte_buffer, unsigned long bytes_size,
              const char *label) {
  FINGERPRINT *fp = fp_init_bytes(byte_buffer, bytes_size, label);
  add_new_fingerprint(fpl, fp);
  return;
}

/**
 * @brief Convert entire fingerprint list to string representation
 * @param fpl Fingerprint list to convert
 * @return Allocated string containing all fingerprints separated by newlines, or NULL on error
 * @note Each line follows format: "filename:filesize:bf_count:blocks:HEXDATA"
 * @note Caller must free returned string with str_free()
 */
char *
fpl_str(FINGERPRINT_LIST *fpl) {
  if (!fpl || !fpl->list)
    return NULL;

  // estimate total length
  size_t total_len = 0;
  for (FINGERPRINT *fp = fpl->list; fp; fp = fp->next) {
    size_t meta = strlen(fp->file_name) + 64;             // filename + ints + colons
    size_t hex = (fp->amount_of_BF + 1) * FILTERSIZE * 2; // 2 hex chars per byte
    total_len += meta + hex + 1;                          // +1 for newline or final NUL
  }

  char *result = calloc(1, total_len + 1); // +1 for final NUL
  if (!result)
    return NULL;

  // fill buffer
  size_t pos = 0;
  for (FINGERPRINT *fp = fpl->list; fp; fp = fp->next) {
    // metadata header
    int n = snprintf(result + pos, total_len + 1 - pos, "%s:%d:%d:%d:", fp->file_name, fp->filesize,
                     fp->amount_of_BF + 1, fp->bf_list_last_element->amount_of_blocks);
    if (n < 0 || (size_t)n >= total_len + 1 - pos) {
      free(result);
      return NULL;
    }
    pos += n;

    // bloom-filter bytes as hex
    for (BLOOMFILTER *bf = fp->bf_list; bf; bf = bf->next) {
      for (int j = 0; j < FILTERSIZE; j++) {
        if (pos + 2 >= total_len + 1) {
          result[total_len] = '\0';
          return result;
        }
        int w = snprintf(result + pos, total_len + 1 - pos, "%02X", bf->array[j]);
        if (w != 2) {
          free(result);
          return NULL;
        }
        pos += 2;
      }
    }

    // newline between entries
    if (fp->next) {
      if (pos < total_len)
        result[pos++] = '\n';
    }
  }

  // final NULL
  result[pos < total_len ? pos : total_len] = '\0';
  return result;
}

/**
 * @brief Free a string allocated by fp_str() or fpl_str()
 * @param str String to free
 * @note Safe to call with NULL pointer
 */
void
str_free(char *str) {
  if (str != NULL) {
    free(str);
  }
}

typedef struct {
  char *name1;
  char *name2;
  uint8_t score;
} compare_t;

typedef struct {
  compare_t *list;
  size_t size;
} compare_list_t;

/**
 * @brief Compare fingerprint similarity score between two fingerprints
 * @param fp1 First fingerprint to compare
 * @param fp2 Second fingerprint to compare
 * @return Similarity score as uint8_t (0-100)
 */
uint8_t
fp_compare(FINGERPRINT *fp1, FINGERPRINT *fp2) {
  return (uint8_t)fingerprint_compare(fp1, fp2);
}

/**
 * @brief Compare every fingerprint with every other fingerprint in a list
 * @param fpl Fingerprint list to process
 * @param threshold Minimum similarity score to include in results
 * @return Allocated compare_list_t containing all matches above threshold, or NULL on error
 * @note Avoids duplicate comparisons (A vs B, but not B vs A)
 * @note Caller must free returned structure with cl_free()
 */
compare_list_t *
cl_fpl_all(FINGERPRINT_LIST *fpl, uint8_t threshold) {
  if (!fpl || fpl->size == 0)
    return NULL;

  compare_list_t *cl = malloc(sizeof(compare_list_t));
  if (!cl)
    return NULL;

  // Maximum possible comparisons: n*(n-1)/2
  size_t max_size = (fpl->size * (fpl->size - 1)) / 2;
  cl->list = calloc(max_size, sizeof(compare_t));
  if (!cl->list) {
    free(cl);
    return NULL;
  }

  size_t count = 0;
  FINGERPRINT *fp1 = fpl->list;

  while (fp1) {
    FINGERPRINT *fp2 = fp1->next;
    while (fp2) {
      uint8_t score = fp_compare(fp1, fp2);
      if (score >= threshold) {
        cl->list[count].name1 = fp1->file_name;
        cl->list[count].name2 = fp2->file_name;
        cl->list[count].score = score;
        count++;
      }
      fp2 = fp2->next;
    }
    fp1 = fp1->next;
  }

  cl->size = count;
  return cl;
}

/**
 * @brief Compare every fingerprint in first list against every fingerprint in second list
 * @param fpl1 First fingerprint list
 * @param fpl2 Second fingerprint list
 * @param threshold Minimum similarity score to include in results
 * @return Allocated compare_list_t containing all cross-matches above threshold, or NULL on error
 * @note Performs full cross-product comparison (size1 * size2 comparisons)
 * @note Caller must free returned structure with cl_free()
 */
compare_list_t *
cl_fpl_vs_fpl(FINGERPRINT_LIST *fpl1, FINGERPRINT_LIST *fpl2, uint8_t threshold) {
  if (!fpl1 || !fpl2 || fpl1->size == 0 || fpl2->size == 0)
    return NULL;

  compare_list_t *cl = malloc(sizeof(compare_list_t));
  if (!cl)
    return NULL;

  // Maximum possible comparisons: size1 * size2
  size_t max_size = fpl1->size * fpl2->size;
  cl->list = calloc(max_size, sizeof(compare_t));
  if (!cl->list) {
    free(cl);
    return NULL;
  }

  size_t count = 0;
  FINGERPRINT *fp1 = fpl1->list;

  while (fp1) {
    FINGERPRINT *fp2 = fpl2->list;
    while (fp2) {
      uint8_t score = fp_compare(fp1, fp2);
      if (score >= threshold) {
        cl->list[count].name1 = fp1->file_name;
        cl->list[count].name2 = fp2->file_name;
        cl->list[count].score = score;
        count++;
      }
      fp2 = fp2->next;
    }
    fp1 = fp1->next;
  }

  cl->size = count;
  return cl;
}

/**
 * @brief Compare one fingerprint against all fingerprints in a list
 * @param target Single fingerprint to compare against the list
 * @param fpl Fingerprint list to compare against
 * @param threshold Minimum similarity score to include in results
 * @return Allocated compare_list_t containing all matches above threshold, or NULL on error
 * @note Target fingerprint appears as name1 in all results
 * @note Caller must free returned structure with cl_free()
 */
compare_list_t *
cl_fp_vs_fpl(FINGERPRINT *target, FINGERPRINT_LIST *fpl, uint8_t threshold) {
  if (!target || !fpl || fpl->size == 0)
    return NULL;

  compare_list_t *cl = malloc(sizeof(compare_list_t));
  if (!cl)
    return NULL;

  cl->list = calloc(fpl->size, sizeof(compare_t));
  if (!cl->list) {
    free(cl);
    return NULL;
  }

  size_t count = 0;
  FINGERPRINT *fp = fpl->list;

  while (fp) {
    uint8_t score = fp_compare(target, fp);
    if (score >= threshold) {
      cl->list[count].name1 = target->file_name;
      cl->list[count].name2 = fp->file_name;
      cl->list[count].score = score;
      count++;
    }
    fp = fp->next;
  }

  cl->size = count;
  return cl;
}

/**
 * @brief Free memory allocated for compare_list_t structure
 * @param cl Compare list to free
 * @note Safe to call with NULL pointer
 */
void
cl_free(compare_list_t *cl) {
  if (cl) {
    free((void *)cl->list);
    free(cl);
  }
}

// Helper function to convert hex string to byte array
void
hex_to_bytes(const char *hex_str, unsigned char *bytes, int byte_count) {
  for (int i = 0; i < byte_count; i++) {
    unsigned int temp; // Use a temporary variable of the correct type
    sscanf(hex_str + 2 * i, "%02X", &temp);
    bytes[i] = (unsigned char)temp; // Assign the value to the char array
  }
}

// Parse a fingerprint string back into a FINGERPRINT struct
// Format: "filename:filesize:number_of_filters:blocks_in_last_filter:HEXDATA"
FINGERPRINT *
parse_fingerprint_string(const char *fp_string) {
  if (!fp_string) {
    return NULL;
  }

  FINGERPRINT *fp = init_empty_fingerprint();
  if (!fp) {
    return NULL; // Should not happen if init_empty_fingerprint exits on failure
  }

  char *str_copy = strdup(fp_string);
  if (!str_copy) {
    fingerprint_destroy(fp);
    return NULL;
  }

  char *saveptr;
  char *token;

  // 1. Filename
  if (!(token = strtok_r(str_copy, ":", &saveptr)))
    goto error;
  strncpy(fp->file_name, token, sizeof(fp->file_name) - 1);
  fp->file_name[sizeof(fp->file_name) - 1] = '\0';

  // 2. Filesize
  if (!(token = strtok_r(NULL, ":", &saveptr)))
    goto error;
  fp->filesize = (unsigned int)strtoul(token, NULL, 10);

  // 3. Amount of Bloom Filters
  if (!(token = strtok_r(NULL, ":", &saveptr)))
    goto error;
  fp->amount_of_BF = (unsigned int)strtoul(token, NULL, 10) - 1;

  // 4. Blocks in the last filter
  if (!(token = strtok_r(NULL, ":", &saveptr)))
    goto error;
  int blocks_in_last_filter = atoi(token);

  // 5. Hex Data
  if (!(token = strtok_r(NULL, "", &saveptr)))
    goto error; // Read the rest of the string

  // Check if there is enough hex data for the declared number of filters
  size_t required_len = ((size_t)fp->amount_of_BF + 1) * FILTERSIZE * 2;
  if (strlen(token) < required_len) {
    goto error;
  }

  BLOOMFILTER *current_bf = NULL;
  for (unsigned int i = 0; i <= fp->amount_of_BF; i++) {
    if (i == 0) {
      current_bf = fp->bf_list;
    } else {
      // Allocate new filters for the rest of the list
      current_bf = (BLOOMFILTER *)calloc(1, sizeof(BLOOMFILTER));
      if (!current_bf)
        goto error;
      // Link it to the previous one
      fp->bf_list_last_element->next = current_bf;
      fp->bf_list_last_element = current_bf;
    }

    // Convert hex data for the current filter
    hex_to_bytes(token + (i * FILTERSIZE * 2), current_bf->array, FILTERSIZE);

    // Assign block count
    if (i == fp->amount_of_BF) {
      current_bf->amount_of_blocks = blocks_in_last_filter;
    } else {
      current_bf->amount_of_blocks = MAXBLOCKS; // Assumes full filter
    }
  }

  free(str_copy);
  return fp;

error:
  free(str_copy);
  fingerprint_destroy(fp);
  return NULL;
}

// Main comparison function that operates on fingerprint strings
// Uses your existing fingerprint_compare function
int
str_compare(const char *fp_string1, const char *fp_string2) {
  if (!fp_string1 || !fp_string2) {
    return 0; // Invalid input
  }

  FINGERPRINT *fp1 = parse_fingerprint_string(fp_string1);
  FINGERPRINT *fp2 = parse_fingerprint_string(fp_string2);

  int score = 0;
  // Only perform comparison if both fingerprints were parsed successfully
  if (fp1 && fp2) {
    score = fingerprint_compare(fp1, fp2);
  }

  if (fp1) {
    fingerprint_destroy(fp1);
  }
  if (fp2) {
    fingerprint_destroy(fp2);
  }

  return score;
}
