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

__attribute__((constructor)) void
init_modes(void) {
  mode = (MODES *)malloc(sizeof(MODES));
  mode->compare = false;
  mode->gen_compare = false;
  mode->compareLists = false;
  mode->file_comparison = false;
  mode->helpmessage = false;
  mode->print = false;
  mode->threshold = 1;
  mode->recursive = false;
  mode->path_list_compare = false;
}

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

FINGERPRINT *
fp_init(void) {
  return init_empty_fingerprint();
}

void
fp_destroy(FINGERPRINT *fp) {
  fingerprint_destroy(fp);
}

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

FINGERPRINT *
fp_init_file(char *filename, const char *label) {
  FINGERPRINT *fp = init_empty_fingerprint();
  fp_add_file(fp, filename, label);
  return fp;
}

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

int
fp_add_bytes(FINGERPRINT *fp, unsigned char *byte_buffer, unsigned long bytes_size,
             const char *label) {
  // use existing field
  // TODO: fix
  strcpy(fp->file_name, label);
  fp->filesize = bytes_size;

  fp_hash_bytes(fp, byte_buffer, bytes_size);
  return 0;
}

FINGERPRINT *
fp_init_bytes(unsigned char *byte_buffer, unsigned long bytes_size, const char *label) {
  FINGERPRINT *fp = init_empty_fingerprint();
  fp_add_bytes(fp, byte_buffer, bytes_size, label);
  return fp;
}

uint8_t
fp_fp_compare(FINGERPRINT *fp1, FINGERPRINT *fp2) {
  return (uint8_t)fingerprint_compare(fp1, fp2);
}

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

FINGERPRINT_LIST *
fpl_init(void) {
  return init_empty_fingerprintList();
}

void
fpl_destroy(FINGERPRINT_LIST *fpl) {
  fingerprintList_destroy(fpl);
}

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
        FINGERPRINT *fp = fp_init_file(filename, label);
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

  return;
}

void
fpl_add_bytes(FINGERPRINT_LIST *fpl, unsigned char *byte_buffer, unsigned long bytes_size,
              const char *label) {
  FINGERPRINT *fp = fp_init_bytes(byte_buffer, bytes_size, label);
  add_new_fingerprint(fpl, fp);
  return;
}

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

compare_list_t *
cl_fpl_all(FINGERPRINT_LIST *fpl, uint8_t threshold) {
  compare_list_t *cl = (compare_list_t *)malloc(sizeof(compare_list_t));
  if (!cl) {
    return NULL;
  }

  // Allocate for theoretical maximum
  size_t max_size = (fpl->size * (fpl->size + 1)) / 2;
  cl->list = (compare_t *)calloc(max_size, sizeof(compare_t));
  if (!cl->list) {
    free(cl);
    return NULL;
  }

  size_t iter = 0;
  uint8_t score = 0;
  FINGERPRINT *fp2, *fp1 = fpl->list;

  while (fp1 != NULL) {
    fp2 = fp1->next;
    while (fp2 != NULL) {
      score = fingerprint_compare(fp1, fp2);
      if (score >= threshold) {
        cl->list[iter].name1 = fp1->file_name;
        cl->list[iter].name2 = fp2->file_name;
        cl->list[iter++].score = score;
      }
      fp2 = fp2->next;
    }
    fp1 = fp1->next;
  }

  cl->size = iter;

  return cl;
}

void
cl_free(compare_list_t *cl) {
  if (cl) {
    free((void *)cl->list);
    free(cl);
  }
}
