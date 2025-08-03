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
  init_empty_fingerprint();
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

void
fp_get(FINGERPRINT *fp, char *buffer, size_t size) {
  /* FORMAT: filename:filesize:number of filters:blocks in last filter*/
  int offset = snprintf(buffer, size, "%s:%d:%d:%d:", fp->file_name, fp->filesize,
                        fp->amount_of_BF + 1, fp->bf_list_last_element->amount_of_blocks);

  BLOOMFILTER *bf = fp->bf_list;
  while (bf != NULL) {
    // Print each Bloom filter as a 2-digit-hex value
    for (int j = 0; j < FILTERSIZE; j++)
      offset += snprintf(buffer + offset, size - offset, "%02X", bf->array[j]);

    // move to next Bloom filter
    bf = bf->next;
  }
}



FINGERPRINT_LIST *
fpl_init(void) {
  init_empty_fingerprintList();
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

void
fpl_get(FINGERPRINT_LIST *fpl, char *buffer, size_t size) {
  FINGERPRINT *tmp = fpl->list;
  int offset = 0;

  char temp[1024]; // temporary buffer for one fingerprint

  while (tmp != NULL && offset < size - 1) {
    fp_get(tmp, temp, sizeof(temp));

    int len = snprintf(buffer + offset, size - offset, "%s", temp);

    if (len < 0 || len >= (int)(size - offset)) {
      break; // would overflow, stop writing
    }

    offset += len;

    // add new line only between elements
    if (tmp->next != NULL && offset < size - 1) {
      buffer[offset++] = '\n';
    }

    tmp = tmp->next;
  }

  buffer[offset < size ? offset : size - 1] = '\0'; // safe null-termination
}


