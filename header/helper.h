#ifndef MRSH_HELPER_H
#define MRSH_HELPER_H

#include <stdbool.h>
#include <dirent.h>
#include <stdio.h>
#include <sys/stat.h>

#include "config.h"

bool is_file(const char *path);
bool is_dir(const char *path);
int open_regular_file(const char *filename, FILE **handle_out);
int open_regular_file_checked(const char *filename,
                              const struct stat *expected,
                              FILE **handle_out);
int open_regular_file_follow_checked(const char *filename,
                                     const struct stat *expected,
                                     FILE **handle_out);
int open_directory_checked(const char *filename,
                           const struct stat *expected,
                           DIR **directory_out);
FILE *getFileHandle(const char *filename);

#endif /* MRSH_HELPER_H */
