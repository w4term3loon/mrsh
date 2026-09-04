#ifndef MRSH_UTIL_H
#define MRSH_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "config.h"

int find_file_size(FILE *handle, uint64_t *size_out);
uint64 fnv64_buf(const unsigned char *buffer, size_t length);

#endif /* MRSH_UTIL_H */
