#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <sys/types.h>

#include "../header/util.h"

int find_file_size(FILE *handle, uint64_t *size_out)
{
#ifdef _WIN32
    __int64 original_position;
    __int64 end_position;
#else
    off_t original_position;
    off_t end_position;
#endif

    if (handle == NULL || size_out == NULL) {
        return MRSH_ERR_INVALID;
    }

    original_position =
#ifdef _WIN32
        _ftelli64(handle);
#else
        ftello(handle);
#endif
    if (original_position < 0) {
        return MRSH_ERR_IO;
    }
    if (
#ifdef _WIN32
        _fseeki64(handle, 0, SEEK_END)
#else
        fseeko(handle, (off_t)0, SEEK_END)
#endif
        != 0) {
        return MRSH_ERR_IO;
    }

    end_position =
#ifdef _WIN32
        _ftelli64(handle);
#else
        ftello(handle);
#endif
    if (
#ifdef _WIN32
        _fseeki64(handle, original_position, SEEK_SET)
#else
        fseeko(handle, original_position, SEEK_SET)
#endif
        != 0) {
        return MRSH_ERR_IO;
    }
    if (end_position < 0) {
        return MRSH_ERR_IO;
    }

    *size_out = (uint64_t)end_position;
    return MRSH_OK;
}

uint64 fnv64_buf(const unsigned char *buffer, size_t length)
{
    uint64 hash = UINT64_C(0xcbf29ce484222325);
    const uint64 prime = UINT64_C(0x00000100000001b3);
    size_t index;

    if (buffer == NULL && length != 0U) {
        return hash;
    }

    for (index = 0U; index < length; ++index) {
        hash ^= buffer[index];
        hash *= prime;
    }
    return hash;
}
