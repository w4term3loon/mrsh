#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../header/hashing.h"
#define FNV64_OFFSET UINT64_C(0xcbf29ce484222325)
#define FNV64_PRIME  UINT64_C(0x00000100000001b3)
#define READ_BUFFER_SIZE 65536U
#define HASH_LOOKAHEAD_SIZE (SKIPPED_BYTES + 1U)
#define HASH_READ_EOF 1

typedef struct {
    uchar window[ROLLING_WINDOW];
    uint32 rolling_data[4];
    uint64 fnv_hash;
    uint64_t bytes_seen;
    size_t skip_remaining;
#ifdef network
    bool waiting_for_first_boundary;
#endif
} HASH_STATE;

typedef struct {
    unsigned char buffer[READ_BUFFER_SIZE];
    size_t position;
    size_t length;
    FILE *file;
    int descriptor;
    uint64_t descriptor_offset;
    bool use_descriptor;
} HASH_READER;

uint32 roll_hashx(unsigned char c, uchar window[ROLLING_WINDOW],
                  uint32 rh_data[4])
{
    size_t window_position;

    if (window == NULL || rh_data == NULL) {
        return 0U;
    }

    window_position = rh_data[0] % ROLLING_WINDOW;
    rh_data[2] -= rh_data[1];
    rh_data[2] += ROLLING_WINDOW * (uint32)c;
    rh_data[1] += c;
    rh_data[1] -= window[window_position];
    window[window_position] = c;
    ++rh_data[0];
    rh_data[3] <<= 5U;
    rh_data[3] ^= c;

    return rh_data[1] + rh_data[2] + rh_data[3];
}

uint32 djb2x(unsigned char c, uchar window[ROLLING_WINDOW], size_t n)
{
    uint32 hash = 5381U;
    size_t index;

    if (window == NULL) {
        return 0U;
    }

    window[n % ROLLING_WINDOW] = c;
    for (index = 0U; index < ROLLING_WINDOW; ++index) {
        unsigned char value = window[(n + index) % ROLLING_WINDOW];
        hash = ((hash << 5U) + hash) + value;
    }
    return hash;
}

static void hash_state_init(HASH_STATE *state)
{
    memset(state, 0, sizeof(*state));
    state->fnv_hash = FNV64_OFFSET;
#ifdef network
    state->waiting_for_first_boundary = true;
#endif
}

static int hash_state_add_byte(HASH_STATE *state, FINGERPRINT *fingerprint,
                               unsigned char byte, bool skip_is_available)
{
    uint64 rolling_value;
    int status = MRSH_OK;

    if (state->bytes_seen == UINT64_MAX) {
        return MRSH_ERR_RANGE;
    }
    ++state->bytes_seen;
    state->fnv_hash ^= byte;
    state->fnv_hash *= FNV64_PRIME;

    if (state->skip_remaining != 0U) {
        --state->skip_remaining;
        return MRSH_OK;
    }

    rolling_value = roll_hashx(byte, state->window, state->rolling_data);
    if (rolling_value % BLOCK_SIZE == BLOCK_SIZE - 1U) {
#ifdef network
        if (state->waiting_for_first_boundary) {
            state->waiting_for_first_boundary = false;
        } else {
            status = add_hash_to_fingerprint(fingerprint, state->fnv_hash);
        }
#else
        status = add_hash_to_fingerprint(fingerprint, state->fnv_hash);
#endif
        if (status != MRSH_OK) {
            return status;
        }

        state->fnv_hash = FNV64_OFFSET;
        if (skip_is_available) {
            state->skip_remaining = SKIPPED_BYTES;
        }
    }
    return MRSH_OK;
}

static int hash_state_finish(HASH_STATE *state, FINGERPRINT *fingerprint)
{
#ifndef network
    if (state->bytes_seen != 0U) {
        return add_hash_to_fingerprint(fingerprint, state->fnv_hash);
    }
#else
    (void)state;
    (void)fingerprint;
#endif
    return MRSH_OK;
}

static int hash_reader_next(HASH_READER *reader, unsigned char *byte_out)
{
    if (reader == NULL || byte_out == NULL) {
        return MRSH_ERR_INVALID;
    }
    if (reader->position == reader->length) {
        if (reader->use_descriptor) {
            ssize_t read_result;

            if (reader->descriptor_offset > (uint64_t)INT64_MAX) {
                return MRSH_ERR_RANGE;
            }
            do {
                read_result = pread(reader->descriptor, reader->buffer,
                                    sizeof(reader->buffer),
                                    (off_t)reader->descriptor_offset);
            } while (read_result < 0 && errno == EINTR);
            if (read_result < 0) {
                return MRSH_ERR_IO;
            }
            if (read_result == 0) {
                return HASH_READ_EOF;
            }
            reader->length = (size_t)read_result;
            if (reader->descriptor_offset >
                UINT64_MAX - (uint64_t)reader->length) {
                return MRSH_ERR_RANGE;
            }
            reader->descriptor_offset += (uint64_t)reader->length;
        } else {
            reader->length = fread(reader->buffer, 1U,
                                   sizeof(reader->buffer), reader->file);
            if (reader->length == 0U) {
                return ferror(reader->file) != 0 ? MRSH_ERR_IO : HASH_READ_EOF;
            }
        }
        reader->position = 0U;
    }
    *byte_out = reader->buffer[reader->position++];
    return MRSH_OK;
}

static int hash_reader_to_fingerprint(FINGERPRINT *fingerprint,
                                      HASH_READER *reader)
{
    unsigned char lookahead[HASH_LOOKAHEAD_SIZE];
    size_t head = 0U;
    size_t count = 0U;
    bool reached_eof = false;
    HASH_STATE state;
    int status;

    hash_state_init(&state);
    while (count < HASH_LOOKAHEAD_SIZE && !reached_eof) {
        unsigned char byte = 0U;
        status = hash_reader_next(reader, &byte);
        if (status == HASH_READ_EOF) {
            reached_eof = true;
        } else if (status != MRSH_OK) {
            return status;
        } else {
            lookahead[(head + count) % HASH_LOOKAHEAD_SIZE] = byte;
            ++count;
        }
    }

    while (count != 0U) {
        unsigned char byte = lookahead[head];
        bool skip_is_available = count == HASH_LOOKAHEAD_SIZE;

        head = (head + 1U) % HASH_LOOKAHEAD_SIZE;
        --count;
        status = hash_state_add_byte(&state, fingerprint, byte,
                                     skip_is_available);
        if (status != MRSH_OK) {
            return status;
        }

        while (count < HASH_LOOKAHEAD_SIZE && !reached_eof) {
            status = hash_reader_next(reader, &byte);
            if (status == HASH_READ_EOF) {
                reached_eof = true;
            } else if (status != MRSH_OK) {
                return status;
            } else {
                lookahead[(head + count) % HASH_LOOKAHEAD_SIZE] = byte;
                ++count;
            }
        }
    }

    status = hash_state_finish(&state, fingerprint);
    if (status == MRSH_OK) {
        fingerprint->filesize = state.bytes_seen;
    }
    return status;
}

int hashPacketBuffer(FINGERPRINT *fingerprint, const unsigned char *packet,
                     size_t length)
{
    HASH_STATE state;
    size_t index;
    int status;

    if (fingerprint == NULL || (packet == NULL && length != 0U)) {
        return MRSH_ERR_INVALID;
    }

    hash_state_init(&state);
    for (index = 0U; index < length; ++index) {
        bool skip_is_available =
            length - index - 1U >= (size_t)SKIPPED_BYTES;
        status = hash_state_add_byte(&state, fingerprint, packet[index],
                                     skip_is_available);
        if (status != MRSH_OK) {
            return status;
        }
    }
    status = hash_state_finish(&state, fingerprint);
    if (status == MRSH_OK) {
        fingerprint->filesize = (uint64_t)length;
    }
    return status;
}

int hashFileToFingerprint(FINGERPRINT *fingerprint, FILE *handle)
{
    HASH_READER reader = {0};

    if (fingerprint == NULL || handle == NULL) {
        return MRSH_ERR_INVALID;
    }
    if (fseek(handle, 0L, SEEK_SET) != 0) {
        /* Newly opened non-seekable and virtual streams are already at their
         * beginning. A failed positioning attempt must not prevent streaming. */
        clearerr(handle);
    }
    reader.file = handle;
    return hash_reader_to_fingerprint(fingerprint, &reader);
}

int hashFileDescriptorToFingerprint(FINGERPRINT *fingerprint, int descriptor)
{
    struct stat attributes;
    HASH_READER reader = {0};
    int stat_result;

    if (fingerprint == NULL || descriptor < 0) {
        return MRSH_ERR_INVALID;
    }
    do {
        stat_result = fstat(descriptor, &attributes);
    } while (stat_result != 0 && errno == EINTR);
    if (stat_result != 0) {
        return MRSH_ERR_IO;
    }
    if (!S_ISREG(attributes.st_mode) || attributes.st_size < (off_t)0) {
        return MRSH_ERR_INVALID;
    }
    reader.descriptor = descriptor;
    reader.use_descriptor = true;
    return hash_reader_to_fingerprint(fingerprint, &reader);
}
