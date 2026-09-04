#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../header/bloomfilter.h"

static int hex_nibble(char value)
{
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

BLOOMFILTER *init_empty_BF(void)
{
    return calloc(1U, sizeof(BLOOMFILTER));
}

void destroy_bf(BLOOMFILTER *bf)
{
    free(bf);
}

int bloom_set_bit(unsigned char *bit_array, uint16_t value)
{
    size_t byte_position;
    unsigned int bit_position;

    if (bit_array == NULL || value >= BLOOMFILTERBITSIZE) {
        return MRSH_ERR_INVALID;
    }

    byte_position = (size_t)value >> 3U;
    bit_position = (unsigned int)value & 7U;
    bit_array[byte_position] |= (unsigned char)(1U << bit_position);
    return MRSH_OK;
}

int add_hash_to_bloomfilter(BLOOMFILTER *bf, uint64 hash_value)
{
    unsigned int already_set = 0U;
    unsigned int index;

    if (bf == NULL) {
        return MRSH_ERR_INVALID;
    }

    for (index = 0U; index < SUBHASHES; ++index) {
        uint16_t masked_bits =
            (uint16_t)((hash_value >> (SHIFTOPS * index)) & MASK);
        size_t byte_position = (size_t)masked_bits >> 3U;
        unsigned int bit_position = (unsigned int)masked_bits & 7U;
        unsigned char mask = (unsigned char)(1U << bit_position);

        if ((bf->array[byte_position] & mask) != 0U) {
            ++already_set;
        }
        bf->array[byte_position] |= mask;
    }

    if (already_set != SUBHASHES) {
        if (bf->amount_of_blocks == UINT32_MAX) {
            return MRSH_ERR_RANGE;
        }
        ++bf->amount_of_blocks;
    }
    return MRSH_OK;
}

uint16_t count_bits_set_to_one_of_BF(const unsigned char *filter)
{
    uint16_t count = 0U;
    size_t index;

    if (filter == NULL) {
        return 0U;
    }

    for (index = 0U; index < FILTERSIZE; ++index) {
        unsigned int byte = filter[index];
        while (byte != 0U) {
            byte &= byte - 1U;
            ++count;
        }
    }
    return count;
}

uint16_t bloom_common_bits(const unsigned char *bit_array_one,
                           const unsigned char *bit_array_two)
{
    uint16_t count = 0U;
    size_t index;

    if (bit_array_one == NULL || bit_array_two == NULL) {
        return 0U;
    }

    for (index = 0U; index < FILTERSIZE; ++index) {
        unsigned int byte = bit_array_one[index] & bit_array_two[index];
        while (byte != 0U) {
            byte &= byte - 1U;
            ++count;
        }
    }
    return count;
}

int convert_hex_binary(const char *hex_string, BLOOMFILTER *bf)
{
    size_t index;

    if (hex_string == NULL || bf == NULL ||
        strlen(hex_string) != FILTERSIZE * 2U) {
        return MRSH_ERR_FORMAT;
    }

    for (index = 0U; index < FILTERSIZE; ++index) {
        int high = hex_nibble(hex_string[index * 2U]);
        int low = hex_nibble(hex_string[index * 2U + 1U]);
        if (high < 0 || low < 0) {
            memset(bf->array, 0, sizeof(bf->array));
            return MRSH_ERR_FORMAT;
        }
        bf->array[index] = (unsigned char)((unsigned int)high << 4U |
                                          (unsigned int)low);
    }
    return MRSH_OK;
}
