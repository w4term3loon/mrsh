#ifndef MRSH_BLOOMFILTER_H
#define MRSH_BLOOMFILTER_H

#include <stdint.h>

#include "config.h"

typedef struct BLOOMFILTER {
    unsigned char array[FILTERSIZE];
    uint32_t amount_of_blocks;
    struct BLOOMFILTER *next;
} BLOOMFILTER;

BLOOMFILTER *init_empty_BF(void);
void destroy_bf(BLOOMFILTER *bf);

int bloom_set_bit(unsigned char *bit_array, uint16_t value);
uint16_t count_bits_set_to_one_of_BF(const unsigned char *filter);
uint16_t bloom_common_bits(const unsigned char *bit_array_one,
                           const unsigned char *bit_array_two);

int add_hash_to_bloomfilter(BLOOMFILTER *bf, uint64 hash_value);
int convert_hex_binary(const char *hex_string, BLOOMFILTER *bf);

#endif /* MRSH_BLOOMFILTER_H */
