#ifndef MRSH_HASHING_H
#define MRSH_HASHING_H

#include <stddef.h>
#include <stdio.h>

#include "config.h"
#include "fingerprint.h"

uint32 roll_hashx(unsigned char c, uchar window[ROLLING_WINDOW],
                  uint32 rh_data[4]);
uint32 djb2x(unsigned char c, uchar window[ROLLING_WINDOW], size_t n);

int hashFileToFingerprint(FINGERPRINT *fingerprint, FILE *handle);
/* Hash a borrowed regular descriptor with pread(); ownership and offset stay
 * with the caller. */
int hashFileDescriptorToFingerprint(FINGERPRINT *fingerprint, int descriptor);
int hashPacketBuffer(FINGERPRINT *fingerprint, const unsigned char *packet,
                     size_t length);

#endif /* MRSH_HASHING_H */
