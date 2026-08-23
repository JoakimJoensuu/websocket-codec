#ifndef RNG_H
#define RNG_H

/**
 * Default mask PRNG (xorshift32). Not a CSPRNG.
 */

#include <stdint.h>

enum : uint32_t { RNG_SEED = 0xC0FFEEU };

uint32_t rng_next(void *ctx);

#endif
