#include "rng.h"

#include <stdint.h>

enum : unsigned {
  RNG_SHIFT_A = 13,
  RNG_SHIFT_B = 17,
  RNG_SHIFT_C = 5,
};

enum : uint32_t { RNG_ZERO_ESCAPE = 0xA5A5A5A5U };

uint32_t rng_next(void *ctx) {
  uint32_t *state = (uint32_t *)ctx;
  uint32_t value = *state;
  value ^= value << RNG_SHIFT_A;
  value ^= value >> RNG_SHIFT_B;
  value ^= value << RNG_SHIFT_C;
  if (value == 0) {
    value = RNG_ZERO_ESCAPE;
  }
  *state = value;
  return value;
}
