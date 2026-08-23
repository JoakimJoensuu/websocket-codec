#include "utf8.h"

#include <stddef.h>
#include <stdint.h>

enum : uint8_t {
  UTF8_ASCII_MAX = 0x7F,
  UTF8_LEAD2_MASK = 0x1F,
  UTF8_LEAD3_MASK = 0x0F,
  UTF8_LEAD4_MASK = 0x07,
  UTF8_CONT_HI = 0xC0,
  UTF8_CONT_TAG = 0x80,
  UTF8_CONT_MASK = 0x3F,
};

enum : unsigned { UTF8_CONT_BITS = 6 };

void utf8_init(utf8 *state) {
  state->codep = 0;
  state->need = 0;
}

static int feed_byte(utf8 *state, unsigned byte) {
  if (state->need == 0) {
    if (byte <= UTF8_ASCII_MAX) {
      return 0;
    }
    if (byte >= 0xC2U && byte <= 0xDFU) {
      state->codep = (uint32_t)(byte & UTF8_LEAD2_MASK);
      state->need = 1;
      return 0;
    }
    if (byte >= 0xE0U && byte <= 0xEFU) {
      state->codep = (uint32_t)(byte & UTF8_LEAD3_MASK);
      state->need = 2;
      return 0;
    }
    if (byte >= 0xF0U && byte <= 0xF4U) {
      state->codep = (uint32_t)(byte & UTF8_LEAD4_MASK);
      state->need = 3;
      return 0;
    }
    return -1;
  }

  if ((byte & UTF8_CONT_HI) != UTF8_CONT_TAG) {
    return -1;
  }

  /* Overlong / surrogate / out-of-range checks on the first continuation. */
  if (state->need == 2 && state->codep == 0x0U) {
    /* 3-byte sequence started with E0: second byte must be A0-BF. */
    if (byte < 0xA0U) {
      return -1;
    }
  } else if (state->need == 2 && state->codep == 0xDU) {
    /* ED: second byte must be 80-9F (no UTF-16 surrogates). */
    if (byte > 0x9FU) {
      return -1;
    }
  } else if (state->need == 3 && state->codep == 0x0U) {
    /* F0: second byte must be 90-BF. */
    if (byte < 0x90U) {
      return -1;
    }
  } else if (state->need == 3 && state->codep == 0x4U) {
    /* F4: second byte must be 80-8F (U+10FFFF max). */
    if (byte > 0x8FU) {
      return -1;
    }
  }

  state->codep =
      (state->codep << UTF8_CONT_BITS) | (uint32_t)(byte & UTF8_CONT_MASK);
  state->need--;
  return 0;
}

int utf8_feed(utf8 *state, const uint8_t *src, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (feed_byte(state, src[i]) != 0) {
      return -1;
    }
  }
  return 0;
}

int utf8_finish(const utf8 *state) { return state->need == 0 ? 0 : -1; }
