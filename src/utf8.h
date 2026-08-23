#ifndef UTF8_H
#define UTF8_H

/**
 * Incremental well-formed UTF-8 (RFC 3629 §3) for RFC 6455 text. A code
 * point may split across frames; incomplete is OK until the message ends.
 */

#include <stddef.h>
#include <stdint.h>

typedef struct utf8 {
  int need; /**< Remaining octets after the first; 0 if idle. */
  uint8_t next_min;
  uint8_t next_max;
} utf8;

void utf8_init(utf8 *state);

/** 0 if still valid (including an incomplete sequence), -1 on reject. */
int utf8_feed(utf8 *state, const uint8_t *src, size_t len);

/** 0 if idle, -1 if a sequence is unfinished. */
int utf8_finish(const utf8 *state);

#endif
