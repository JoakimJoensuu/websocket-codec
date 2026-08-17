#ifndef SWS_UTF8_H
#define SWS_UTF8_H

/**
 * Incremental UTF-8 for RFC 6455 text. A code point may split across frames;
 * incomplete is OK until the message ends.
 */

#include <stddef.h>
#include <stdint.h>

typedef struct sws_utf8 {
    uint32_t codep;
    int need; /**< Remaining continuation bytes; 0 if idle. */
} sws_utf8;

void sws_utf8_init(sws_utf8 *u);

/** 0 if still valid (including an incomplete sequence), -1 on reject. */
int sws_utf8_feed(sws_utf8 *u, const uint8_t *p, size_t n);

/** 0 if idle, -1 if a sequence is unfinished. */
int sws_utf8_finish(const sws_utf8 *u);

#endif
