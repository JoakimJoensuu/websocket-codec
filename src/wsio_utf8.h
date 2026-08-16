#ifndef WSIO_UTF8_H
#define WSIO_UTF8_H

/**
 * @file wsio_utf8.h
 * @brief Streaming UTF-8 validator for RFC 6455 text payloads.
 *
 * A code point may be split across frames. Only a rejected sequence, or an
 * unfinished sequence at the end of a message, is an error.
 */

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Incremental UTF-8 decoder state.
 */
typedef struct wsio_utf8 {
    uint32_t codep; /**< Code point being assembled. */
    int need;       /**< Remaining continuation bytes; 0 if idle. */
} wsio_utf8;

/**
 * @brief Reset @p u to the start of a stream.
 */
void wsio_utf8_init(wsio_utf8 *u);

/**
 * @brief Consume @p n bytes.
 *
 * @return 0 if still valid (including an incomplete sequence at the end of
 *         this chunk), -1 on reject.
 */
int wsio_utf8_feed(wsio_utf8 *u, const uint8_t *p, size_t n);

/**
 * @brief Require a complete code point (end of message).
 *
 * @return 0 if idle, -1 if a sequence is unfinished.
 */
int wsio_utf8_finish(const wsio_utf8 *u);

#endif
