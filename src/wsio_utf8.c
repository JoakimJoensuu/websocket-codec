/*
 * Copyright 2026 Joakim Joensuu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Streaming UTF-8 validator for RFC 6455 text payloads. Fragment boundaries
 * may split a code point; only a rejected sequence or an unfinished sequence
 * at the end of a message is an error (RFC 6455 §5.6, §8.1).
 */

#include "wsio_utf8.h"

void wsio_utf8_init(wsio_utf8 *u)
{
    u->codep = 0;
    u->need = 0;
}

static int feed_byte(wsio_utf8 *u, uint8_t b)
{
    if (u->need == 0) {
        if (b <= 0x7Fu) {
            return 0;
        }
        if (b >= 0xC2u && b <= 0xDFu) {
            u->codep = (uint32_t)(b & 0x1Fu);
            u->need = 1;
            return 0;
        }
        if (b >= 0xE0u && b <= 0xEFu) {
            u->codep = (uint32_t)(b & 0x0Fu);
            u->need = 2;
            return 0;
        }
        if (b >= 0xF0u && b <= 0xF4u) {
            u->codep = (uint32_t)(b & 0x07u);
            u->need = 3;
            return 0;
        }
        return -1;
    }

    if ((b & 0xC0u) != 0x80u) {
        return -1;
    }

    /* Overlong / surrogate / out-of-range checks on the first continuation. */
    if (u->need == 2 && u->codep == 0x0u) {
        /* 3-byte sequence started with E0: second byte must be A0-BF. */
        if (b < 0xA0u) {
            return -1;
        }
    } else if (u->need == 2 && u->codep == 0xDu) {
        /* ED: second byte must be 80-9F (no UTF-16 surrogates). */
        if (b > 0x9Fu) {
            return -1;
        }
    } else if (u->need == 3 && u->codep == 0x0u) {
        /* F0: second byte must be 90-BF. */
        if (b < 0x90u) {
            return -1;
        }
    } else if (u->need == 3 && u->codep == 0x4u) {
        /* F4: second byte must be 80-8F (U+10FFFF max). */
        if (b > 0x8Fu) {
            return -1;
        }
    }

    u->codep = (u->codep << 6) | (uint32_t)(b & 0x3Fu);
    u->need--;
    return 0;
}

int wsio_utf8_feed(wsio_utf8 *u, const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (feed_byte(u, p[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

int wsio_utf8_finish(const wsio_utf8 *u)
{
    return u->need == 0 ? 0 : -1;
}
