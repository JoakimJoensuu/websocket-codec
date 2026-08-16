/*
 * Copyright 2026 Joakim Joensuu
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef WSIO_UTF8_H
#define WSIO_UTF8_H

#include <stddef.h>
#include <stdint.h>

typedef struct wsio_utf8 {
    uint32_t codep;
    int need; /* remaining continuation bytes */
} wsio_utf8;

void wsio_utf8_init(wsio_utf8 *u);

/* Returns 0 while valid, -1 on reject. Incomplete sequences are OK
 * until wsio_utf8_finish(). */
int wsio_utf8_feed(wsio_utf8 *u, const uint8_t *p, size_t n);
int wsio_utf8_finish(const wsio_utf8 *u);

#endif
