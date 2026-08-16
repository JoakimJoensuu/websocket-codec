/*
 * Copyright 2026 Joakim Joensuu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef WSIO_H
#define WSIO_H

/*
 * wsio: sans-I/O WebSocket data framing (RFC 6455 sections 5-7).
 *
 * This library does not speak HTTP, TCP, or TLS. The opening handshake
 * (RFC 6455 section 4) is the application's job. After the HTTP upgrade
 * succeeds, feed socket bytes in and drain protocol bytes out.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WSIO_VERSION_MAJOR 0
#define WSIO_VERSION_MINOR 1
#define WSIO_VERSION_PATCH 0

typedef enum {
    WSIO_ROLE_CLIENT = 0,
    WSIO_ROLE_SERVER = 1
} wsio_role;

typedef enum {
    WSIO_OK = 0,
    WSIO_ERR_NOMEM = -1,
    WSIO_ERR_PROTOCOL = -2,
    WSIO_ERR_UTF8 = -3,
    WSIO_ERR_TOO_BIG = -4,
    WSIO_ERR_CLOSED = -5,
    WSIO_ERR_INVAL = -6
} wsio_err;

typedef enum {
    WSIO_OP_CONT = 0x0,
    WSIO_OP_TEXT = 0x1,
    WSIO_OP_BIN = 0x2,
    WSIO_OP_CLOSE = 0x8,
    WSIO_OP_PING = 0x9,
    WSIO_OP_PONG = 0xA
} wsio_opcode;

typedef enum {
    WSIO_CLOSE_NORMAL = 1000,
    WSIO_CLOSE_GOING_AWAY = 1001,
    WSIO_CLOSE_PROTOCOL = 1002,
    WSIO_CLOSE_UNSUPPORTED = 1003,
    WSIO_CLOSE_NO_STATUS = 1005,
    WSIO_CLOSE_ABNORMAL = 1006,
    WSIO_CLOSE_INVALID_DATA = 1007,
    WSIO_CLOSE_POLICY = 1008,
    WSIO_CLOSE_TOO_BIG = 1009,
    WSIO_CLOSE_MANDATORY_EXT = 1010,
    WSIO_CLOSE_INTERNAL = 1011
} wsio_close_code;

typedef enum {
    WSIO_EV_NONE = 0,
    WSIO_EV_TEXT,
    WSIO_EV_BIN,
    WSIO_EV_PING,
    WSIO_EV_PONG,
    WSIO_EV_CLOSE,
    WSIO_EV_ERROR
} wsio_event_kind;

typedef struct wsio_event {
    wsio_event_kind kind;
    const uint8_t *data;
    size_t len;
    uint16_t close_code;
} wsio_event;

typedef struct wsio_config {
    wsio_role role;
    size_t max_message_size; /* 0 => 16 MiB */
    int auto_pong;           /* default 1: reply to ping with pong */
    int auto_close;          /* default 1: reply to close */
    uint32_t (*rng)(void *ctx); /* client masking; NULL => internal PRNG */
    void *rng_ctx;
} wsio_config;

typedef struct wsio wsio;

/* role-only constructor; other fields use defaults. */
wsio *wsio_create(wsio_role role);
wsio *wsio_create_cfg(const wsio_config *cfg);
void wsio_destroy(wsio *ws);

/*
 * Push bytes received from the peer. Always copies any unparsed tail
 * internally. Returns WSIO_OK, or a negative wsio_err after a protocol
 * failure (a Close frame is queued when possible — still drain output).
 */
int wsio_feed(wsio *ws, const uint8_t *src, size_t len);

/* Bytes that must be written to the peer. */
size_t wsio_pending(const wsio *ws);
const uint8_t *wsio_peek(const wsio *ws, size_t *len);
void wsio_consume(wsio *ws, size_t n);
size_t wsio_write(wsio *ws, uint8_t *dst, size_t cap);

/*
 * Next application event. Payload pointers remain valid until the next
 * wsio_feed / wsio_poll / wsio_send* / wsio_destroy call.
 */
wsio_event wsio_poll(wsio *ws);

int wsio_send(wsio *ws, wsio_opcode opcode, const uint8_t *data, size_t len, int fin);
int wsio_send_text(wsio *ws, const uint8_t *data, size_t len);
int wsio_send_bin(wsio *ws, const uint8_t *data, size_t len);
int wsio_send_ping(wsio *ws, const uint8_t *data, size_t len);
int wsio_send_pong(wsio *ws, const uint8_t *data, size_t len);

/* code == 0 sends an empty Close payload. */
int wsio_send_close(wsio *ws, uint16_t code, const uint8_t *reason, size_t reason_len);

int wsio_closing(const wsio *ws);
int wsio_closed(const wsio *ws);
wsio_err wsio_error(const wsio *ws);
uint16_t wsio_last_close(const wsio *ws);

/* RFC 6455 close-code registry check (codes that may appear on the wire). */
int wsio_close_code_valid(uint16_t code);

#ifdef __cplusplus
}
#endif

#endif /* WSIO_H */
