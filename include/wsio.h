#ifndef WSIO_H
#define WSIO_H

/**
 * Sans-I/O WebSocket data framing (RFC 6455 §§5–7). No HTTP, TCP, or TLS.
 * After the opening handshake, feed socket bytes in and drain protocol bytes out.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WSIO_VERSION_MAJOR 0
#define WSIO_VERSION_MINOR 1
#define WSIO_VERSION_PATCH 0

/** Clients mask every outgoing frame; servers must not (RFC 6455 §5.3). */
typedef enum {
    WSIO_ROLE_CLIENT = 0,
    WSIO_ROLE_SERVER = 1
} wsio_role;

/**
 * Programming errors abort; there is no invalid-argument code.
 * Negative values are peer or resource failures.
 */
typedef enum {
    WSIO_OK = 0,
    WSIO_ERR_NOMEM = -1,
    WSIO_ERR_PROTOCOL = -2,
    WSIO_ERR_UTF8 = -3,
    WSIO_ERR_TOO_BIG = -4,
    WSIO_ERR_CLOSED = -5 /**< Further input after Close. */
} wsio_err;

typedef enum {
    WSIO_OP_CONT = 0x0,
    WSIO_OP_TEXT = 0x1,
    WSIO_OP_BIN = 0x2,
    WSIO_OP_CLOSE = 0x8,
    WSIO_OP_PING = 0x9,
    WSIO_OP_PONG = 0xA
} wsio_opcode;

/** 1005/1006/1015 are never sent on the wire. */
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
    WSIO_EV_PING, /**< Auto-pong may already be queued. */
    WSIO_EV_PONG,
    WSIO_EV_CLOSE,
    WSIO_EV_ERROR /**< A Close frame is usually queued. */
} wsio_event_kind;

/** @p data is valid until the next wsio_feed, wsio_poll, wsio_send*, or wsio_destroy. */
typedef struct wsio_event {
    wsio_event_kind kind;
    const uint8_t *data;
    size_t len;
    uint16_t close_code; /**< WSIO_EV_CLOSE and WSIO_EV_ERROR. */
} wsio_event;

typedef struct wsio_config {
    wsio_role role;
    size_t max_message_size;    /**< 0 means 16 MiB. */
    bool auto_pong;
    bool auto_close;
    uint32_t (*rng)(void *ctx); /**< NULL uses an internal PRNG (not a CSPRNG). */
    void *rng_ctx;
} wsio_config;

typedef struct wsio wsio;

wsio *wsio_create(wsio_role role);

/** Unlike wsio_create, auto_pong / auto_close are used as given (false = off). */
wsio *wsio_create_cfg(const wsio_config *cfg);

/** NULL is allowed. */
void wsio_destroy(wsio *ws);

/**
 * Unparsed tail is copied internally. After a protocol failure a Close is
 * queued when possible; still drain output.
 */
int wsio_feed(wsio *ws, const uint8_t *src, size_t len);

size_t wsio_pending(const wsio *ws);

const uint8_t *wsio_peek(const wsio *ws, size_t *len);

void wsio_consume(wsio *ws, size_t n);

size_t wsio_write(wsio *ws, uint8_t *dst, size_t cap);

wsio_event wsio_poll(wsio *ws);

/** Text with @p fin set must be valid UTF-8. Use this for explicit fragmentation. */
int wsio_send(wsio *ws, wsio_opcode opcode, const uint8_t *data, size_t len, bool fin);

int wsio_send_text(wsio *ws, const uint8_t *data, size_t len);

int wsio_send_bin(wsio *ws, const uint8_t *data, size_t len);

int wsio_send_ping(wsio *ws, const uint8_t *data, size_t len);

int wsio_send_pong(wsio *ws, const uint8_t *data, size_t len);

/**
 * @p code 0 sends an empty payload. Otherwise it must be allowed on the wire
 * (@ref wsio_close_code_valid). @p reason is ignored if @p code is 0; at most
 * 123 bytes.
 */
int wsio_send_close(wsio *ws, uint16_t code, const uint8_t *reason, size_t reason_len);

bool wsio_closing(const wsio *ws);

bool wsio_closed(const wsio *ws);

wsio_err wsio_error(const wsio *ws);

uint16_t wsio_last_close(const wsio *ws);

/** True for 1000–1014 except 1004/1005/1006, and for 3000–4999. */
bool wsio_close_code_valid(uint16_t code);

#ifdef __cplusplus
}
#endif

#endif /* WSIO_H */
