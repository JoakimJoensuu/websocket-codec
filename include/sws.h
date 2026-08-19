#ifndef SWS_H
#define SWS_H

/**
 * Sans-I/O WebSocket data framing (RFC 6455 §§5–7). No HTTP, TCP, or TLS.
 * After the opening handshake, feed socket bytes in and drain protocol bytes out.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SWS_VERSION_MAJOR 0
#define SWS_VERSION_MINOR 1
#define SWS_VERSION_PATCH 0

/** Clients mask every outgoing frame; servers must not (RFC 6455 §5.3). */
typedef enum {
    SWS_ROLE_CLIENT = 0,
    SWS_ROLE_SERVER = 1
} sws_role;

/**
 * Programming errors abort; there is no invalid-argument code.
 * Negative values are peer or resource failures.
 */
typedef enum {
    SWS_OK = 0,
    SWS_ERR_NOMEM = -1,
    SWS_ERR_PROTOCOL = -2,
    SWS_ERR_UTF8 = -3,
    SWS_ERR_TOO_BIG = -4,
    SWS_ERR_CLOSED = -5 /**< Further input after Close. */
} sws_err;

typedef enum {
    SWS_OP_CONT = 0x0,
    SWS_OP_TEXT = 0x1,
    SWS_OP_BIN = 0x2,
    SWS_OP_CLOSE = 0x8,
    SWS_OP_PING = 0x9,
    SWS_OP_PONG = 0xA
} sws_opcode;

/** 1005/1006/1015 are never sent on the wire. */
typedef enum {
    SWS_CLOSE_NORMAL = 1000,
    SWS_CLOSE_GOING_AWAY = 1001,
    SWS_CLOSE_PROTOCOL = 1002,
    SWS_CLOSE_UNSUPPORTED = 1003,
    SWS_CLOSE_NO_STATUS = 1005,
    SWS_CLOSE_ABNORMAL = 1006,
    SWS_CLOSE_INVALID_DATA = 1007,
    SWS_CLOSE_POLICY = 1008,
    SWS_CLOSE_TOO_BIG = 1009,
    SWS_CLOSE_MANDATORY_EXT = 1010,
    SWS_CLOSE_INTERNAL = 1011
} sws_close_code;

typedef enum {
    SWS_EV_NONE = 0,
    SWS_EV_TEXT,
    SWS_EV_BIN,
    SWS_EV_PING, /**< Auto-pong may already be queued. */
    SWS_EV_PONG,
    SWS_EV_CLOSE,
    SWS_EV_ERROR /**< A Close frame is usually queued. */
} sws_event_kind;

/**
 * Payload bytes are copied. A sws_result batch is valid until the next
 * sws_feed or sws_destroy; send does not invalidate it.
 */
typedef struct sws_event {
    sws_event_kind kind;
    const uint8_t *data;
    size_t len;
    uint16_t close_code; /**< SWS_EV_CLOSE and SWS_EV_ERROR. */
} sws_event;

typedef struct sws_result {
    sws_err err;
    const sws_event *evs;
    size_t n;
} sws_result;

typedef struct sws_config {
    sws_role role;
    size_t max_message_size;    /**< Inbound assembled-message cap. Must be > 0. */
    bool auto_pong;
    bool auto_close;
    uint32_t (*rng)(void *ctx); /**< NULL uses an internal PRNG (not a CSPRNG). */
    void *rng_ctx;
} sws_config;

typedef struct sws sws;

/** auto_pong and auto_close on. Set role and max_message_size before create_cfg. */
void sws_config_default(sws_config *cfg);

/** sws_config_default() plus @p role and @p max_message_size. NULL on OOM. */
sws *sws_create(sws_role role, size_t max_message_size);

/** NULL on OOM. Does not apply sws_config_default. */
sws *sws_create_cfg(const sws_config *cfg);

/** @p ws may be NULL. */
void sws_destroy(sws *ws);

/**
 * Incomplete frames stay buffered. Each call replaces the previous batch
 * (including @p len 0). On failure a Close is queued when possible; drain it.
 */
sws_result sws_feed(sws *ws, const uint8_t *src, size_t len);

/** Outbound bytes not yet consumed. */
size_t sws_pending(const sws *ws);

/**
 * Pointer into the outbound buffer; empty yields NULL and *@p len == 0.
 * Invalid after send, consume, write, or destroy.
 */
const uint8_t *sws_peek(const sws *ws, size_t *len);

/** @p n may be less than sws_pending (partial socket write). */
void sws_consume(sws *ws, size_t n);

/** Copy min(pending, @p cap) into @p dst and consume that many. */
size_t sws_write(sws *ws, uint8_t *dst, size_t cap);

/**
 * Fragment with TEXT/BIN fin=0, CONT…, then fin=1. TEXT with fin must be
 * valid UTF-8. Control frames must be fin and ≤125 bytes.
 */
sws_err sws_send(sws *ws, sws_opcode opcode, const uint8_t *data, size_t len, bool fin);

/** One FIN frame; payload UTF-8. */
sws_err sws_send_text(sws *ws, const uint8_t *data, size_t len);

/** One FIN frame; payload unchecked. */
sws_err sws_send_bin(sws *ws, const uint8_t *data, size_t len);

/** ≤125 bytes. */
sws_err sws_send_ping(sws *ws, const uint8_t *data, size_t len);

/** ≤125 bytes. */
sws_err sws_send_pong(sws *ws, const uint8_t *data, size_t len);

/**
 * @p code 0 is an empty Close. Otherwise a wire-legal code; @p reason at
 * most 123 UTF-8 bytes and ignored when @p code is 0.
 */
sws_err sws_send_close(sws *ws, uint16_t code, const uint8_t *reason, size_t reason_len);

/** Close sent or received. */
bool sws_closing(const sws *ws);

/** Close sent and received. */
bool sws_closed(const sws *ws);

/** Sticky after a peer or resource failure. */
sws_err sws_error(const sws *ws);

/** 1005 until a Close is sent or received. */
uint16_t sws_last_close(const sws *ws);

/** 1000–1014 except 1004/1005/1006, and 3000–4999. */
bool sws_close_code_valid(uint16_t code);

#endif /* SWS_H */
