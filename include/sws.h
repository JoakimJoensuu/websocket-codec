#ifndef SWS_H
#define SWS_H

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

/** Inbound result of sws_feed. */
typedef struct sws_result {
    sws_err err;
    const sws_event *evs;
    size_t n;
} sws_result;

typedef struct sws_config {
    sws_role role;
    size_t max_message_size;    /**< 0 means 16 MiB. */
    bool auto_pong;
    bool auto_close;
    uint32_t (*rng)(void *ctx); /**< NULL uses an internal PRNG (not a CSPRNG). */
    void *rng_ctx;
} sws_config;

typedef struct sws sws;

sws *sws_create(sws_role role);

/** Unlike sws_create, auto_pong / auto_close are used as given (false = off). */
sws *sws_create_cfg(const sws_config *cfg);

/** NULL is allowed. */
void sws_destroy(sws *ws);

/**
 * Parse @p src. Completed frames are copied into the returned batch.
 * Unparsed tail is kept internally. After a protocol failure a Close is
 * queued when possible; still drain output.
 */
sws_result sws_feed(sws *ws, const uint8_t *src, size_t len);

size_t sws_pending(const sws *ws);

const uint8_t *sws_peek(const sws *ws, size_t *len);

void sws_consume(sws *ws, size_t n);

size_t sws_write(sws *ws, uint8_t *dst, size_t cap);

/** Text with @p fin set must be valid UTF-8. Use this for explicit fragmentation. */
int sws_send(sws *ws, sws_opcode opcode, const uint8_t *data, size_t len, bool fin);

int sws_send_text(sws *ws, const uint8_t *data, size_t len);

int sws_send_bin(sws *ws, const uint8_t *data, size_t len);

int sws_send_ping(sws *ws, const uint8_t *data, size_t len);

int sws_send_pong(sws *ws, const uint8_t *data, size_t len);

/**
 * @p code 0 sends an empty payload. Otherwise it must be allowed on the wire
 * (@ref sws_close_code_valid). @p reason is ignored if @p code is 0; at most
 * 123 bytes.
 */
int sws_send_close(sws *ws, uint16_t code, const uint8_t *reason, size_t reason_len);

bool sws_closing(const sws *ws);

bool sws_closed(const sws *ws);

sws_err sws_error(const sws *ws);

uint16_t sws_last_close(const sws *ws);

/** True for 1000–1014 except 1004/1005/1006, and for 3000–4999. */
bool sws_close_code_valid(uint16_t code);

#ifdef __cplusplus
}
#endif

#endif /* SWS_H */
