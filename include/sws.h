#ifndef SWS_H
#define SWS_H

/**
 * @brief Sans-I/O WebSocket data framing (RFC 6455 §§5–7).
 *
 * No HTTP, TCP, or TLS. After the opening handshake, feed socket bytes in
 * and drain protocol bytes out.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SWS_VERSION_MAJOR 0
#define SWS_VERSION_MINOR 1
#define SWS_VERSION_PATCH 0

/** @brief Clients mask every outgoing frame; servers must not (RFC 6455 §5.3). */
typedef enum {
    SWS_ROLE_CLIENT = 0,
    SWS_ROLE_SERVER = 1
} sws_role;

/**
 * @brief Peer or resource failures. Programming errors abort; there is no
 *        invalid-argument code.
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

/** @brief 1005/1006/1015 are never sent on the wire. */
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
 * @brief One completed inbound frame.
 *
 * Payload bytes are copied. A @c sws_result batch is valid until the next
 * sws_feed or sws_destroy; sws_queue_* does not invalidate it.
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

/**
 * @brief Set auto_pong and auto_close; zero the rest.
 *
 * Set @c role and @c max_message_size before sws_create_cfg.
 */
void sws_config_default(sws_config *cfg);

/**
 * @brief sws_config_default() plus @p role and @p max_message_size.
 * @param max_message_size Inbound assembled-message cap; must be > 0.
 * @return Heap session, or NULL on OOM.
 */
sws *sws_create(sws_role role, size_t max_message_size);

/**
 * @brief Create from @p cfg as given; does not apply sws_config_default.
 * @return Heap session, or NULL on OOM.
 */
sws *sws_create_cfg(const sws_config *cfg);

/**
 * @brief Parse @p src. Incomplete frames stay buffered.
 *
 * Each call replaces the previous batch, including @p len 0. On failure a
 * Close is queued when possible; drain it.
 * @return @c err and any completed events from this call.
 */
sws_result sws_feed(sws *ws, const uint8_t *src, size_t len);

/**
 * @brief One FIN text frame.
 * @param data Valid UTF-8.
 * @return #SWS_OK or #SWS_ERR_NOMEM.
 */
sws_err sws_queue_text(sws *ws, const uint8_t *data, size_t len);

/**
 * @brief One FIN binary frame; payload is not UTF-8-checked.
 * @return #SWS_OK or #SWS_ERR_NOMEM.
 */
sws_err sws_queue_bin(sws *ws, const uint8_t *data, size_t len);

/**
 * @param data At most 125 bytes.
 * @return #SWS_OK or #SWS_ERR_NOMEM.
 */
sws_err sws_queue_ping(sws *ws, const uint8_t *data, size_t len);

/**
 * @param data At most 125 bytes.
 * @return #SWS_OK or #SWS_ERR_NOMEM.
 */
sws_err sws_queue_pong(sws *ws, const uint8_t *data, size_t len);

/**
 * @param code 0 queues an empty payload. Otherwise a wire-legal code
 *             (#sws_close_code_valid).
 * @param reason Ignored if @p code is 0; at most 123 UTF-8 bytes.
 * @return #SWS_OK or #SWS_ERR_NOMEM.
 */
sws_err sws_queue_close(sws *ws, uint16_t code, const uint8_t *reason, size_t reason_len);

/**
 * @return True for 1000–1014 except 1004/1005/1006, and for 3000–4999.
 */
bool sws_close_code_valid(uint16_t code);

/**
 * @brief One frame. Fragment with TEXT/BIN @p fin 0, CONT…, then @p fin 1.
 * @param opcode Control frames must be fin and ≤125 bytes.
 * @param fin TEXT with fin requires valid UTF-8.
 * @return #SWS_OK or #SWS_ERR_NOMEM.
 */
sws_err sws_queue(sws *ws, sws_opcode opcode, const uint8_t *data, size_t len, bool fin);

/**
 * @brief View of the outbound buffer.
 * @param[out] len 0 if empty.
 * @return Pointer into the buffer, or NULL if empty.
 * @note Invalid after queue, mark_consumed, write, or destroy.
 */
const uint8_t *sws_peek(const sws *ws, size_t *len);

/**
 * @param n May be less than sws_pending (partial socket write).
 */
void sws_mark_consumed(sws *ws, size_t n);

/**
 * @brief Copy outbound bytes into @p dst and mark them consumed.
 * @return Bytes copied, @c min(pending, cap).
 */
size_t sws_write(sws *ws, uint8_t *dst, size_t cap);

/**
 * @return Outbound bytes still queued.
 */
size_t sws_pending(const sws *ws);

/**
 * @return True if Close has been queued or received.
 */
bool sws_closing(const sws *ws);

/**
 * @return True if Close has been queued and received.
 */
bool sws_closed(const sws *ws);

/**
 * @return Last peer or resource failure, sticky; #SWS_OK otherwise.
 */
sws_err sws_error(const sws *ws);

/**
 * @return Close code, or 1005 until a Close is queued or received.
 */
uint16_t sws_last_close(const sws *ws);

/**
 * @param ws May be NULL.
 */
void sws_destroy(sws *ws);

#endif /* SWS_H */
