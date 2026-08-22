#ifndef SWSF_H
#define SWSF_H

/**
 * @brief Sans-I/O WebSocket framer (RFC 6455 §§5–7).
 *
 * No HTTP, TCP, or TLS. After the opening handshake, feed socket bytes in
 * and send the returned frames out.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SWSF_VERSION_MAJOR 0
#define SWSF_VERSION_MINOR 1
#define SWSF_VERSION_PATCH 0

/**
 * @brief Peer or resource failures. Programming errors abort; there is no
 *        invalid-argument code.
 */
typedef enum {
    SWSF_OK = 0,
    SWSF_ERR_NOMEM = -1,
    SWSF_ERR_PROTOCOL = -2,
    SWSF_ERR_UTF8 = -3,
    SWSF_ERR_CLOSED = -4 /**< Further input after Close. */
} swsf_err;

typedef enum {
    SWSF_OP_CONT = 0x0,
    SWSF_OP_TEXT = 0x1,
    SWSF_OP_BIN = 0x2,
    SWSF_OP_CLOSE = 0x8,
    SWSF_OP_PING = 0x9,
    SWSF_OP_PONG = 0xA
} swsf_opcode;

/** @brief 1005/1006/1015 are never sent on the wire. */
typedef enum {
    SWSF_CLOSE_NORMAL = 1000,
    SWSF_CLOSE_GOING_AWAY = 1001,
    SWSF_CLOSE_PROTOCOL = 1002,
    SWSF_CLOSE_UNSUPPORTED = 1003,
    SWSF_CLOSE_NO_STATUS = 1005,
    SWSF_CLOSE_ABNORMAL = 1006,
    SWSF_CLOSE_INVALID_DATA = 1007,
    SWSF_CLOSE_POLICY = 1008,
    SWSF_CLOSE_TOO_BIG = 1009,
    SWSF_CLOSE_MANDATORY_EXT = 1010,
    SWSF_CLOSE_INTERNAL = 1011
} swsf_close_code;

typedef enum {
    SWSF_EV_NONE = 0,
    SWSF_EV_TEXT,
    SWSF_EV_BIN,
    SWSF_EV_PING,
    SWSF_EV_PONG,
    SWSF_EV_CLOSE,
    SWSF_EV_ERROR /**< A Close frame is usually in swsf_result.out. */
} swsf_event_kind;

/**
 * @brief Encoded wire bytes.
 *
 * @c p is NULL and @c n is 0 when there is nothing to send, or when a frame
 * helper fails (OOM). A successful frame is never empty: it includes a header.
 */
typedef struct swsf_bytes {
    const uint8_t *p;
    size_t n;
} swsf_bytes;

/**
 * @brief One completed inbound message or control frame.
 *
 * Payload bytes are copied. A @c swsf_result batch (events and @c out) is valid
 * until the next swsf_feed or swsf_destroy. Frame helpers do not invalidate it.
 */
typedef struct swsf_event {
    swsf_event_kind kind;
    const uint8_t *data;
    size_t len;
    uint16_t close_code; /**< SWSF_EV_CLOSE and SWSF_EV_ERROR. */
} swsf_event;

typedef struct swsf_result {
    swsf_err err;
    const swsf_event *evs;
    size_t n;
    swsf_bytes out; /**< Pong, Close echo, and fail Close from this parse. */
} swsf_result;

typedef struct swsf swsf;

/**
 * @param rng NULL uses an internal PRNG (not a CSPRNG). Clients mask every
 *            outgoing frame.
 * @return Heap session, or NULL on OOM.
 */
swsf *swsf_create_client(uint32_t (*rng)(void *ctx), void *rng_ctx);

/**
 * @brief Servers never mask.
 * @return Heap session, or NULL on OOM.
 */
swsf *swsf_create_server(void);

/**
 * @brief Parse @p src. Incomplete frames stay buffered.
 *
 * Each call replaces the previous batch, including @p len 0. Ping is answered
 * with Pong, and an inbound Close is echoed, unless a Close was already sent.
 * On failure a Close is encoded when possible. Send @c out before the next
 * swsf_feed.
 * @return @c err, completed events, and any reply frames from this call.
 */
swsf_result swsf_feed(swsf *ws, const uint8_t *src, size_t len);

/**
 * @brief One FIN text frame. @p data must be valid UTF-8.
 * @return Encoded bytes, or empty on OOM. Invalid after the next frame helper
 *         on @p ws.
 */
swsf_bytes swsf_text_frame(swsf *ws, const uint8_t *data, size_t len);

/**
 * @brief One FIN binary frame; payload is not UTF-8-checked.
 * @return Encoded bytes, or empty on OOM. Invalid after the next frame helper
 *         on @p ws.
 */
swsf_bytes swsf_bin_frame(swsf *ws, const uint8_t *data, size_t len);

/**
 * @param data At most 125 bytes. Allowed between fragments.
 * @return Encoded bytes, or empty on OOM. Invalid after the next frame helper
 *         on @p ws.
 */
swsf_bytes swsf_ping_frame(swsf *ws, const uint8_t *data, size_t len);

/**
 * @brief Unsolicited Pong. Inbound Ping is already answered in swsf_feed @c out.
 * @param data At most 125 bytes. Allowed between fragments.
 * @return Encoded bytes, or empty on OOM. Invalid after the next frame helper
 *         on @p ws.
 */
swsf_bytes swsf_pong_frame(swsf *ws, const uint8_t *data, size_t len);

/**
 * @brief Initiate Close. Inbound Close is already echoed in swsf_feed @c out.
 * @param code 0 encodes an empty payload. Otherwise a wire-legal code
 *             (#swsf_close_code_valid).
 * @param reason Ignored if @p code is 0; at most 123 UTF-8 bytes.
 * @return Encoded bytes, or empty on OOM. Invalid after the next frame helper
 *         on @p ws.
 */
swsf_bytes swsf_close_frame(swsf *ws, uint16_t code, const uint8_t *reason,
                          size_t reason_len);

/**
 * @brief FIN=0 piece of a message.
 *
 * First piece: #SWSF_OP_TEXT or #SWSF_OP_BIN. Later pieces: #SWSF_OP_CONT.
 * A text fragment need not be valid UTF-8 by itself; illegal sequences abort.
 * Binary is not UTF-8-checked.
 * @return Encoded bytes, or empty on OOM. Invalid after the next frame helper
 *         on @p ws.
 */
swsf_bytes swsf_fragment(swsf *ws, swsf_opcode opcode, const uint8_t *data, size_t len);

/**
 * @brief CONT + FIN=1; ends the message started with swsf_fragment.
 *
 * An unfinished UTF-8 sequence on a text message aborts.
 * @return Encoded bytes, or empty on OOM. Invalid after the next frame helper
 *         on @p ws.
 */
swsf_bytes swsf_fragment_end(swsf *ws, const uint8_t *data, size_t len);

/**
 * @return True for 1000–1014 except 1004/1005/1006, and for 3000–4999.
 */
bool swsf_close_code_valid(uint16_t code);

/**
 * @return True if Close has been sent or received.
 */
bool swsf_closing(const swsf *ws);

/**
 * @return True if Close has been sent and received.
 */
bool swsf_closed(const swsf *ws);

/**
 * @return Last peer or resource failure, sticky; #SWSF_OK otherwise.
 */
swsf_err swsf_error(const swsf *ws);

/**
 * @return Close code, or 1005 until a Close is sent or received.
 */
uint16_t swsf_last_close(const swsf *ws);

/**
 * @param ws May be NULL.
 */
void swsf_destroy(swsf *ws);

#endif /* SWSF_H */
