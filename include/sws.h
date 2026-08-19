#ifndef SWS_H
#define SWS_H

/**
 * @brief Sans-I/O WebSocket data framing (RFC 6455 §§5–7).
 *
 * No HTTP, TCP, or TLS. After the opening handshake, feed socket bytes in
 * and send the returned frames out.
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
    SWS_ERR_CLOSED = -4 /**< Further input after Close. */
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
    SWS_EV_PING,
    SWS_EV_PONG,
    SWS_EV_CLOSE,
    SWS_EV_ERROR /**< A Close frame is usually in sws_result.out. */
} sws_event_kind;

/**
 * @brief Encoded wire bytes.
 *
 * @c p is NULL and @c n is 0 when there is nothing to send, or when a frame
 * helper fails (OOM). A successful frame is never empty: it includes a header.
 */
typedef struct sws_bytes {
    const uint8_t *p;
    size_t n;
} sws_bytes;

/**
 * @brief One completed inbound message or control frame.
 *
 * Payload bytes are copied. A @c sws_result batch (events and @c out) is valid
 * until the next sws_feed or sws_destroy. Frame helpers do not invalidate it.
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
    sws_bytes out; /**< Pong, Close echo, and fail Close from this parse. */
} sws_result;

typedef struct sws_config {
    sws_role role;
    uint32_t (*rng)(void *ctx); /**< NULL uses an internal PRNG (not a CSPRNG). */
    void *rng_ctx;
} sws_config;

typedef struct sws sws;

/**
 * @brief Zero the struct. Set @c role before sws_create_cfg.
 */
void sws_config_default(sws_config *cfg);

/**
 * @return Heap session, or NULL on OOM.
 */
sws *sws_create(sws_role role);

/**
 * @brief Create from @p cfg as given; does not apply sws_config_default.
 * @return Heap session, or NULL on OOM.
 */
sws *sws_create_cfg(const sws_config *cfg);

/**
 * @brief Parse @p src. Incomplete frames stay buffered.
 *
 * Each call replaces the previous batch, including @p len 0. Ping is answered
 * with Pong, and an inbound Close is echoed, unless a Close was already sent.
 * On failure a Close is encoded when possible. Send @c out before the next
 * sws_feed.
 * @return @c err, completed events, and any reply frames from this call.
 */
sws_result sws_feed(sws *ws, const uint8_t *src, size_t len);

/**
 * @brief One FIN text frame. @p data must be valid UTF-8.
 * @return Encoded bytes, or empty on OOM. Invalid after the next frame helper
 *         on @p ws.
 */
sws_bytes sws_text_frame(sws *ws, const uint8_t *data, size_t len);

/**
 * @brief One FIN binary frame; payload is not UTF-8-checked.
 * @return Encoded bytes, or empty on OOM. Invalid after the next frame helper
 *         on @p ws.
 */
sws_bytes sws_bin_frame(sws *ws, const uint8_t *data, size_t len);

/**
 * @param data At most 125 bytes. Allowed between fragments.
 * @return Encoded bytes, or empty on OOM. Invalid after the next frame helper
 *         on @p ws.
 */
sws_bytes sws_ping_frame(sws *ws, const uint8_t *data, size_t len);

/**
 * @brief Unsolicited Pong. Inbound Ping is already answered in sws_feed @c out.
 * @param data At most 125 bytes. Allowed between fragments.
 * @return Encoded bytes, or empty on OOM. Invalid after the next frame helper
 *         on @p ws.
 */
sws_bytes sws_pong_frame(sws *ws, const uint8_t *data, size_t len);

/**
 * @brief Initiate Close. Inbound Close is already echoed in sws_feed @c out.
 * @param code 0 encodes an empty payload. Otherwise a wire-legal code
 *             (#sws_close_code_valid).
 * @param reason Ignored if @p code is 0; at most 123 UTF-8 bytes.
 * @return Encoded bytes, or empty on OOM. Invalid after the next frame helper
 *         on @p ws.
 */
sws_bytes sws_close_frame(sws *ws, uint16_t code, const uint8_t *reason,
                          size_t reason_len);

/**
 * @brief FIN=0 piece of a message.
 *
 * First piece: #SWS_OP_TEXT or #SWS_OP_BIN. Later pieces: #SWS_OP_CONT.
 * A fragment need not be valid UTF-8 by itself.
 * @return Encoded bytes, or empty on OOM. Invalid after the next frame helper
 *         on @p ws.
 */
sws_bytes sws_fragment(sws *ws, sws_opcode opcode, const uint8_t *data, size_t len);

/**
 * @brief CONT + FIN=1; ends the message started with sws_fragment.
 * @return Encoded bytes, or empty on OOM. Invalid after the next frame helper
 *         on @p ws.
 */
sws_bytes sws_fragment_end(sws *ws, const uint8_t *data, size_t len);

/**
 * @return True for 1000–1014 except 1004/1005/1006, and for 3000–4999.
 */
bool sws_close_code_valid(uint16_t code);

/**
 * @return True if Close has been sent or received.
 */
bool sws_closing(const sws *ws);

/**
 * @return True if Close has been sent and received.
 */
bool sws_closed(const sws *ws);

/**
 * @return Last peer or resource failure, sticky; #SWS_OK otherwise.
 */
sws_err sws_error(const sws *ws);

/**
 * @return Close code, or 1005 until a Close is sent or received.
 */
uint16_t sws_last_close(const sws *ws);

/**
 * @param ws May be NULL.
 */
void sws_destroy(sws *ws);

#endif /* SWS_H */
