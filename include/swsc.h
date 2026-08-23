#ifndef SWSC_H
#define SWSC_H

/**
 * @brief Sans-I/O WebSocket codec (RFC 6455 §§5–7).
 *
 * No HTTP, TCP, or TLS. After the opening handshake, feed socket bytes in
 * and send the returned frames out.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum : int {
  SWSC_VERSION_MAJOR = 0,
  SWSC_VERSION_MINOR = 1,
  SWSC_VERSION_PATCH = 0,
};

enum : uint8_t {
  SWSC_CTRL_MAX = 125, /**< 7-bit length and control payload max. */
  SWSC_CLOSE_CODE_LEN = 2,
  SWSC_REASON_MAX = SWSC_CTRL_MAX - SWSC_CLOSE_CODE_LEN,
};

/**
 * @brief Peer or resource failures. Programming errors abort; there is no
 *        invalid-argument code.
 */
typedef enum {
  SWSC_OK = 0,
  SWSC_ERR_NOMEM = -1,
  SWSC_ERR_PROTOCOL = -2,
  SWSC_ERR_UTF8 = -3,
  SWSC_ERR_CLOSED = -4, /**< Further input after Close. */
} swsc_err;

typedef enum : unsigned {
  SWSC_OP_CONT = 0x0,
  SWSC_OP_TEXT = 0x1,
  SWSC_OP_BIN = 0x2,
  SWSC_OP_CLOSE = 0x8,
  SWSC_OP_PING = 0x9,
  SWSC_OP_PONG = 0xA,
} swsc_opcode;

/** @brief 1005/1006/1015 are never sent on the wire. */
typedef enum {
  SWSC_CLOSE_NORMAL = 1000,
  SWSC_CLOSE_GOING_AWAY = 1001,
  SWSC_CLOSE_PROTOCOL = 1002,
  SWSC_CLOSE_UNSUPPORTED = 1003,
  SWSC_CLOSE_NO_STATUS = 1005,
  SWSC_CLOSE_ABNORMAL = 1006,
  SWSC_CLOSE_INVALID_DATA = 1007,
  SWSC_CLOSE_POLICY = 1008,
  SWSC_CLOSE_TOO_BIG = 1009,
  SWSC_CLOSE_MANDATORY_EXT = 1010,
  SWSC_CLOSE_INTERNAL = 1011,
} swsc_close_code;

typedef enum {
  SWSC_EV_NONE = 0,
  SWSC_EV_TEXT,
  SWSC_EV_BIN,
  SWSC_EV_PING,
  SWSC_EV_PONG,
  SWSC_EV_CLOSE,
  SWSC_EV_ERROR, /**< A Close frame is usually in swsc_result.out. */
} swsc_event_kind;

/**
 * @brief Encoded wire bytes.
 *
 * @c p is nullptr and @c n is 0 when there is nothing to send, or when a frame
 * helper fails (OOM). A successful frame is never empty: it includes a header.
 */
typedef struct swsc_bytes {
  const uint8_t *p;
  size_t n;
} swsc_bytes;

/**
 * @brief One completed inbound message or control frame.
 *
 * Payload bytes are copied. A @c swsc_result batch (events and @c out) is valid
 * until the next swsc_feed or swsc_destroy. Frame helpers do not invalidate it.
 */
typedef struct swsc_event {
  swsc_event_kind kind;
  const uint8_t *data;
  size_t len;
  uint16_t close_code; /**< SWSC_EV_CLOSE and SWSC_EV_ERROR. */
} swsc_event;

typedef struct swsc_result {
  swsc_err err;
  const swsc_event *evs;
  size_t n;
  swsc_bytes out; /**< Pong, Close echo, and fail Close from this parse. */
} swsc_result;

typedef struct swsc swsc;

/**
 * @param rng nullptr uses an internal PRNG (not a CSPRNG). Clients mask every
 *            outgoing frame.
 * @return Heap session, or nullptr on OOM.
 */
swsc *swsc_create_client(uint32_t (*rng)(void *ctx), void *rng_ctx);

/**
 * @brief Servers never mask.
 * @return Heap session, or nullptr on OOM.
 */
swsc *swsc_create_server();

/**
 * @brief Parse @p src. Incomplete frames stay buffered.
 *
 * Each call replaces the previous batch, including @p len 0. Ping is answered
 * with Pong, and an inbound Close is echoed, unless a Close was already sent.
 * On failure a Close is encoded when possible. Send @c out before the next
 * swsc_feed.
 * @return @c err, completed events, and any reply frames from this call.
 */
swsc_result swsc_feed(swsc *ws, const uint8_t *src, size_t len);

/**
 * @brief One FIN text frame. @p data must be valid UTF-8.
 * @return Encoded bytes, or empty on OOM. Invalid after the next frame helper
 *         on @p ws.
 */
swsc_bytes swsc_text_frame(swsc *ws, const uint8_t *data, size_t len);

/**
 * @brief One FIN binary frame; payload is not UTF-8-checked.
 * @return Encoded bytes, or empty on OOM. Invalid after the next frame helper
 *         on @p ws.
 */
swsc_bytes swsc_bin_frame(swsc *ws, const uint8_t *data, size_t len);

/**
 * @param data At most #SWSC_CTRL_MAX bytes. Allowed between fragments.
 * @return Encoded bytes, or empty on OOM. Invalid after the next frame helper
 *         on @p ws.
 */
swsc_bytes swsc_ping_frame(swsc *ws, const uint8_t *data, size_t len);

/**
 * @brief Unsolicited Pong. Inbound Ping is already answered in swsc_feed @c
 * out.
 * @param data At most #SWSC_CTRL_MAX bytes. Allowed between fragments.
 * @return Encoded bytes, or empty on OOM. Invalid after the next frame helper
 *         on @p ws.
 */
swsc_bytes swsc_pong_frame(swsc *ws, const uint8_t *data, size_t len);

/**
 * @brief Initiate Close. Inbound Close is already echoed in swsc_feed @c out.
 * @param code 0 encodes an empty payload. Otherwise a wire-legal code
 *             (#swsc_close_code_valid).
 * @param reason Ignored if @p code is 0; at most #SWSC_REASON_MAX UTF-8 bytes.
 * @return Encoded bytes, or empty on OOM. Invalid after the next frame helper
 *         on @p ws.
 */
swsc_bytes swsc_close_frame(swsc *ws, uint16_t code, const uint8_t *reason,
                            size_t reason_len);

/**
 * @brief FIN=0 piece of a message.
 *
 * First piece: #SWSC_OP_TEXT or #SWSC_OP_BIN. Later pieces: #SWSC_OP_CONT.
 * A text fragment need not be valid UTF-8 by itself; illegal sequences abort.
 * Binary is not UTF-8-checked.
 * @return Encoded bytes, or empty on OOM. Invalid after the next frame helper
 *         on @p ws.
 */
swsc_bytes swsc_fragment(swsc *ws, swsc_opcode opcode, const uint8_t *data,
                         size_t len);

/**
 * @brief CONT + FIN=1; ends the message started with swsc_fragment.
 *
 * An unfinished UTF-8 sequence on a text message aborts.
 * @return Encoded bytes, or empty on OOM. Invalid after the next frame helper
 *         on @p ws.
 */
swsc_bytes swsc_fragment_end(swsc *ws, const uint8_t *data, size_t len);

/**
 * @return True for 1000–1014 except 1004/1005/1006, and for 3000–4999.
 */
bool swsc_close_code_valid(uint16_t code);

/**
 * @return True if Close has been sent or received.
 */
bool swsc_closing(const swsc *ws);

/**
 * @return True if Close has been sent and received.
 */
bool swsc_closed(const swsc *ws);

/**
 * @return Last peer or resource failure, sticky; #SWSC_OK otherwise.
 */
swsc_err swsc_error(const swsc *ws);

/**
 * @return Close code, or 1005 until a Close is sent or received.
 */
uint16_t swsc_last_close(const swsc *ws);

/**
 * @param ws May be nullptr.
 */
void swsc_destroy(swsc *ws);

#endif /* SWSC_H */
