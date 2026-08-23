#ifndef SWSC_H
#define SWSC_H

/**
 * @brief Sans-I/O WebSocket codec (RFC 6455 §§5–7).
 *
 * No HTTP, TCP, or TLS. After the opening handshake, feed bytes in
 * and send encoded frames out.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum : int {
  SWSC_VERSION_MAJOR = 0,
  SWSC_VERSION_MINOR = 1,
  SWSC_VERSION_PATCH = 0,
};

struct swsc;

/**
 * @brief Encoded wire bytes.
 *
 * @c data is nullptr and @c length is 0 when a helper fails. A successful
 * frame is never empty: it includes a header.
 */
struct swsc_bytes {
  const uint8_t *data;
  size_t length;
};

enum : uint8_t {
  SWSC_CTRL_MAX = 125, /**< 7-bit length and control payload max. */
  SWSC_CLOSE_CODE_LEN = 2,
  SWSC_REASON_MAX = SWSC_CTRL_MAX - SWSC_CLOSE_CODE_LEN,
};

/** @brief 1005/1006/1015 are never sent on the wire. */
enum swsc_close_code {
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
};

enum swsc_event_kind {
  SWSC_EV_TEXT = 1,
  SWSC_EV_BIN,
  SWSC_EV_PING,
  SWSC_EV_PONG,
  SWSC_EV_CLOSE,
  SWSC_EV_ERROR,
};

/**
 * @brief One completed inbound message or control frame.
 *
 * Payload bytes are copied. A @c struct swsc_result batch is valid until the
 * next swsc_feed or swsc_destroy. Encode helpers do not invalidate it.
 */
struct swsc_event {
  enum swsc_event_kind kind;
  const uint8_t *data;
  size_t length;
  uint16_t close_code; /**< SWSC_EV_CLOSE and SWSC_EV_ERROR. */
};

/**
 * @brief Peer or resource failures, and encode UTF-8 / OOM.
 */
enum swsc_err {
  SWSC_OK = 0,
  SWSC_ERR_NOMEM = -1,
  SWSC_ERR_PROTOCOL = -2,
  SWSC_ERR_UTF8 = -3,
  SWSC_ERR_CLOSED = -4, /**< Further input after Close. */
};

struct swsc_result {
  enum swsc_err err;
  const struct swsc_event *events;
  size_t events_cnt;
};

/**
 * @brief Encode result.
 *
 * @c bytes is empty unless @c err is #SWSC_OK. Invalid after the next encode
 * helper on the same session.
 */
struct swsc_enc {
  enum swsc_err err;
  struct swsc_bytes bytes;
};

/**
 * @param rng nullptr uses an internal PRNG (not a CSPRNG). Clients mask every
 *            outgoing frame.
 * @return Heap session, or nullptr on OOM.
 */
struct swsc *swsc_create_client(uint32_t (*rng)(void *ctx), void *rng_ctx);

/**
 * @brief Servers never mask.
 * @return Heap session, or nullptr on OOM.
 */
struct swsc *swsc_create_server();

/**
 * @param ws May be nullptr.
 */
void swsc_destroy(struct swsc *ws);

/**
 * @brief One FIN text frame.
 * @return #SWSC_ERR_UTF8 if @p data is not valid UTF-8; #SWSC_ERR_NOMEM on OOM.
 */
struct swsc_enc swsc_text_frame(struct swsc *ws, const uint8_t *data, size_t length);

/**
 * @brief One FIN binary frame; payload is not UTF-8-checked.
 */
struct swsc_enc swsc_bin_frame(struct swsc *ws, const uint8_t *data, size_t length);

/**
 * @param data At most #SWSC_CTRL_MAX bytes. Allowed between fragments.
 */
struct swsc_enc swsc_ping_frame(struct swsc *ws, const uint8_t *data, size_t length);

/**
 * @brief Unsolicited Pong. Answer inbound Ping with this helper.
 * @param data At most #SWSC_CTRL_MAX bytes. Allowed between fragments.
 */
struct swsc_enc swsc_pong_frame(struct swsc *ws, const uint8_t *data, size_t length);

/**
 * @brief Encode Close. Echo inbound Close with the event's code and reason.
 * @param code 0 or #SWSC_CLOSE_NO_STATUS encodes an empty payload. Otherwise a
 *             wire-legal code (#swsc_close_code_valid).
 * @param reason Ignored if the payload is empty; at most #SWSC_REASON_MAX UTF-8
 *               bytes.
 */
struct swsc_enc swsc_close_frame(struct swsc *ws, uint16_t code, const uint8_t *reason,
                                 size_t reason_len);

/**
 * @return True for 1000–1014 except 1004/1005/1006, and for 3000–4999.
 */
bool swsc_close_code_valid(uint16_t code);

/**
 * @brief FIN=0 text piece. First call starts a message; later calls continue it.
 *
 * A piece need not be valid UTF-8 by itself; #SWSC_ERR_UTF8 on an illegal
 * sequence.
 */
struct swsc_enc swsc_text_fragment(struct swsc *ws, const uint8_t *data, size_t length);

/**
 * @brief CONT + FIN=1; ends the text message started with swsc_text_fragment.
 *
 * #SWSC_ERR_UTF8 on an illegal or unfinished sequence.
 */
struct swsc_enc swsc_text_fragment_end(struct swsc *ws, const uint8_t *data, size_t length);

/**
 * @brief FIN=0 binary piece. First call starts a message; later calls continue it.
 */
struct swsc_enc swsc_bin_fragment(struct swsc *ws, const uint8_t *data, size_t length);

/**
 * @brief CONT + FIN=1; ends the binary message started with swsc_bin_fragment.
 */
struct swsc_enc swsc_bin_fragment_end(struct swsc *ws, const uint8_t *data, size_t length);

/**
 * @brief Parse @p src. Incomplete frames stay buffered.
 *
 * Each call replaces the previous batch, including @p length 0. Encode Pong,
 * Close echo, and fail Close with the helpers. Send those bytes before the next
 * swsc_feed if the peer must see them first.
 * @return @c err and completed events from this call.
 */
struct swsc_result swsc_feed(struct swsc *ws, const uint8_t *src, size_t length);

/**
 * @return True if Close has been sent or received.
 */
bool swsc_closing(const struct swsc *ws);

/**
 * @return True if Close has been sent and received.
 */
bool swsc_closed(const struct swsc *ws);

/**
 * @return Close code, or 1005 until a Close is sent or received.
 */
uint16_t swsc_last_close(const struct swsc *ws);

/**
 * @return Last peer or resource failure, sticky; #SWSC_OK otherwise.
 */
enum swsc_err swsc_error(const struct swsc *ws);

#endif /* SWSC_H */
