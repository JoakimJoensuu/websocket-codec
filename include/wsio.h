#ifndef WSIO_H
#define WSIO_H

/**
 * @file wsio.h
 * @brief Sans-I/O WebSocket data framing (RFC 6455 sections 5–7).
 *
 * This library does not speak HTTP, TCP, or TLS. After the opening handshake
 * (RFC 6455 section 4), feed socket bytes in and drain protocol bytes out.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WSIO_VERSION_MAJOR 0
#define WSIO_VERSION_MINOR 1
#define WSIO_VERSION_PATCH 0

/**
 * @brief Masking role for this endpoint.
 *
 * Clients must mask every outgoing frame; servers must not (RFC 6455 §5.3).
 */
typedef enum {
    WSIO_ROLE_CLIENT = 0, /**< Outgoing frames are masked. */
    WSIO_ROLE_SERVER = 1  /**< Outgoing frames are unmasked. */
} wsio_role;

/**
 * @brief Library result codes.
 *
 * @c WSIO_OK is zero. All errors are negative. Programming errors abort
 * rather than returning a code; there is no invalid-argument error.
 */
typedef enum {
    WSIO_OK = 0,            /**< Success. */
    WSIO_ERR_NOMEM = -1,    /**< Allocation failed. */
    WSIO_ERR_PROTOCOL = -2, /**< RFC 6455 protocol violation (from the peer). */
    WSIO_ERR_UTF8 = -3,     /**< Invalid UTF-8 from the peer. */
    WSIO_ERR_TOO_BIG = -4,  /**< Message exceeds @ref wsio_config.max_message_size. */
    WSIO_ERR_CLOSED = -5    /**< Further input after Close. */
} wsio_err;

/**
 * @brief WebSocket opcodes (RFC 6455 §5.2).
 */
typedef enum {
    WSIO_OP_CONT = 0x0,  /**< Continuation of a fragmented message. */
    WSIO_OP_TEXT = 0x1,  /**< Text (UTF-8) data. */
    WSIO_OP_BIN = 0x2,   /**< Binary data. */
    WSIO_OP_CLOSE = 0x8, /**< Close control frame. */
    WSIO_OP_PING = 0x9,  /**< Ping control frame. */
    WSIO_OP_PONG = 0xA   /**< Pong control frame. */
} wsio_opcode;

/**
 * @brief Close status codes that may appear in the API.
 *
 * Codes 1005/1006/1015 are never sent on the wire; they are local only.
 */
typedef enum {
    WSIO_CLOSE_NORMAL = 1000,         /**< Normal closure. */
    WSIO_CLOSE_GOING_AWAY = 1001,     /**< Endpoint is going away. */
    WSIO_CLOSE_PROTOCOL = 1002,       /**< Protocol error. */
    WSIO_CLOSE_UNSUPPORTED = 1003,    /**< Unsupported data. */
    WSIO_CLOSE_NO_STATUS = 1005,      /**< No status received (not on the wire). */
    WSIO_CLOSE_ABNORMAL = 1006,       /**< Abnormal closure (not on the wire). */
    WSIO_CLOSE_INVALID_DATA = 1007,   /**< Invalid payload data (UTF-8). */
    WSIO_CLOSE_POLICY = 1008,         /**< Policy violation. */
    WSIO_CLOSE_TOO_BIG = 1009,        /**< Message too big. */
    WSIO_CLOSE_MANDATORY_EXT = 1010,  /**< Mandatory extension missing. */
    WSIO_CLOSE_INTERNAL = 1011        /**< Internal error. */
} wsio_close_code;

/**
 * @brief Kind of event returned by @ref wsio_poll.
 */
typedef enum {
    WSIO_EV_NONE = 0, /**< No event ready. */
    WSIO_EV_TEXT,     /**< Complete text message. */
    WSIO_EV_BIN,      /**< Complete binary message. */
    WSIO_EV_PING,     /**< Ping payload (auto-pong may already be queued). */
    WSIO_EV_PONG,     /**< Pong payload. */
    WSIO_EV_CLOSE,    /**< Close handshake frame. */
    WSIO_EV_ERROR     /**< Protocol failure; a Close frame is usually queued. */
} wsio_event_kind;

/**
 * @brief Application-visible event.
 *
 * @p data remains valid until the next @ref wsio_feed, @ref wsio_poll,
 * @ref wsio_send, or @ref wsio_destroy call.
 */
typedef struct wsio_event {
    wsio_event_kind kind; /**< Event type. */
    const uint8_t *data;  /**< Payload bytes, or NULL. */
    size_t len;           /**< Payload length in bytes. */
    uint16_t close_code;  /**< Set for @ref WSIO_EV_CLOSE and @ref WSIO_EV_ERROR. */
} wsio_event;

/**
 * @brief Connection configuration for @ref wsio_create_cfg.
 */
typedef struct wsio_config {
    wsio_role role;             /**< Client or server masking rules. */
    size_t max_message_size;    /**< 0 means 16 MiB. */
    int auto_pong;              /**< Non-zero: reply to ping with pong. */
    int auto_close;             /**< Non-zero: reply to close. */
    uint32_t (*rng)(void *ctx); /**< Client mask generator; NULL uses an internal PRNG. */
    void *rng_ctx;              /**< Passed to @p rng. */
} wsio_config;

/**
 * @brief Opaque connection state.
 */
typedef struct wsio wsio;

/**
 * @brief Create a connection with default limits and auto ping/close replies.
 *
 * @param role Client or server.
 * @return New connection, or NULL on allocation failure.
 */
wsio *wsio_create(wsio_role role);

/**
 * @brief Create a connection from @p cfg.
 *
 * @param cfg Required. @c auto_pong / @c auto_close are used as given (0 = off).
 *            A NULL @p cfg aborts.
 * @return New connection, or NULL on allocation failure.
 */
wsio *wsio_create_cfg(const wsio_config *cfg);

/**
 * @brief Free @p ws and all buffers it owns.
 *
 * @param ws May be NULL.
 */
void wsio_destroy(wsio *ws);

/**
 * @brief Push bytes received from the peer.
 *
 * Unparsed tail is copied internally. After a protocol failure a Close frame
 * is queued when possible; still drain output. A NULL @p ws, or @p len > 0
 * with a NULL @p src, aborts.
 *
 * @param ws  Connection.
 * @param src Inbound bytes. May be NULL iff @p len is 0.
 * @param len Byte count.
 * @return @ref WSIO_OK, or a negative @ref wsio_err for peer/resource failures.
 */
int wsio_feed(wsio *ws, const uint8_t *src, size_t len);

/**
 * @brief Number of outbound bytes waiting to be written to the peer.
 */
size_t wsio_pending(const wsio *ws);

/**
 * @brief Pointer to the outbound byte queue.
 *
 * @param[out] len Required. Set to the pending length (0 if none).
 * @return Pointer into the queue, or NULL if empty.
 */
const uint8_t *wsio_peek(const wsio *ws, size_t *len);

/**
 * @brief Drop @p n bytes from the front of the outbound queue after a send.
 */
void wsio_consume(wsio *ws, size_t n);

/**
 * @brief Copy up to @p cap pending bytes into @p dst and consume them.
 *
 * @return Bytes copied.
 */
size_t wsio_write(wsio *ws, uint8_t *dst, size_t cap);

/**
 * @brief Next application event, or @ref WSIO_EV_NONE.
 *
 * Payload pointers are valid until the next mutating call (see @ref wsio_event).
 */
wsio_event wsio_poll(wsio *ws);

/**
 * @brief Queue a frame. Used for explicit fragmentation (@p fin).
 *
 * Text with @p fin set must be valid UTF-8. Invalid arguments, illegal
 * opcodes, control frames over 125 bytes, or send after Close abort.
 */
int wsio_send(wsio *ws, wsio_opcode opcode, const uint8_t *data, size_t len, int fin);

/**
 * @brief Queue an unfragmented text message.
 */
int wsio_send_text(wsio *ws, const uint8_t *data, size_t len);

/**
 * @brief Queue an unfragmented binary message.
 */
int wsio_send_bin(wsio *ws, const uint8_t *data, size_t len);

/**
 * @brief Queue a ping. @p len must be at most 125.
 */
int wsio_send_ping(wsio *ws, const uint8_t *data, size_t len);

/**
 * @brief Queue a pong. @p len must be at most 125.
 */
int wsio_send_pong(wsio *ws, const uint8_t *data, size_t len);

/**
 * @brief Queue a Close frame.
 *
 * @param code 0 sends an empty payload. Otherwise it must be a code allowed
 *             on the wire (@ref wsio_close_code_valid).
 * @param reason UTF-8 reason; ignored if @p code is 0. At most 123 bytes.
 */
int wsio_send_close(wsio *ws, uint16_t code, const uint8_t *reason, size_t reason_len);

/**
 * @brief Non-zero if a Close has been sent or received.
 */
int wsio_closing(const wsio *ws);

/**
 * @brief Non-zero if Close has been both sent and received.
 */
int wsio_closed(const wsio *ws);

/**
 * @brief Last error, or @ref WSIO_OK.
 */
wsio_err wsio_error(const wsio *ws);

/**
 * @brief Last close code (peer or locally generated).
 */
uint16_t wsio_last_close(const wsio *ws);

/**
 * @brief Whether @p code may appear on the wire as a Close status.
 *
 * True for 1000–1014 except 1004/1005/1006, and for 3000–4999.
 */
int wsio_close_code_valid(uint16_t code);

#ifdef __cplusplus
}
#endif

#endif /* WSIO_H */
