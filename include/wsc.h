#ifndef WSC_H
#define WSC_H

/**
 * Encode and decode WebSocket frames (RFC 6455 §§5.2–5.3).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum wsc_err {
  WSC_OK                     = 0,
  WSC_ERR_NO_MEMORY          = -1,
  WSC_ERR_LENGTH_NOT_MINIMAL = -2,
  WSC_ERR_LENGTH64_MSB       = -3,
};

enum wsc_opcode : uint8_t {
  WSC_OPCODE_CONTINUATION = 0x0,
  WSC_OPCODE_TEXT         = 0x1,
  WSC_OPCODE_BINARY       = 0x2,
  WSC_OPCODE_CLOSE        = 0x8,
  WSC_OPCODE_PING         = 0x9,
  WSC_OPCODE_PONG         = 0xA,
};

enum : unsigned { WSC_MASKING_KEY_LENGTH = 4 };

struct wsc_frame {
  const uint8_t *payload;
  size_t payload_length;
  uint8_t masking_key[WSC_MASKING_KEY_LENGTH];
  uint8_t opcode;
  bool fin;
  bool rsv1;
  bool rsv2;
  bool rsv3;
  bool masked;
};

struct wsc_encoding_result {
  enum wsc_err err;
  uint8_t *data;
  size_t data_length;
};

struct wsc_decoding_result {
  enum wsc_err err;
  const struct wsc_frame *frames;
  size_t frames_count;
};

struct wsc_decoder;

#ifdef WSC_HOSTED

/** @return Heap decoder, or nullptr on OOM. */
struct wsc_decoder *wsc_decoder_create();

/**
 * @return Encoding result. On success, @c encoding_result.data is heap-allocated
 *         and the caller frees it. On @c WSC_ERR_NO_MEMORY, @c data is nullptr and
 *         @c data_length is 0.
 */
struct wsc_encoding_result wsc_encode(const struct wsc_frame *frame);

/**
 * @param decoder May be nullptr.
 */
void wsc_decoder_destroy(struct wsc_decoder *decoder);

/**
 * Parse @p source. Incomplete frames stay in the decoder.
 *
 * Completed frames and payloads are heap-allocated and unmasked (masking is wire
 * format, RFC 6455 §5.3). The caller owns @c decoding_result.frames and each
 * @c payload; free them with wsc_decoding_result_destroy. A later feed does not
 * invalidate prior results.
 * @c decoding_result.err other than WSC_OK leaves the decoder unusable; later feeds
 * return the same error until a new decoder is created. Frames already in that
 * result are still owned by the caller.
 */
struct wsc_decoding_result wsc_decoder_feed(struct wsc_decoder *decoder, const uint8_t *source,
                                            size_t length);

/**
 * Frees @c result->frames and each payload. No-op if @p result is nullptr or has
 * no frames. Safe to call once per feed result.
 */
void wsc_decoding_result_destroy(struct wsc_decoding_result *result);

#elifndef WSC_HOSTED

/**
 * Decoder state is stored at the first suitably aligned address in @p arena;
 * remaining arena is used for allocations. The handle may differ from
 * @p arena when alignment padding is needed. Does not take ownership of @p arena.
 * @return Opaque handle into @p arena, or nullptr if @p arena is too small.
 */
struct wsc_decoder *wsc_decoder_create(unsigned char *arena, size_t capacity);

/** Wire size of one encoded frame. */
size_t wsc_encoded_length(const struct wsc_frame *frame);

/**
 * Write one frame into @p destination.
 *
 * @p destination_capacity must be at least wsc_encoded_length(@p frame); smaller is a
 * programming error. If @c frame->masked, the payload is masked with
 * @c frame->masking_key.
 * @return Bytes written (same as wsc_encoded_length(@p frame)).
 */
size_t wsc_encode(uint8_t *destination, size_t destination_capacity, const struct wsc_frame *frame);

/**
 * Parse @p source. Incomplete frames stay in the decoder.
 *
 * Completed frames and payloads are stored in the arena and unmasked (masking is
 * wire format, RFC 6455 §5.3). They are valid until the next wsc_decoder_feed.
 * @c decoding_result.err other than WSC_OK leaves the decoder unusable; later feeds
 * return the same error until a new decoder is created.
 */
struct wsc_decoding_result wsc_decoder_feed(struct wsc_decoder *decoder, const uint8_t *source,
                                            size_t length);

#endif

#endif /* WSC_H */
