#ifndef WSC_H
#define WSC_H

/**
 * Encode and decode WebSocket frames (RFC 6455 §§5.2–5.3).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum wsc_status {
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
  enum wsc_status status;
  uint8_t *data;
  size_t data_length;
};

struct wsc_decoding_result {
  enum wsc_status status;
  const struct wsc_frame *frames;
  size_t frames_count;
  size_t source_consumed;
};

struct wsc_decoder;

#ifdef WSC_HOSTED

/** @return Decoder, or nullptr on OOM. */
struct wsc_decoder *wsc_decoder_create();

/**
 * @return Encoding result. On success, the caller frees @c encoding_result.data.
 *         On @c WSC_ERR_NO_MEMORY, @c encoding_result.data is nullptr and
 *         @c encoding_result.data_length is 0.
 */
struct wsc_encoding_result wsc_encode(const struct wsc_frame *frame);

/**
 * @param decoder May be nullptr.
 */
void wsc_decoder_destroy(struct wsc_decoder *decoder);

/**
 * Parse @p source. Incomplete frames stay in the decoder.
 *
 * Completed frames and payloads are unmasked. The caller owns
 * @c decoding_result.frames and each frame's payload; free them with
 * wsc_decoding_result_free. A later feed does not invalidate prior results.
 * @c decoding_result.source_consumed is how many bytes of @p source were accepted;
 * re-feed the remainder after @c WSC_ERR_NO_MEMORY.
 * @c decoding_result.status of @c WSC_ERR_NO_MEMORY does not kill the decoder; free
 * held results or retry later. Protocol errors leave the decoder unusable until a
 * new one is created. Frames already in that result are still owned by the caller.
 */
struct wsc_decoding_result wsc_decoder_feed(struct wsc_decoder *decoder, const uint8_t *source,
                                            size_t length);

/**
 * Frees @c decoding_result.frames and each frame's payload. No-op if there are no
 * frames. After return those pointers must not be used. Safe to call once per feed
 * result.
 */
void wsc_decoding_result_free(struct wsc_decoding_result result);

#elifndef WSC_HOSTED

/**
 * Does not take ownership of @p arena. The returned handle may differ from
 * @p arena.
 * @return Opaque handle into @p arena, or nullptr if @p arena is too small.
 */
struct wsc_decoder *wsc_decoder_create(unsigned char *arena, size_t capacity);

size_t wsc_encoded_frame_length(const struct wsc_frame *frame);

/**
 * Write one frame into @p destination.
 *
 * @p destination_capacity must be at least wsc_encoded_frame_length(@p frame);
 * smaller is a programming error. If @c frame->masked, the payload is masked with
 * @c frame->masking_key.
 * @return Bytes written (same as wsc_encoded_frame_length(@p frame)).
 */
size_t wsc_encode(uint8_t *destination, size_t destination_capacity, const struct wsc_frame *frame);

/**
 * Parse @p source. Incomplete frames stay in the decoder.
 *
 * Completed frames and payloads are stored in the arena and unmasked. They are
 * valid until the next wsc_decoder_feed.
 * @c decoding_result.source_consumed is how many bytes of @p source were accepted;
 * re-feed the remainder after @c WSC_ERR_NO_MEMORY.
 * @c decoding_result.status of @c WSC_ERR_NO_MEMORY does not kill the decoder; finish
 * with the result before the next feed, then re-feed the unconsumed suffix. A larger
 * arena needs a new decoder and a replay of the full in-progress frame (bytes already
 * accepted on earlier feeds, then the remainder). Protocol errors leave the decoder
 * unusable until a new one is created.
 */
struct wsc_decoding_result wsc_decoder_feed(struct wsc_decoder *decoder, const uint8_t *source,
                                            size_t length);

#endif

#endif /* WSC_H */
