#ifndef WSC_H
#define WSC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum wsc_status {
  WSC_INCOMPLETE             = 1,
  WSC_OK                     = 0,
  WSC_ERR_NO_MEMORY          = -1,
  WSC_ERR_LENGTH_NOT_MINIMAL = -2,
  WSC_ERR_LENGTH64_MSB       = -3,
#ifndef WSC_HOSTED
  WSC_ERR_PAYLOAD_EXCEEDS_CAPACITY = -4,
#endif
  WSC_ERR_LENGTH_EXCEEDS_SIZE = -5,
};

enum wsc_opcode : uint8_t {
  WSC_OPCODE_CONTINUATION = 0x0,
  WSC_OPCODE_TEXT         = 0x1,
  WSC_OPCODE_BINARY       = 0x2,
  WSC_OPCODE_CLOSE        = 0x8,
  WSC_OPCODE_PING         = 0x9,
  WSC_OPCODE_PONG         = 0xA,
};

enum wsc_masking_key : unsigned { WSC_MASKING_KEY_LENGTH = 4 };

struct wsc_frame {
  const uint8_t *payload;
  uint64_t payload_length;
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
#ifdef WSC_HOSTED
  const struct wsc_frame *frames;
  size_t frames_count;
#elifndef WSC_HOSTED
  struct wsc_frame frame;
#endif
  size_t source_consumed;
};

struct wsc_decoder;

#ifdef WSC_HOSTED

/** @return Decoder, or nullptr on OOM. */
struct wsc_decoder *wsc_decoder_create();

/**
 * If @c frame->masked, the payload in @c wsc_encoding_result.data is masked
 * with @c frame->masking_key.
 *
 * @return Encoding result. On success, the caller frees @c wsc_encoding_result.data.
 *         On @c WSC_ERR_NO_MEMORY, @c wsc_encoding_result.data is nullptr and
 *         @c wsc_encoding_result.data_length is 0.
 */
struct wsc_encoding_result wsc_encode(const struct wsc_frame *frame);

/**
 * @param decoder May be nullptr.
 */
void wsc_decoder_destroy(struct wsc_decoder *decoder);

/**
 * Parse @p source. Incomplete frames stay in the decoder.
 *
 * Completed frames and payloads are unmasked.
 *
 * The caller owns @c wsc_decoding_result.frames and each frame's payload; free them with
 * wsc_decoding_result_free. A later feed does not invalidate prior results.
 *
 * @c wsc_decoding_result.source_consumed is how many bytes of @p source were accepted;
 * re-feed the remainder after @c WSC_ERR_NO_MEMORY.
 *
 * @c wsc_decoding_result.status of @c WSC_ERR_NO_MEMORY does not kill the decoder; free
 * held results or retry later.
 *
 * @c WSC_ERR_LENGTH_EXCEEDS_SIZE and protocol errors leave
 * the decoder unusable until a new one is created. Completed frames returned in the result are
 * still owned by the caller.
 */
struct wsc_decoding_result wsc_decoder_feed(struct wsc_decoder *decoder, const uint8_t *source,
                                            size_t source_length);

/**
 * Frees @c wsc_decoding_result.frames and each frame's payload. No-op if there are no
 * frames. After return those pointers must not be used. Safe to call once per feed
 * result.
 */
void wsc_decoding_result_free(struct wsc_decoding_result result);

#elifndef WSC_HOSTED

static constexpr size_t wsc_decoder_opaque_size =
    sizeof(struct wsc_frame) + (alignof(struct wsc_frame) - 1) +
    (sizeof(uint8_t) * (2 + 8 + WSC_MASKING_KEY_LENGTH)) + (alignof(uint8_t) - 1) +
    sizeof(uint8_t *) + (alignof(uint8_t *) - 1) + sizeof(size_t) + (alignof(size_t) - 1) +
    sizeof(size_t) + (alignof(size_t) - 1) + sizeof(size_t) + (alignof(size_t) - 1) +
    sizeof(size_t) + (alignof(size_t) - 1) + sizeof(unsigned) + (alignof(unsigned) - 1) +
    sizeof(enum wsc_status) + (alignof(enum wsc_status) - 1) + (alignof(struct wsc_frame) - 1);

/**
 * Contents are private.
 */
struct wsc_decoder {
  alignas(struct wsc_frame) alignas(uint8_t *) alignas(size_t) alignas(unsigned) alignas(
      enum wsc_status) unsigned char opaque[wsc_decoder_opaque_size];
};

/**
 * Prepare @p decoder to parse. Payload bytes are written into @p payload.
 * @p payload_capacity is the largest payload accepted.
 */
void wsc_decoder_init(struct wsc_decoder *decoder, uint8_t *payload, size_t payload_capacity);

/**
 * Replace the buffer that receives payload bytes. @p payload_capacity is the largest
 * payload accepted. Use this after @c WSC_ERR_PAYLOAD_EXCEEDS_CAPACITY, or before the
 * next frame.
 */
void wsc_decoder_set_payload_buffer(struct wsc_decoder *decoder, uint8_t *payload,
                                    size_t payload_capacity);

uint64_t wsc_encoded_frame_length(const struct wsc_frame *frame);

/**
 * Write one frame into @p destination.
 *
 * @p destination must have room for wsc_encoded_frame_length(@p frame). If
 * @c frame->masked, the payload is masked with @c frame->masking_key.
 * @return Bytes written (same as wsc_encoded_frame_length(@p frame)).
 */
size_t wsc_encode(uint8_t *destination, const struct wsc_frame *frame);

/**
 * Parse @p source into at most one frame. Incomplete frames stay in the decoder.
 *
 * Payload bytes are written into the buffer installed on @p decoder.
 * @c WSC_OK means @c wsc_decoding_result.frame is complete. Its payload addresses that
 * buffer. @c WSC_INCOMPLETE means more source is required.
 * @c wsc_decoding_result.source_consumed is how many bytes of @p source were accepted.
 * Re-feed the unconsumed suffix.
 * On @c WSC_ERR_PAYLOAD_EXCEEDS_CAPACITY the payload was not accepted. Pass a larger
 * buffer to wsc_decoder_set_payload_buffer and re-feed the suffix. @c WSC_ERR_LENGTH_EXCEEDS_SIZE
 * and protocol errors leave the decoder unusable until wsc_decoder_init.
 */
struct wsc_decoding_result wsc_decoder_feed(struct wsc_decoder *decoder, const uint8_t *source,
                                            size_t source_length);

#endif

#endif /* WSC_H */
