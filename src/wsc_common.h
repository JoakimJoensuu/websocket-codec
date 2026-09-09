#ifndef WSC_COMMON_H
#define WSC_COMMON_H

#include "wsc.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

enum : unsigned {
  WSC_HEADER_BASE  = 2,
  WSC_LENGTH16_EXT = 2,
  WSC_LENGTH64_EXT = 8,
  WSC_HEADER_MAX   = WSC_HEADER_BASE + WSC_LENGTH64_EXT + WSC_MASKING_KEY_LENGTH,
};

enum : unsigned {
  WSC_LENGTH7_MAX = 125,
  WSC_LENGTH16    = 126,
  WSC_LENGTH64    = 127,
};

enum : uint8_t {
  WSC_FIN_BIT      = 0x80,
  WSC_RSV1_BIT     = 0x40,
  WSC_RSV2_BIT     = 0x20,
  WSC_RSV3_BIT     = 0x10,
  WSC_OPCODE_MASK  = 0x0F,
  WSC_MASK_BIT     = 0x80,
  WSC_LENGTH7_MASK = 0x7F,
};

enum : uint64_t { WSC_LENGTH64_MSB = 0x8000000000000000 };

enum : unsigned {
  WSC_BUFFER_INIT = 256,
  WSC_FRAMES_INIT = 8,
};

enum : unsigned { WSC_BYTE_BITS = CHAR_BIT };

enum wsc_parse_state { WSC_STATE_HEADER = 0, WSC_STATE_PAYLOAD, WSC_STATE_DEAD };

struct wsc_buffer {
  uint8_t *data;
  size_t length;
  size_t capacity;
};

struct wsc_decoder_data;

[[noreturn]] void wsc_trap();

void wsc_decoder_state_init(struct wsc_decoder_data *decoder);

int wsc_buffer_reserve(struct wsc_decoder_data *decoder, struct wsc_buffer *buffer,
                       size_t minimum_capacity);

void wsc_clear_frames(struct wsc_decoder_data *decoder);

int wsc_frames_reserve(struct wsc_decoder_data *decoder, size_t capacity);

enum wsc_status wsc_attach_payload(struct wsc_decoder_data *decoder, struct wsc_frame *frame);

void wsc_discard_payload(struct wsc_frame *frame);

void wsc_payload_emitted(struct wsc_decoder_data *decoder);

#ifdef WSC_HOSTED
size_t wsc_encoded_frame_length(const struct wsc_frame *frame);
#endif

size_t wsc_encode_buffer(uint8_t *destination, size_t destination_capacity,
                         const struct wsc_frame *frame);

struct wsc_decoding_result wsc_decoder_feed_data(struct wsc_decoder_data *decoder,
                                                 const uint8_t *source, size_t length);

#endif /* WSC_COMMON_H */
