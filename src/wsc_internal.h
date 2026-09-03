#ifndef WSC_INTERNAL_H
#define WSC_INTERNAL_H

#include "wsc.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef WSC_HOSTED
#include "ringalloc.h"
#endif

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

struct wsc_decoder {
  uint64_t payload_length;
  uint64_t payload_received;
  struct wsc_buffer payload;
#ifndef WSC_HOSTED
  struct ringalloc *ringalloc;
  size_t allocation_count;
#endif
  struct wsc_frame *frames;
  size_t frames_count;
  size_t frames_capacity;
  size_t header_received;
  size_t header_total;
  enum wsc_parse_state state;
  unsigned mask_offset;
  enum wsc_err last_err;
  bool fin;
  bool rsv1;
  bool rsv2;
  bool rsv3;
  bool masked;
  uint8_t opcode;
  uint8_t masking_key[WSC_MASKING_KEY_LENGTH];
  uint8_t header[WSC_HEADER_MAX];
};

#ifdef WSC_HOSTED
#include <stdlib.h>
#define wsc_trap() abort()
#else
#define wsc_trap() unreachable()
#endif

void wsc_decoder_state_init(struct wsc_decoder *decoder);

int wsc_buffer_reserve(struct wsc_decoder *decoder, struct wsc_buffer *buffer,
                       size_t minimum_capacity);

void wsc_clear_frames(struct wsc_decoder *decoder);

int wsc_frames_reserve(struct wsc_decoder *decoder, size_t capacity);

enum wsc_err wsc_attach_payload(struct wsc_decoder *decoder, struct wsc_frame *frame);

void wsc_discard_payload(struct wsc_frame *frame);

void wsc_payload_emitted(struct wsc_decoder *decoder);

void wsc_decoder_free(struct wsc_decoder *decoder);

#ifdef WSC_HOSTED
size_t wsc_encoded_length(const struct wsc_frame *frame);
#endif

size_t wsc_encode_buffer(uint8_t *destination, size_t destination_capacity,
                          const struct wsc_frame *frame);

#endif /* WSC_INTERNAL_H */
