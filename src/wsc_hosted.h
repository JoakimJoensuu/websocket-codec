#ifndef WSC_HOSTED_H
#define WSC_HOSTED_H

#include "wsc_internal.h"

#include <stdlib.h>

#define wsc_trap() abort()

struct wsc_decoder_data {
  uint64_t payload_length;
  uint64_t payload_received;
  struct wsc_buffer payload;
  struct wsc_frame *frames;
  size_t frames_count;
  size_t frames_capacity;
  size_t header_received;
  size_t header_total;
  enum wsc_parse_state state;
  unsigned mask_offset;
  enum wsc_status last_status;
  bool fin;
  bool rsv1;
  bool rsv2;
  bool rsv3;
  bool masked;
  uint8_t opcode;
  uint8_t masking_key[WSC_MASKING_KEY_LENGTH];
  uint8_t header[WSC_HEADER_MAX];
};

void wsc_decoder_free(struct wsc_decoder_data *decoder);

size_t wsc_encoded_frame_length(const struct wsc_frame *frame);

#endif /* WSC_HOSTED_H */
