#ifndef WSC_FREESTANDING_H
#define WSC_FREESTANDING_H

#include "wsc_common.h"

#include <ringalloc.h>
#include <string.h>

#define wsc_trap() unreachable()

struct wsc_decoder_data {
  uint64_t payload_length;
  uint64_t payload_received;
  struct wsc_buffer payload;
  struct ringalloc *ringalloc;
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

#endif /* WSC_FREESTANDING_H */
