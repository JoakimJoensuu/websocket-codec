#include "wsc_common.h"

#include "wsc.h"

#include <stdint.h>
#include <string.h>

uint16_t read_uint16(const uint8_t *source) {
  return (uint16_t)(((unsigned)source[0] << WSC_BYTE_BITS) | (unsigned)source[1]);
}

uint64_t read_uint64(const uint8_t *source) {
  uint64_t value = 0;
  for (int i = 0; i < (int)sizeof(uint64_t); i++) {
    value = (value << WSC_BYTE_BITS) | (uint64_t)source[i];
  }
  return value;
}

void apply_mask(uint8_t *data, size_t length, const uint8_t key[WSC_MASKING_KEY_LENGTH],
                unsigned offset) {
  for (size_t i = 0; i < length; i++) {
    data[i] = (uint8_t)((unsigned)data[i] ^ key[(offset + i) & (WSC_MASKING_KEY_LENGTH - 1U)]);
  }
}

size_t header_length(unsigned byte1) {
  size_t header_length = WSC_HEADER_BASE;
  unsigned length7 = byte1 & WSC_LENGTH7_MASK;
  if (length7 == WSC_LENGTH16) {
    header_length += WSC_LENGTH16_EXT;
  } else if (length7 == WSC_LENGTH64) {
    header_length += WSC_LENGTH64_EXT;
  }
  if ((byte1 & WSC_MASK_BIT) != 0) {
    header_length += WSC_MASKING_KEY_LENGTH;
  }
  return header_length;
}

size_t encoded_frame_length(const struct wsc_frame *frame) {
  if (frame == nullptr) {
    wsc_trap();
  }
  size_t header_length = WSC_HEADER_BASE;
  if (frame->payload_length > WSC_LENGTH7_MAX) {
    header_length += frame->payload_length > UINT16_MAX ? WSC_LENGTH64_EXT : WSC_LENGTH16_EXT;
  }
  if (frame->masked) {
    header_length += WSC_MASKING_KEY_LENGTH;
  }
  if (frame->payload_length > ((size_t)-1) - header_length) {
    wsc_trap();
  }
  return header_length + frame->payload_length;
}

static size_t write_frame(uint8_t *destination, const struct wsc_frame *frame) {
  uint8_t header[WSC_HEADER_MAX];
  size_t header_length = WSC_HEADER_BASE;

  header[0] = (uint8_t)((frame->fin ? (unsigned)WSC_FIN_BIT : 0U) |
                        (frame->rsv1 ? (unsigned)WSC_RSV1_BIT : 0U) |
                        (frame->rsv2 ? (unsigned)WSC_RSV2_BIT : 0U) |
                        (frame->rsv3 ? (unsigned)WSC_RSV3_BIT : 0U) |
                        ((unsigned)frame->opcode & (unsigned)WSC_OPCODE_MASK));
  if (frame->payload_length <= WSC_LENGTH7_MAX) {
    header[1] = (uint8_t)frame->payload_length;
  } else if (frame->payload_length <= UINT16_MAX) {
    header[1] = WSC_LENGTH16;
    header[WSC_HEADER_BASE] = (uint8_t)((unsigned)(uint16_t)frame->payload_length >> WSC_BYTE_BITS);
    header[WSC_HEADER_BASE + 1] = (uint8_t)(uint16_t)frame->payload_length;
    header_length = WSC_HEADER_BASE + WSC_LENGTH16_EXT;
  } else {
    header[1] = WSC_LENGTH64;
    {
      uint64_t value = (uint64_t)frame->payload_length;
      for (int i = (int)sizeof(uint64_t) - 1; i >= 0; i--) {
        header[WSC_HEADER_BASE + (size_t)i] = (uint8_t)value;
        value >>= WSC_BYTE_BITS;
      }
    }
    header_length = WSC_HEADER_BASE + WSC_LENGTH64_EXT;
  }
  if (frame->masked) {
    header[1] = (uint8_t)((unsigned)header[1] | WSC_MASK_BIT);
    memcpy(header + header_length, frame->masking_key, WSC_MASKING_KEY_LENGTH);
    header_length += WSC_MASKING_KEY_LENGTH;
  }

  memcpy(destination, header, header_length);
  if (frame->payload_length > 0) {
    memcpy(destination + header_length, frame->payload, frame->payload_length);
    if (frame->masked) {
      apply_mask(destination + header_length, frame->payload_length, frame->masking_key, 0);
    }
  }
  return header_length + frame->payload_length;
}

size_t wsc_encode_buffer(uint8_t *destination, size_t destination_capacity,
                         const struct wsc_frame *frame) {
  if (frame == nullptr) {
    wsc_trap();
  }
  if (frame->payload_length > 0 && frame->payload == nullptr) {
    wsc_trap();
  }
  if (frame->opcode > WSC_OPCODE_MASK) {
    wsc_trap();
  }
  if (frame->payload_length > (size_t)(WSC_LENGTH64_MSB - 1)) {
    wsc_trap();
  }
  size_t total = encoded_frame_length(frame);
  if (destination == nullptr) {
    wsc_trap();
  }
  if (destination_capacity < total) {
    wsc_trap();
  }
  return write_frame(destination, frame);
}
