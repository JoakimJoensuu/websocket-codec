#include "wsc_common.h"

#include "wsc.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

uint16_t wsc_read_uint16(const uint8_t *source) {
  return (uint16_t)(((unsigned)source[0] << WSC_BYTE_BITS) | (unsigned)source[1]);
}

uint64_t wsc_read_uint64(const uint8_t *source) {
  uint64_t value = 0;
  for (int i = 0; i < (int)sizeof(uint64_t); i++) {
    value = (value << WSC_BYTE_BITS) | (uint64_t)source[i];
  }
  return value;
}

void wsc_write_uint16(uint8_t *destination, uint16_t value) {
  destination[0] = (uint8_t)((unsigned)value >> WSC_BYTE_BITS);
  destination[1] = (uint8_t)value;
}

void wsc_write_uint64(uint8_t *destination, uint64_t value) {
  for (int i = (int)sizeof(uint64_t) - 1; i >= 0; i--) {
    destination[i] = (uint8_t)value;
    value >>= WSC_BYTE_BITS;
  }
}

void wsc_apply_mask(uint8_t *data, size_t length, const uint8_t key[WSC_MASKING_KEY_LENGTH],
                    unsigned offset) {
  for (size_t i = 0; i < length; i++) {
    data[i] = (uint8_t)((unsigned)data[i] ^ key[(offset + i) & (WSC_MASKING_KEY_LENGTH - 1U)]);
  }
}

size_t wsc_encoded_header_length(size_t payload_length, bool masked) {
  size_t header_length = WSC_HEADER_BASE;
  if (payload_length > UINT16_MAX) {
    header_length += WSC_LENGTH64_EXT;
  } else if (payload_length > WSC_LENGTH7_MAX) {
    header_length += WSC_LENGTH16_EXT;
  }
  if (masked) {
    header_length += WSC_MASKING_KEY_LENGTH;
  }
  return header_length;
}

size_t wsc_header_length(unsigned byte1) {
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
