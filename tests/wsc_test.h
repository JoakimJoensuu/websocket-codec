#ifndef WSC_TEST_H
#define WSC_TEST_H

enum : unsigned {
  WSC_TEST_HEADER_BASE    = 2,
  WSC_TEST_LEN16_EXT      = 2,
  WSC_TEST_LEN64_EXT      = 8,
  WSC_TEST_LEN7_MAX       = 125,
  WSC_TEST_LEN16          = 126,
  WSC_TEST_LEN64          = 127,
  WSC_TEST_INTO_TOO_SMALL = 8,
  WSC_TEST_INTO_ARENA     = 4096,
  WSC_TEST_INTO_TIGHT     = 256,
};

enum : uint8_t {
  WSC_TEST_FIN_BIT        = 0x80,
  WSC_TEST_RSV1_BIT       = 0x40,
  WSC_TEST_RSV2_BIT       = 0x20,
  WSC_TEST_RSV3_BIT       = 0x10,
  WSC_TEST_RSV_MASK       = 0x70,
  WSC_TEST_OPCODE_MASK    = 0x0F,
  WSC_TEST_MASK_BIT       = 0x80,
  WSC_TEST_LEN7_MASK      = 0x7F,
  WSC_TEST_FILL_MID       = 0xab,
  WSC_TEST_FILL_WIDE      = 0xcd,
  WSC_TEST_LEN64_MSB_BYTE = 0x80,
};

enum : unsigned { WSC_TEST_BYTE_BITS = 8 };

static inline void wsc_test_write_uint16(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)((unsigned)value >> WSC_TEST_BYTE_BITS);
  dst[1] = (uint8_t)value;
}

static inline void wsc_test_write_uint64(uint8_t *dst, uint64_t value) {
  for (int i = (int)sizeof(uint64_t) - 1; i >= 0; i--) {
    dst[i] = (uint8_t)value;
    value >>= WSC_TEST_BYTE_BITS;
  }
}

static inline void wsc_test_xor_mask(uint8_t *data, size_t length,
                                     const uint8_t key[WSC_MASKING_KEY_LEN]) {
  for (size_t i = 0; i < length; i++) {
    data[i] = (uint8_t)((unsigned)data[i] ^ key[i & (WSC_MASKING_KEY_LEN - 1U)]);
  }
}

static inline size_t wsc_test_craft(uint8_t *dst, size_t dst_capacity, bool fin, unsigned rsv,
                                    uint8_t opcode, const uint8_t *masking_key, unsigned len7,
                                    const uint8_t *payload, size_t payload_len) {
  size_t header_length = WSC_TEST_HEADER_BASE;
  size_t total = 0;

  if (len7 == WSC_TEST_LEN16) {
    header_length += WSC_TEST_LEN16_EXT;
  } else if (len7 == WSC_TEST_LEN64) {
    header_length += WSC_TEST_LEN64_EXT;
  }
  if (masking_key != nullptr) {
    header_length += WSC_MASKING_KEY_LEN;
  }
  total = header_length + payload_len;
  assert_that(total <= dst_capacity, is_true);

  dst[0] = (uint8_t)((fin ? (unsigned)WSC_TEST_FIN_BIT : 0U) | ((rsv << 4U) & WSC_TEST_RSV_MASK) |
                     ((unsigned)opcode & (unsigned)WSC_TEST_OPCODE_MASK));
  dst[1] = (uint8_t)len7;
  if (len7 == WSC_TEST_LEN16) {
    wsc_test_write_uint16(dst + WSC_TEST_HEADER_BASE, (uint16_t)payload_len);
  } else if (len7 == WSC_TEST_LEN64) {
    wsc_test_write_uint64(dst + WSC_TEST_HEADER_BASE, (uint64_t)payload_len);
  } else {
    dst[1] = (uint8_t)payload_len;
  }
  if (masking_key != nullptr) {
    dst[1] = (uint8_t)((unsigned)dst[1] | WSC_TEST_MASK_BIT);
    memcpy(dst + (header_length - WSC_MASKING_KEY_LEN), masking_key, WSC_MASKING_KEY_LEN);
  }
  if (payload_len > 0) {
    memcpy(dst + header_length, payload, payload_len);
    if (masking_key != nullptr) {
      wsc_test_xor_mask(dst + header_length, payload_len, masking_key);
    }
  }
  return total;
}

static inline void wsc_test_assert_frame(const struct wsc_frame *actual,
                                         const struct wsc_frame *expected) {
  assert_that(actual->fin, is_equal_to(expected->fin));
  assert_that(actual->rsv1, is_equal_to(expected->rsv1));
  assert_that(actual->rsv2, is_equal_to(expected->rsv2));
  assert_that(actual->rsv3, is_equal_to(expected->rsv3));
  assert_that(actual->opcode, is_equal_to(expected->opcode));
  assert_that(actual->masked, is_equal_to(expected->masked));
  assert_that(actual->payload_len, is_equal_to(expected->payload_len));
  if (expected->payload_len > 0) {
    assert_that(actual->payload, is_non_null);
    assert_that(memcmp(actual->payload, expected->payload, expected->payload_len), is_equal_to(0));
  } else {
    assert_that(actual->payload, is_null);
  }
  if (expected->masked) {
    assert_that(memcmp(actual->masking_key, expected->masking_key, WSC_MASKING_KEY_LEN),
                is_equal_to(0));
  }
}

static inline struct wsc_frame wsc_test_make_frame(bool fin, uint8_t opcode, const uint8_t *payload,
                                                   size_t payload_len, const uint8_t *masking_key) {
  struct wsc_frame frame;
  memset(&frame, 0, sizeof(frame));
  frame.payload = payload;
  frame.payload_len = payload_len;
  frame.opcode = opcode;
  frame.fin = fin;
  if (masking_key != nullptr) {
    frame.masked = true;
    memcpy(frame.masking_key, masking_key, WSC_MASKING_KEY_LEN);
  }
  return frame;
}

#endif /* WSC_TEST_H */
