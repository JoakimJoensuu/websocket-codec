#ifndef WSC_TEST_H
#define WSC_TEST_H

enum : unsigned {
  WSC_TEST_HEADER_BASE     = 2,
  WSC_TEST_LENGTH16_EXT    = 2,
  WSC_TEST_LENGTH64_EXT    = 8,
  WSC_TEST_LENGTH7_MAX     = 125,
  WSC_TEST_LENGTH16        = 126,
  WSC_TEST_LENGTH64        = 127,
  WSC_TEST_ARENA_TOO_SMALL = 8,
  WSC_TEST_ARENA_SIZE      = 8192,
  WSC_TEST_ARENA_TIGHT     = 1024,
};

enum : uint8_t {
  WSC_TEST_FIN_BIT           = 0x80,
  WSC_TEST_RSV1_BIT          = 0x40,
  WSC_TEST_RSV2_BIT          = 0x20,
  WSC_TEST_RSV3_BIT          = 0x10,
  WSC_TEST_RSV_MASK          = 0x70,
  WSC_TEST_OPCODE_MASK       = 0x0F,
  WSC_TEST_MASK_BIT          = 0x80,
  WSC_TEST_LENGTH7_MASK      = 0x7F,
  WSC_TEST_FILL_MID          = 0xab,
  WSC_TEST_FILL_WIDE         = 0xcd,
  WSC_TEST_LENGTH64_MSB_BYTE = 0x80,
};

enum : unsigned { WSC_TEST_BYTE_BITS = 8 };

static inline void wsc_test_write_uint16(uint8_t *destination, uint16_t value) {
  destination[0] = (uint8_t)((unsigned)value >> WSC_TEST_BYTE_BITS);
  destination[1] = (uint8_t)value;
}

static inline void wsc_test_write_uint64(uint8_t *destination, uint64_t value) {
  for (int i = (int)sizeof(uint64_t) - 1; i >= 0; i--) {
    destination[i] = (uint8_t)value;
    value >>= WSC_TEST_BYTE_BITS;
  }
}

static inline void wsc_test_xor_mask(uint8_t *data, size_t length,
                                     const uint8_t key[WSC_MASKING_KEY_LENGTH]) {
  for (size_t i = 0; i < length; i++) {
    data[i] = (uint8_t)((unsigned)data[i] ^ key[i & (WSC_MASKING_KEY_LENGTH - 1U)]);
  }
}

static inline size_t wsc_test_craft(uint8_t *destination, size_t destination_capacity, bool fin,
                                    unsigned rsv, uint8_t opcode, const uint8_t *masking_key,
                                    unsigned length7, const uint8_t *payload,
                                    size_t payload_length) {
  size_t header_length = WSC_TEST_HEADER_BASE;
  size_t total = 0;

  if (length7 == WSC_TEST_LENGTH16) {
    header_length += WSC_TEST_LENGTH16_EXT;
  } else if (length7 == WSC_TEST_LENGTH64) {
    header_length += WSC_TEST_LENGTH64_EXT;
  }
  if (masking_key != nullptr) {
    header_length += WSC_MASKING_KEY_LENGTH;
  }
  total = header_length + payload_length;
  assert_that(total <= destination_capacity, is_true);

  destination[0] =
      (uint8_t)((fin ? (unsigned)WSC_TEST_FIN_BIT : 0U) | ((rsv << 4U) & WSC_TEST_RSV_MASK) |
                ((unsigned)opcode & (unsigned)WSC_TEST_OPCODE_MASK));
  destination[1] = (uint8_t)length7;
  if (length7 == WSC_TEST_LENGTH16) {
    wsc_test_write_uint16(destination + WSC_TEST_HEADER_BASE, (uint16_t)payload_length);
  } else if (length7 == WSC_TEST_LENGTH64) {
    wsc_test_write_uint64(destination + WSC_TEST_HEADER_BASE, (uint64_t)payload_length);
  } else {
    destination[1] = (uint8_t)payload_length;
  }
  if (masking_key != nullptr) {
    destination[1] = (uint8_t)((unsigned)destination[1] | WSC_TEST_MASK_BIT);
    memcpy(destination + (header_length - WSC_MASKING_KEY_LENGTH), masking_key,
           WSC_MASKING_KEY_LENGTH);
  }
  if (payload_length > 0) {
    memcpy(destination + header_length, payload, payload_length);
    if (masking_key != nullptr) {
      wsc_test_xor_mask(destination + header_length, payload_length, masking_key);
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
  assert_that(actual->payload_length, is_equal_to(expected->payload_length));
  if (expected->payload_length > 0) {
    assert_that(actual->payload, is_non_null);
    assert_that(memcmp(actual->payload, expected->payload, expected->payload_length),
                is_equal_to(0));
  } else {
    assert_that(actual->payload, is_null);
  }
  if (expected->masked) {
    assert_that(memcmp(actual->masking_key, expected->masking_key, WSC_MASKING_KEY_LENGTH),
                is_equal_to(0));
  }
}

static inline struct wsc_frame wsc_test_make_frame(bool fin, uint8_t opcode, const uint8_t *payload,
                                                   size_t payload_length,
                                                   const uint8_t *masking_key) {
  struct wsc_frame frame;
  memset(&frame, 0, sizeof(frame));
  frame.payload = payload;
  frame.payload_length = payload_length;
  frame.opcode = opcode;
  frame.fin = fin;
  if (masking_key != nullptr) {
    frame.masked = true;
    memcpy(frame.masking_key, masking_key, WSC_MASKING_KEY_LENGTH);
  }
  return frame;
}

#endif /* WSC_TEST_H */
