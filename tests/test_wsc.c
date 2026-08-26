#include "wsc.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum : unsigned {
  HDR_BASE  = 2,
  LEN16_EXT = 2,
  LEN64_EXT = 8,
  LEN7_MAX  = 125,
  LEN16     = 126,
  LEN64     = 127,
};

enum : uint8_t {
  FIN_BIT        = 0x80,
  RSV1_BIT       = 0x40,
  RSV2_BIT       = 0x20,
  RSV3_BIT       = 0x10,
  RSV_MASK       = 0x70,
  OPCODE_MASK    = 0x0F,
  MASK_BIT       = 0x80,
  LEN7_MASK      = 0x7F,
  FILL_MID       = 0xab,
  FILL_WIDE      = 0xcd,
  LEN64_MSB_BYTE = 0x80,
};

enum : unsigned { BYTE_BITS = 8 };

static void wr16(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)((unsigned)value >> BYTE_BITS);
  dst[1] = (uint8_t)value;
}

static void wr64(uint8_t *dst, uint64_t value) {
  for (int i = (int)sizeof(uint64_t) - 1; i >= 0; i--) {
    dst[i] = (uint8_t)value;
    value >>= BYTE_BITS;
  }
}

static void xor_mask(uint8_t *data, size_t length, const uint8_t key[WSC_MASK_LEN]) {
  for (size_t i = 0; i < length; i++) {
    data[i] = (uint8_t)((unsigned)data[i] ^ key[i & (WSC_MASK_LEN - 1U)]);
  }
}

static size_t craft(uint8_t *dst, size_t dst_cap, bool fin, unsigned rsv, uint8_t opcode,
                    const uint8_t *mask_key, unsigned len7, const uint8_t *payload,
                    size_t payload_len) {
  size_t hlen = HDR_BASE;
  size_t total = 0;

  if (len7 == LEN16) {
    hlen += LEN16_EXT;
  } else if (len7 == LEN64) {
    hlen += LEN64_EXT;
  }
  if (mask_key != nullptr) {
    hlen += WSC_MASK_LEN;
  }
  total = hlen + payload_len;
  assert(total <= dst_cap);

  dst[0] = (uint8_t)((fin ? (unsigned)FIN_BIT : 0U) | ((rsv << 4U) & RSV_MASK) |
                     ((unsigned)opcode & (unsigned)OPCODE_MASK));
  dst[1] = (uint8_t)len7;
  if (len7 == LEN16) {
    wr16(dst + HDR_BASE, (uint16_t)payload_len);
  } else if (len7 == LEN64) {
    wr64(dst + HDR_BASE, (uint64_t)payload_len);
  } else {
    dst[1] = (uint8_t)payload_len;
  }
  if (mask_key != nullptr) {
    dst[1] = (uint8_t)((unsigned)dst[1] | MASK_BIT);
    memcpy(dst + (hlen - WSC_MASK_LEN), mask_key, WSC_MASK_LEN);
  }
  if (payload_len > 0) {
    memcpy(dst + hlen, payload, payload_len);
    if (mask_key != nullptr) {
      xor_mask(dst + hlen, payload_len, mask_key);
    }
  }
  return total;
}

static void assert_frame(const struct wsc_frame *got, const struct wsc_frame *want) {
  assert(got->fin == want->fin);
  assert(got->rsv1 == want->rsv1);
  assert(got->rsv2 == want->rsv2);
  assert(got->rsv3 == want->rsv3);
  assert(got->opcode == want->opcode);
  assert(got->masked == want->masked);
  assert(got->payload_len == want->payload_len);
  if (want->payload_len > 0) {
    assert(got->payload != nullptr);
    assert(memcmp(got->payload, want->payload, want->payload_len) == 0);
  } else {
    assert(got->payload == nullptr);
  }
  if (want->masked) {
    assert(memcmp(got->mask_key, want->mask_key, WSC_MASK_LEN) == 0);
  }
}

static struct wsc_frame make_frame(bool fin, uint8_t opcode, const uint8_t *payload,
                                   size_t payload_len, const uint8_t *mask_key) {
  struct wsc_frame frame;
  memset(&frame, 0, sizeof frame);
  frame.payload = payload;
  frame.payload_len = payload_len;
  frame.opcode = opcode;
  frame.fin = fin;
  if (mask_key != nullptr) {
    frame.masked = true;
    memcpy(frame.mask_key, mask_key, WSC_MASK_LEN);
  }
  return frame;
}

static uint8_t *encode_buf(const struct wsc_frame *frame, size_t *wire_len) {
  size_t need = wsc_encoded_len(frame);
  uint8_t *buf = (uint8_t *)malloc(need);
  assert(buf != nullptr);
  *wire_len = wsc_encode(buf, need, frame);
  assert(*wire_len == need);
  return buf;
}

static void roundtrip(const struct wsc_frame *want) {
  size_t wire_len = 0;
  uint8_t *buf = encode_buf(want, &wire_len);
  struct wsc_dec *dec = wsc_dec_create();
  struct wsc_result result;
  assert(dec != nullptr);
  result = wsc_dec_feed(dec, buf, wire_len);
  assert(result.err == WSC_OK);
  assert(result.frames_cnt == 1);
  assert_frame(&result.frames[0], want);
  wsc_dec_destroy(dec);
  free(buf);
}

static void roundtrip_split(const struct wsc_frame *want, size_t first) {
  size_t wire_len = 0;
  uint8_t *buf = encode_buf(want, &wire_len);
  struct wsc_dec *dec = wsc_dec_create();
  struct wsc_result result;
  assert(dec != nullptr);
  assert(first < wire_len);
  result = wsc_dec_feed(dec, buf, first);
  assert(result.err == WSC_OK);
  assert(result.frames_cnt == 0);
  result = wsc_dec_feed(dec, buf + first, wire_len - first);
  assert(result.err == WSC_OK);
  assert(result.frames_cnt == 1);
  assert_frame(&result.frames[0], want);
  wsc_dec_destroy(dec);
  free(buf);
}

static void test_rfc_unmasked_hello() {
  const uint8_t wire[] = {0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f};
  const uint8_t hello[] = {'H', 'e', 'l', 'l', 'o'};
  struct wsc_frame want = make_frame(true, WSC_OP_TEXT, hello, sizeof hello, nullptr);
  struct wsc_dec *dec = wsc_dec_create();
  struct wsc_result result;
  assert(dec != nullptr);
  result = wsc_dec_feed(dec, wire, sizeof wire);
  assert(result.err == WSC_OK);
  assert(result.frames_cnt == 1);
  assert_frame(&result.frames[0], &want);
  wsc_dec_destroy(dec);
}

static void test_rfc_masked_hello() {
  const uint8_t wire[] = {0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58};
  const uint8_t hello[] = {'H', 'e', 'l', 'l', 'o'};
  const uint8_t key[] = {0x37, 0xfa, 0x21, 0x3d};
  struct wsc_frame want = make_frame(true, WSC_OP_TEXT, hello, sizeof hello, key);
  struct wsc_dec *dec = wsc_dec_create();
  struct wsc_result result;
  assert(dec != nullptr);
  result = wsc_dec_feed(dec, wire, sizeof wire);
  assert(result.err == WSC_OK);
  assert(result.frames_cnt == 1);
  assert_frame(&result.frames[0], &want);
  wsc_dec_destroy(dec);
}

static void test_roundtrip_sizes() {
  const size_t sizes[] = {0, 1, LEN7_MAX, LEN7_MAX + 1, UINT16_MAX, (size_t)UINT16_MAX + 1};
  const uint8_t key[] = {1, 2, 3, 4};
  for (size_t idx = 0; idx < sizeof sizes / sizeof sizes[0]; idx++) {
    size_t length = sizes[idx];
    uint8_t *payload = nullptr;
    struct wsc_frame frame;
    if (length > 0) {
      payload = (uint8_t *)malloc(length);
      assert(payload != nullptr);
      for (size_t i = 0; i < length; i++) {
        payload[i] = (uint8_t)(i * 3U);
      }
    }
    frame = make_frame(true, WSC_OP_BIN, payload, length, nullptr);
    roundtrip(&frame);
    frame = make_frame(true, WSC_OP_BIN, payload, length, key);
    roundtrip(&frame);
    free(payload);
  }
}

static void test_header_length_bytes() {
  uint8_t one = 1;
  uint8_t mid[LEN7_MAX + 1];
  uint8_t *wide = nullptr;
  struct wsc_frame frame;
  size_t wire_len = 0;
  uint8_t *buf = nullptr;

  memset(mid, FILL_MID, sizeof mid);
  frame = make_frame(true, WSC_OP_BIN, &one, 1, nullptr);
  buf = encode_buf(&frame, &wire_len);
  assert(wire_len == HDR_BASE + 1);
  assert((buf[1] & MASK_BIT) == 0);
  assert((buf[1] & LEN7_MASK) == 1);
  free(buf);

  frame = make_frame(true, WSC_OP_BIN, mid, sizeof mid, nullptr);
  buf = encode_buf(&frame, &wire_len);
  assert(wire_len == HDR_BASE + LEN16_EXT + sizeof mid);
  assert(buf[1] == LEN16);
  free(buf);

  wide = (uint8_t *)malloc((size_t)UINT16_MAX + 1);
  assert(wide != nullptr);
  memset(wide, FILL_WIDE, (size_t)UINT16_MAX + 1);
  frame = make_frame(true, WSC_OP_BIN, wide, (size_t)UINT16_MAX + 1, nullptr);
  buf = encode_buf(&frame, &wire_len);
  assert(wire_len == HDR_BASE + LEN64_EXT + (size_t)UINT16_MAX + 1);
  assert(buf[1] == LEN64);
  free(buf);
  free(wide);
}

static void test_split_and_empty_feed() {
  const uint8_t hello[] = {'h', 'i'};
  const uint8_t key[] = {9, 8, 7, 6};
  struct wsc_frame want = make_frame(true, WSC_OP_TEXT, hello, sizeof hello, key);
  size_t wire_len = 0;
  uint8_t *buf = encode_buf(&want, &wire_len);
  struct wsc_dec *dec = wsc_dec_create();
  struct wsc_result result;
  assert(dec != nullptr);

  result = wsc_dec_feed(dec, buf, 1);
  assert(result.err == WSC_OK);
  assert(result.frames_cnt == 0);
  result = wsc_dec_feed(dec, nullptr, 0);
  assert(result.err == WSC_OK);
  assert(result.frames_cnt == 0);
  result = wsc_dec_feed(dec, buf + 1, 1);
  assert(result.err == WSC_OK);
  assert(result.frames_cnt == 0);
  result = wsc_dec_feed(dec, buf + 2, wire_len - 2);
  assert(result.err == WSC_OK);
  assert(result.frames_cnt == 1);
  assert_frame(&result.frames[0], &want);

  wsc_dec_destroy(dec);
  free(buf);

  roundtrip_split(&want, 3);
}

static void test_byte_at_a_time() {
  const uint8_t hello[] = {'h', 'i', '!'};
  const uint8_t key[] = {0x11, 0x22, 0x33, 0x44};
  struct wsc_frame want = make_frame(true, WSC_OP_TEXT, hello, sizeof hello, key);
  size_t wire_len = 0;
  uint8_t *buf = encode_buf(&want, &wire_len);
  struct wsc_dec *dec = wsc_dec_create();
  struct wsc_result result;
  assert(dec != nullptr);
  for (size_t i = 0; i < wire_len; i++) {
    result = wsc_dec_feed(dec, buf + i, 1);
    assert(result.err == WSC_OK);
    if (i + 1 < wire_len) {
      assert(result.frames_cnt == 0);
    } else {
      assert(result.frames_cnt == 1);
      assert_frame(&result.frames[0], &want);
    }
  }
  wsc_dec_destroy(dec);
  free(buf);
}

static void test_rsv_opcode_fin() {
  const uint8_t payload[] = {0xff, 0x00};
  struct wsc_frame frame = make_frame(false, 0x3, payload, sizeof payload, nullptr);
  frame.rsv1 = true;
  frame.rsv3 = true;
  roundtrip(&frame);
  frame = make_frame(true, WSC_OP_PING, payload, sizeof payload, nullptr);
  roundtrip(&frame);
  frame = make_frame(false, WSC_OP_CLOSE, payload, sizeof payload, nullptr);
  roundtrip(&frame);
}

static void test_two_frames_one_feed() {
  const uint8_t first_payload[] = {'a'};
  const uint8_t second_payload[] = {'b', 'b'};
  struct wsc_frame first =
      make_frame(true, WSC_OP_TEXT, first_payload, sizeof first_payload, nullptr);
  struct wsc_frame second =
      make_frame(true, WSC_OP_BIN, second_payload, sizeof second_payload, nullptr);
  size_t first_len = 0;
  size_t second_len = 0;
  uint8_t *first_buf = encode_buf(&first, &first_len);
  uint8_t *second_buf = encode_buf(&second, &second_len);
  uint8_t *both = (uint8_t *)malloc(first_len + second_len);
  struct wsc_dec *dec = wsc_dec_create();
  struct wsc_result result;
  assert(both != nullptr);
  assert(dec != nullptr);
  memcpy(both, first_buf, first_len);
  memcpy(both + first_len, second_buf, second_len);
  result = wsc_dec_feed(dec, both, first_len + second_len);
  assert(result.err == WSC_OK);
  assert(result.frames_cnt == 2);
  assert_frame(&result.frames[0], &first);
  assert_frame(&result.frames[1], &second);
  wsc_dec_destroy(dec);
  free(both);
  free(first_buf);
  free(second_buf);
}

static void test_non_minimal_len16() {
  uint8_t buf[HDR_BASE + LEN16_EXT + 1];
  const uint8_t payload[] = {0x01};
  size_t wire_len =
      craft(buf, sizeof buf, true, 0, WSC_OP_BIN, nullptr, LEN16, payload, sizeof payload);
  struct wsc_dec *dec = wsc_dec_create();
  struct wsc_result result;
  assert(dec != nullptr);
  result = wsc_dec_feed(dec, buf, wire_len);
  assert(result.err == WSC_ERR_NONMINIMAL);
  assert(result.frames_cnt == 0);
  result = wsc_dec_feed(dec, buf, wire_len);
  assert(result.err == WSC_ERR_NONMINIMAL);
  wsc_dec_destroy(dec);
}

static void test_non_minimal_len64() {
  uint8_t buf[HDR_BASE + LEN64_EXT + 1];
  const uint8_t payload[] = {0x11};
  size_t wire_len =
      craft(buf, sizeof buf, true, 0, WSC_OP_BIN, nullptr, LEN64, payload, sizeof payload);
  struct wsc_dec *dec = wsc_dec_create();
  struct wsc_result result;
  assert(dec != nullptr);
  result = wsc_dec_feed(dec, buf, wire_len);
  assert(result.err == WSC_ERR_NONMINIMAL);
  wsc_dec_destroy(dec);
}

static void test_len64_msb() {
  uint8_t buf[HDR_BASE + LEN64_EXT];
  struct wsc_dec *dec = wsc_dec_create();
  struct wsc_result result;
  memset(buf, 0, sizeof buf);
  buf[0] = (uint8_t)(FIN_BIT | WSC_OP_BIN);
  buf[1] = LEN64;
  buf[2] = LEN64_MSB_BYTE;
  assert(dec != nullptr);
  result = wsc_dec_feed(dec, buf, sizeof buf);
  assert(result.err == WSC_ERR_LEN64_MSB);
  wsc_dec_destroy(dec);
}

static void test_masked_raw_header() {
  const uint8_t key[] = {0x01, 0x02, 0x03, 0x04};
  const uint8_t payload[] = {0x10, 0x20, 0x30, 0x40, 0x50};
  uint8_t buf[HDR_BASE + WSC_MASK_LEN + sizeof payload];
  size_t wire_len = craft(buf, sizeof buf, true, 0, WSC_OP_BIN, key, (unsigned)sizeof payload,
                          payload, sizeof payload);
  struct wsc_frame want = make_frame(true, WSC_OP_BIN, payload, sizeof payload, key);
  struct wsc_dec *dec = wsc_dec_create();
  struct wsc_result result;
  assert(dec != nullptr);
  result = wsc_dec_feed(dec, buf, wire_len);
  assert(result.err == WSC_OK);
  assert(result.frames_cnt == 1);
  assert_frame(&result.frames[0], &want);
  wsc_dec_destroy(dec);
}

int main() {
  test_rfc_unmasked_hello();
  test_rfc_masked_hello();
  test_roundtrip_sizes();
  test_header_length_bytes();
  test_split_and_empty_feed();
  test_byte_at_a_time();
  test_rsv_opcode_fin();
  test_two_frames_one_feed();
  test_non_minimal_len16();
  test_non_minimal_len64();
  test_len64_msb();
  test_masked_raw_header();
  return 0;
}
