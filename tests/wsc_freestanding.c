#include <cgreen/assertions.h>
#include <cgreen/constraint_syntax_helpers.h>
#include <cgreen/reporter.h>
#include <cgreen/runner.h>
#include <cgreen/suite.h>
#include <cgreen/text_reporter.h>
#include <cgreen/unit.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wsc.h>

#include "wsc_test.h"

enum { PAYLOAD_CAPACITY = 256 };

struct opened {
  struct wsc_decoder decoder;
  uint8_t payload[PAYLOAD_CAPACITY];
};

static uint8_t *encode_wire(const struct wsc_frame *frame, size_t *wire_length) {
  uint64_t encoded_length = wsc_encoded_frame_length(frame);
  uint8_t *wire = malloc((size_t)encoded_length);
  assert_that(wire, is_non_null);
  *wire_length = wsc_encode(wire, frame);
  return wire;
}

static struct wsc_decoding_result feed(struct opened *opened, const uint8_t *source,
                                       size_t source_length) {
  return wsc_decoder_feed(&opened->decoder, source, source_length);
}

static void open_decoder(struct opened *opened) {
  wsc_decoder_init(&opened->decoder, opened->payload, sizeof(opened->payload));
}

static void roundtrip(const struct wsc_frame *want) {
  size_t wire_length = 0;
  uint8_t *wire = encode_wire(want, &wire_length);
  struct opened opened;
  struct wsc_decoding_result result;
  open_decoder(&opened);
  result = feed(&opened, wire, wire_length);
  assert_that(result.status, is_equal_to(WSC_OK));
  assert_that(result.source_consumed, is_equal_to(wire_length));
  wsc_test_assert_frame(&result.frame, want);
  free(wire);
}

static void roundtrip_split(const struct wsc_frame *want, size_t first) {
  size_t wire_length = 0;
  uint8_t *wire = encode_wire(want, &wire_length);
  struct opened opened;
  struct wsc_decoding_result result;
  open_decoder(&opened);
  assert_that(first < wire_length, is_true);
  result = feed(&opened, wire, first);
  assert_that(result.status, is_equal_to(WSC_INCOMPLETE));
  assert_that(result.source_consumed, is_equal_to(first));
  result = feed(&opened, wire + first, wire_length - first);
  assert_that(result.status, is_equal_to(WSC_OK));
  wsc_test_assert_frame(&result.frame, want);
  free(wire);
}

Ensure(rfc_unmasked_hello) {
  const uint8_t wire[] = {0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f};
  const uint8_t hello[] = {'H', 'e', 'l', 'l', 'o'};
  struct wsc_frame want = wsc_test_make_frame(true, WSC_OPCODE_TEXT, hello, sizeof(hello), nullptr);
  struct opened opened;
  struct wsc_decoding_result result;
  open_decoder(&opened);
  result = feed(&opened, wire, sizeof(wire));
  assert_that(result.status, is_equal_to(WSC_OK));
  wsc_test_assert_frame(&result.frame, &want);
}

Ensure(rfc_masked_hello) {
  const uint8_t wire[] = {0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58};
  const uint8_t hello[] = {'H', 'e', 'l', 'l', 'o'};
  const uint8_t key[] = {0x37, 0xfa, 0x21, 0x3d};
  struct wsc_frame want = wsc_test_make_frame(true, WSC_OPCODE_TEXT, hello, sizeof(hello), key);
  struct opened opened;
  struct wsc_decoding_result result;
  open_decoder(&opened);
  result = feed(&opened, wire, sizeof(wire));
  assert_that(result.status, is_equal_to(WSC_OK));
  wsc_test_assert_frame(&result.frame, &want);
}

Ensure(roundtrip_sizes) {
  const size_t sizes[] = {0, 1, WSC_TEST_LENGTH7_MAX, WSC_TEST_LENGTH7_MAX + 1};
  const uint8_t key[] = {1, 2, 3, 4};
  for (size_t index = 0; index < sizeof(sizes) / sizeof(sizes[0]); index++) {
    size_t length = sizes[index];
    uint8_t *payload = nullptr;
    struct wsc_frame frame;
    if (0 < length) {
      payload = malloc(length);
      assert_that(payload, is_non_null);
      for (size_t i = 0; i < length; i++) {
        payload[i] = (uint8_t)(i * 3U);
      }
    }
    frame = wsc_test_make_frame(true, WSC_OPCODE_BINARY, payload, length, nullptr);
    roundtrip(&frame);
    frame = wsc_test_make_frame(true, WSC_OPCODE_BINARY, payload, length, key);
    roundtrip(&frame);
    free(payload);
  }
}

Ensure(header_length_bytes) {
  uint8_t one = 1;
  uint8_t mid[WSC_TEST_LENGTH7_MAX + 1];
  uint8_t *wide = nullptr;
  struct wsc_frame frame;
  size_t wire_length = 0;
  uint8_t *wire = nullptr;

  memset(mid, WSC_TEST_FILL_MID, sizeof(mid));
  frame = wsc_test_make_frame(true, WSC_OPCODE_BINARY, &one, 1, nullptr);
  wire = encode_wire(&frame, &wire_length);
  assert_that(wire_length, is_equal_to(WSC_TEST_HEADER_BASE + 1));
  assert_that((wire[1] & WSC_TEST_MASK_BIT), is_equal_to(0));
  assert_that((wire[1] & WSC_TEST_LENGTH7_MASK), is_equal_to(1));
  free(wire);

  frame = wsc_test_make_frame(true, WSC_OPCODE_BINARY, mid, sizeof(mid), nullptr);
  wire = encode_wire(&frame, &wire_length);
  assert_that(wire_length, is_equal_to(WSC_TEST_HEADER_BASE + WSC_TEST_LENGTH16_EXT + sizeof(mid)));
  assert_that(wire[1], is_equal_to(WSC_TEST_LENGTH16));
  free(wire);

  wide = malloc((size_t)UINT16_MAX + 1);
  assert_that(wide, is_non_null);
  memset(wide, WSC_TEST_FILL_WIDE, (size_t)UINT16_MAX + 1);
  frame = wsc_test_make_frame(true, WSC_OPCODE_BINARY, wide, (size_t)UINT16_MAX + 1, nullptr);
  wire = encode_wire(&frame, &wire_length);
  assert_that(wire_length,
              is_equal_to(WSC_TEST_HEADER_BASE + WSC_TEST_LENGTH64_EXT + (size_t)UINT16_MAX + 1));
  assert_that(wire[1], is_equal_to(WSC_TEST_LENGTH64));
  free(wire);
  free(wide);
}

Ensure(split_and_empty_feed) {
  const uint8_t hello[] = {'h', 'i'};
  const uint8_t key[] = {9, 8, 7, 6};
  struct wsc_frame want = wsc_test_make_frame(true, WSC_OPCODE_TEXT, hello, sizeof(hello), key);
  size_t wire_length = 0;
  uint8_t *wire = encode_wire(&want, &wire_length);
  struct opened opened;
  struct wsc_decoding_result result;
  open_decoder(&opened);

  result = feed(&opened, wire, 1);
  assert_that(result.status, is_equal_to(WSC_INCOMPLETE));
  assert_that(result.source_consumed, is_equal_to(1));
  result = feed(&opened, nullptr, 0);
  assert_that(result.status, is_equal_to(WSC_INCOMPLETE));
  result = feed(&opened, wire + 1, 1);
  assert_that(result.status, is_equal_to(WSC_INCOMPLETE));
  result = feed(&opened, wire + 2, wire_length - 2);
  assert_that(result.status, is_equal_to(WSC_OK));
  wsc_test_assert_frame(&result.frame, &want);

  free(wire);

  roundtrip_split(&want, 3);
}

Ensure(byte_at_a_time) {
  const uint8_t hello[] = {'h', 'i', '!'};
  const uint8_t key[] = {0x11, 0x22, 0x33, 0x44};
  struct wsc_frame want = wsc_test_make_frame(true, WSC_OPCODE_TEXT, hello, sizeof(hello), key);
  size_t wire_length = 0;
  uint8_t *wire = encode_wire(&want, &wire_length);
  struct opened opened;
  struct wsc_decoding_result result;
  open_decoder(&opened);
  for (size_t i = 0; i < wire_length; i++) {
    result = feed(&opened, wire + i, 1);
    assert_that(result.source_consumed, is_equal_to(1));
    if (i + 1 < wire_length) {
      assert_that(result.status, is_equal_to(WSC_INCOMPLETE));
    } else {
      assert_that(result.status, is_equal_to(WSC_OK));
      wsc_test_assert_frame(&result.frame, &want);
    }
  }
  free(wire);
}

Ensure(rsv_opcode_fin) {
  const uint8_t payload[] = {0xff, 0x00};
  struct wsc_frame frame = wsc_test_make_frame(false, 0x3, payload, sizeof(payload), nullptr);
  frame.rsv1 = true;
  frame.rsv3 = true;
  roundtrip(&frame);
  frame = wsc_test_make_frame(true, WSC_OPCODE_PING, payload, sizeof(payload), nullptr);
  roundtrip(&frame);
  frame = wsc_test_make_frame(false, WSC_OPCODE_CLOSE, payload, sizeof(payload), nullptr);
  roundtrip(&frame);
}

Ensure(one_frame_per_feed) {
  const uint8_t first_payload[] = {'a'};
  const uint8_t second_payload[] = {'b', 'b'};
  struct wsc_frame first =
      wsc_test_make_frame(true, WSC_OPCODE_TEXT, first_payload, sizeof(first_payload), nullptr);
  struct wsc_frame second =
      wsc_test_make_frame(true, WSC_OPCODE_BINARY, second_payload, sizeof(second_payload), nullptr);
  size_t first_length = 0;
  size_t second_length = 0;
  uint8_t *first_wire = encode_wire(&first, &first_length);
  uint8_t *second_wire = encode_wire(&second, &second_length);
  uint8_t *both = malloc(first_length + second_length);
  struct opened opened;
  struct wsc_decoding_result result;
  assert_that(both, is_non_null);
  open_decoder(&opened);
  memcpy(both, first_wire, first_length);
  memcpy(both + first_length, second_wire, second_length);

  result = feed(&opened, both, first_length + second_length);
  assert_that(result.status, is_equal_to(WSC_OK));
  assert_that(result.source_consumed, is_equal_to(first_length));
  wsc_test_assert_frame(&result.frame, &first);

  result = feed(&opened, both + first_length, second_length);
  assert_that(result.status, is_equal_to(WSC_OK));
  wsc_test_assert_frame(&result.frame, &second);

  free(both);
  free(first_wire);
  free(second_wire);
}

Ensure(partial_payload) {
  const uint8_t body[] = {'h', 'i', '!'};
  struct wsc_frame want = wsc_test_make_frame(true, WSC_OPCODE_TEXT, body, sizeof(body), nullptr);
  size_t wire_length = 0;
  uint8_t *wire = encode_wire(&want, &wire_length);
  size_t header_length = wire_length - sizeof(body);
  size_t first = header_length + 1;
  struct opened opened;
  struct wsc_decoding_result result;
  open_decoder(&opened);

  result = feed(&opened, wire, first);
  assert_that(result.status, is_equal_to(WSC_INCOMPLETE));
  assert_that(result.source_consumed, is_equal_to(first));

  result = feed(&opened, wire + first, wire_length - first);
  assert_that(result.status, is_equal_to(WSC_OK));
  wsc_test_assert_frame(&result.frame, &want);
  free(wire);
}

enum {
  exceeds_payload_length = 16,
  exceeds_small_capacity = 4,
  exceeds_fill           = 0x5a,
  split_fill             = 0x11,
};

Ensure(payload_exceeds_capacity) {
  uint8_t body[exceeds_payload_length];
  struct wsc_frame want;
  size_t wire_length = 0;
  uint8_t *wire = nullptr;
  size_t header_length = 0;
  struct wsc_decoder decoder;
  uint8_t small[exceeds_small_capacity];
  uint8_t large[sizeof(body)];
  struct wsc_decoding_result result;
  memset(body, exceeds_fill, sizeof(body));
  want = wsc_test_make_frame(true, WSC_OPCODE_BINARY, body, sizeof(body), nullptr);
  wire = encode_wire(&want, &wire_length);
  header_length = wire_length - sizeof(body);
  wsc_decoder_init(&decoder, small, sizeof(small));

  result = wsc_decoder_feed(&decoder, wire, wire_length);
  assert_that(result.status, is_equal_to(WSC_ERR_PAYLOAD_EXCEEDS_CAPACITY));
  assert_that(result.source_consumed, is_equal_to(header_length));

  wsc_decoder_set_payload_buffer(&decoder, large, sizeof(large));
  result = wsc_decoder_feed(&decoder, wire + header_length, wire_length - header_length);
  assert_that(result.status, is_equal_to(WSC_OK));
  wsc_test_assert_frame(&result.frame, &want);
  free(wire);
}

Ensure(payload_exceeds_after_split_header) {
  enum { first_byte = 1 };
  uint8_t body[exceeds_payload_length];
  struct wsc_frame want;
  size_t wire_length = 0;
  uint8_t *wire = nullptr;
  size_t header_length = 0;
  struct wsc_decoder decoder;
  uint8_t small[exceeds_small_capacity];
  uint8_t large[sizeof(body)];
  struct wsc_decoding_result result;
  struct wsc_decoding_result again;
  memset(body, split_fill, sizeof(body));
  want = wsc_test_make_frame(true, WSC_OPCODE_BINARY, body, sizeof(body), nullptr);
  wire = encode_wire(&want, &wire_length);
  header_length = wire_length - sizeof(body);
  wsc_decoder_init(&decoder, small, sizeof(small));

  result = wsc_decoder_feed(&decoder, wire, first_byte);
  assert_that(result.status, is_equal_to(WSC_INCOMPLETE));
  assert_that(result.source_consumed, is_equal_to(first_byte));

  again = wsc_decoder_feed(&decoder, wire + first_byte, wire_length - first_byte);
  assert_that(again.status, is_equal_to(WSC_ERR_PAYLOAD_EXCEEDS_CAPACITY));
  assert_that(again.source_consumed, is_equal_to(header_length - first_byte));

  wsc_decoder_set_payload_buffer(&decoder, large, sizeof(large));
  result = wsc_decoder_feed(&decoder, wire + header_length, wire_length - header_length);
  assert_that(result.status, is_equal_to(WSC_OK));
  wsc_test_assert_frame(&result.frame, &want);
  free(wire);
}

Ensure(non_minimal_length16) {
  uint8_t wire[WSC_TEST_HEADER_BASE + WSC_TEST_LENGTH16_EXT + 1];
  const uint8_t payload[] = {0x01};
  size_t wire_length = wsc_test_craft(wire, sizeof(wire), true, 0, WSC_OPCODE_BINARY, nullptr,
                                      WSC_TEST_LENGTH16, payload, sizeof(payload));
  struct opened opened;
  struct wsc_decoding_result result;
  open_decoder(&opened);
  result = feed(&opened, wire, wire_length);
  assert_that(result.status, is_equal_to(WSC_ERR_LENGTH_NOT_MINIMAL));
  result = feed(&opened, wire, wire_length);
  assert_that(result.status, is_equal_to(WSC_ERR_LENGTH_NOT_MINIMAL));
}

Ensure(non_minimal_length64) {
  uint8_t wire[WSC_TEST_HEADER_BASE + WSC_TEST_LENGTH64_EXT + 1];
  const uint8_t payload[] = {0x11};
  size_t wire_length = wsc_test_craft(wire, sizeof(wire), true, 0, WSC_OPCODE_BINARY, nullptr,
                                      WSC_TEST_LENGTH64, payload, sizeof(payload));
  struct opened opened;
  struct wsc_decoding_result result;
  open_decoder(&opened);
  result = feed(&opened, wire, wire_length);
  assert_that(result.status, is_equal_to(WSC_ERR_LENGTH_NOT_MINIMAL));
}

Ensure(length64_msb) {
  uint8_t wire[WSC_TEST_HEADER_BASE + WSC_TEST_LENGTH64_EXT];
  struct opened opened;
  struct wsc_decoding_result result;
  memset(wire, 0, sizeof(wire));
  wire[0] = (uint8_t)(WSC_TEST_FIN_BIT | WSC_OPCODE_BINARY);
  wire[1] = WSC_TEST_LENGTH64;
  wire[2] = WSC_TEST_LENGTH64_MSB_BYTE;
  open_decoder(&opened);
  result = feed(&opened, wire, sizeof(wire));
  assert_that(result.status, is_equal_to(WSC_ERR_LENGTH64_MSB));
}

#if SIZE_MAX < UINT64_MAX
Ensure(length_exceeds_size) {
  uint8_t wire[WSC_TEST_HEADER_BASE + WSC_TEST_LENGTH64_EXT];
  struct opened opened;
  struct wsc_decoding_result result;
  memset(wire, 0, sizeof(wire));
  wire[0] = (uint8_t)(WSC_TEST_FIN_BIT | WSC_OPCODE_BINARY);
  wire[1] = WSC_TEST_LENGTH64;
  wsc_test_write_uint64(wire + WSC_TEST_HEADER_BASE, (uint64_t)SIZE_MAX + 1);
  open_decoder(&opened);
  result = feed(&opened, wire, sizeof(wire));
  assert_that(result.status, is_equal_to(WSC_ERR_LENGTH_EXCEEDS_SIZE));
  assert_that(result.source_consumed, is_equal_to(sizeof(wire)));
  result = feed(&opened, wire, sizeof(wire));
  assert_that(result.status, is_equal_to(WSC_ERR_LENGTH_EXCEEDS_SIZE));
  assert_that(result.source_consumed, is_equal_to(0));
}
#endif

Ensure(masked_raw_header) {
  const uint8_t key[] = {0x01, 0x02, 0x03, 0x04};
  const uint8_t payload[] = {0x10, 0x20, 0x30, 0x40, 0x50};
  uint8_t wire[WSC_TEST_HEADER_BASE + WSC_MASKING_KEY_LENGTH + sizeof(payload)];
  size_t wire_length = wsc_test_craft(wire, sizeof(wire), true, 0, WSC_OPCODE_BINARY, key,
                                      (unsigned)sizeof(payload), payload, sizeof(payload));
  struct wsc_frame want =
      wsc_test_make_frame(true, WSC_OPCODE_BINARY, payload, sizeof(payload), key);
  struct opened opened;
  struct wsc_decoding_result result;
  open_decoder(&opened);
  result = feed(&opened, wire, wire_length);
  assert_that(result.status, is_equal_to(WSC_OK));
  wsc_test_assert_frame(&result.frame, &want);
}

int main() {
  auto suite = create_test_suite();
  add_test(suite, rfc_unmasked_hello);
  add_test(suite, rfc_masked_hello);
  add_test(suite, roundtrip_sizes);
  add_test(suite, header_length_bytes);
  add_test(suite, split_and_empty_feed);
  add_test(suite, byte_at_a_time);
  add_test(suite, rsv_opcode_fin);
  add_test(suite, one_frame_per_feed);
  add_test(suite, partial_payload);
  add_test(suite, payload_exceeds_capacity);
  add_test(suite, payload_exceeds_after_split_header);
  add_test(suite, non_minimal_length16);
  add_test(suite, non_minimal_length64);
  add_test(suite, length64_msb);
#if SIZE_MAX < UINT64_MAX
  add_test(suite, length_exceeds_size);
#endif
  add_test(suite, masked_raw_header);
  auto reporter = create_text_reporter();
  int result = run_test_suite(suite, reporter);
  destroy_test_suite(suite);
  destroy_reporter(reporter);
  return result;
}
