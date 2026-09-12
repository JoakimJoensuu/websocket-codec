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

struct decoder_ctx {
  uint8_t storage[WSC_TEST_ARENA_SIZE];
};

static struct wsc_decoder *decoder_open(struct decoder_ctx *ctx) {
  return wsc_decoder_create(ctx->storage, sizeof(ctx->storage));
}

static uint8_t *encode_wire(const struct wsc_frame *frame, size_t *wire_length) {
  size_t encoded_length = wsc_encoded_frame_length(frame);
  uint8_t *wire = malloc(encoded_length);
  assert_that(wire, is_non_null);
  *wire_length = wsc_encode(wire, encoded_length, frame);
  return wire;
}

static void roundtrip(const struct wsc_frame *want) {
  size_t wire_length = 0;
  uint8_t *wire = encode_wire(want, &wire_length);
  struct decoder_ctx ctx;
  struct wsc_decoder *decoder = decoder_open(&ctx);
  struct wsc_decoding_result result;
  assert_that(decoder, is_non_null);
  result = wsc_decoder_feed(decoder, wire, wire_length);
  assert_that(result.status, is_equal_to(WSC_OK));
  assert_that(result.frames_count, is_equal_to(1));
  wsc_test_assert_frame(&result.frames[0], want);
  free(wire);
}

static void roundtrip_split(const struct wsc_frame *want, size_t first) {
  size_t wire_length = 0;
  uint8_t *wire = encode_wire(want, &wire_length);
  struct decoder_ctx ctx;
  struct wsc_decoder *decoder = decoder_open(&ctx);
  struct wsc_decoding_result result;
  assert_that(decoder, is_non_null);
  assert_that(first < wire_length, is_true);
  result = wsc_decoder_feed(decoder, wire, first);
  assert_that(result.status, is_equal_to(WSC_OK));
  assert_that(result.frames_count, is_equal_to(0));
  result = wsc_decoder_feed(decoder, wire + first, wire_length - first);
  assert_that(result.status, is_equal_to(WSC_OK));
  assert_that(result.frames_count, is_equal_to(1));
  wsc_test_assert_frame(&result.frames[0], want);
  free(wire);
}

Ensure(rfc_unmasked_hello) {
  const uint8_t wire[] = {0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f};
  const uint8_t hello[] = {'H', 'e', 'l', 'l', 'o'};
  struct wsc_frame want = wsc_test_make_frame(true, WSC_OPCODE_TEXT, hello, sizeof(hello), nullptr);
  struct decoder_ctx ctx;
  struct wsc_decoder *decoder = decoder_open(&ctx);
  struct wsc_decoding_result result;
  assert_that(decoder, is_non_null);
  result = wsc_decoder_feed(decoder, wire, sizeof(wire));
  assert_that(result.status, is_equal_to(WSC_OK));
  assert_that(result.frames_count, is_equal_to(1));
  wsc_test_assert_frame(&result.frames[0], &want);
}

Ensure(rfc_masked_hello) {
  const uint8_t wire[] = {0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58};
  const uint8_t hello[] = {'H', 'e', 'l', 'l', 'o'};
  const uint8_t key[] = {0x37, 0xfa, 0x21, 0x3d};
  struct wsc_frame want = wsc_test_make_frame(true, WSC_OPCODE_TEXT, hello, sizeof(hello), key);
  struct decoder_ctx ctx;
  struct wsc_decoder *decoder = decoder_open(&ctx);
  struct wsc_decoding_result result;
  assert_that(decoder, is_non_null);
  result = wsc_decoder_feed(decoder, wire, sizeof(wire));
  assert_that(result.status, is_equal_to(WSC_OK));
  assert_that(result.frames_count, is_equal_to(1));
  wsc_test_assert_frame(&result.frames[0], &want);
}

Ensure(roundtrip_sizes) {
  const size_t sizes[] = {0, 1, WSC_TEST_LENGTH7_MAX, WSC_TEST_LENGTH7_MAX + 1};
  const uint8_t key[] = {1, 2, 3, 4};
  for (size_t idx = 0; idx < sizeof(sizes) / sizeof(sizes[0]); idx++) {
    size_t length = sizes[idx];
    uint8_t *payload = nullptr;
    struct wsc_frame frame;
    if (length > 0) {
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
  struct decoder_ctx ctx;
  struct wsc_decoder *decoder = decoder_open(&ctx);
  struct wsc_decoding_result result;
  assert_that(decoder, is_non_null);

  result = wsc_decoder_feed(decoder, wire, 1);
  assert_that(result.status, is_equal_to(WSC_OK));
  assert_that(result.frames_count, is_equal_to(0));
  result = wsc_decoder_feed(decoder, nullptr, 0);
  assert_that(result.status, is_equal_to(WSC_OK));
  assert_that(result.frames_count, is_equal_to(0));
  result = wsc_decoder_feed(decoder, wire + 1, 1);
  assert_that(result.status, is_equal_to(WSC_OK));
  assert_that(result.frames_count, is_equal_to(0));
  result = wsc_decoder_feed(decoder, wire + 2, wire_length - 2);
  assert_that(result.status, is_equal_to(WSC_OK));
  assert_that(result.frames_count, is_equal_to(1));
  wsc_test_assert_frame(&result.frames[0], &want);

  free(wire);

  roundtrip_split(&want, 3);
}

Ensure(byte_at_a_time) {
  const uint8_t hello[] = {'h', 'i', '!'};
  const uint8_t key[] = {0x11, 0x22, 0x33, 0x44};
  struct wsc_frame want = wsc_test_make_frame(true, WSC_OPCODE_TEXT, hello, sizeof(hello), key);
  size_t wire_length = 0;
  uint8_t *wire = encode_wire(&want, &wire_length);
  struct decoder_ctx ctx;
  struct wsc_decoder *decoder = decoder_open(&ctx);
  struct wsc_decoding_result result;
  assert_that(decoder, is_non_null);
  for (size_t i = 0; i < wire_length; i++) {
    result = wsc_decoder_feed(decoder, wire + i, 1);
    assert_that(result.status, is_equal_to(WSC_OK));
    if (i + 1 < wire_length) {
      assert_that(result.frames_count, is_equal_to(0));
    } else {
      assert_that(result.frames_count, is_equal_to(1));
      wsc_test_assert_frame(&result.frames[0], &want);
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

Ensure(two_frames_one_feed) {
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
  struct decoder_ctx ctx;
  struct wsc_decoder *decoder = decoder_open(&ctx);
  struct wsc_decoding_result result;
  assert_that(both, is_non_null);
  assert_that(decoder, is_non_null);
  memcpy(both, first_wire, first_length);
  memcpy(both + first_length, second_wire, second_length);
  result = wsc_decoder_feed(decoder, both, first_length + second_length);
  assert_that(result.status, is_equal_to(WSC_OK));
  assert_that(result.frames_count, is_equal_to(2));
  wsc_test_assert_frame(&result.frames[0], &first);
  wsc_test_assert_frame(&result.frames[1], &second);
  free(both);
  free(first_wire);
  free(second_wire);
}

Ensure(non_minimal_length16) {
  uint8_t wire[WSC_TEST_HEADER_BASE + WSC_TEST_LENGTH16_EXT + 1];
  const uint8_t payload[] = {0x01};
  size_t wire_length = wsc_test_craft(wire, sizeof(wire), true, 0, WSC_OPCODE_BINARY, nullptr,
                                      WSC_TEST_LENGTH16, payload, sizeof(payload));
  struct decoder_ctx ctx;
  struct wsc_decoder *decoder = decoder_open(&ctx);
  struct wsc_decoding_result result;
  assert_that(decoder, is_non_null);
  result = wsc_decoder_feed(decoder, wire, wire_length);
  assert_that(result.status, is_equal_to(WSC_ERR_LENGTH_NOT_MINIMAL));
  assert_that(result.frames_count, is_equal_to(0));
  result = wsc_decoder_feed(decoder, wire, wire_length);
  assert_that(result.status, is_equal_to(WSC_ERR_LENGTH_NOT_MINIMAL));
}

Ensure(non_minimal_length64) {
  uint8_t wire[WSC_TEST_HEADER_BASE + WSC_TEST_LENGTH64_EXT + 1];
  const uint8_t payload[] = {0x11};
  size_t wire_length = wsc_test_craft(wire, sizeof(wire), true, 0, WSC_OPCODE_BINARY, nullptr,
                                      WSC_TEST_LENGTH64, payload, sizeof(payload));
  struct decoder_ctx ctx;
  struct wsc_decoder *decoder = decoder_open(&ctx);
  struct wsc_decoding_result result;
  assert_that(decoder, is_non_null);
  result = wsc_decoder_feed(decoder, wire, wire_length);
  assert_that(result.status, is_equal_to(WSC_ERR_LENGTH_NOT_MINIMAL));
}

Ensure(len64_msb) {
  uint8_t wire[WSC_TEST_HEADER_BASE + WSC_TEST_LENGTH64_EXT];
  struct decoder_ctx ctx;
  struct wsc_decoder *decoder = decoder_open(&ctx);
  struct wsc_decoding_result result;
  memset(wire, 0, sizeof(wire));
  wire[0] = (uint8_t)(WSC_TEST_FIN_BIT | WSC_OPCODE_BINARY);
  wire[1] = WSC_TEST_LENGTH64;
  wire[2] = WSC_TEST_LENGTH64_MSB_BYTE;
  assert_that(decoder, is_non_null);
  result = wsc_decoder_feed(decoder, wire, sizeof(wire));
  assert_that(result.status, is_equal_to(WSC_ERR_LENGTH64_MSB));
}

Ensure(masked_raw_header) {
  const uint8_t key[] = {0x01, 0x02, 0x03, 0x04};
  const uint8_t payload[] = {0x10, 0x20, 0x30, 0x40, 0x50};
  uint8_t wire[WSC_TEST_HEADER_BASE + WSC_MASKING_KEY_LENGTH + sizeof(payload)];
  size_t wire_length = wsc_test_craft(wire, sizeof(wire), true, 0, WSC_OPCODE_BINARY, key,
                                      (unsigned)sizeof(payload), payload, sizeof(payload));
  struct wsc_frame want =
      wsc_test_make_frame(true, WSC_OPCODE_BINARY, payload, sizeof(payload), key);
  struct decoder_ctx ctx;
  struct wsc_decoder *decoder = decoder_open(&ctx);
  struct wsc_decoding_result result;
  assert_that(decoder, is_non_null);
  result = wsc_decoder_feed(decoder, wire, wire_length);
  assert_that(result.status, is_equal_to(WSC_OK));
  assert_that(result.frames_count, is_equal_to(1));
  wsc_test_assert_frame(&result.frames[0], &want);
}

Ensure(caller_buffer_too_small) {
  uint8_t storage[WSC_TEST_ARENA_TOO_SMALL];
  assert_that(wsc_decoder_create(storage, sizeof(storage)), is_null);
}

Ensure(caller_buffer_roundtrip_and_split) {
  const uint8_t hello[] = {'h', 'i', '!'};
  const uint8_t key[] = {0x11, 0x22, 0x33, 0x44};
  struct wsc_frame want = wsc_test_make_frame(true, WSC_OPCODE_TEXT, hello, sizeof(hello), key);
  size_t wire_length = 0;
  uint8_t *wire = encode_wire(&want, &wire_length);
  uint8_t storage[WSC_TEST_ARENA_SIZE];
  struct wsc_decoder *decoder = wsc_decoder_create(storage, sizeof(storage));
  struct wsc_decoding_result result;
  assert_that(decoder, is_non_null);

  result = wsc_decoder_feed(decoder, wire, wire_length);
  assert_that(result.status, is_equal_to(WSC_OK));
  assert_that(result.frames_count, is_equal_to(1));
  wsc_test_assert_frame(&result.frames[0], &want);

  result = wsc_decoder_feed(decoder, wire, 1);
  assert_that(result.status, is_equal_to(WSC_OK));
  assert_that(result.frames_count, is_equal_to(0));
  result = wsc_decoder_feed(decoder, wire + 1, wire_length - 1);
  assert_that(result.status, is_equal_to(WSC_OK));
  assert_that(result.frames_count, is_equal_to(1));
  wsc_test_assert_frame(&result.frames[0], &want);

  free(wire);
}

Ensure(caller_buffer_two_frames) {
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
  uint8_t storage[WSC_TEST_ARENA_SIZE];
  struct wsc_decoder *decoder = wsc_decoder_create(storage, sizeof(storage));
  struct wsc_decoding_result result;
  assert_that(both, is_non_null);
  assert_that(decoder, is_non_null);
  memcpy(both, first_wire, first_length);
  memcpy(both + first_length, second_wire, second_length);
  result = wsc_decoder_feed(decoder, both, first_length + second_length);
  assert_that(result.status, is_equal_to(WSC_OK));
  assert_that(result.frames_count, is_equal_to(2));
  wsc_test_assert_frame(&result.frames[0], &first);
  wsc_test_assert_frame(&result.frames[1], &second);
  free(both);
  free(first_wire);
  free(second_wire);
}

Ensure(caller_buffer_complete_then_split) {
  const uint8_t first_payload[] = {'a'};
  const uint8_t second_payload[] = {'b', 'b', 'b'};
  struct wsc_frame first =
      wsc_test_make_frame(true, WSC_OPCODE_TEXT, first_payload, sizeof(first_payload), nullptr);
  struct wsc_frame second =
      wsc_test_make_frame(true, WSC_OPCODE_BINARY, second_payload, sizeof(second_payload), nullptr);
  size_t first_length = 0;
  size_t second_length = 0;
  uint8_t *first_wire = encode_wire(&first, &first_length);
  uint8_t *second_wire = encode_wire(&second, &second_length);
  uint8_t *both = malloc(first_length + second_length);
  uint8_t storage[WSC_TEST_ARENA_SIZE];
  struct wsc_decoder *decoder = wsc_decoder_create(storage, sizeof(storage));
  struct wsc_decoding_result result;
  assert_that(both, is_non_null);
  assert_that(decoder, is_non_null);
  memcpy(both, first_wire, first_length);
  memcpy(both + first_length, second_wire, second_length);

  result = wsc_decoder_feed(decoder, both, first_length + WSC_TEST_HEADER_BASE + 1);
  assert_that(result.status, is_equal_to(WSC_OK));
  assert_that(result.frames_count, is_equal_to(1));
  wsc_test_assert_frame(&result.frames[0], &first);

  result = wsc_decoder_feed(decoder, both + first_length + WSC_TEST_HEADER_BASE + 1,
                            second_length - WSC_TEST_HEADER_BASE - 1);
  assert_that(result.status, is_equal_to(WSC_OK));
  assert_that(result.frames_count, is_equal_to(1));
  wsc_test_assert_frame(&result.frames[0], &second);

  free(both);
  free(first_wire);
  free(second_wire);
}

Ensure(caller_buffer_no_memory) {
  const uint8_t payload[WSC_TEST_LENGTH7_MAX] = {0};
  struct wsc_frame frame =
      wsc_test_make_frame(true, WSC_OPCODE_BINARY, payload, sizeof(payload), nullptr);
  size_t wire_length = 0;
  uint8_t *wire = encode_wire(&frame, &wire_length);
  uint8_t storage[WSC_TEST_ARENA_TIGHT];
  struct wsc_decoder *decoder = wsc_decoder_create(storage, sizeof(storage));
  struct wsc_decoding_result result;
  assert_that(wire, is_non_null);
  assert_that(decoder, is_non_null);
  result = wsc_decoder_feed(decoder, wire, wire_length);
  assert_that(result.status, is_equal_to(WSC_ERR_NO_MEMORY));
  free(wire);
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
  add_test(suite, two_frames_one_feed);
  add_test(suite, non_minimal_length16);
  add_test(suite, non_minimal_length64);
  add_test(suite, len64_msb);
  add_test(suite, masked_raw_header);
  add_test(suite, caller_buffer_too_small);
  add_test(suite, caller_buffer_roundtrip_and_split);
  add_test(suite, caller_buffer_two_frames);
  add_test(suite, caller_buffer_complete_then_split);
  add_test(suite, caller_buffer_no_memory);
  auto reporter = create_text_reporter();
  int result = run_test_suite(suite, reporter);
  destroy_test_suite(suite);
  destroy_reporter(reporter);
  return result;
}
