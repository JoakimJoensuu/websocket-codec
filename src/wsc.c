#include "wsc.h"

#ifdef WSC_HOSTED
#include <stdlib.h>
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

enum header_section_lengths : unsigned {
  HEADER_BASE_LENGTH    = 2,
  LENGTH16_FIELD_LENGTH = 2,
  LENGTH64_FIELD_LENGTH = 8,
  HEADER_MAX_LENGTH     = HEADER_BASE_LENGTH + LENGTH64_FIELD_LENGTH + WSC_MASKING_KEY_LENGTH,
};

enum payload_length_codes : unsigned {
  LENGTH16_CODE = 126,
  LENGTH64_CODE = 127,
};

enum header_first_byte_masks : uint8_t {
  FIN_BIT     = 0b10000000,
  RSV1_BIT    = 0b01000000,
  RSV2_BIT    = 0b00100000,
  RSV3_BIT    = 0b00010000,
  OPCODE_MASK = 0b00001111,
};

enum header_second_byte_masks : uint8_t {
  MASK_BIT     = 0x80,
  LENGTH7_MASK = 0x7F,
};

enum : uint64_t {
  LENGTH7_MAX  = 125,
  LENGTH64_MSB = 0x8000000000000000,
  LENGTH64_MAX = LENGTH64_MSB - 1,
};

enum : unsigned { BYTE_BASE = 256 };

[[noreturn]] static void trap() {
#ifdef WSC_HOSTED
  abort();
#else
  unreachable();
#endif
}

static size_t minimum(size_t left, size_t right) {
  return left < right ? left : right;
}

static size_t memcpy_minimum(void *destination, size_t destination_length, const void *source,
                             size_t source_length) {
  size_t copy_length = minimum(destination_length, source_length);
  memcpy(destination, source, copy_length);
  return copy_length;
}

static uint16_t extended_payload_length16(const uint8_t *field) {
  return (uint16_t)(((unsigned)field[0] * BYTE_BASE) + field[1]);
}

static uint64_t extended_payload_length64(const uint8_t *field) {
  uint64_t value = 0;
  for (int i = 0; i < (int)sizeof(uint64_t); i++) {
    value = (value * BYTE_BASE) + field[i];
  }
  return value;
}

static void mask(uint8_t *data, size_t length, const uint8_t key[WSC_MASKING_KEY_LENGTH]) {
  for (size_t i = 0; i < length; i++) {
    data[i] = (uint8_t)((unsigned)data[i] ^ key[i & (WSC_MASKING_KEY_LENGTH - 1U)]);
  }
}

static void unmask(struct wsc_frame *frame, uint8_t *payload) {
  mask(payload, (size_t)frame->payload_length, frame->masking_key);
}

static size_t header_length(unsigned byte1) {
  const uint8_t length_field = byte1 & LENGTH7_MASK;

  size_t header_length = HEADER_BASE_LENGTH;
  if (length_field == LENGTH16_CODE) {
    header_length += LENGTH16_FIELD_LENGTH;
  } else if (length_field == LENGTH64_CODE) {
    header_length += LENGTH64_FIELD_LENGTH;
  }

  bool masked = (byte1 & MASK_BIT) != 0;
  if (masked) {
    header_length += WSC_MASKING_KEY_LENGTH;
  }

  return header_length;
}

static enum wsc_status parse_payload_length(const uint8_t *header, uint64_t *payload_length) {
  uint8_t byte1 = header[1];
  const uint8_t length_field = byte1 & LENGTH7_MASK;

  if (length_field == LENGTH16_CODE) {
    const uint8_t *extended_length_field = header + HEADER_BASE_LENGTH;
    *payload_length = extended_payload_length16(extended_length_field);
    if (*payload_length <= LENGTH7_MAX) {
      return WSC_ERR_PROTOCOL_LENGTH_NOT_MINIMAL;
    }
  } else if (length_field == LENGTH64_CODE) {
    const uint8_t *extended_length_field = header + HEADER_BASE_LENGTH;
    *payload_length = extended_payload_length64(extended_length_field);
    if ((*payload_length & LENGTH64_MSB) != 0) {
      return WSC_ERR_PROTOCOL_LENGTH64_MSB;
    }
    if (*payload_length <= UINT16_MAX) {
      return WSC_ERR_PROTOCOL_LENGTH_NOT_MINIMAL;
    }
  } else {
    *payload_length = length_field;
  }

  if (SIZE_MAX < *payload_length) {
    *payload_length = 0;
    return WSC_ERR_LENGTH_EXCEEDS_SIZE;
  }

  return WSC_OK;
}

static uint64_t encoded_frame_length(const struct wsc_frame *frame) {
  if (frame == nullptr) trap();
  if (0 < frame->payload_length && frame->payload == nullptr) trap();
  if (((unsigned)frame->opcode & ~(unsigned)OPCODE_MASK) != 0) trap();
  if (LENGTH64_MAX < frame->payload_length) trap();

  uint64_t header_length = HEADER_BASE_LENGTH;
  if (LENGTH7_MAX < frame->payload_length) {
    header_length +=
        UINT16_MAX < frame->payload_length ? LENGTH64_FIELD_LENGTH : LENGTH16_FIELD_LENGTH;
  }
  if (frame->masked) {
    header_length += WSC_MASKING_KEY_LENGTH;
  }
  return header_length + frame->payload_length;
}

static size_t encode_header(uint8_t header[HEADER_MAX_LENGTH], const struct wsc_frame *frame) {
  size_t header_length = HEADER_BASE_LENGTH;

  header[0] =
      (uint8_t)((frame->fin ? (unsigned)FIN_BIT : 0U) | (frame->rsv1 ? (unsigned)RSV1_BIT : 0U) |
                (frame->rsv2 ? (unsigned)RSV2_BIT : 0U) | (frame->rsv3 ? (unsigned)RSV3_BIT : 0U) |
                ((unsigned)frame->opcode & OPCODE_MASK));

  if (frame->payload_length <= LENGTH7_MAX) {
    header[1] = (uint8_t)frame->payload_length;
  } else if (frame->payload_length <= UINT16_MAX) {
    header[1] = LENGTH16_CODE;
    header[HEADER_BASE_LENGTH] = (uint8_t)(frame->payload_length / BYTE_BASE);
    header[HEADER_BASE_LENGTH + 1] = (uint8_t)(frame->payload_length % BYTE_BASE);
    header_length = HEADER_BASE_LENGTH + LENGTH16_FIELD_LENGTH;
  } else {
    header[1] = LENGTH64_CODE;
    {
      uint64_t value = frame->payload_length;
      for (int i = (int)sizeof(uint64_t) - 1; 0 <= i; i--) {
        header[HEADER_BASE_LENGTH + (size_t)i] = (uint8_t)(value % BYTE_BASE);
        value /= BYTE_BASE;
      }
    }
    header_length = HEADER_BASE_LENGTH + LENGTH64_FIELD_LENGTH;
  }
  if (frame->masked) {
    header[1] = (uint8_t)((unsigned)header[1] | MASK_BIT);
    memcpy(header + header_length, frame->masking_key, WSC_MASKING_KEY_LENGTH);
    header_length += WSC_MASKING_KEY_LENGTH;
  }

  return header_length;
}

static size_t encode(uint8_t *destination, const struct wsc_frame *frame) {
  uint64_t length = encoded_frame_length(frame);
  if (SIZE_MAX < length) {
    trap();
  }
  if (destination == nullptr) {
    trap();
  }

  uint8_t header[HEADER_MAX_LENGTH];
  size_t header_length = encode_header(header, frame);
  memcpy(destination, header, header_length);

  if (0 < frame->payload_length) {
    size_t payload_length = (size_t)frame->payload_length;
    memcpy(destination + header_length, frame->payload, payload_length);
    if (frame->masked) {
      mask(destination + header_length, payload_length, frame->masking_key);
    }
  }

  return (size_t)length;
}

struct progress {
  const uint8_t *source;
  size_t source_length;
  size_t source_consumed;
};

static void consume(struct progress *progress, size_t filled) {
  progress->source += filled;
  progress->source_length -= filled;
  progress->source_consumed += filled;
}

struct header_bytes {
  uint8_t data[HEADER_MAX_LENGTH];
  size_t received;
  size_t expected_length;
};

static size_t fill_header(struct header_bytes *header, const uint8_t *source,
                          size_t source_length) {
  uint8_t *unfilled_header = header->data + header->received;
  size_t unfilled_header_length = header->expected_length - header->received;
  size_t copy_length =
      memcpy_minimum(unfilled_header, unfilled_header_length, source, source_length);
  header->received += copy_length;
  return copy_length;
}

#ifdef WSC_HOSTED

enum parse_state {
  STATE_HEADER_BASE = 0,
  STATE_REST_OF_HEADER,
  STATE_DECODE_HEADER,
  STATE_PREPARE_PAYLOAD,
  STATE_PAYLOAD,
  STATE_ATTACH_PAYLOAD,
  STATE_PUBLISH,
  STATE_NEED_SOURCE_FOR_HEADER_BASE,
  STATE_NEED_SOURCE_FOR_REST_OF_HEADER,
  STATE_NEED_SOURCE_FOR_PAYLOAD,
  STATE_NO_MEMORY_FOR_PREPARE_PAYLOAD,
  STATE_NO_MEMORY_FOR_PUBLISH,
  STATE_DEAD,
};

struct payload_bytes {
  uint8_t *data;
  size_t received;
};

struct frames {
  struct wsc_frame *data;
  size_t count;
  size_t capacity;
};

struct wsc_decoder {
  struct payload_bytes payload;
  struct header_bytes header;
  struct wsc_frame frame;
  struct frames ready_frames;
  enum parse_state step;
  enum wsc_status last_status;
};

enum : unsigned { INITIAL_FRAME_CAPACITY = 1 };

static enum parse_state copy_header_base(struct header_bytes *header, struct progress *progress) {
  if (progress->source_length == 0) {
    return STATE_NEED_SOURCE_FOR_HEADER_BASE;
  }
  header->expected_length = HEADER_BASE_LENGTH;
  size_t filled = fill_header(header, progress->source, progress->source_length);
  consume(progress, filled);
  if (header->received < HEADER_BASE_LENGTH) {
    return STATE_NEED_SOURCE_FOR_HEADER_BASE;
  }
  header->expected_length = header_length(header->data[1]);
  if (header->received < header->expected_length) {
    return STATE_REST_OF_HEADER;
  }
  return STATE_DECODE_HEADER;
}

static enum parse_state copy_rest_of_header(struct header_bytes *header,
                                            struct progress *progress) {
  if (progress->source_length == 0) {
    return STATE_NEED_SOURCE_FOR_REST_OF_HEADER;
  }
  size_t filled = fill_header(header, progress->source, progress->source_length);
  consume(progress, filled);
  if (header->received < header->expected_length) {
    return STATE_NEED_SOURCE_FOR_REST_OF_HEADER;
  }
  return STATE_DECODE_HEADER;
}

static enum parse_state decode_header(struct wsc_decoder *decoder) {
  unsigned byte0 = decoder->header.data[0];
  unsigned byte1 = decoder->header.data[1];

  decoder->frame.fin = (byte0 & FIN_BIT) != 0;
  decoder->frame.rsv1 = (byte0 & RSV1_BIT) != 0;
  decoder->frame.rsv2 = (byte0 & RSV2_BIT) != 0;
  decoder->frame.rsv3 = (byte0 & RSV3_BIT) != 0;
  decoder->frame.opcode = (uint8_t)(byte0 & OPCODE_MASK);
  decoder->frame.masked = (byte1 & MASK_BIT) != 0;

  uint64_t payload_length = 0;
  enum wsc_status status = parse_payload_length(decoder->header.data, &payload_length);
  if (status != WSC_OK) {
    decoder->last_status = status;
    return STATE_DEAD;
  }

  if (decoder->frame.masked) {
    const uint8_t *masking_key_field =
        decoder->header.data + (header_length(byte1) - WSC_MASKING_KEY_LENGTH);
    memcpy(decoder->frame.masking_key, masking_key_field, WSC_MASKING_KEY_LENGTH);
  } else {
    memset(decoder->frame.masking_key, 0, WSC_MASKING_KEY_LENGTH);
  }

  decoder->frame.payload_length = payload_length;
  return STATE_PREPARE_PAYLOAD;
}

static bool reserve_payload(struct payload_bytes *payload, size_t capacity) {
  uint8_t *data = malloc(capacity);
  if (data == nullptr) {
    return false;
  }
  payload->data = data;
  return true;
}

static enum parse_state prepare_payload(struct wsc_frame *frame, struct payload_bytes *payload) {
  frame->payload = nullptr;
  payload->received = 0;
  if (frame->payload_length == 0) {
    return STATE_PUBLISH;
  }
  if (reserve_payload(payload, (size_t)frame->payload_length)) {
    return STATE_PAYLOAD;
  }
  return STATE_NO_MEMORY_FOR_PREPARE_PAYLOAD;
}

static enum parse_state copy_payload(struct wsc_frame *frame, struct payload_bytes *payload,
                                     struct progress *progress) {
  if (progress->source_length == 0) {
    return STATE_NEED_SOURCE_FOR_PAYLOAD;
  }
  if (payload->data == nullptr) {
    trap();
  }
  uint8_t *unfilled_payload = payload->data + payload->received;
  size_t unfilled_payload_length = (size_t)frame->payload_length - payload->received;
  size_t filled = memcpy_minimum(unfilled_payload, unfilled_payload_length, progress->source,
                                 progress->source_length);
  payload->received += filled;
  consume(progress, filled);
  if (payload->received < frame->payload_length) {
    return STATE_NEED_SOURCE_FOR_PAYLOAD;
  }
  return STATE_ATTACH_PAYLOAD;
}

static enum parse_state attach_payload(struct wsc_frame *frame, struct payload_bytes *payload) {
  if (payload->data == nullptr) {
    trap();
  }
  if (frame->masked && 0 < frame->payload_length) {
    unmask(frame, payload->data);
  }
  frame->payload = payload->data;
  payload->data = nullptr;
  payload->received = 0;
  return STATE_PUBLISH;
}

static bool reserve_frames(struct frames *ready_frames) {
  if (ready_frames->count < ready_frames->capacity) {
    return true;
  }
  size_t capacity = ready_frames->capacity ? ready_frames->capacity * 2 : INITIAL_FRAME_CAPACITY;
  if (capacity <= ready_frames->capacity) {
    return false;
  }
  if (SIZE_MAX / sizeof(struct wsc_frame) < capacity) {
    return false;
  }
  size_t bytes = capacity * sizeof(struct wsc_frame);
  struct wsc_frame *new_buffer = realloc(ready_frames->data, bytes);
  if (new_buffer == nullptr) {
    return false;
  }
  ready_frames->data = new_buffer;
  ready_frames->capacity = capacity;
  return true;
}

static bool append_frame(struct frames *ready_frames, struct wsc_frame frame) {
  if (!reserve_frames(ready_frames)) {
    return false;
  }
  ready_frames->data[ready_frames->count] = frame;
  ready_frames->count++;
  return true;
}

static enum parse_state publish_frame(struct wsc_decoder *decoder) {
  if (!append_frame(&decoder->ready_frames, decoder->frame)) {
    return STATE_NO_MEMORY_FOR_PUBLISH;
  }
  decoder->payload.received = 0;
  decoder->header.received = 0;
  decoder->header.expected_length = HEADER_BASE_LENGTH;
  return STATE_HEADER_BASE;
}

static void drop_result(struct frames *ready_frames) {
  ready_frames->data = nullptr;
  ready_frames->count = 0;
  ready_frames->capacity = 0;
}

struct wsc_decoding_result wsc_decoder_feed(struct wsc_decoder *decoder, const uint8_t *source,
                                            size_t source_length) {
  if (decoder == nullptr) {
    trap();
  }
  if (0 < source_length && source == nullptr) {
    trap();
  }

  drop_result(&decoder->ready_frames);

  struct progress progress = {
      .source = source,
      .source_length = source_length,
      .source_consumed = 0,
  };
  for (;;) {
    switch (decoder->step) {
    case STATE_HEADER_BASE:
      decoder->step = copy_header_base(&decoder->header, &progress);
      break;
    case STATE_REST_OF_HEADER:
      decoder->step = copy_rest_of_header(&decoder->header, &progress);
      break;
    case STATE_DECODE_HEADER:
      decoder->step = decode_header(decoder);
      break;
    case STATE_PREPARE_PAYLOAD:
      decoder->step = prepare_payload(&decoder->frame, &decoder->payload);
      break;
    case STATE_PAYLOAD:
      decoder->step = copy_payload(&decoder->frame, &decoder->payload, &progress);
      break;
    case STATE_ATTACH_PAYLOAD:
      decoder->step = attach_payload(&decoder->frame, &decoder->payload);
      break;
    case STATE_PUBLISH:
      decoder->step = publish_frame(decoder);
      break;
    case STATE_NEED_SOURCE_FOR_HEADER_BASE:
      decoder->step = STATE_HEADER_BASE;
      return (struct wsc_decoding_result){
          .status = WSC_OK,
          .frames = decoder->ready_frames.data,
          .frames_count = decoder->ready_frames.count,
          .source_consumed = progress.source_consumed,
      };
    case STATE_NEED_SOURCE_FOR_REST_OF_HEADER:
      decoder->step = STATE_REST_OF_HEADER;
      return (struct wsc_decoding_result){
          .status = WSC_OK,
          .frames = decoder->ready_frames.data,
          .frames_count = decoder->ready_frames.count,
          .source_consumed = progress.source_consumed,
      };
    case STATE_NEED_SOURCE_FOR_PAYLOAD:
      decoder->step = STATE_PAYLOAD;
      return (struct wsc_decoding_result){
          .status = WSC_OK,
          .frames = decoder->ready_frames.data,
          .frames_count = decoder->ready_frames.count,
          .source_consumed = progress.source_consumed,
      };
    case STATE_NO_MEMORY_FOR_PREPARE_PAYLOAD:
      decoder->step = STATE_PREPARE_PAYLOAD;
      return (struct wsc_decoding_result){
          .status = WSC_ERR_NO_MEMORY,
          .frames = decoder->ready_frames.data,
          .frames_count = decoder->ready_frames.count,
          .source_consumed = progress.source_consumed,
      };
    case STATE_NO_MEMORY_FOR_PUBLISH:
      decoder->step = STATE_PUBLISH;
      return (struct wsc_decoding_result){
          .status = WSC_ERR_NO_MEMORY,
          .frames = decoder->ready_frames.data,
          .frames_count = decoder->ready_frames.count,
          .source_consumed = progress.source_consumed,
      };
    case STATE_DEAD:
      return (struct wsc_decoding_result){
          .status = decoder->last_status,
          .frames = decoder->ready_frames.data,
          .frames_count = decoder->ready_frames.count,
          .source_consumed = progress.source_consumed,
      };
    }
  }
}

struct wsc_decoder *wsc_decoder_create() {
  struct wsc_decoder *decoder = malloc(sizeof(*decoder));
  if (decoder == nullptr) return nullptr;

  *decoder = (struct wsc_decoder){
      .step = STATE_HEADER_BASE,
      .header.expected_length = HEADER_BASE_LENGTH,
  };
  return decoder;
}

struct wsc_encoding_result wsc_encode(const struct wsc_frame *frame) {
  if (frame == nullptr) trap();

  uint64_t length = encoded_frame_length(frame);
  if (SIZE_MAX < length) {
    trap();
  }
  size_t total = (size_t)length;

  struct wsc_encoding_result result = {
      .status = WSC_OK,
      .data_length = total,
      .data = malloc(total),
  };

  if (result.data == nullptr) {
    result.status = WSC_ERR_NO_MEMORY;
    result.data_length = 0;
    return result;
  }
  encode(result.data, frame);
  return result;
}

void wsc_decoder_destroy(struct wsc_decoder *decoder) {
  if (decoder == nullptr) {
    return;
  }
  if (decoder->step == STATE_PUBLISH) {
    free((void *)decoder->frame.payload);
  }
  free(decoder->payload.data);
  free(decoder);
}

void wsc_decoding_result_free(struct wsc_decoding_result result) {
  if (result.frames == nullptr) {
    return;
  }
  for (size_t i = 0; i < result.frames_count; i++) {
    free((void *)result.frames[i].payload);
  }
  free((void *)result.frames);
}

#else

enum parse_state : unsigned {
  STATE_HEADER_BASE = 0,
  STATE_REST_OF_HEADER,
  STATE_DECODE_HEADER,
  STATE_PREPARE_PAYLOAD,
  STATE_PAYLOAD,
  STATE_PUBLISH,
  STATE_NEED_SOURCE_FOR_HEADER_BASE,
  STATE_NEED_SOURCE_FOR_REST_OF_HEADER,
  STATE_NEED_SOURCE_FOR_PAYLOAD,
  STATE_PAYLOAD_EXCEEDS_CAPACITY,
  STATE_DEAD,
};

struct payload_buffer {
  uint8_t *data;
  size_t received;
  size_t capacity;
};

struct decoder {
  struct wsc_frame frame;
  struct header_bytes header;
  struct payload_buffer payload;
  enum parse_state step;
  enum wsc_status status;
};

static_assert(sizeof(struct decoder) <= sizeof(struct wsc_decoder));
static_assert(alignof(struct decoder) <= alignof(struct wsc_decoder));

static struct decoder transparent_decoder(const struct wsc_decoder *decoder) {
  struct decoder state;
  memcpy(&state, decoder->opaque, sizeof(state));
  return state;
}

static struct wsc_decoder opaque_decoder(const struct decoder *state) {
  struct wsc_decoder opaque = {0};
  memcpy(opaque.opaque, state, sizeof(*state));
  return opaque;
}

static void set_payload(struct payload_buffer *payload, uint8_t *data, size_t capacity) {
  if (data == nullptr && 0 < capacity) {
    trap();
  }
  payload->data = data;
  payload->capacity = capacity;
}

static enum parse_state copy_header_base(struct header_bytes *header, struct progress *progress) {
  if (progress->source_length == 0) {
    return STATE_NEED_SOURCE_FOR_HEADER_BASE;
  }
  header->expected_length = HEADER_BASE_LENGTH;
  size_t filled = fill_header(header, progress->source, progress->source_length);
  consume(progress, filled);
  if (header->received < HEADER_BASE_LENGTH) {
    return STATE_NEED_SOURCE_FOR_HEADER_BASE;
  }
  header->expected_length = header_length(header->data[1]);
  if (header->received < header->expected_length) {
    return STATE_REST_OF_HEADER;
  }
  return STATE_DECODE_HEADER;
}

static enum parse_state copy_rest_of_header(struct header_bytes *header,
                                            struct progress *progress) {
  if (progress->source_length == 0) {
    return STATE_NEED_SOURCE_FOR_REST_OF_HEADER;
  }
  size_t filled = fill_header(header, progress->source, progress->source_length);
  consume(progress, filled);
  if (header->received < header->expected_length) {
    return STATE_NEED_SOURCE_FOR_REST_OF_HEADER;
  }
  return STATE_DECODE_HEADER;
}

static enum parse_state decode_header(struct decoder *state) {
  unsigned byte0 = state->header.data[0];
  unsigned byte1 = state->header.data[1];

  state->frame.fin = (byte0 & FIN_BIT) != 0;
  state->frame.rsv1 = (byte0 & RSV1_BIT) != 0;
  state->frame.rsv2 = (byte0 & RSV2_BIT) != 0;
  state->frame.rsv3 = (byte0 & RSV3_BIT) != 0;
  state->frame.opcode = (uint8_t)(byte0 & OPCODE_MASK);
  state->frame.masked = (byte1 & MASK_BIT) != 0;
  state->frame.payload = nullptr;

  uint64_t payload_length = 0;
  enum wsc_status status = parse_payload_length(state->header.data, &payload_length);
  if (status != WSC_OK) {
    state->status = status;
    return STATE_DEAD;
  }

  if (state->frame.masked) {
    const uint8_t *masking_key_field =
        state->header.data + (header_length(byte1) - WSC_MASKING_KEY_LENGTH);
    memcpy(state->frame.masking_key, masking_key_field, WSC_MASKING_KEY_LENGTH);
  } else {
    memset(state->frame.masking_key, 0, WSC_MASKING_KEY_LENGTH);
  }

  state->frame.payload_length = payload_length;
  return STATE_PREPARE_PAYLOAD;
}

static enum parse_state prepare_payload(struct wsc_frame *frame, struct payload_buffer *payload) {
  frame->payload = nullptr;
  payload->received = 0;
  if (frame->payload_length == 0) {
    return STATE_PUBLISH;
  }
  if (payload->capacity < frame->payload_length) {
    return STATE_PAYLOAD_EXCEEDS_CAPACITY;
  }
  if (payload->data == nullptr) {
    trap();
  }
  return STATE_PAYLOAD;
}

static enum parse_state copy_payload(struct wsc_frame *frame, struct payload_buffer *payload,
                                     struct progress *progress) {
  if (progress->source_length == 0) {
    return STATE_NEED_SOURCE_FOR_PAYLOAD;
  }
  if (payload->data == nullptr) {
    trap();
  }
  uint8_t *unfilled_payload = payload->data + payload->received;
  size_t unfilled_payload_length = (size_t)frame->payload_length - payload->received;
  size_t filled = memcpy_minimum(unfilled_payload, unfilled_payload_length, progress->source,
                                 progress->source_length);
  payload->received += filled;
  consume(progress, filled);
  if (payload->received < frame->payload_length) {
    return STATE_NEED_SOURCE_FOR_PAYLOAD;
  }
  return STATE_PUBLISH;
}

static void publish_frame(struct decoder *state) {
  if (state->frame.masked && 0 < state->frame.payload_length) {
    unmask(&state->frame, state->payload.data);
  }
  if (state->frame.payload_length == 0) {
    state->frame.payload = nullptr;
  } else {
    state->frame.payload = state->payload.data;
  }
  state->payload.received = 0;
  state->header.received = 0;
  state->header.expected_length = HEADER_BASE_LENGTH;
  state->step = STATE_HEADER_BASE;
}

static struct wsc_decoding_result decoding_result(const struct decoder *state,
                                                  enum wsc_status status, size_t source_consumed) {
  struct wsc_decoding_result result = {
      .status = status,
      .source_consumed = source_consumed,
  };
  if (status == WSC_OK) {
    result.frame = state->frame;
  }
  return result;
}

void wsc_decoder_init(struct wsc_decoder *decoder, uint8_t *payload, size_t payload_capacity) {
  if (decoder == nullptr) {
    trap();
  }
  struct decoder state = {
      .header.expected_length = HEADER_BASE_LENGTH,
      .step = STATE_HEADER_BASE,
  };
  set_payload(&state.payload, payload, payload_capacity);
  *decoder = opaque_decoder(&state);
}

void wsc_decoder_set_payload_buffer(struct wsc_decoder *decoder, uint8_t *payload,
                                    size_t payload_capacity) {
  if (decoder == nullptr) {
    trap();
  }
  struct decoder state = transparent_decoder(decoder);
  if (state.step == STATE_PAYLOAD) {
    trap();
  }
  set_payload(&state.payload, payload, payload_capacity);
  *decoder = opaque_decoder(&state);
}

struct wsc_decoding_result wsc_decoder_feed(struct wsc_decoder *decoder, const uint8_t *source,
                                            size_t source_length) {
  if (decoder == nullptr) {
    trap();
  }
  if (0 < source_length && source == nullptr) {
    trap();
  }
  struct decoder state = transparent_decoder(decoder);

  struct progress progress = {
      .source = source,
      .source_length = source_length,
      .source_consumed = 0,
  };
  for (;;) {
    switch (state.step) {
    case STATE_HEADER_BASE:
      state.step = copy_header_base(&state.header, &progress);
      break;
    case STATE_REST_OF_HEADER:
      state.step = copy_rest_of_header(&state.header, &progress);
      break;
    case STATE_DECODE_HEADER:
      state.step = decode_header(&state);
      break;
    case STATE_PREPARE_PAYLOAD:
      state.step = prepare_payload(&state.frame, &state.payload);
      break;
    case STATE_PAYLOAD:
      state.step = copy_payload(&state.frame, &state.payload, &progress);
      break;
    case STATE_PUBLISH:
      publish_frame(&state);
      *decoder = opaque_decoder(&state);
      return decoding_result(&state, WSC_OK, progress.source_consumed);
    case STATE_NEED_SOURCE_FOR_HEADER_BASE:
      state.step = STATE_HEADER_BASE;
      *decoder = opaque_decoder(&state);
      return decoding_result(&state, WSC_INCOMPLETE, progress.source_consumed);
    case STATE_NEED_SOURCE_FOR_REST_OF_HEADER:
      state.step = STATE_REST_OF_HEADER;
      *decoder = opaque_decoder(&state);
      return decoding_result(&state, WSC_INCOMPLETE, progress.source_consumed);
    case STATE_NEED_SOURCE_FOR_PAYLOAD:
      state.step = STATE_PAYLOAD;
      *decoder = opaque_decoder(&state);
      return decoding_result(&state, WSC_INCOMPLETE, progress.source_consumed);
    case STATE_PAYLOAD_EXCEEDS_CAPACITY:
      state.step = STATE_PREPARE_PAYLOAD;
      *decoder = opaque_decoder(&state);
      return decoding_result(&state, WSC_ERR_PAYLOAD_EXCEEDS_CAPACITY, progress.source_consumed);
    case STATE_DEAD:
      *decoder = opaque_decoder(&state);
      return decoding_result(&state, state.status, progress.source_consumed);
    default:
      trap();
    }
  }
}

uint64_t wsc_encoded_frame_length(const struct wsc_frame *frame) {
  return encoded_frame_length(frame);
}

size_t wsc_encode(uint8_t *destination, const struct wsc_frame *frame) {
  return encode(destination, frame);
}

#endif
