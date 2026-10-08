#include "wsc.h"

#ifdef WSC_HOSTED
#include <stdlib.h>
#else
#include <ringalloc.h>
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

enum : uint8_t {
  LENGTH7_MAX = 125,
};

enum payload_length_codes : unsigned {
  LENGTH16_CODE = 126,
  LENGTH64_CODE = 127,
};

enum header_first_byte_masks : uint8_t {
  FIN_BIT     = 0x80,
  RSV1_BIT    = 0x40,
  RSV2_BIT    = 0x20,
  RSV3_BIT    = 0x10,
  OPCODE_MASK = 0x0F,
};

enum header_second_byte_masks : uint8_t {
  MASK_BIT     = 0x80,
  LENGTH7_MASK = 0x7F,
};

enum : uint64_t { LENGTH64_MSB = 0x8000000000000000 };

enum initial_capacities : unsigned {
  BUFFER_INIT = 256,
  FRAMES_INIT = 8,
};

enum byte_radix : unsigned { BYTE_RADIX = 256 };

enum parse_state {
  STATE_HEADER_BASE = 0,
  STATE_REST_OF_HEADER,
  STATE_PARSE_HEADER,
  STATE_PREPARE_PAYLOAD,
  STATE_PAYLOAD,
  STATE_PREPARE_PUBLISH,
  STATE_ATTACH_PAYLOAD,
  STATE_PUBLISH,
  STATE_NEED_SOURCE_FOR_HEADER_BASE,
  STATE_NEED_SOURCE_FOR_REST_OF_HEADER,
  STATE_NEED_SOURCE_FOR_PAYLOAD,
  STATE_NO_MEMORY_FOR_PREPARE_PAYLOAD,
  STATE_NO_MEMORY_FOR_ATTACH_PAYLOAD,
  STATE_NO_MEMORY_FOR_PUBLISH,
  STATE_DEAD,
};

struct buffer {
  uint8_t *data;
  size_t received;
  size_t capacity;
};

struct header {
  uint8_t data[HEADER_MAX_LENGTH];
  size_t received;
  size_t expected_length;
};

struct wsc_decoder {
  struct wsc_frame incoming;
  struct buffer payload;
#ifndef WSC_HOSTED
  struct ringalloc *allocator;
#endif
  struct wsc_frame *frames;
  size_t frames_count;
  size_t frames_capacity;
  struct header header;
  enum parse_state state;
  enum wsc_status last_status;
};

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
  return (uint16_t)(((unsigned)field[0] * BYTE_RADIX) + field[1]);
}

static uint64_t extended_payload_length64(const uint8_t *field) {
  uint64_t value = 0;
  for (int i = 0; i < (int)sizeof(uint64_t); i++) {
    value = (value * BYTE_RADIX) + field[i];
  }
  return value;
}

static void apply_mask(uint8_t *data, size_t length, const uint8_t key[WSC_MASKING_KEY_LENGTH]) {
  for (size_t i = 0; i < length; i++) {
    data[i] = (uint8_t)((unsigned)data[i] ^ key[i & (WSC_MASKING_KEY_LENGTH - 1U)]);
  }
}

static void mask(struct wsc_frame *frame, uint8_t *payload) {
  if (frame->masked && 0 < frame->payload_length) {
    apply_mask(payload, frame->payload_length, frame->masking_key);
  }
}

static void unmask(struct wsc_frame *frame, uint8_t *payload) {
  mask(frame, payload);
}

static size_t header_length(unsigned byte1) {
  const uint8_t length_field = byte1 & LENGTH7_MASK;

  size_t header_length = HEADER_BASE_LENGTH;
  if (length_field == LENGTH16_CODE) {
    header_length += LENGTH16_FIELD_LENGTH;
  } else if (length_field == LENGTH64_CODE) {
    header_length += LENGTH64_FIELD_LENGTH;
  }
  if ((byte1 & MASK_BIT) != 0) {
    header_length += WSC_MASKING_KEY_LENGTH;
  }
  return header_length;
}

static enum wsc_status parse_payload_length(const uint8_t *header, uint64_t *payload_length) {
  uint8_t byte1 = header[1];
  const uint8_t length_field = byte1 & LENGTH7_MASK;
  uint64_t length = length_field;

  if (length == LENGTH16_CODE) {
    const uint8_t *extended_length_field = header + HEADER_BASE_LENGTH;
    length = extended_payload_length16(extended_length_field);
    if (length <= LENGTH7_MAX) {
      return WSC_ERR_LENGTH_NOT_MINIMAL;
    }
  } else if (length == LENGTH64_CODE) {
    const uint8_t *extended_length_field = header + HEADER_BASE_LENGTH;
    length = extended_payload_length64(extended_length_field);
    if ((length & LENGTH64_MSB) != 0) {
      return WSC_ERR_LENGTH64_MSB;
    }
    if (length <= UINT16_MAX) {
      return WSC_ERR_LENGTH_NOT_MINIMAL;
    }
  }

  if (SIZE_MAX < length) {
    return WSC_ERR_LENGTH_EXCEEDS_SIZE;
  }

  *payload_length = length;
  return WSC_OK;
}

static size_t encoded_frame_length(const struct wsc_frame *frame) {
  if (frame == nullptr) trap();
  if (0 < frame->payload_length && frame->payload == nullptr) trap();
  if (((unsigned)frame->opcode & ~(unsigned)OPCODE_MASK) != 0) trap();
  if ((size_t)(LENGTH64_MSB - 1) < frame->payload_length) trap();

  size_t header_length = HEADER_BASE_LENGTH;
  if (LENGTH7_MAX < frame->payload_length) {
    header_length +=
        UINT16_MAX < frame->payload_length ? LENGTH64_FIELD_LENGTH : LENGTH16_FIELD_LENGTH;
  }
  if (frame->masked) {
    header_length += WSC_MASKING_KEY_LENGTH;
  }
  if (SIZE_MAX - header_length < frame->payload_length) {
    trap();
  }
  return header_length + frame->payload_length;
}

static size_t encode(uint8_t *destination, const struct wsc_frame *frame) {
  size_t total = encoded_frame_length(frame);
  if (destination == nullptr) {
    trap();
  }
  uint8_t header[HEADER_MAX_LENGTH];
  size_t header_length = HEADER_BASE_LENGTH;

  header[0] =
      (uint8_t)((frame->fin ? (unsigned)FIN_BIT : 0U) | (frame->rsv1 ? (unsigned)RSV1_BIT : 0U) |
                (frame->rsv2 ? (unsigned)RSV2_BIT : 0U) | (frame->rsv3 ? (unsigned)RSV3_BIT : 0U) |
                ((unsigned)frame->opcode & OPCODE_MASK));

  if (frame->payload_length <= LENGTH7_MAX) {
    header[1] = (uint8_t)frame->payload_length;
  } else if (frame->payload_length <= UINT16_MAX) {
    header[1] = LENGTH16_CODE;
    header[HEADER_BASE_LENGTH] = (uint8_t)(frame->payload_length / BYTE_RADIX);
    header[HEADER_BASE_LENGTH + 1] = (uint8_t)(frame->payload_length % BYTE_RADIX);
    header_length = HEADER_BASE_LENGTH + LENGTH16_FIELD_LENGTH;
  } else {
    header[1] = LENGTH64_CODE;
    {
      uint64_t value = frame->payload_length;
      for (int i = (int)sizeof(uint64_t) - 1; i >= 0; i--) {
        header[HEADER_BASE_LENGTH + (size_t)i] = (uint8_t)(value % BYTE_RADIX);
        value /= BYTE_RADIX;
      }
    }
    header_length = HEADER_BASE_LENGTH + LENGTH64_FIELD_LENGTH;
  }
  if (frame->masked) {
    header[1] = (uint8_t)((unsigned)header[1] | MASK_BIT);
    memcpy(header + header_length, frame->masking_key, WSC_MASKING_KEY_LENGTH);
    header_length += WSC_MASKING_KEY_LENGTH;
  }

  memcpy(destination, header, header_length);
  if (0 < frame->payload_length) {
    memcpy(destination + header_length, frame->payload, frame->payload_length);
    if (frame->masked) {
      apply_mask(destination + header_length, frame->payload_length, frame->masking_key);
    }
  }
  return total;
}

#ifdef WSC_HOSTED

static bool reserve_payload(struct wsc_decoder *decoder, size_t minimum_capacity) {
  struct buffer *buffer = &decoder->payload;
  if (minimum_capacity <= buffer->capacity) {
    return true;
  }
  size_t capacity = buffer->capacity ? buffer->capacity : BUFFER_INIT;
  while (capacity < minimum_capacity) {
    if (SIZE_MAX / 2 < capacity) {
      capacity = minimum_capacity;
      break;
    }
    capacity *= 2;
  }
  uint8_t *new_buffer = realloc(buffer->data, capacity);
  if (new_buffer == nullptr) {
    return false;
  }
  buffer->data = new_buffer;
  buffer->capacity = capacity;
  return true;
}

static bool reserve_frames(struct wsc_decoder *decoder, size_t capacity) {
  if (capacity <= decoder->frames_capacity) {
    return false;
  }
  if (SIZE_MAX / sizeof(struct wsc_frame) < capacity) {
    return false;
  }
  size_t bytes = capacity * sizeof(struct wsc_frame);
  struct wsc_frame *new_buffer = realloc(decoder->frames, bytes);
  if (new_buffer == nullptr) {
    return false;
  }
  decoder->frames = new_buffer;
  decoder->frames_capacity = capacity;
  return true;
}

#else

static bool reserve_payload(struct wsc_decoder *decoder, size_t minimum_capacity) {
  struct buffer *buffer = &decoder->payload;
  if (minimum_capacity <= buffer->capacity) {
    return true;
  }
  if (buffer->data != nullptr) {
    uint8_t *new_buffer = ra_reallocate(decoder->allocator, buffer->data, minimum_capacity);
    if (new_buffer == nullptr) {
      return false;
    }
    buffer->data = new_buffer;
    buffer->capacity = minimum_capacity;
    return true;
  }
  uint8_t *new_buffer = ra_allocate(decoder->allocator, minimum_capacity);
  if (new_buffer == nullptr) {
    return false;
  }
  buffer->data = new_buffer;
  buffer->capacity = minimum_capacity;
  return true;
}

static bool reserve_frames(struct wsc_decoder *decoder, size_t capacity) {
  if (capacity <= decoder->frames_capacity) {
    return false;
  }
  if (SIZE_MAX / sizeof(struct wsc_frame) < capacity) {
    return false;
  }
  size_t bytes = capacity * sizeof(struct wsc_frame);
  if (decoder->frames != nullptr) {
    struct wsc_frame *new_buffer = ra_reallocate(decoder->allocator, decoder->frames, bytes);
    if (new_buffer != nullptr) {
      decoder->frames = new_buffer;
      decoder->frames_capacity = capacity;
      return true;
    }
  }
  struct wsc_frame *new_buffer = ra_allocate(decoder->allocator, bytes);
  if (new_buffer == nullptr) {
    return false;
  }
  if (decoder->frames != nullptr && 0 < decoder->frames_count) {
    memcpy(new_buffer, decoder->frames, decoder->frames_count * sizeof(*new_buffer));
  }
  decoder->frames = new_buffer;
  decoder->frames_capacity = capacity;
  return true;
}

#endif

static bool append_frame(struct wsc_decoder *decoder, struct wsc_frame frame) {
  if (decoder->frames_count == decoder->frames_capacity) {
    size_t capacity = decoder->frames_capacity ? decoder->frames_capacity * 2 : FRAMES_INIT;
    if (!reserve_frames(decoder, capacity)) {
      return false;
    }
  }
  decoder->frames[decoder->frames_count] = frame;
  decoder->frames_count++;
  return true;
}

#ifdef WSC_HOSTED

static enum parse_state attach_payload(struct wsc_decoder *decoder) {
  if (decoder->payload.data == nullptr) {
    trap();
  }
  uint8_t *copy = malloc(decoder->incoming.payload_length);
  if (copy == nullptr) {
    return STATE_NO_MEMORY_FOR_ATTACH_PAYLOAD;
  }
  memcpy(copy, decoder->payload.data, decoder->incoming.payload_length);
  decoder->incoming.payload = copy;
  return STATE_PUBLISH;
}

static void drop_result(struct wsc_decoder *decoder) {
  decoder->frames = nullptr;
  decoder->frames_count = 0;
  decoder->frames_capacity = 0;
}

static enum parse_state publish_frame(struct wsc_decoder *decoder) {
  if (!append_frame(decoder, decoder->incoming)) {
    return STATE_NO_MEMORY_FOR_PUBLISH;
  }
  decoder->payload.received = 0;
  decoder->header.received = 0;
  decoder->header.expected_length = HEADER_BASE_LENGTH;
  return STATE_HEADER_BASE;
}

#else

static enum parse_state attach_payload(struct wsc_decoder *decoder) {
  if (decoder->payload.data == nullptr) {
    trap();
  }
  decoder->incoming.payload = decoder->payload.data;
  return STATE_PUBLISH;
}

static void drop_result(struct wsc_decoder *decoder) {
  if ((decoder->state == STATE_PAYLOAD || decoder->state == STATE_ATTACH_PAYLOAD ||
       decoder->state == STATE_PUBLISH) &&
      decoder->payload.data != nullptr) {
    ra_free_before(decoder->allocator, decoder->payload.data);
  } else {
    ra_free_all(decoder->allocator);
    decoder->payload.data = nullptr;
    decoder->payload.received = 0;
    decoder->payload.capacity = 0;
  }
  decoder->frames = nullptr;
  decoder->frames_count = 0;
  decoder->frames_capacity = 0;
}

static enum parse_state publish_frame(struct wsc_decoder *decoder) {
  if (!append_frame(decoder, decoder->incoming)) {
    return STATE_NO_MEMORY_FOR_PUBLISH;
  }
  decoder->payload.data = nullptr;
  decoder->payload.capacity = 0;
  decoder->payload.received = 0;
  decoder->header.received = 0;
  decoder->header.expected_length = HEADER_BASE_LENGTH;
  return STATE_HEADER_BASE;
}

#endif

static size_t fill_header(struct header *header, const uint8_t *source, size_t source_length) {
  uint8_t *unfilled_header = header->data + header->received;
  size_t unfilled_header_length = header->expected_length - header->received;
  size_t copy_length =
      memcpy_minimum(unfilled_header, unfilled_header_length, source, source_length);
  header->received += copy_length;
  return copy_length;
}

static size_t fill_payload(struct wsc_decoder *decoder, const uint8_t *source,
                           size_t source_length) {
  if (decoder->payload.data == nullptr) {
    trap();
  }

  uint8_t *unfilled_payload = decoder->payload.data + decoder->payload.received;
  size_t unfilled_payload_length = decoder->incoming.payload_length - decoder->payload.received;
  size_t copy_length =
      memcpy_minimum(unfilled_payload, unfilled_payload_length, source, source_length);
  decoder->payload.received += copy_length;
  return copy_length;
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

static enum parse_state copy_header_base(struct wsc_decoder *decoder, struct progress *progress) {
  if (progress->source_length == 0) {
    return STATE_NEED_SOURCE_FOR_HEADER_BASE;
  }
  decoder->header.expected_length = HEADER_BASE_LENGTH;
  size_t filled = fill_header(&decoder->header, progress->source, progress->source_length);
  consume(progress, filled);
  if (decoder->header.received < HEADER_BASE_LENGTH) {
    return STATE_NEED_SOURCE_FOR_HEADER_BASE;
  }
  decoder->header.expected_length = header_length(decoder->header.data[1]);
  if (decoder->header.received < decoder->header.expected_length) {
    return STATE_REST_OF_HEADER;
  }
  return STATE_PARSE_HEADER;
}

static enum parse_state copy_rest_of_header(struct wsc_decoder *decoder,
                                            struct progress *progress) {
  if (progress->source_length == 0) {
    return STATE_NEED_SOURCE_FOR_REST_OF_HEADER;
  }
  size_t filled = fill_header(&decoder->header, progress->source, progress->source_length);
  consume(progress, filled);
  if (decoder->header.received < decoder->header.expected_length) {
    return STATE_NEED_SOURCE_FOR_REST_OF_HEADER;
  }
  return STATE_PARSE_HEADER;
}

static enum parse_state parse_header(struct wsc_decoder *decoder) {
  unsigned byte0 = decoder->header.data[0];
  unsigned byte1 = decoder->header.data[1];

  decoder->incoming.fin = (byte0 & FIN_BIT) != 0;
  decoder->incoming.rsv1 = (byte0 & RSV1_BIT) != 0;
  decoder->incoming.rsv2 = (byte0 & RSV2_BIT) != 0;
  decoder->incoming.rsv3 = (byte0 & RSV3_BIT) != 0;
  decoder->incoming.opcode = (uint8_t)(byte0 & OPCODE_MASK);
  decoder->incoming.masked = (byte1 & MASK_BIT) != 0;

  uint64_t payload_length = 0;
  enum wsc_status status = parse_payload_length(decoder->header.data, &payload_length);
  if (status != WSC_OK) {
    decoder->last_status = status;
    return STATE_DEAD;
  }

  if (decoder->incoming.masked) {
    const uint8_t *masking_key_field =
        decoder->header.data + (header_length(byte1) - WSC_MASKING_KEY_LENGTH);
    memcpy(decoder->incoming.masking_key, masking_key_field, WSC_MASKING_KEY_LENGTH);
  } else {
    memset(decoder->incoming.masking_key, 0, WSC_MASKING_KEY_LENGTH);
  }

  decoder->incoming.payload_length = (size_t)payload_length;
  return STATE_PREPARE_PAYLOAD;
}

static enum parse_state prepare_payload(struct wsc_decoder *decoder) {
  decoder->incoming.payload = nullptr;
  decoder->payload.received = 0;
  if (decoder->incoming.payload_length == 0) {
    return STATE_PUBLISH;
  }
  if (reserve_payload(decoder, decoder->incoming.payload_length)) {
    return STATE_PAYLOAD;
  }
  return STATE_NO_MEMORY_FOR_PREPARE_PAYLOAD;
}

static enum parse_state copy_payload(struct wsc_decoder *decoder, struct progress *progress) {
  if (progress->source_length == 0) {
    return STATE_NEED_SOURCE_FOR_PAYLOAD;
  }
  size_t filled = fill_payload(decoder, progress->source, progress->source_length);
  consume(progress, filled);
  if (decoder->payload.received < decoder->incoming.payload_length) {
    return STATE_NEED_SOURCE_FOR_PAYLOAD;
  }
  return STATE_PREPARE_PUBLISH;
}

static enum parse_state prepare_publish(struct wsc_decoder *decoder) {
  unmask(&decoder->incoming, decoder->payload.data);
  return STATE_ATTACH_PAYLOAD;
}

struct wsc_decoding_result wsc_decoder_feed(struct wsc_decoder *decoder, const uint8_t *source,
                                            size_t source_length) {
  if (decoder == nullptr) {
    trap();
  }
  if (0 < source_length && source == nullptr) {
    trap();
  }

  drop_result(decoder);

  struct progress progress = {
      .source = source,
      .source_length = source_length,
      .source_consumed = 0,
  };
  for (;;) {
    switch (decoder->state) {
    case STATE_HEADER_BASE:
      decoder->state = copy_header_base(decoder, &progress);
      break;
    case STATE_REST_OF_HEADER:
      decoder->state = copy_rest_of_header(decoder, &progress);
      break;
    case STATE_PARSE_HEADER:
      decoder->state = parse_header(decoder);
      break;
    case STATE_PREPARE_PAYLOAD:
      decoder->state = prepare_payload(decoder);
      break;
    case STATE_PAYLOAD:
      decoder->state = copy_payload(decoder, &progress);
      break;
    case STATE_PREPARE_PUBLISH:
      decoder->state = prepare_publish(decoder);
      break;
    case STATE_ATTACH_PAYLOAD:
      decoder->state = attach_payload(decoder);
      break;
    case STATE_PUBLISH:
      decoder->state = publish_frame(decoder);
      break;
    case STATE_NEED_SOURCE_FOR_HEADER_BASE:
      decoder->state = STATE_HEADER_BASE;
      return (struct wsc_decoding_result){
          .status = WSC_OK,
          .frames = decoder->frames,
          .frames_count = decoder->frames_count,
          .source_consumed = progress.source_consumed,
      };
    case STATE_NEED_SOURCE_FOR_REST_OF_HEADER:
      decoder->state = STATE_REST_OF_HEADER;
      return (struct wsc_decoding_result){
          .status = WSC_OK,
          .frames = decoder->frames,
          .frames_count = decoder->frames_count,
          .source_consumed = progress.source_consumed,
      };
    case STATE_NEED_SOURCE_FOR_PAYLOAD:
      decoder->state = STATE_PAYLOAD;
      return (struct wsc_decoding_result){
          .status = WSC_OK,
          .frames = decoder->frames,
          .frames_count = decoder->frames_count,
          .source_consumed = progress.source_consumed,
      };
    case STATE_NO_MEMORY_FOR_PREPARE_PAYLOAD:
      decoder->state = STATE_PREPARE_PAYLOAD;
      return (struct wsc_decoding_result){
          .status = WSC_ERR_NO_MEMORY,
          .frames = decoder->frames,
          .frames_count = decoder->frames_count,
          .source_consumed = progress.source_consumed,
      };
    case STATE_NO_MEMORY_FOR_ATTACH_PAYLOAD:
      decoder->state = STATE_ATTACH_PAYLOAD;
      return (struct wsc_decoding_result){
          .status = WSC_ERR_NO_MEMORY,
          .frames = decoder->frames,
          .frames_count = decoder->frames_count,
          .source_consumed = progress.source_consumed,
      };
    case STATE_NO_MEMORY_FOR_PUBLISH:
      decoder->state = STATE_PUBLISH;
      return (struct wsc_decoding_result){
          .status = WSC_ERR_NO_MEMORY,
          .frames = decoder->frames,
          .frames_count = decoder->frames_count,
          .source_consumed = progress.source_consumed,
      };
    case STATE_DEAD:
      return (struct wsc_decoding_result){
          .status = decoder->last_status,
          .frames = decoder->frames,
          .frames_count = decoder->frames_count,
          .source_consumed = progress.source_consumed,
      };
    }
  }
}

#ifdef WSC_HOSTED

struct wsc_decoder *wsc_decoder_create() {
  struct wsc_decoder *decoder = malloc(sizeof(*decoder));
  if (decoder == nullptr) return nullptr;

  *decoder = (struct wsc_decoder){
      .state = STATE_HEADER_BASE,
      .header.expected_length = HEADER_BASE_LENGTH,
  };
  return decoder;
}

struct wsc_encoding_result wsc_encode(const struct wsc_frame *frame) {
  if (frame == nullptr) trap();

  size_t total = encoded_frame_length(frame);

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
  if (decoder->state == STATE_PUBLISH) {
    free((void *)decoder->incoming.payload);
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

struct wsc_decoder *wsc_decoder_create(unsigned char *arena, size_t capacity) {
  if (arena == nullptr) trap();

  size_t alignment = alignof(struct wsc_decoder);
  size_t padding = (alignment - ((uintptr_t)arena % alignment)) % alignment;
  if (capacity < padding) return nullptr;

  unsigned char *remaining_arena = arena + padding;
  size_t remaining_capacity = capacity - padding;

  if (remaining_capacity < sizeof(struct wsc_decoder)) return nullptr;
  struct wsc_decoder *decoder = (struct wsc_decoder *)remaining_arena;

  remaining_arena += sizeof(*decoder);
  remaining_capacity -= sizeof(*decoder);

  struct ringalloc *allocator = ra_create(remaining_arena, remaining_capacity);
  if (allocator == nullptr) return nullptr;

  *decoder = (struct wsc_decoder){
      .state = STATE_HEADER_BASE,
      .header.expected_length = HEADER_BASE_LENGTH,
      .allocator = allocator,
  };
  return decoder;
}

size_t wsc_encoded_frame_length(const struct wsc_frame *frame) {
  return encoded_frame_length(frame);
}

size_t wsc_encode(uint8_t *destination, const struct wsc_frame *frame) {
  return encode(destination, frame);
}

#endif
