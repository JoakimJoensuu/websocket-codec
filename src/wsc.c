#include "wsc.h"

#ifdef WSC_HOSTED
#include <stdlib.h>
#else
#include <ringalloc.h>
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

enum header_section_sizes : unsigned {
  HEADER_BASE_SIZE  = 2,
  LENGTH16_EXT_SIZE = 2,
  LENGTH64_EXT_SIZE = 8,
  HEADER_MAX_SIZE   = HEADER_BASE_SIZE + LENGTH64_EXT_SIZE + WSC_MASKING_KEY_LENGTH,
};

enum payload_length_codes : unsigned {
  LENGTH7_MAX = 125,
  LENGTH16    = 126,
  LENGTH64    = 127,
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

enum length64_field : uint64_t { LENGTH64_MSB = 0x8000000000000000 };

enum initial_capacities : unsigned {
  BUFFER_INIT = 256,
  FRAMES_INIT = 8,
};

enum byte_radix : unsigned { BYTE_RADIX = 256 };

enum parse_state { STATE_HEADER = 0, STATE_PAYLOAD, STATE_DEAD };

struct buffer {
  uint8_t *data;
  size_t length;
  size_t capacity;
};

struct wsc_decoder {
  uint64_t payload_length;
  struct buffer payload;
#ifndef WSC_HOSTED
  struct ringalloc *allocator;
#endif
  struct wsc_frame *frames;
  size_t frames_count;
  size_t frames_capacity;
  size_t header_received;
  size_t header_expected_length;
  enum parse_state state;
  unsigned mask_offset;
  enum wsc_status last_status;
  bool fin;
  bool rsv1;
  bool rsv2;
  bool rsv3;
  bool masked;
  uint8_t opcode;
  uint8_t masking_key[WSC_MASKING_KEY_LENGTH];
  uint8_t header[HEADER_MAX_SIZE];
};

[[noreturn]] static void trap() {
#ifdef WSC_HOSTED
  abort();
#else
  unreachable();
#endif
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

static void apply_mask(uint8_t *data, size_t length, const uint8_t key[WSC_MASKING_KEY_LENGTH],
                       unsigned offset) {
  for (size_t i = 0; i < length; i++) {
    data[i] = (uint8_t)((unsigned)data[i] ^ key[(offset + i) & (WSC_MASKING_KEY_LENGTH - 1U)]);
  }
}

static size_t header_length(unsigned byte1) {
  size_t header_length = HEADER_BASE_SIZE;
  unsigned length7 = byte1 & LENGTH7_MASK;
  if (length7 == LENGTH16) {
    header_length += LENGTH16_EXT_SIZE;
  } else if (length7 == LENGTH64) {
    header_length += LENGTH64_EXT_SIZE;
  }
  if ((byte1 & MASK_BIT) != 0) {
    header_length += WSC_MASKING_KEY_LENGTH;
  }
  return header_length;
}

static size_t encoded_frame_length(const struct wsc_frame *frame) {
  if (frame == nullptr) trap();

  size_t header_length = HEADER_BASE_SIZE;
  if (frame->payload_length > LENGTH7_MAX) {
    header_length += frame->payload_length > UINT16_MAX ? LENGTH64_EXT_SIZE : LENGTH16_EXT_SIZE;
  }
  if (frame->masked) {
    header_length += WSC_MASKING_KEY_LENGTH;
  }
  if (frame->payload_length > ((size_t)-1) - header_length) {
    trap();
  }
  return header_length + frame->payload_length;
}

static size_t encode_into(uint8_t *destination, const struct wsc_frame *frame) {
  if (frame == nullptr) {
    trap();
  }
  if (frame->payload_length > 0 && frame->payload == nullptr) {
    trap();
  }
  if (frame->opcode > OPCODE_MASK) {
    trap();
  }
  if (frame->payload_length > (size_t)(LENGTH64_MSB - 1)) {
    trap();
  }
  if (destination == nullptr) {
    trap();
  }
  uint8_t header[HEADER_MAX_SIZE];
  size_t header_length = HEADER_BASE_SIZE;

  header[0] =
      (uint8_t)((frame->fin ? (unsigned)FIN_BIT : 0U) | (frame->rsv1 ? (unsigned)RSV1_BIT : 0U) |
                (frame->rsv2 ? (unsigned)RSV2_BIT : 0U) | (frame->rsv3 ? (unsigned)RSV3_BIT : 0U) |
                ((unsigned)frame->opcode & OPCODE_MASK));
  if (frame->payload_length <= LENGTH7_MAX) {
    header[1] = (uint8_t)frame->payload_length;
  } else if (frame->payload_length <= UINT16_MAX) {
    header[1] = LENGTH16;
    header[HEADER_BASE_SIZE] = (uint8_t)(frame->payload_length / BYTE_RADIX);
    header[HEADER_BASE_SIZE + 1] = (uint8_t)(frame->payload_length % BYTE_RADIX);
    header_length = HEADER_BASE_SIZE + LENGTH16_EXT_SIZE;
  } else {
    header[1] = LENGTH64;
    {
      uint64_t value = frame->payload_length;
      for (int i = (int)sizeof(uint64_t) - 1; i >= 0; i--) {
        header[HEADER_BASE_SIZE + (size_t)i] = (uint8_t)(value % BYTE_RADIX);
        value /= BYTE_RADIX;
      }
    }
    header_length = HEADER_BASE_SIZE + LENGTH64_EXT_SIZE;
  }
  if (frame->masked) {
    header[1] = (uint8_t)((unsigned)header[1] | MASK_BIT);
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

#ifdef WSC_HOSTED

static int reserve_payload(struct wsc_decoder *decoder, size_t minimum_capacity) {
  struct buffer *buffer = &decoder->payload;
  if (minimum_capacity <= buffer->capacity) {
    return 0;
  }
  size_t capacity = buffer->capacity ? buffer->capacity : BUFFER_INIT;
  while (capacity < minimum_capacity) {
    if (capacity > ((size_t)-1) / 2) {
      capacity = minimum_capacity;
      break;
    }
    capacity *= 2;
  }
  uint8_t *new_buffer = realloc(buffer->data, capacity);
  if (new_buffer == nullptr) {
    return -1;
  }
  buffer->data = new_buffer;
  buffer->capacity = capacity;
  return 0;
}

static int frames_reserve(struct wsc_decoder *decoder, size_t capacity) {
  if (capacity <= decoder->frames_capacity) {
    return -1;
  }
  if (capacity > ((size_t)-1) / sizeof(struct wsc_frame)) {
    return -1;
  }
  size_t bytes = capacity * sizeof(struct wsc_frame);
  struct wsc_frame *new_buffer = realloc(decoder->frames, bytes);
  if (new_buffer == nullptr) {
    return -1;
  }
  decoder->frames = new_buffer;
  decoder->frames_capacity = capacity;
  return 0;
}

#else

static int reserve_payload(struct wsc_decoder *decoder, size_t minimum_capacity) {
  struct buffer *buffer = &decoder->payload;
  if (minimum_capacity <= buffer->capacity) {
    return 0;
  }
  if (buffer->data != nullptr) {
    uint8_t *new_buffer = ra_reallocate(decoder->allocator, buffer->data, minimum_capacity);
    if (new_buffer == nullptr) {
      return -1;
    }
    buffer->data = new_buffer;
    buffer->capacity = minimum_capacity;
    return 0;
  }
  uint8_t *new_buffer = ra_allocate(decoder->allocator, minimum_capacity);
  if (new_buffer == nullptr) {
    return -1;
  }
  buffer->data = new_buffer;
  buffer->capacity = minimum_capacity;
  return 0;
}

static int frames_reserve(struct wsc_decoder *decoder, size_t capacity) {
  if (capacity <= decoder->frames_capacity) {
    return -1;
  }
  if (capacity > ((size_t)-1) / sizeof(struct wsc_frame)) {
    return -1;
  }
  size_t bytes = capacity * sizeof(struct wsc_frame);
  if (decoder->frames != nullptr) {
    struct wsc_frame *new_buffer = ra_reallocate(decoder->allocator, decoder->frames, bytes);
    if (new_buffer != nullptr) {
      decoder->frames = new_buffer;
      decoder->frames_capacity = capacity;
      return 0;
    }
  }
  struct wsc_frame *new_buffer = ra_allocate(decoder->allocator, bytes);
  if (new_buffer == nullptr) {
    return -1;
  }
  if (decoder->frames != nullptr && decoder->frames_count > 0) {
    memcpy(new_buffer, decoder->frames, decoder->frames_count * sizeof(*new_buffer));
  }
  decoder->frames = new_buffer;
  decoder->frames_capacity = capacity;
  return 0;
}

#endif

static int frames_push(struct wsc_decoder *decoder, struct wsc_frame frame) {
  if (decoder->frames_count == decoder->frames_capacity) {
    size_t capacity = decoder->frames_capacity ? decoder->frames_capacity * 2 : FRAMES_INIT;
    if (frames_reserve(decoder, capacity) != 0) {
      return -1;
    }
  }
  decoder->frames[decoder->frames_count] = frame;
  decoder->frames_count++;
  return 0;
}

#ifdef WSC_HOSTED

static enum wsc_status attach_payload(const uint8_t *source, struct wsc_frame *frame) {
  if (source == nullptr) {
    trap();
  }
  uint8_t *copy = malloc(frame->payload_length);
  if (copy == nullptr) {
    return WSC_ERR_NO_MEMORY;
  }
  memcpy(copy, source, frame->payload_length);
  frame->payload = copy;
  return WSC_OK;
}

static void begin_feed(struct wsc_decoder *decoder) {
  decoder->frames = nullptr;
  decoder->frames_count = 0;
  decoder->frames_capacity = 0;
}

static enum wsc_status finish_frame(struct wsc_decoder *decoder) {
  struct wsc_frame frame = {
      .payload = nullptr,
      .payload_length = (size_t)decoder->payload_length,
      .opcode = decoder->opcode,
      .fin = decoder->fin,
      .rsv1 = decoder->rsv1,
      .rsv2 = decoder->rsv2,
      .rsv3 = decoder->rsv3,
      .masked = decoder->masked,
  };
  memcpy(frame.masking_key, decoder->masking_key, WSC_MASKING_KEY_LENGTH);

  if (frame.payload_length > 0) {
    enum wsc_status status = attach_payload(decoder->payload.data, &frame);
    if (status != WSC_OK) {
      return status;
    }
  }
  if (frames_push(decoder, frame) != 0) {
    free((void *)frame.payload);
    return WSC_ERR_NO_MEMORY;
  }
  decoder->payload.length = 0;
  return WSC_OK;
}

#else

static enum wsc_status attach_payload(const uint8_t *source, struct wsc_frame *frame) {
  if (source == nullptr) {
    trap();
  }
  frame->payload = source;
  return WSC_OK;
}

static void begin_feed(struct wsc_decoder *decoder) {
  if (decoder->state == STATE_PAYLOAD && decoder->payload.data != nullptr) {
    ra_free_before(decoder->allocator, decoder->payload.data);
  } else {
    ra_free_all(decoder->allocator);
    decoder->payload.data = nullptr;
    decoder->payload.length = 0;
    decoder->payload.capacity = 0;
  }
  decoder->frames = nullptr;
  decoder->frames_count = 0;
  decoder->frames_capacity = 0;
}

static enum wsc_status finish_frame(struct wsc_decoder *decoder) {
  struct wsc_frame frame = {
      .payload = nullptr,
      .payload_length = (size_t)decoder->payload_length,
      .opcode = decoder->opcode,
      .fin = decoder->fin,
      .rsv1 = decoder->rsv1,
      .rsv2 = decoder->rsv2,
      .rsv3 = decoder->rsv3,
      .masked = decoder->masked,
  };
  memcpy(frame.masking_key, decoder->masking_key, WSC_MASKING_KEY_LENGTH);

  if (frame.payload_length > 0) {
    enum wsc_status status = attach_payload(decoder->payload.data, &frame);
    if (status != WSC_OK) {
      return status;
    }
  }
  if (frames_push(decoder, frame) != 0) {
    return WSC_ERR_NO_MEMORY;
  }
  decoder->payload.data = nullptr;
  decoder->payload.capacity = 0;
  decoder->payload.length = 0;
  return WSC_OK;
}

#endif

static enum wsc_status fail(struct wsc_decoder *decoder, enum wsc_status status) {
  decoder->last_status = status;
  decoder->state = STATE_DEAD;
  return status;
}

static void reset_header(struct wsc_decoder *decoder) {
  decoder->state = STATE_HEADER;
  decoder->header_received = 0;
  decoder->header_expected_length = HEADER_BASE_SIZE;
  decoder->mask_offset = 0;
}

static enum wsc_status parse_header(struct wsc_decoder *decoder) {
  unsigned byte0 = decoder->header[0];
  unsigned byte1 = decoder->header[1];
  unsigned length7 = byte1 & LENGTH7_MASK;
  size_t offset = HEADER_BASE_SIZE;
  uint64_t payload_length = 0;

  decoder->fin = (byte0 & FIN_BIT) != 0;
  decoder->rsv1 = (byte0 & RSV1_BIT) != 0;
  decoder->rsv2 = (byte0 & RSV2_BIT) != 0;
  decoder->rsv3 = (byte0 & RSV3_BIT) != 0;
  decoder->opcode = (uint8_t)(byte0 & OPCODE_MASK);
  decoder->masked = (byte1 & MASK_BIT) != 0;

  if (length7 == LENGTH16) {
    payload_length = extended_payload_length16(decoder->header + HEADER_BASE_SIZE);
    offset = HEADER_BASE_SIZE + LENGTH16_EXT_SIZE;
    if (payload_length <= LENGTH7_MAX) {
      return fail(decoder, WSC_ERR_LENGTH_NOT_MINIMAL);
    }
  } else if (length7 == LENGTH64) {
    payload_length = extended_payload_length64(decoder->header + HEADER_BASE_SIZE);
    offset = HEADER_BASE_SIZE + LENGTH64_EXT_SIZE;
    if ((payload_length & LENGTH64_MSB) != 0) {
      return fail(decoder, WSC_ERR_LENGTH64_MSB);
    }
    if (payload_length <= UINT16_MAX) {
      return fail(decoder, WSC_ERR_LENGTH_NOT_MINIMAL);
    }
  } else {
    payload_length = length7;
  }

  if (decoder->masked) {
    memcpy(decoder->masking_key, decoder->header + offset, WSC_MASKING_KEY_LENGTH);
  } else {
    memset(decoder->masking_key, 0, WSC_MASKING_KEY_LENGTH);
  }

  if (payload_length > (uint64_t)(size_t)-1) {
    return WSC_ERR_NO_MEMORY;
  }

  decoder->payload_length = payload_length;
  decoder->mask_offset = 0;
  decoder->payload.length = 0;

  if (payload_length == 0) {
    enum wsc_status status = finish_frame(decoder);
    if (status != WSC_OK) {
      return status;
    }
    reset_header(decoder);
    return WSC_OK;
  }

  if (reserve_payload(decoder, (size_t)payload_length) != 0) {
    return WSC_ERR_NO_MEMORY;
  }
  decoder->state = STATE_PAYLOAD;
  return WSC_OK;
}

static size_t feed_header(struct wsc_decoder *decoder, enum wsc_status *status,
                          const uint8_t *source, size_t source_length) {
  size_t used = 0;
  if (decoder->header_received < HEADER_BASE_SIZE) {
    decoder->header_expected_length = HEADER_BASE_SIZE;
  }

  size_t take = decoder->header_expected_length - decoder->header_received;
  if (take > source_length) {
    take = source_length;
  }
  if (take > 0) {
    memcpy(decoder->header + decoder->header_received, source, take);
    decoder->header_received += take;
    used = take;
    if (decoder->header_received >= HEADER_BASE_SIZE) {
      decoder->header_expected_length = header_length(decoder->header[1]);
    }
  }

  if (decoder->header_received < decoder->header_expected_length ||
      decoder->header_expected_length < HEADER_BASE_SIZE) {
    return used;
  }

  *status = parse_header(decoder);
  if (*status == WSC_ERR_NO_MEMORY && take > 0) {
    decoder->header_received -= take;
    if (decoder->header_received < HEADER_BASE_SIZE) {
      decoder->header_expected_length = HEADER_BASE_SIZE;
    } else {
      decoder->header_expected_length = header_length(decoder->header[1]);
    }
    return 0;
  }
  return used;
}

static size_t feed_payload(struct wsc_decoder *decoder, enum wsc_status *status,
                           const uint8_t *source, size_t source_length) {
  size_t left = (size_t)decoder->payload_length - decoder->payload.length;
  size_t take = source_length;
  if (take > left) {
    take = left;
  }
  if (decoder->payload.data == nullptr) {
    trap();
  }
  memcpy(decoder->payload.data + decoder->payload.length, source, take);
  if (decoder->masked) {
    apply_mask(decoder->payload.data + decoder->payload.length, take, decoder->masking_key,
               decoder->mask_offset);
  }
  decoder->mask_offset = (decoder->mask_offset + (unsigned)take) & (WSC_MASKING_KEY_LENGTH - 1U);
  decoder->payload.length += take;

  if (decoder->payload.length < decoder->payload_length) {
    return take;
  }

  *status = finish_frame(decoder);
  if (*status != WSC_OK) {
    decoder->payload.length -= take;
    decoder->mask_offset = (decoder->mask_offset - (unsigned)take) & (WSC_MASKING_KEY_LENGTH - 1U);
    return 0;
  }
  reset_header(decoder);
  return take;
}

struct wsc_decoding_result wsc_decoder_feed(struct wsc_decoder *decoder, const uint8_t *source,
                                            size_t source_length) {
  if (decoder == nullptr) {
    trap();
  }
  if (source_length > 0 && source == nullptr) {
    trap();
  }
  begin_feed(decoder);
  if (decoder->state == STATE_DEAD) {
    return (struct wsc_decoding_result){
        .status = decoder->last_status,
        .frames = decoder->frames_count ? decoder->frames : nullptr,
        .frames_count = decoder->frames_count,
        .source_consumed = 0,
    };
  }

  struct wsc_decoding_result result = {
      .status = WSC_OK,
      .frames = nullptr,
      .frames_count = 0,
      .source_consumed = 0,
  };

  while (result.source_consumed < source_length && decoder->state != STATE_DEAD) {
    if (decoder->state == STATE_HEADER) {
      result.source_consumed +=
          feed_header(decoder, &result.status, source + result.source_consumed,
                      source_length - result.source_consumed);
    } else {
      result.source_consumed +=
          feed_payload(decoder, &result.status, source + result.source_consumed,
                       source_length - result.source_consumed);
    }
    result.frames = decoder->frames_count ? decoder->frames : nullptr;
    result.frames_count = decoder->frames_count;
    if (result.status != WSC_OK) {
      break;
    }
  }

  return result;
}

#ifdef WSC_HOSTED

struct wsc_decoder *wsc_decoder_create() {
  struct wsc_decoder *decoder = calloc(1, sizeof(*decoder));
  if (decoder == nullptr) {
    return nullptr;
  }
  decoder->state = STATE_HEADER;
  decoder->header_expected_length = HEADER_BASE_SIZE;
  return decoder;
}

struct wsc_encoding_result wsc_encode(const struct wsc_frame *frame) {
  if (frame == nullptr) trap();

  struct wsc_encoding_result result = {.status = WSC_OK};
  size_t total = encoded_frame_length(frame);

  result.data_length = total;
  result.data = malloc(total);
  if (result.data == nullptr) {
    result.status = WSC_ERR_NO_MEMORY;
    result.data_length = 0;
    return result;
  }
  encode_into(result.data, frame);
  return result;
}

void wsc_decoder_destroy(struct wsc_decoder *decoder) {
  if (decoder == nullptr) {
    return;
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
  if (arena == nullptr) {
    trap();
  }
  size_t padding =
      (alignof(struct wsc_decoder) - ((uintptr_t)arena % alignof(struct wsc_decoder))) %
      alignof(struct wsc_decoder);
  if (padding > capacity || sizeof(struct wsc_decoder) > capacity - padding) {
    return nullptr;
  }
  unsigned char *end = arena + capacity;
  unsigned char *slot = arena + padding;
  unsigned char *rest = slot + sizeof(struct wsc_decoder);
  struct ringalloc *allocator = ra_create(rest, (size_t)(end - rest));
  if (allocator == nullptr) {
    return nullptr;
  }
  struct wsc_decoder *decoder = (struct wsc_decoder *)slot;
  *decoder = (struct wsc_decoder){
      .allocator = allocator,
      .state = STATE_HEADER,
      .header_expected_length = HEADER_BASE_SIZE,
  };
  return decoder;
}

size_t wsc_encoded_frame_length(const struct wsc_frame *frame) {
  return encoded_frame_length(frame);
}

size_t wsc_encode(uint8_t *destination, const struct wsc_frame *frame) {
  return encode_into(destination, frame);
}

#endif
