#include "wsc.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <ringalloc.h>

enum : unsigned {
  WSC_HEADER_BASE  = 2,
  WSC_LENGTH16_EXT = 2,
  WSC_LENGTH64_EXT = 8,
  WSC_HEADER_MAX   = WSC_HEADER_BASE + WSC_LENGTH64_EXT + WSC_MASKING_KEY_LENGTH,
};

enum : unsigned {
  WSC_LENGTH7_MAX = 125,
  WSC_LENGTH16    = 126,
  WSC_LENGTH64    = 127,
};

enum : uint8_t {
  WSC_FIN_BIT      = 0x80,
  WSC_RSV1_BIT     = 0x40,
  WSC_RSV2_BIT     = 0x20,
  WSC_RSV3_BIT     = 0x10,
  WSC_OPCODE_MASK  = 0x0F,
  WSC_MASK_BIT     = 0x80,
  WSC_LENGTH7_MASK = 0x7F,
};

enum : uint64_t { WSC_LENGTH64_MSB = 0x8000000000000000 };

enum : unsigned {
  WSC_BUFFER_INIT = 256,
  WSC_FRAMES_INIT = 8,
};

enum : unsigned { WSC_BYTE_BITS = CHAR_BIT };

enum wsc_parse_state { WSC_STATE_HEADER = 0, WSC_STATE_PAYLOAD, WSC_STATE_DEAD };

struct wsc_buffer {
  uint8_t *data;
  size_t length;
  size_t capacity;
};

struct wsc_decoder {
  uint64_t payload_length;
  uint64_t payload_received;
  struct wsc_buffer payload;
  struct ringalloc *ringalloc;
  struct wsc_frame *frames;
  size_t frames_count;
  size_t frames_capacity;
  size_t header_received;
  size_t header_total;
  enum wsc_parse_state state;
  unsigned mask_offset;
  enum wsc_status last_status;
  bool fin;
  bool rsv1;
  bool rsv2;
  bool rsv3;
  bool masked;
  uint8_t opcode;
  uint8_t masking_key[WSC_MASKING_KEY_LENGTH];
  uint8_t header[WSC_HEADER_MAX];
};

[[noreturn]] static void wsc_trap() {
  unreachable();
}

static int wsc_buffer_reserve(struct wsc_decoder *decoder, struct wsc_buffer *buffer,
                              size_t minimum_capacity) {
  if (minimum_capacity <= buffer->capacity) {
    return 0;
  }
  if (buffer->data != nullptr) {
    uint8_t *new_buffer = ra_reallocate(decoder->ringalloc, buffer->data, minimum_capacity);
    if (new_buffer == nullptr) {
      return -1;
    }
    buffer->data = new_buffer;
    buffer->capacity = minimum_capacity;
    return 0;
  }
  uint8_t *new_buffer = ra_allocate(decoder->ringalloc, minimum_capacity);
  if (new_buffer == nullptr) {
    return -1;
  }
  buffer->data = new_buffer;
  buffer->capacity = minimum_capacity;
  return 0;
}

static void wsc_clear_frames(struct wsc_decoder *decoder) {
  if (decoder->state == WSC_STATE_PAYLOAD && decoder->payload.data != nullptr) {
    ra_free_before(decoder->ringalloc, decoder->payload.data);
  } else {
    ra_free_all(decoder->ringalloc);
    decoder->payload.data = nullptr;
    decoder->payload.length = 0;
    decoder->payload.capacity = 0;
  }
  decoder->frames = nullptr;
  decoder->frames_count = 0;
  decoder->frames_capacity = 0;
}

static int wsc_frames_reserve(struct wsc_decoder *decoder, size_t capacity) {
  if (capacity <= decoder->frames_capacity) {
    return -1;
  }
  if (capacity > ((size_t)-1) / sizeof(struct wsc_frame)) {
    return -1;
  }
  size_t bytes = capacity * sizeof(struct wsc_frame);
  if (decoder->frames != nullptr) {
    struct wsc_frame *new_buffer = ra_reallocate(decoder->ringalloc, decoder->frames, bytes);
    if (new_buffer != nullptr) {
      decoder->frames = new_buffer;
      decoder->frames_capacity = capacity;
      return 0;
    }
  }
  struct wsc_frame *new_buffer = ra_allocate(decoder->ringalloc, bytes);
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

static enum wsc_status wsc_attach_payload(struct wsc_decoder *decoder, struct wsc_frame *frame) {
  if (decoder->payload.data == nullptr) {
    wsc_trap();
  }
  frame->payload = decoder->payload.data;
  return WSC_OK;
}

static void wsc_discard_payload(struct wsc_frame *frame) {
  (void)frame;
}

static void wsc_payload_emitted(struct wsc_decoder *decoder) {
  decoder->payload.data = nullptr;
  decoder->payload.capacity = 0;
}

static uint16_t read_uint16(const uint8_t *source) {
  return (uint16_t)(((unsigned)source[0] << WSC_BYTE_BITS) | (unsigned)source[1]);
}

static uint64_t read_uint64(const uint8_t *source) {
  uint64_t value = 0;
  for (int i = 0; i < (int)sizeof(uint64_t); i++) {
    value = (value << WSC_BYTE_BITS) | (uint64_t)source[i];
  }
  return value;
}

static void write_uint16(uint8_t *destination, uint16_t value) {
  destination[0] = (uint8_t)((unsigned)value >> WSC_BYTE_BITS);
  destination[1] = (uint8_t)value;
}

static void write_uint64(uint8_t *destination, uint64_t value) {
  for (int i = (int)sizeof(uint64_t) - 1; i >= 0; i--) {
    destination[i] = (uint8_t)value;
    value >>= WSC_BYTE_BITS;
  }
}

static void apply_mask(uint8_t *data, size_t length, const uint8_t key[WSC_MASKING_KEY_LENGTH],
                       unsigned offset) {
  for (size_t i = 0; i < length; i++) {
    data[i] = (uint8_t)((unsigned)data[i] ^ key[(offset + i) & (WSC_MASKING_KEY_LENGTH - 1U)]);
  }
}

static size_t encoded_header_length(size_t payload_length, bool masked) {
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

static size_t header_length(unsigned byte1) {
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

static void require_frame(const struct wsc_frame *frame) {
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
    write_uint16(header + WSC_HEADER_BASE, (uint16_t)frame->payload_length);
    header_length = WSC_HEADER_BASE + WSC_LENGTH16_EXT;
  } else {
    header[1] = WSC_LENGTH64;
    write_uint64(header + WSC_HEADER_BASE, (uint64_t)frame->payload_length);
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

static size_t wsc_encode_buffer(uint8_t *destination, size_t destination_capacity,
                                const struct wsc_frame *frame) {
  size_t total = wsc_encoded_frame_length(frame);
  if (destination == nullptr) {
    wsc_trap();
  }
  if (destination_capacity < total) {
    wsc_trap();
  }
  return write_frame(destination, frame);
}

static struct wsc_decoding_result make_result(struct wsc_decoder *decoder, size_t source_consumed,
                                              enum wsc_status status) {
  return (struct wsc_decoding_result){
      .status = status,
      .frames = decoder->frames_count ? decoder->frames : nullptr,
      .frames_count = decoder->frames_count,
      .source_consumed = source_consumed,
  };
}

static enum wsc_status fail(struct wsc_decoder *decoder, enum wsc_status status) {
  decoder->last_status = status;
  decoder->state = WSC_STATE_DEAD;
  return status;
}

static bool header_ready(const struct wsc_decoder *decoder) {
  return decoder->state == WSC_STATE_HEADER && decoder->header_received >= decoder->header_total &&
         decoder->header_total >= WSC_HEADER_BASE;
}

static bool payload_ready(const struct wsc_decoder *decoder) {
  return decoder->state == WSC_STATE_PAYLOAD &&
         decoder->payload_received >= decoder->payload_length;
}

static int frames_push(struct wsc_decoder *decoder, struct wsc_frame frame) {
  if (decoder->frames_count == decoder->frames_capacity) {
    size_t capacity = decoder->frames_capacity ? decoder->frames_capacity * 2 : WSC_FRAMES_INIT;
    if (wsc_frames_reserve(decoder, capacity) != 0) {
      return -1;
    }
  }
  decoder->frames[decoder->frames_count] = frame;
  decoder->frames_count++;
  return 0;
}

static enum wsc_status emit(struct wsc_decoder *decoder) {
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
    enum wsc_status status = wsc_attach_payload(decoder, &frame);
    if (status != WSC_OK) {
      return status;
    }
  }
  if (frames_push(decoder, frame) != 0) {
    wsc_discard_payload(&frame);
    return WSC_ERR_NO_MEMORY;
  }
  wsc_payload_emitted(decoder);
  decoder->payload.length = 0;
  return WSC_OK;
}

static void reset_header(struct wsc_decoder *decoder) {
  decoder->state = WSC_STATE_HEADER;
  decoder->header_received = 0;
  decoder->header_total = WSC_HEADER_BASE;
  decoder->payload_received = 0;
  decoder->mask_offset = 0;
}

static enum wsc_status on_header(struct wsc_decoder *decoder) {
  unsigned byte0 = decoder->header[0];
  unsigned byte1 = decoder->header[1];
  unsigned length7 = byte1 & WSC_LENGTH7_MASK;
  size_t offset = WSC_HEADER_BASE;
  uint64_t payload_length = 0;

  decoder->fin = (byte0 & WSC_FIN_BIT) != 0;
  decoder->rsv1 = (byte0 & WSC_RSV1_BIT) != 0;
  decoder->rsv2 = (byte0 & WSC_RSV2_BIT) != 0;
  decoder->rsv3 = (byte0 & WSC_RSV3_BIT) != 0;
  decoder->opcode = (uint8_t)(byte0 & WSC_OPCODE_MASK);
  decoder->masked = (byte1 & WSC_MASK_BIT) != 0;

  if (length7 == WSC_LENGTH16) {
    payload_length = read_uint16(decoder->header + WSC_HEADER_BASE);
    offset = WSC_HEADER_BASE + WSC_LENGTH16_EXT;
    if (payload_length <= WSC_LENGTH7_MAX) {
      return fail(decoder, WSC_ERR_LENGTH_NOT_MINIMAL);
    }
  } else if (length7 == WSC_LENGTH64) {
    payload_length = read_uint64(decoder->header + WSC_HEADER_BASE);
    offset = WSC_HEADER_BASE + WSC_LENGTH64_EXT;
    if ((payload_length & WSC_LENGTH64_MSB) != 0) {
      return fail(decoder, WSC_ERR_LENGTH64_MSB);
    }
    if (payload_length <= UINT16_MAX) {
      return fail(decoder, WSC_ERR_LENGTH_NOT_MINIMAL);
    }
  } else {
    payload_length = (uint64_t)length7;
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
  decoder->payload_received = 0;
  decoder->mask_offset = 0;
  decoder->payload.length = 0;

  if (payload_length == 0) {
    enum wsc_status status = emit(decoder);
    if (status != WSC_OK) {
      return status;
    }
    reset_header(decoder);
    return WSC_OK;
  }

  if (wsc_buffer_reserve(decoder, &decoder->payload, (size_t)payload_length) != 0) {
    return WSC_ERR_NO_MEMORY;
  }
  decoder->state = WSC_STATE_PAYLOAD;
  return WSC_OK;
}

static enum wsc_status on_payload_done(struct wsc_decoder *decoder) {
  enum wsc_status status = emit(decoder);
  if (status != WSC_OK) {
    return status;
  }
  reset_header(decoder);
  return WSC_OK;
}

static enum wsc_status feed_header(struct wsc_decoder *decoder, const uint8_t *source,
                                   size_t length, size_t *used) {
  *used = 0;
  if (decoder->header_received < WSC_HEADER_BASE) {
    decoder->header_total = WSC_HEADER_BASE;
  }
  size_t take = decoder->header_total - decoder->header_received;
  if (take > length) {
    take = length;
  }
  memcpy(decoder->header + decoder->header_received, source, take);
  decoder->header_received += take;
  *used = take;
  if (decoder->header_received >= WSC_HEADER_BASE) {
    decoder->header_total = header_length(decoder->header[1]);
  }
  if (decoder->header_received < decoder->header_total) {
    return WSC_OK;
  }
  return on_header(decoder);
}

static enum wsc_status feed_payload(struct wsc_decoder *decoder, const uint8_t *source,
                                    size_t length, size_t *used) {
  uint64_t left = decoder->payload_length - decoder->payload_received;
  size_t take = length;
  if ((uint64_t)take > left) {
    take = (size_t)left;
  }
  if (take == 0) {
    *used = 0;
    return WSC_OK;
  }
  if (decoder->payload.data == nullptr) {
    wsc_trap();
  }
  memcpy(decoder->payload.data + decoder->payload.length, source, take);
  if (decoder->masked) {
    apply_mask(decoder->payload.data + decoder->payload.length, take, decoder->masking_key,
               decoder->mask_offset);
  }
  decoder->mask_offset = (decoder->mask_offset + (unsigned)take) & (WSC_MASKING_KEY_LENGTH - 1U);
  decoder->payload.length += take;
  decoder->payload_received += take;
  *used = take;
  if (decoder->payload_received >= decoder->payload_length) {
    return on_payload_done(decoder);
  }
  return WSC_OK;
}

static void wsc_decoder_state_init(struct wsc_decoder *decoder) {
  decoder->state = WSC_STATE_HEADER;
  decoder->header_total = WSC_HEADER_BASE;
}

static struct wsc_decoding_result wsc_decoder_feed_data(struct wsc_decoder *decoder,
                                                        const uint8_t *source, size_t length) {
  if (length > 0 && source == nullptr) {
    wsc_trap();
  }
  wsc_clear_frames(decoder);
  if (decoder->state == WSC_STATE_DEAD) {
    return make_result(decoder, 0, decoder->last_status);
  }

  enum wsc_status status = WSC_OK;
  if (payload_ready(decoder)) {
    status = on_payload_done(decoder);
    if (status != WSC_OK) {
      return make_result(decoder, 0, status);
    }
  } else if (header_ready(decoder)) {
    status = on_header(decoder);
    if (status != WSC_OK) {
      return make_result(decoder, 0, status);
    }
  }

  size_t offset = 0;
  while (offset < length && decoder->state != WSC_STATE_DEAD) {
    size_t used = 0;
    if (decoder->state == WSC_STATE_HEADER) {
      status = feed_header(decoder, source + offset, length - offset, &used);
    } else {
      status = feed_payload(decoder, source + offset, length - offset, &used);
    }
    offset += used;
    if (status != WSC_OK) {
      break;
    }
    if (used == 0) {
      break;
    }
  }
  return make_result(decoder, offset, status);
}

struct wsc_decoder *wsc_decoder_create(unsigned char *arena, size_t capacity) {
  if (arena == nullptr) {
    wsc_trap();
  }
  size_t align = alignof(struct wsc_decoder);
  size_t skip = ((uintptr_t)arena % align == 0) ? 0 : align - ((uintptr_t)arena % align);
  if (skip > capacity || sizeof(struct wsc_decoder) > capacity - skip) {
    return nullptr;
  }
  unsigned char *slot = arena + skip;
  size_t after = skip + sizeof(struct wsc_decoder);
  struct wsc_decoder local = {};
  local.ringalloc = ra_create(arena + after, capacity - after);
  if (local.ringalloc == nullptr) {
    return nullptr;
  }
  wsc_decoder_state_init(&local);
  memcpy(slot, &local, sizeof(local));
  return (struct wsc_decoder *)slot;
}

size_t wsc_encoded_frame_length(const struct wsc_frame *frame) {
  require_frame(frame);
  size_t header_length = encoded_header_length(frame->payload_length, frame->masked);
  if (frame->payload_length > ((size_t)-1) - header_length) {
    wsc_trap();
  }
  return header_length + frame->payload_length;
}

size_t wsc_encode(uint8_t *destination, size_t destination_capacity,
                  const struct wsc_frame *frame) {
  return wsc_encode_buffer(destination, destination_capacity, frame);
}

struct wsc_decoding_result wsc_decoder_feed(struct wsc_decoder *decoder, const uint8_t *source,
                                            size_t length) {
  if (decoder == nullptr) {
    wsc_trap();
  }
  struct wsc_decoder local = *decoder;
  struct wsc_decoding_result result = wsc_decoder_feed_data(&local, source, length);
  *decoder = local;
  return result;
}
