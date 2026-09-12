#include "wsc.h"
#include "wsc_common.h"

#include <ringalloc.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct wsc_decoder_data {
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

static int wsc_buffer_reserve(struct wsc_decoder_data *decoder, struct wsc_buffer *buffer,
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

static void wsc_clear_frames(struct wsc_decoder_data *decoder) {
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

static int wsc_frames_reserve(struct wsc_decoder_data *decoder, size_t capacity) {
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

static enum wsc_status wsc_attach_payload(struct wsc_decoder_data *decoder,
                                          struct wsc_frame *frame) {
  if (decoder->payload.data == nullptr) {
    wsc_trap();
  }
  frame->payload = decoder->payload.data;
  return WSC_OK;
}

static void wsc_discard_payload(struct wsc_frame *frame) {
  (void)frame;
}

static void wsc_payload_emitted(struct wsc_decoder_data *decoder) {
  decoder->payload.data = nullptr;
  decoder->payload.capacity = 0;
}

#include "wsc_decode.c"

struct wsc_decoder *wsc_decoder_create(unsigned char *arena, size_t capacity) {
  if (arena == nullptr) {
    wsc_trap();
  }
  size_t align = alignof(struct wsc_decoder_data);
  size_t skip = ((uintptr_t)arena % align == 0) ? 0 : align - ((uintptr_t)arena % align);
  if (skip > capacity || sizeof(struct wsc_decoder_data) > capacity - skip) {
    return nullptr;
  }
  unsigned char *slot = arena + skip;
  size_t after = skip + sizeof(struct wsc_decoder_data);
  struct wsc_decoder_data data = {};
  data.ringalloc = ra_create(arena + after, capacity - after);
  if (data.ringalloc == nullptr) {
    return nullptr;
  }
  wsc_decoder_state_init(&data);
  memcpy(slot, &data, sizeof(data));
  return (struct wsc_decoder *)slot;
}

struct wsc_decoding_result wsc_decoder_feed(struct wsc_decoder *decoder, const uint8_t *source,
                                            size_t length) {
  if (decoder == nullptr) {
    wsc_trap();
  }
  struct wsc_decoder_data data;
  memcpy(&data, decoder, sizeof(data));
  struct wsc_decoding_result result = wsc_decoder_feed_data(&data, source, length);
  memcpy(decoder, &data, sizeof(data));
  return result;
}

size_t wsc_encode(uint8_t *destination, size_t destination_capacity,
                  const struct wsc_frame *frame) {
  return wsc_encode_buffer(destination, destination_capacity, frame);
}
