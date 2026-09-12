#include "wsc.h"
#include "wsc_common.h"

#include <ringalloc.h>
#include <stdint.h>
#include <string.h>

[[noreturn]] void wsc_trap() {
  unreachable();
}

int wsc_buffer_reserve(struct wsc_decoder *decoder, struct wsc_buffer *buffer,
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

void wsc_clear_frames(struct wsc_decoder *decoder) {
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

int wsc_frames_reserve(struct wsc_decoder *decoder, size_t capacity) {
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

enum wsc_status wsc_attach_payload(struct wsc_decoder *decoder, struct wsc_frame *frame) {
  if (decoder->payload.data == nullptr) {
    wsc_trap();
  }
  frame->payload = decoder->payload.data;
  return WSC_OK;
}

void wsc_discard_payload(struct wsc_frame *frame) {
  (void)frame;
}

void wsc_payload_emitted(struct wsc_decoder *decoder) {
  decoder->payload.data = nullptr;
  decoder->payload.capacity = 0;
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

size_t wsc_encode(uint8_t *destination, size_t destination_capacity,
                  const struct wsc_frame *frame) {
  return wsc_encode_buffer(destination, destination_capacity, frame);
}

struct wsc_decoding_result wsc_decoder_feed(struct wsc_decoder *decoder, const uint8_t *source,
                                            size_t length) {
  if (decoder == nullptr) {
    wsc_trap();
  }
  return wsc_decoder_feed_data(decoder, source, length);
}
