#include "ringalloc.h"
#include "wsc.h"
#include "wsc_internal.h"

#include <stdint.h>
#include <string.h>

int wsc_buffer_reserve(struct wsc_decoder *decoder, struct wsc_buffer *buffer,
                       size_t minimum_capacity) {
  if (minimum_capacity <= buffer->capacity) {
    return 0;
  }
  if (buffer->data != nullptr) {
    uint8_t *new_buffer =
        (uint8_t *)ra_reallocate(decoder->ringalloc, buffer->data, minimum_capacity);
    if (new_buffer == nullptr) {
      return -1;
    }
    buffer->data = new_buffer;
    buffer->capacity = minimum_capacity;
    return 0;
  }
  uint8_t *new_buffer = (uint8_t *)ra_allocate(decoder->ringalloc, minimum_capacity);
  if (new_buffer == nullptr) {
    return -1;
  }
  buffer->data = new_buffer;
  buffer->capacity = minimum_capacity;
  return 0;
}

void wsc_clear_frames(struct wsc_decoder *decoder) {
  if (decoder->state == WSC_STATE_PAYLOAD && decoder->payload.data != nullptr) {
    size_t capacity = decoder->payload.capacity;
    size_t length = decoder->payload.length;
    uint8_t *old = decoder->payload.data;
    ra_reset(decoder->ringalloc);
    uint8_t *fresh = (uint8_t *)ra_allocate(decoder->ringalloc, capacity);
    if (fresh == nullptr) {
      wsc_trap();
    }
    memmove(fresh, old, length);
    decoder->payload.data = fresh;
    decoder->payload.capacity = capacity;
    decoder->payload.length = length;
  } else {
    ra_reset(decoder->ringalloc);
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
    struct wsc_frame *new_buffer =
        (struct wsc_frame *)ra_reallocate(decoder->ringalloc, decoder->frames, bytes);
    if (new_buffer != nullptr) {
      decoder->frames = new_buffer;
      decoder->frames_capacity = capacity;
      return 0;
    }
  }
  struct wsc_frame *new_buffer = (struct wsc_frame *)ra_allocate(decoder->ringalloc, bytes);
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

enum wsc_err wsc_attach_payload(struct wsc_decoder *decoder, struct wsc_frame *frame) {
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

void wsc_decoder_free(struct wsc_decoder *decoder) {
  (void)decoder;
}

struct wsc_decoder *wsc_decoder_create(void *buffer, size_t capacity) {
  if (buffer == nullptr) {
    wsc_trap();
  }
  uint8_t *raw = (uint8_t *)buffer;
  size_t align = alignof(struct wsc_decoder);
  size_t skip = ((uintptr_t)raw % align == 0) ? 0 : align - ((uintptr_t)raw % align);
  if (skip > capacity || sizeof(struct wsc_decoder) > capacity - skip) {
    return nullptr;
  }
  struct wsc_decoder *decoder = (struct wsc_decoder *)(raw + skip);
  memset(decoder, 0, sizeof(*decoder));
  size_t after = skip + sizeof(*decoder);
  decoder->ringalloc = ra_initialize((unsigned char *)(raw + after), capacity - after);
  if (decoder->ringalloc == nullptr) {
    return nullptr;
  }
  wsc_decoder_state_init(decoder);
  return decoder;
}
