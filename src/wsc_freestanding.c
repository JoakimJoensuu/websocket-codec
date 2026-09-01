#include "ringalloc.h"
#include "wsc.h"
#include "wsc_internal.h"

#include <stdint.h>
#include <string.h>

static void *ring_alloc(struct wsc_decoder *decoder, size_t size) {
  void *ptr = ra_allocate(decoder->ringalloc, size);
  if (ptr != nullptr) {
    decoder->alloc_count++;
  }
  return ptr;
}

static void ring_free(struct wsc_decoder *decoder) {
  void *oldest = decoder->payload.data;
  if (oldest == nullptr) {
    oldest = decoder->frames;
  }
  if (oldest == nullptr) {
    wsc_trap();
  }
  ra_free(decoder->ringalloc, oldest);
  decoder->alloc_count--;
}

static void ring_reset(struct wsc_decoder *decoder) {
  ra_reset(decoder->ringalloc);
  decoder->alloc_count = 0;
}

int wsc_buffer_reserve(struct wsc_decoder *decoder, struct wsc_buffer *buffer,
                       size_t minimum_capacity) {
  uint8_t *new_buffer = nullptr;
  if (minimum_capacity <= buffer->capacity) {
    return 0;
  }
  if (buffer->data != nullptr) {
    new_buffer = (uint8_t *)ra_reallocate(decoder->ringalloc, buffer->data, minimum_capacity);
    if (new_buffer != nullptr) {
      buffer->capacity = minimum_capacity;
      return 0;
    }
    return -1;
  }
  new_buffer = (uint8_t *)ring_alloc(decoder, minimum_capacity);
  if (new_buffer == nullptr) {
    return -1;
  }
  if (buffer->data != nullptr && buffer->length > 0) {
    memcpy(new_buffer, buffer->data, buffer->length);
  }
  buffer->data = new_buffer;
  buffer->capacity = minimum_capacity;
  return 0;
}

void wsc_clear_frames(struct wsc_decoder *decoder) {
  if (decoder->state == WSC_ST_PAYLOAD && decoder->payload.data != nullptr) {
    while (decoder->alloc_count > 1) {
      ring_free(decoder);
    }
  } else {
    ring_reset(decoder);
    decoder->payload.data = nullptr;
    decoder->payload.length = 0;
    decoder->payload.capacity = 0;
  }
  decoder->frames = nullptr;
  decoder->frames_count = 0;
  decoder->frames_capacity = 0;
}

int wsc_frames_reserve(struct wsc_decoder *decoder, size_t capacity) {
  size_t bytes = 0;
  struct wsc_frame *new_buffer = nullptr;
  if (capacity <= decoder->frames_capacity) {
    return -1;
  }
  if (capacity > ((size_t)-1) / sizeof(struct wsc_frame)) {
    return -1;
  }
  bytes = capacity * sizeof(struct wsc_frame);
  if (decoder->frames != nullptr) {
    new_buffer = (struct wsc_frame *)ra_reallocate(decoder->ringalloc, decoder->frames, bytes);
    if (new_buffer != nullptr) {
      decoder->frames_capacity = capacity;
      return 0;
    }
  }
  new_buffer = (struct wsc_frame *)ring_alloc(decoder, bytes);
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

struct wsc_decoder *wsc_decoder_create(void *buf, size_t capacity) {
  uint8_t *raw = nullptr;
  size_t align = alignof(struct wsc_decoder);
  size_t skip = 0;
  size_t after = 0;
  struct wsc_decoder *decoder = nullptr;

  if (buf == nullptr) {
    wsc_trap();
  }
  raw = (uint8_t *)buf;
  skip = ((uintptr_t)raw % align == 0) ? 0 : align - ((uintptr_t)raw % align);
  if (skip > capacity || sizeof(struct wsc_decoder) > capacity - skip) {
    return nullptr;
  }
  decoder = (struct wsc_decoder *)(raw + skip);
  memset(decoder, 0, sizeof(*decoder));
  after = skip + sizeof(*decoder);
  decoder->ringalloc = ra_initialize((unsigned char *)(raw + after), capacity - after);
  if (decoder->ringalloc == nullptr) {
    return nullptr;
  }
  wsc_decoder_state_init(decoder);
  return decoder;
}
