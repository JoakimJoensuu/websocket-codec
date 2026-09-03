#include "ringalloc.h"
#include "wsc.h"
#include "wsc_internal.h"

#include <stdint.h>
#include <string.h>

static int ring_track_push(struct wsc_decoder *decoder, void *pointer) {
  if (decoder->allocation_count >= WSC_RING_TRACK_MAX) {
    return -1;
  }
  decoder->ring_track[decoder->allocation_count] = pointer;
  decoder->allocation_count++;
  return 0;
}

static void ring_track_replace(struct wsc_decoder *decoder, void *const *slot, void *new_pointer) {
  if (slot < decoder->ring_track || slot >= decoder->ring_track + decoder->allocation_count) {
    wsc_trap();
  }
  *(void **)slot = new_pointer;
}

static void *const *ring_track_find(struct wsc_decoder *decoder, void *pointer) {
  for (size_t index = 0; index < decoder->allocation_count; index++) {
    if (decoder->ring_track[index] == pointer) {
      return &decoder->ring_track[index];
    }
  }
  return nullptr;
}

static void ring_free_oldest(struct wsc_decoder *decoder) {
  if (decoder->allocation_count == 0) {
    wsc_trap();
  }
  ra_free(decoder->ringalloc, decoder->ring_track[0]);
  decoder->allocation_count--;
  if (decoder->allocation_count > 0) {
    memmove((void *)decoder->ring_track, (const void *)(decoder->ring_track + 1),
            decoder->allocation_count * sizeof(decoder->ring_track[0]));
  }
}

static void *ring_alloc(struct wsc_decoder *decoder, size_t size) {
  void *pointer = nullptr;
  if (decoder->allocation_count >= WSC_RING_TRACK_MAX) {
    return nullptr;
  }
  pointer = ra_allocate(decoder->ringalloc, size);
  if (pointer == nullptr) {
    return nullptr;
  }
  if (ring_track_push(decoder, pointer) != 0) {
    wsc_trap();
  }
  return pointer;
}

static void ring_reset(struct wsc_decoder *decoder) {
  ra_reset(decoder->ringalloc);
  decoder->allocation_count = 0;
}

int wsc_buffer_reserve(struct wsc_decoder *decoder, struct wsc_buffer *buffer,
                       size_t minimum_capacity) {
  uint8_t *new_buffer = nullptr;
  if (minimum_capacity <= buffer->capacity) {
    return 0;
  }
  if (buffer->data != nullptr) {
    new_buffer = (uint8_t *)ra_reallocate(decoder->ringalloc, buffer->data, minimum_capacity);
    if (new_buffer == nullptr) {
      return -1;
    }
    if (new_buffer != buffer->data) {
      void *const *slot = ring_track_find(decoder, buffer->data);
      if (slot == nullptr) {
        wsc_trap();
      }
      ring_track_replace(decoder, slot, new_buffer);
      buffer->data = new_buffer;
    }
    buffer->capacity = minimum_capacity;
    return 0;
  }
  new_buffer = (uint8_t *)ring_alloc(decoder, minimum_capacity);
  if (new_buffer == nullptr) {
    return -1;
  }
  buffer->data = new_buffer;
  buffer->capacity = minimum_capacity;
  return 0;
}

void wsc_clear_frames(struct wsc_decoder *decoder) {
  if (decoder->state == WSC_STATE_PAYLOAD && decoder->payload.data != nullptr) {
    while (decoder->allocation_count > 1) {
      if (decoder->ring_track[0] == decoder->payload.data) {
        wsc_trap();
      }
      ring_free_oldest(decoder);
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
      if (new_buffer != decoder->frames) {
        void *const *slot = ring_track_find(decoder, decoder->frames);
        if (slot == nullptr) {
          wsc_trap();
        }
        ring_track_replace(decoder, slot, new_buffer);
        decoder->frames = new_buffer;
      }
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

struct wsc_decoder *wsc_decoder_create(void *buffer, size_t capacity) {
  uint8_t *raw = nullptr;
  size_t align = alignof(struct wsc_decoder);
  size_t skip = 0;
  size_t after = 0;
  struct wsc_decoder *decoder = nullptr;

  if (buffer == nullptr) {
    wsc_trap();
  }
  raw = (uint8_t *)buffer;
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
