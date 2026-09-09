#ifndef WSC_HOSTED_H
#define WSC_HOSTED_H

#include "wsc.h"
#include "wsc_common.h"

#include <stdlib.h>
#include <string.h>

struct wsc_decoder_data {
  uint64_t payload_length;
  uint64_t payload_received;
  struct wsc_buffer payload;
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

[[noreturn]] static inline void wsc_trap() {
  abort();
}

static inline int wsc_buffer_reserve(struct wsc_decoder_data *decoder, struct wsc_buffer *buffer,
                                     size_t minimum_capacity) {
  (void)decoder;
  if (minimum_capacity <= buffer->capacity) {
    return 0;
  }
  size_t capacity = buffer->capacity ? buffer->capacity : WSC_BUFFER_INIT;
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

static inline void wsc_clear_frames(struct wsc_decoder_data *decoder) {
  for (size_t i = 0; i < decoder->frames_count; i++) {
    free((void *)decoder->frames[i].payload);
    decoder->frames[i].payload = nullptr;
  }
  decoder->frames_count = 0;
}

static inline int wsc_frames_reserve(struct wsc_decoder_data *decoder, size_t capacity) {
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

static inline enum wsc_status wsc_attach_payload(struct wsc_decoder_data *decoder,
                                                 struct wsc_frame *frame) {
  if (decoder->payload.data == nullptr) {
    wsc_trap();
  }
  uint8_t *copy = malloc(frame->payload_length);
  if (copy == nullptr) {
    return WSC_ERR_NO_MEMORY;
  }
  memcpy(copy, decoder->payload.data, frame->payload_length);
  frame->payload = copy;
  return WSC_OK;
}

static inline void wsc_discard_payload(struct wsc_frame *frame) {
  free((void *)frame->payload);
  frame->payload = nullptr;
}

static inline void wsc_payload_emitted(struct wsc_decoder_data *decoder) {
  (void)decoder;
}

static inline void wsc_decoder_free(struct wsc_decoder_data *decoder) {
  wsc_clear_frames(decoder);
  free(decoder->frames);
  free(decoder->payload.data);
  decoder->frames = nullptr;
  decoder->payload.data = nullptr;
  decoder->payload.length = 0;
  decoder->payload.capacity = 0;
}

#endif /* WSC_HOSTED_H */
