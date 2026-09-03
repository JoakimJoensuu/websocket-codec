#include "wsc.h"
#include "wsc_internal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int wsc_buffer_reserve(struct wsc_decoder *decoder, struct wsc_buffer *buffer,
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

void wsc_clear_frames(struct wsc_decoder *decoder) {
  for (size_t i = 0; i < decoder->frames_count; i++) {
    free((void *)decoder->frames[i].payload);
    decoder->frames[i].payload = nullptr;
  }
  decoder->frames_count = 0;
}

int wsc_frames_reserve(struct wsc_decoder *decoder, size_t capacity) {
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

enum wsc_err wsc_attach_payload(struct wsc_decoder *decoder, struct wsc_frame *frame) {
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

void wsc_discard_payload(struct wsc_frame *frame) {
  free((void *)frame->payload);
  frame->payload = nullptr;
}

void wsc_payload_emitted(struct wsc_decoder *decoder) {
  (void)decoder;
}

void wsc_decoder_free(struct wsc_decoder *decoder) {
  wsc_clear_frames(decoder);
  free(decoder->frames);
  free(decoder->payload.data);
  free(decoder);
}

struct wsc_decoder *wsc_decoder_create() {
  struct wsc_decoder *decoder = calloc(1, sizeof(*decoder));
  if (decoder == nullptr) {
    return nullptr;
  }
  wsc_decoder_state_init(decoder);
  return decoder;
}

struct wsc_encoding_result wsc_encode(const struct wsc_frame *frame) {
  struct wsc_encoding_result result = {.err = WSC_OK};
  size_t total = wsc_encoded_length(frame);

  result.data_length = total;
  result.data = malloc(total);
  if (result.data == nullptr) {
    result.err = WSC_ERR_NO_MEMORY;
    result.data_length = 0;
    return result;
  }
  wsc_encode_buffer(result.data, total, frame);
  return result;
}
