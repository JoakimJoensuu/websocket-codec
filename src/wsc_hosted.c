#include "wsc_hosted.h"
#include "wsc.h"
#include "wsc_internal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int wsc_buffer_reserve(struct wsc_decoder_data *decoder, struct wsc_buffer *buffer,
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

void wsc_clear_frames(struct wsc_decoder_data *decoder) {
  for (size_t i = 0; i < decoder->frames_count; i++) {
    free((void *)decoder->frames[i].payload);
    decoder->frames[i].payload = nullptr;
  }
  decoder->frames_count = 0;
}

int wsc_frames_reserve(struct wsc_decoder_data *decoder, size_t capacity) {
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

enum wsc_err wsc_attach_payload(struct wsc_decoder_data *decoder, struct wsc_frame *frame) {
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

void wsc_payload_emitted(struct wsc_decoder_data *decoder) {
  (void)decoder;
}

void wsc_decoder_free(struct wsc_decoder_data *decoder) {
  wsc_clear_frames(decoder);
  free(decoder->frames);
  free(decoder->payload.data);
  decoder->frames = nullptr;
  decoder->payload.data = nullptr;
  decoder->payload.length = 0;
  decoder->payload.capacity = 0;
}

struct wsc_decoder *wsc_decoder_create() {
  struct wsc_decoder_data *data = calloc(1, sizeof(*data));
  if (data == nullptr) {
    return nullptr;
  }
  wsc_decoder_state_init(data);
  return (struct wsc_decoder *)data;
}

void wsc_decoder_destroy(struct wsc_decoder *decoder) {
  if (decoder == nullptr) {
    return;
  }
  struct wsc_decoder_data *data = (struct wsc_decoder_data *)decoder;
  wsc_decoder_free(data);
  free(data);
}

struct wsc_decoding_result wsc_decoder_feed(struct wsc_decoder *decoder, const uint8_t *source,
                                            size_t length) {
  if (decoder == nullptr) {
    wsc_trap();
  }
  struct wsc_decoder_data *data = (struct wsc_decoder_data *)decoder;
  struct wsc_decoding_result result = wsc_decoder_feed_data(data, source, length);
  data->frames = nullptr;
  data->frames_count = 0;
  data->frames_capacity = 0;
  return result;
}

void wsc_decoding_result_destroy(struct wsc_decoding_result *result) {
  if (result == nullptr) {
    return;
  }
  if (result->frames == nullptr) {
    result->frames_count = 0;
    return;
  }
  for (size_t i = 0; i < result->frames_count; i++) {
    free((void *)result->frames[i].payload);
  }
  free((void *)result->frames);
  result->frames = nullptr;
  result->frames_count = 0;
}

struct wsc_encoding_result wsc_encode(const struct wsc_frame *frame) {
  struct wsc_encoding_result result = {.err = WSC_OK};
  size_t total = wsc_encoded_frame_length(frame);

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
