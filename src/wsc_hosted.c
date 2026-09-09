#include "wsc_hosted.h"
#include "wsc.h"
#include "wsc_common.h"

#include <stdint.h>
#include <stdlib.h>

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

void wsc_decoding_result_free(struct wsc_decoding_result result) {
  if (result.frames == nullptr) {
    return;
  }
  for (size_t i = 0; i < result.frames_count; i++) {
    free((void *)result.frames[i].payload);
  }
  free((void *)result.frames);
}

struct wsc_encoding_result wsc_encode(const struct wsc_frame *frame) {
  struct wsc_encoding_result result = {.status = WSC_OK};
  size_t total = wsc_encoded_frame_length(frame);

  result.data_length = total;
  result.data = malloc(total);
  if (result.data == nullptr) {
    result.status = WSC_ERR_NO_MEMORY;
    result.data_length = 0;
    return result;
  }
  wsc_encode_buffer(result.data, total, frame);
  return result;
}
