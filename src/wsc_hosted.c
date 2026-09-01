#include "wsc_internal.h"

int wsc_buf_reserve(struct wsc_decoder *dec, struct wsc_buf *buf, size_t need) {
  uint8_t *nbuf = nullptr;
  size_t cap = 0;
  (void)dec;
  if (need <= buf->cap) {
    return 0;
  }
  cap = buf->cap ? buf->cap : WSC_BUF_INIT;
  while (cap < need) {
    if (cap > ((size_t)-1) / 2) {
      cap = need;
      break;
    }
    cap *= 2;
  }
  nbuf = (uint8_t *)realloc(buf->data, cap);
  if (nbuf == nullptr) {
    return -1;
  }
  buf->data = nbuf;
  buf->cap = cap;
  return 0;
}

void wsc_clear_frames(struct wsc_decoder *dec) {
  for (size_t i = 0; i < dec->frames_count; i++) {
    free((void *)dec->frames[i].payload);
    dec->frames[i].payload = nullptr;
  }
  dec->frames_count = 0;
}

int wsc_frames_reserve(struct wsc_decoder *dec, size_t cap) {
  size_t bytes = 0;
  struct wsc_frame *nbuf = nullptr;
  if (cap <= dec->frames_cap) {
    return -1;
  }
  if (cap > ((size_t)-1) / sizeof(struct wsc_frame)) {
    return -1;
  }
  bytes = cap * sizeof(struct wsc_frame);
  nbuf = (struct wsc_frame *)realloc(dec->frames, bytes);
  if (nbuf == nullptr) {
    return -1;
  }
  dec->frames = nbuf;
  dec->frames_cap = cap;
  return 0;
}

enum wsc_err wsc_attach_payload(struct wsc_decoder *dec, struct wsc_frame *frame) {
  uint8_t *copy = nullptr;
  if (dec->payload.data == nullptr) {
    wsc_trap();
  }
  copy = (uint8_t *)malloc(frame->payload_len);
  if (copy == nullptr) {
    return WSC_ERR_NO_MEMORY;
  }
  memcpy(copy, dec->payload.data, frame->payload_len);
  frame->payload = copy;
  return WSC_OK;
}

void wsc_discard_payload(struct wsc_frame *frame) {
  free((void *)frame->payload);
  frame->payload = nullptr;
}

void wsc_payload_emitted(struct wsc_decoder *dec) {
  (void)dec;
}

void wsc_decoder_free(struct wsc_decoder *decoder) {
  wsc_clear_frames(decoder);
  free(decoder->frames);
  free(decoder->payload.data);
  free(decoder);
}

struct wsc_decoder *wsc_decoder_create() {
  struct wsc_decoder *dec = (struct wsc_decoder *)calloc(1, sizeof(*dec));
  if (dec == nullptr) {
    return nullptr;
  }
  wsc_decoder_state_init(dec);
  return dec;
}

struct wsc_encoding_result wsc_encode(const struct wsc_frame *frame) {
  struct wsc_encoding_result result = {.err = WSC_OK};
  size_t total = wsc_encoded_len(frame);

  result.data_len = total;
  result.data = (uint8_t *)malloc(total);
  if (result.data == nullptr) {
    result.err = WSC_ERR_NO_MEMORY;
    result.data_len = 0;
    return result;
  }
  wsc_encode_into(result.data, total, frame);
  return result;
}
