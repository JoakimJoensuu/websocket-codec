#include "wsc_internal.h"

static void *ring_alloc(struct wsc_decoder *dec, size_t size) {
  void *ptr = ra_allocate(dec->ringalloc, size);
  if (ptr != nullptr) {
    dec->alloc_count++;
  }
  return ptr;
}

static void ring_free(struct wsc_decoder *dec) {
  void *oldest = dec->payload.data;
  if (oldest == nullptr) {
    oldest = dec->frames;
  }
  if (oldest == nullptr) {
    wsc_trap();
  }
  ra_free(dec->ringalloc, oldest);
  dec->alloc_count--;
}

static void ring_reset(struct wsc_decoder *dec) {
  ra_reset(dec->ringalloc);
  dec->alloc_count = 0;
}

int wsc_buf_reserve(struct wsc_decoder *dec, struct wsc_buf *buf, size_t need) {
  uint8_t *nbuf = nullptr;
  if (need <= buf->cap) {
    return 0;
  }
  if (buf->data != nullptr) {
    nbuf = (uint8_t *)ra_reallocate(dec->ringalloc, buf->data, need);
    if (nbuf != nullptr) {
      buf->cap = need;
      return 0;
    }
    return -1;
  }
  nbuf = (uint8_t *)ring_alloc(dec, need);
  if (nbuf == nullptr) {
    return -1;
  }
  if (buf->data != nullptr && buf->length > 0) {
    memcpy(nbuf, buf->data, buf->length);
  }
  buf->data = nbuf;
  buf->cap = need;
  return 0;
}

void wsc_clear_frames(struct wsc_decoder *dec) {
  if (dec->state == WSC_ST_PAYLOAD && dec->payload.data != nullptr) {
    while (dec->alloc_count > 1) {
      ring_free(dec);
    }
  } else {
    ring_reset(dec);
    dec->payload.data = nullptr;
    dec->payload.length = 0;
    dec->payload.cap = 0;
  }
  dec->frames = nullptr;
  dec->frames_count = 0;
  dec->frames_cap = 0;
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
  if (dec->frames != nullptr) {
    nbuf = (struct wsc_frame *)ra_reallocate(dec->ringalloc, dec->frames, bytes);
    if (nbuf != nullptr) {
      dec->frames_cap = cap;
      return 0;
    }
  }
  nbuf = (struct wsc_frame *)ring_alloc(dec, bytes);
  if (nbuf == nullptr) {
    return -1;
  }
  if (dec->frames != nullptr && dec->frames_count > 0) {
    memcpy(nbuf, dec->frames, dec->frames_count * sizeof(*nbuf));
  }
  dec->frames = nbuf;
  dec->frames_cap = cap;
  return 0;
}

enum wsc_err wsc_attach_payload(struct wsc_decoder *dec, struct wsc_frame *frame) {
  if (dec->payload.data == nullptr) {
    wsc_trap();
  }
  frame->payload = dec->payload.data;
  return WSC_OK;
}

void wsc_discard_payload(struct wsc_frame *frame) {
  (void)frame;
}

void wsc_payload_emitted(struct wsc_decoder *dec) {
  dec->payload.data = nullptr;
  dec->payload.cap = 0;
}

void wsc_decoder_free(struct wsc_decoder *decoder) {
  (void)decoder;
}

struct wsc_decoder *wsc_decoder_create_into(void *buf, size_t cap) {
  uint8_t *raw = nullptr;
  size_t align = alignof(struct wsc_decoder);
  size_t skip = 0;
  size_t after = 0;
  struct wsc_decoder *dec = nullptr;

  if (buf == nullptr) {
    wsc_trap();
  }
  raw = (uint8_t *)buf;
  skip = ((uintptr_t)raw % align == 0) ? 0 : align - ((uintptr_t)raw % align);
  if (skip > cap || sizeof(struct wsc_decoder) > cap - skip) {
    return nullptr;
  }
  dec = (struct wsc_decoder *)(raw + skip);
  memset(dec, 0, sizeof(*dec));
  after = skip + sizeof(*dec);
  dec->ringalloc = ra_initialize((unsigned char *)(raw + after), cap - after);
  if (dec->ringalloc == nullptr) {
    return nullptr;
  }
  wsc_decoder_state_init(dec);
  return dec;
}
