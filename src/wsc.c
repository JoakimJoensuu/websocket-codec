#include "wsc.h"

#include "ringalloc.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum : unsigned {
  HDR_BASE  = 2,
  LEN16_EXT = 2,
  LEN64_EXT = 8,
  HDR_MAX   = HDR_BASE + LEN64_EXT + WSC_MASKING_KEY_LEN,
};

enum : unsigned {
  LEN7_MAX = 125,
  LEN16    = 126,
  LEN64    = 127,
};

enum : uint8_t {
  FIN_BIT     = 0x80,
  RSV1_BIT    = 0x40,
  RSV2_BIT    = 0x20,
  RSV3_BIT    = 0x10,
  OPCODE_MASK = 0x0F,
  MASK_BIT    = 0x80,
  LEN7_MASK   = 0x7F,
};

enum : uint64_t { LEN64_MSB = 0x8000000000000000 };

enum : unsigned {
  BUF_INIT    = 256,
  FRAMES_INIT = 8,
};

enum : unsigned { BYTE_BITS = CHAR_BIT };

enum parse_st { ST_HDR = 0, ST_PAYLOAD, ST_DEAD };

struct buf {
  uint8_t *data;
  size_t length;
  size_t cap;
};

struct wsc_decoder {
  uint64_t payload_len;
  uint64_t payload_got;
  struct buf payload;
  struct ringalloc *ringalloc;
  struct wsc_frame *frames;
  size_t frames_count;
  size_t frames_cap;
  size_t alloc_count;
  size_t hdr_got;
  size_t hdr_need;
  enum parse_st state;
  unsigned mask_off;
  enum wsc_err last_err;
  bool fin;
  bool rsv1;
  bool rsv2;
  bool rsv3;
  bool masked;
  uint8_t opcode;
  uint8_t masking_key[WSC_MASKING_KEY_LEN];
  uint8_t hdr[HDR_MAX];
};

static uint16_t rd16(const uint8_t *src) {
  return (uint16_t)(((unsigned)src[0] << BYTE_BITS) | (unsigned)src[1]);
}

static uint64_t rd64(const uint8_t *src) {
  uint64_t value = 0;
  for (int i = 0; i < (int)sizeof(uint64_t); i++) {
    value = (value << BYTE_BITS) | (uint64_t)src[i];
  }
  return value;
}

static void wr16(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)((unsigned)value >> BYTE_BITS);
  dst[1] = (uint8_t)value;
}

static void wr64(uint8_t *dst, uint64_t value) {
  for (int i = (int)sizeof(uint64_t) - 1; i >= 0; i--) {
    dst[i] = (uint8_t)value;
    value >>= BYTE_BITS;
  }
}

static bool ringalloc_used(const struct wsc_decoder *dec) {
  return dec->ringalloc != nullptr;
}

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
    abort();
  }
  ra_free(dec->ringalloc, oldest);
  dec->alloc_count--;
}

static void ring_reset(struct wsc_decoder *dec) {
  ra_reset(dec->ringalloc);
  dec->alloc_count = 0;
}

static int buf_reserve(struct wsc_decoder *dec, struct buf *buf, size_t need) {
  uint8_t *nbuf = nullptr;
  size_t ncap = 0;
  if (need <= buf->cap) {
    return 0;
  }
  if (ringalloc_used(dec)) {
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
  ncap = buf->cap ? buf->cap : BUF_INIT;
  while (ncap < need) {
    if (ncap > ((size_t)-1) / 2) {
      ncap = need;
      break;
    }
    ncap *= 2;
  }
  nbuf = (uint8_t *)realloc(buf->data, ncap);
  if (nbuf == nullptr) {
    return -1;
  }
  buf->data = nbuf;
  buf->cap = ncap;
  return 0;
}

static void apply_mask(uint8_t *data, size_t length, const uint8_t key[WSC_MASKING_KEY_LEN],
                       unsigned off) {
  for (size_t i = 0; i < length; i++) {
    data[i] = (uint8_t)((unsigned)data[i] ^ key[(off + i) & (WSC_MASKING_KEY_LEN - 1U)]);
  }
}

static size_t header_size(size_t payload_len, bool masked) {
  size_t header_length = HDR_BASE;
  if (payload_len > UINT16_MAX) {
    header_length += LEN64_EXT;
  } else if (payload_len > LEN7_MAX) {
    header_length += LEN16_EXT;
  }
  if (masked) {
    header_length += WSC_MASKING_KEY_LEN;
  }
  return header_length;
}

static size_t header_length(unsigned byte1) {
  size_t header_length = HDR_BASE;
  unsigned len7 = byte1 & LEN7_MASK;
  if (len7 == LEN16) {
    header_length += LEN16_EXT;
  } else if (len7 == LEN64) {
    header_length += LEN64_EXT;
  }
  if ((byte1 & MASK_BIT) != 0) {
    header_length += WSC_MASKING_KEY_LEN;
  }
  return header_length;
}

static void require_frame(const struct wsc_frame *frame) {
  if (frame == nullptr) abort();
  if (frame->payload_len > 0 && frame->payload == nullptr) abort();
  if (frame->opcode > OPCODE_MASK) abort();
  if ((uint64_t)frame->payload_len & LEN64_MSB) abort();
}

static size_t encoded_length(const struct wsc_frame *frame) {
  size_t header_length = 0;
  require_frame(frame);
  header_length = header_size(frame->payload_len, frame->masked);
  if (frame->payload_len > ((size_t)-1) - header_length) abort();
  return header_length + frame->payload_len;
}

static size_t write_frame(uint8_t *dst, const struct wsc_frame *frame) {
  uint8_t hdr[HDR_MAX];
  size_t header_length = HDR_BASE;

  hdr[0] =
      (uint8_t)((frame->fin ? (unsigned)FIN_BIT : 0U) | (frame->rsv1 ? (unsigned)RSV1_BIT : 0U) |
                (frame->rsv2 ? (unsigned)RSV2_BIT : 0U) | (frame->rsv3 ? (unsigned)RSV3_BIT : 0U) |
                ((unsigned)frame->opcode & (unsigned)OPCODE_MASK));
  if (frame->payload_len <= LEN7_MAX) {
    hdr[1] = (uint8_t)frame->payload_len;
  } else if (frame->payload_len <= UINT16_MAX) {
    hdr[1] = LEN16;
    wr16(hdr + HDR_BASE, (uint16_t)frame->payload_len);
    header_length = HDR_BASE + LEN16_EXT;
  } else {
    hdr[1] = LEN64;
    wr64(hdr + HDR_BASE, (uint64_t)frame->payload_len);
    header_length = HDR_BASE + LEN64_EXT;
  }
  if (frame->masked) {
    hdr[1] = (uint8_t)((unsigned)hdr[1] | MASK_BIT);
    memcpy(hdr + header_length, frame->masking_key, WSC_MASKING_KEY_LEN);
    header_length += WSC_MASKING_KEY_LEN;
  }

  memcpy(dst, hdr, header_length);
  if (frame->payload_len > 0) {
    memcpy(dst + header_length, frame->payload, frame->payload_len);
    if (frame->masked) {
      apply_mask(dst + header_length, frame->payload_len, frame->masking_key, 0);
    }
  }
  return header_length + frame->payload_len;
}

size_t wsc_encoded_len(const struct wsc_frame *frame) {
  return encoded_length(frame);
}

size_t wsc_encode_into(uint8_t *dst, size_t dst_cap, const struct wsc_frame *frame) {
  size_t total = encoded_length(frame);
  if (dst == nullptr) abort();
  if (dst_cap < total) abort();
  return write_frame(dst, frame);
}

struct wsc_encoding_result wsc_encode(const struct wsc_frame *frame) {
  struct wsc_encoding_result result = {.err = WSC_OK};

  result.data_len = encoded_length(frame);
  result.data = (uint8_t *)malloc(result.data_len);
  if (result.data == nullptr) {
    result.err = WSC_ERR_NO_MEMORY;
    result.data_len = 0;
    return result;
  }
  write_frame(result.data, frame);
  return result;
}

static void clear_frames(struct wsc_decoder *dec) {
  if (ringalloc_used(dec)) {
    if (dec->state == ST_PAYLOAD && dec->payload.data != nullptr) {
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
    return;
  }
  for (size_t i = 0; i < dec->frames_count; i++) {
    free((void *)dec->frames[i].payload);
    dec->frames[i].payload = nullptr;
  }
  dec->frames_count = 0;
}

static struct wsc_decoding_result make_result(struct wsc_decoder *dec) {
  struct wsc_decoding_result result;
  result.err = dec->last_err;
  result.frames = dec->frames_count ? dec->frames : nullptr;
  result.frames_cnt = dec->frames_count;
  return result;
}

static enum wsc_err fail(struct wsc_decoder *dec, enum wsc_err err) {
  dec->last_err = err;
  dec->state = ST_DEAD;
  return err;
}

static int frames_reserve(struct wsc_decoder *dec, size_t ncap) {
  size_t bytes = 0;
  struct wsc_frame *nbuf = nullptr;
  if (ncap <= dec->frames_cap) {
    return -1;
  }
  if (ncap > ((size_t)-1) / sizeof(struct wsc_frame)) {
    return -1;
  }
  bytes = ncap * sizeof(struct wsc_frame);
  if (ringalloc_used(dec)) {
    if (dec->frames != nullptr) {
      nbuf = (struct wsc_frame *)ra_reallocate(dec->ringalloc, dec->frames, bytes);
      if (nbuf != nullptr) {
        dec->frames_cap = ncap;
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
    dec->frames_cap = ncap;
    return 0;
  }
  nbuf = (struct wsc_frame *)realloc(dec->frames, bytes);
  if (nbuf == nullptr) {
    return -1;
  }
  dec->frames = nbuf;
  dec->frames_cap = ncap;
  return 0;
}

static int frames_push(struct wsc_decoder *dec, struct wsc_frame frame) {
  if (dec->frames_count == dec->frames_cap) {
    size_t ncap = dec->frames_cap ? dec->frames_cap * 2 : FRAMES_INIT;
    if (frames_reserve(dec, ncap) != 0) {
      return -1;
    }
  }
  dec->frames[dec->frames_count] = frame;
  dec->frames_count++;
  return 0;
}

static enum wsc_err emit(struct wsc_decoder *dec) {
  struct wsc_frame frame;
  uint8_t *copy = nullptr;

  frame.payload = nullptr;
  frame.payload_len = (size_t)dec->payload_len;
  memcpy(frame.masking_key, dec->masking_key, WSC_MASKING_KEY_LEN);
  frame.opcode = dec->opcode;
  frame.fin = dec->fin;
  frame.rsv1 = dec->rsv1;
  frame.rsv2 = dec->rsv2;
  frame.rsv3 = dec->rsv3;
  frame.masked = dec->masked;

  if (frame.payload_len > 0) {
    if (ringalloc_used(dec)) {
      if (dec->payload.data == nullptr) abort();
      frame.payload = dec->payload.data;
    } else {
      copy = (uint8_t *)malloc(frame.payload_len);
      if (copy == nullptr) {
        return fail(dec, WSC_ERR_NO_MEMORY);
      }
      memcpy(copy, dec->payload.data, frame.payload_len);
      frame.payload = copy;
    }
  }
  if (frames_push(dec, frame) != 0) {
    if (copy != nullptr) {
      free(copy);
    }
    return fail(dec, WSC_ERR_NO_MEMORY);
  }
  if (ringalloc_used(dec)) {
    dec->payload.data = nullptr;
    dec->payload.cap = 0;
  }
  dec->payload.length = 0;
  return WSC_OK;
}

static void reset_header(struct wsc_decoder *dec) {
  dec->state = ST_HDR;
  dec->hdr_got = 0;
  dec->hdr_need = HDR_BASE;
  dec->payload_got = 0;
  dec->mask_off = 0;
}

static enum wsc_err on_header(struct wsc_decoder *dec) {
  unsigned byte0 = dec->hdr[0];
  unsigned byte1 = dec->hdr[1];
  uint64_t plen = 0;
  unsigned len7 = byte1 & LEN7_MASK;
  size_t off = HDR_BASE;

  dec->fin = (byte0 & FIN_BIT) != 0;
  dec->rsv1 = (byte0 & RSV1_BIT) != 0;
  dec->rsv2 = (byte0 & RSV2_BIT) != 0;
  dec->rsv3 = (byte0 & RSV3_BIT) != 0;
  dec->opcode = (uint8_t)(byte0 & OPCODE_MASK);
  dec->masked = (byte1 & MASK_BIT) != 0;

  if (len7 == LEN16) {
    plen = rd16(dec->hdr + HDR_BASE);
    off = HDR_BASE + LEN16_EXT;
    if (plen <= LEN7_MAX) {
      return fail(dec, WSC_ERR_LENGTH_NOT_MINIMAL);
    }
  } else if (len7 == LEN64) {
    plen = rd64(dec->hdr + HDR_BASE);
    off = HDR_BASE + LEN64_EXT;
    if ((plen & LEN64_MSB) != 0) {
      return fail(dec, WSC_ERR_LEN64_MSB);
    }
    if (plen <= UINT16_MAX) {
      return fail(dec, WSC_ERR_LENGTH_NOT_MINIMAL);
    }
  } else {
    plen = (uint64_t)len7;
  }

  if (dec->masked) {
    memcpy(dec->masking_key, dec->hdr + off, WSC_MASKING_KEY_LEN);
  } else {
    memset(dec->masking_key, 0, WSC_MASKING_KEY_LEN);
  }

  if (plen > (uint64_t)(size_t)-1) {
    return fail(dec, WSC_ERR_NO_MEMORY);
  }

  dec->payload_len = plen;
  dec->payload_got = 0;
  dec->mask_off = 0;
  dec->payload.length = 0;

  if (plen == 0) {
    enum wsc_err err = emit(dec);
    if (err != WSC_OK) {
      return err;
    }
    reset_header(dec);
    return WSC_OK;
  }

  if (buf_reserve(dec, &dec->payload, (size_t)plen) != 0) {
    return fail(dec, WSC_ERR_NO_MEMORY);
  }
  dec->state = ST_PAYLOAD;
  return WSC_OK;
}

static enum wsc_err on_payload_done(struct wsc_decoder *dec) {
  enum wsc_err err = emit(dec);
  if (err != WSC_OK) {
    return err;
  }
  reset_header(dec);
  return WSC_OK;
}

static enum wsc_err feed_hdr(struct wsc_decoder *dec, const uint8_t *src, size_t length,
                             size_t *used) {
  size_t take = 0;
  *used = 0;
  if (dec->hdr_got < HDR_BASE) {
    dec->hdr_need = HDR_BASE;
  }
  take = dec->hdr_need - dec->hdr_got;
  if (take > length) {
    take = length;
  }
  memcpy(dec->hdr + dec->hdr_got, src, take);
  dec->hdr_got += take;
  *used = take;
  if (dec->hdr_got >= HDR_BASE) {
    dec->hdr_need = header_length(dec->hdr[1]);
  }
  if (dec->hdr_got < dec->hdr_need) {
    return WSC_OK;
  }
  return on_header(dec);
}

static enum wsc_err feed_payload(struct wsc_decoder *dec, const uint8_t *src, size_t length,
                                 size_t *used) {
  uint64_t left = dec->payload_len - dec->payload_got;
  size_t take = length;
  if ((uint64_t)take > left) {
    take = (size_t)left;
  }
  if (take == 0) {
    *used = 0;
    return WSC_OK;
  }
  if (dec->payload.data == nullptr) abort();
  memcpy(dec->payload.data + dec->payload.length, src, take);
  if (dec->masked) {
    apply_mask(dec->payload.data + dec->payload.length, take, dec->masking_key, dec->mask_off);
  }
  dec->mask_off = (dec->mask_off + (unsigned)take) & (WSC_MASKING_KEY_LEN - 1U);
  dec->payload.length += take;
  dec->payload_got += take;
  *used = take;
  if (dec->payload_got >= dec->payload_len) {
    return on_payload_done(dec);
  }
  return WSC_OK;
}

struct wsc_decoder *wsc_decoder_create() {
  struct wsc_decoder *dec = (struct wsc_decoder *)calloc(1, sizeof(*dec));
  if (dec == nullptr) {
    return nullptr;
  }
  dec->state = ST_HDR;
  dec->hdr_need = HDR_BASE;
  return dec;
}

struct wsc_decoder *wsc_decoder_create_into(void *buf, size_t cap) {
  uint8_t *raw = nullptr;
  size_t align = alignof(struct wsc_decoder);
  size_t skip = 0;
  size_t after = 0;
  struct wsc_decoder *dec = nullptr;

  if (buf == nullptr) abort();
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
  dec->state = ST_HDR;
  dec->hdr_need = HDR_BASE;
  return dec;
}

void wsc_decoder_destroy(struct wsc_decoder *decoder) {
  if (decoder == nullptr) {
    return;
  }
  if (ringalloc_used(decoder)) {
    return;
  }
  clear_frames(decoder);
  free(decoder->frames);
  free(decoder->payload.data);
  free(decoder);
}

struct wsc_decoding_result wsc_decoder_feed(struct wsc_decoder *decoder, const uint8_t *src,
                                            size_t length) {
  size_t off = 0;
  if (decoder == nullptr) abort();
  if (length > 0 && src == nullptr) abort();
  clear_frames(decoder);
  if (decoder->state == ST_DEAD) {
    return make_result(decoder);
  }
  while (off < length && decoder->state != ST_DEAD) {
    size_t used = 0;
    enum wsc_err err = WSC_OK;
    if (decoder->state == ST_HDR) {
      err = feed_hdr(decoder, src + off, length - off, &used);
    } else {
      err = feed_payload(decoder, src + off, length - off, &used);
    }
    off += used;
    if (err != WSC_OK) {
      break;
    }
    if (used == 0) {
      break;
    }
  }
  return make_result(decoder);
}
