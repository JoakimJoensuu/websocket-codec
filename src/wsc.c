#include "wsc.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum : unsigned {
  HDR_BASE  = 2,
  LEN16_EXT = 2,
  LEN64_EXT = 8,
  HDR_MAX   = HDR_BASE + LEN64_EXT + WSC_MASK_LEN,
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

struct wsc_dec {
  uint64_t payload_len;
  uint64_t payload_got;
  struct buf payload;
  struct wsc_frame *frames;
  size_t frames_cnt;
  size_t frames_cap;
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
  uint8_t mask_key[WSC_MASK_LEN];
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

static int buf_reserve(struct buf *buf, size_t need) {
  uint8_t *nbuf = nullptr;
  size_t ncap = 0;
  if (need <= buf->cap) {
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

static void apply_mask(uint8_t *data, size_t length, const uint8_t key[WSC_MASK_LEN],
                       unsigned off) {
  for (size_t i = 0; i < length; i++) {
    data[i] = (uint8_t)((unsigned)data[i] ^ key[(off + i) & (WSC_MASK_LEN - 1U)]);
  }
}

static size_t header_size(size_t payload_len, bool masked) {
  size_t hlen = HDR_BASE;
  if (payload_len > UINT16_MAX) {
    hlen += LEN64_EXT;
  } else if (payload_len > LEN7_MAX) {
    hlen += LEN16_EXT;
  }
  if (masked) {
    hlen += WSC_MASK_LEN;
  }
  return hlen;
}

static size_t header_len(unsigned byte1) {
  size_t hlen = HDR_BASE;
  unsigned len7 = byte1 & LEN7_MASK;
  if (len7 == LEN16) {
    hlen += LEN16_EXT;
  } else if (len7 == LEN64) {
    hlen += LEN64_EXT;
  }
  if ((byte1 & MASK_BIT) != 0) {
    hlen += WSC_MASK_LEN;
  }
  return hlen;
}

static void require_frame(const struct wsc_frame *frame) {
  if (frame == nullptr) abort();
  if (frame->payload_len > 0 && frame->payload == nullptr) abort();
  if (frame->opcode > OPCODE_MASK) abort();
  if ((uint64_t)frame->payload_len & LEN64_MSB) abort();
}

size_t wsc_encoded_len(const struct wsc_frame *frame) {
  size_t hlen = 0;
  require_frame(frame);
  hlen = header_size(frame->payload_len, frame->masked);
  if (frame->payload_len > ((size_t)-1) - hlen) abort();
  return hlen + frame->payload_len;
}

size_t wsc_encode(uint8_t *dst, size_t dst_cap, const struct wsc_frame *frame) {
  uint8_t hdr[HDR_MAX];
  size_t hlen = HDR_BASE;
  size_t total = 0;

  require_frame(frame);
  if (dst == nullptr) abort();
  total = wsc_encoded_len(frame);
  if (dst_cap < total) abort();

  hdr[0] =
      (uint8_t)((frame->fin ? (unsigned)FIN_BIT : 0U) | (frame->rsv1 ? (unsigned)RSV1_BIT : 0U) |
                (frame->rsv2 ? (unsigned)RSV2_BIT : 0U) | (frame->rsv3 ? (unsigned)RSV3_BIT : 0U) |
                ((unsigned)frame->opcode & (unsigned)OPCODE_MASK));
  if (frame->payload_len <= LEN7_MAX) {
    hdr[1] = (uint8_t)frame->payload_len;
  } else if (frame->payload_len <= UINT16_MAX) {
    hdr[1] = LEN16;
    wr16(hdr + HDR_BASE, (uint16_t)frame->payload_len);
    hlen = HDR_BASE + LEN16_EXT;
  } else {
    hdr[1] = LEN64;
    wr64(hdr + HDR_BASE, (uint64_t)frame->payload_len);
    hlen = HDR_BASE + LEN64_EXT;
  }
  if (frame->masked) {
    hdr[1] = (uint8_t)((unsigned)hdr[1] | MASK_BIT);
    memcpy(hdr + hlen, frame->mask_key, WSC_MASK_LEN);
    hlen += WSC_MASK_LEN;
  }

  memcpy(dst, hdr, hlen);
  if (frame->payload_len > 0) {
    memcpy(dst + hlen, frame->payload, frame->payload_len);
    if (frame->masked) {
      apply_mask(dst + hlen, frame->payload_len, frame->mask_key, 0);
    }
  }
  return total;
}

static void clear_frames(struct wsc_dec *dec) {
  for (size_t i = 0; i < dec->frames_cnt; i++) {
    free((void *)dec->frames[i].payload);
    dec->frames[i].payload = nullptr;
  }
  dec->frames_cnt = 0;
}

static struct wsc_result make_result(struct wsc_dec *dec) {
  struct wsc_result result;
  result.err = dec->last_err;
  result.frames = dec->frames_cnt ? dec->frames : nullptr;
  result.frames_cnt = dec->frames_cnt;
  return result;
}

static enum wsc_err fail(struct wsc_dec *dec, enum wsc_err err) {
  dec->last_err = err;
  dec->state = ST_DEAD;
  return err;
}

static int frames_push(struct wsc_dec *dec, struct wsc_frame frame) {
  if (dec->frames_cnt == dec->frames_cap) {
    size_t ncap = dec->frames_cap ? dec->frames_cap * 2 : FRAMES_INIT;
    struct wsc_frame *nbuf = nullptr;
    if (ncap <= dec->frames_cap) {
      return -1;
    }
    nbuf = (struct wsc_frame *)realloc(dec->frames, ncap * sizeof *nbuf);
    if (nbuf == nullptr) {
      return -1;
    }
    dec->frames = nbuf;
    dec->frames_cap = ncap;
  }
  dec->frames[dec->frames_cnt] = frame;
  dec->frames_cnt++;
  return 0;
}

static enum wsc_err emit(struct wsc_dec *dec) {
  struct wsc_frame frame;
  uint8_t *copy = nullptr;

  frame.payload = nullptr;
  frame.payload_len = (size_t)dec->payload_len;
  memcpy(frame.mask_key, dec->mask_key, WSC_MASK_LEN);
  frame.opcode = dec->opcode;
  frame.fin = dec->fin;
  frame.rsv1 = dec->rsv1;
  frame.rsv2 = dec->rsv2;
  frame.rsv3 = dec->rsv3;
  frame.masked = dec->masked;

  if (frame.payload_len > 0) {
    copy = (uint8_t *)malloc(frame.payload_len);
    if (copy == nullptr) {
      return fail(dec, WSC_ERR_NOMEM);
    }
    memcpy(copy, dec->payload.data, frame.payload_len);
    frame.payload = copy;
  }
  if (frames_push(dec, frame) != 0) {
    free(copy);
    return fail(dec, WSC_ERR_NOMEM);
  }
  dec->payload.length = 0;
  return WSC_OK;
}

static void reset_header(struct wsc_dec *dec) {
  dec->state = ST_HDR;
  dec->hdr_got = 0;
  dec->hdr_need = HDR_BASE;
  dec->payload_got = 0;
  dec->mask_off = 0;
}

static enum wsc_err on_header(struct wsc_dec *dec) {
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
      return fail(dec, WSC_ERR_NONMINIMAL);
    }
  } else if (len7 == LEN64) {
    plen = rd64(dec->hdr + HDR_BASE);
    off = HDR_BASE + LEN64_EXT;
    if ((plen & LEN64_MSB) != 0) {
      return fail(dec, WSC_ERR_LEN64_MSB);
    }
    if (plen <= UINT16_MAX) {
      return fail(dec, WSC_ERR_NONMINIMAL);
    }
  } else {
    plen = (uint64_t)len7;
  }

  if (dec->masked) {
    memcpy(dec->mask_key, dec->hdr + off, WSC_MASK_LEN);
  } else {
    memset(dec->mask_key, 0, WSC_MASK_LEN);
  }

  if (plen > (uint64_t)(size_t)-1) {
    return fail(dec, WSC_ERR_NOMEM);
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

  if (buf_reserve(&dec->payload, (size_t)plen) != 0) {
    return fail(dec, WSC_ERR_NOMEM);
  }
  dec->state = ST_PAYLOAD;
  return WSC_OK;
}

static enum wsc_err on_payload_done(struct wsc_dec *dec) {
  enum wsc_err err = emit(dec);
  if (err != WSC_OK) {
    return err;
  }
  reset_header(dec);
  return WSC_OK;
}

static enum wsc_err feed_hdr(struct wsc_dec *dec, const uint8_t *src, size_t length, size_t *used) {
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
    dec->hdr_need = header_len(dec->hdr[1]);
  }
  if (dec->hdr_got < dec->hdr_need) {
    return WSC_OK;
  }
  return on_header(dec);
}

static enum wsc_err feed_payload(struct wsc_dec *dec, const uint8_t *src, size_t length,
                                 size_t *used) {
  uint64_t left = dec->payload_len - dec->payload_got;
  size_t take = length;
  if ((uint64_t)take > left) {
    take = (size_t)left;
  }
  memcpy(dec->payload.data + dec->payload.length, src, take);
  if (dec->masked) {
    apply_mask(dec->payload.data + dec->payload.length, take, dec->mask_key, dec->mask_off);
  }
  dec->mask_off = (dec->mask_off + (unsigned)take) & (WSC_MASK_LEN - 1U);
  dec->payload.length += take;
  dec->payload_got += take;
  *used = take;
  if (dec->payload_got >= dec->payload_len) {
    return on_payload_done(dec);
  }
  return WSC_OK;
}

struct wsc_dec *wsc_dec_create() {
  struct wsc_dec *dec = (struct wsc_dec *)calloc(1, sizeof *dec);
  if (dec == nullptr) {
    return nullptr;
  }
  dec->state = ST_HDR;
  dec->hdr_need = HDR_BASE;
  return dec;
}

void wsc_dec_destroy(struct wsc_dec *dec) {
  if (dec == nullptr) {
    return;
  }
  clear_frames(dec);
  free(dec->frames);
  free(dec->payload.data);
  free(dec);
}

struct wsc_result wsc_dec_feed(struct wsc_dec *dec, const uint8_t *src, size_t length) {
  size_t off = 0;
  if (dec == nullptr) abort();
  if (length > 0 && src == nullptr) abort();
  clear_frames(dec);
  if (dec->state == ST_DEAD) {
    return make_result(dec);
  }
  while (off < length && dec->state != ST_DEAD) {
    size_t used = 0;
    enum wsc_err err = WSC_OK;
    if (dec->state == ST_HDR) {
      err = feed_hdr(dec, src + off, length - off, &used);
    } else {
      err = feed_payload(dec, src + off, length - off, &used);
    }
    off += used;
    if (err != WSC_OK) {
      break;
    }
    if (used == 0) {
      break;
    }
  }
  return make_result(dec);
}
