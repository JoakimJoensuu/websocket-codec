#include "wsc_internal.h"

static uint16_t rd16(const uint8_t *src) {
  return (uint16_t)(((unsigned)src[0] << WSC_BYTE_BITS) | (unsigned)src[1]);
}

static uint64_t rd64(const uint8_t *src) {
  uint64_t value = 0;
  for (int i = 0; i < (int)sizeof(uint64_t); i++) {
    value = (value << WSC_BYTE_BITS) | (uint64_t)src[i];
  }
  return value;
}

static void wr16(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)((unsigned)value >> WSC_BYTE_BITS);
  dst[1] = (uint8_t)value;
}

static void wr64(uint8_t *dst, uint64_t value) {
  for (int i = (int)sizeof(uint64_t) - 1; i >= 0; i--) {
    dst[i] = (uint8_t)value;
    value >>= WSC_BYTE_BITS;
  }
}

static void apply_mask(uint8_t *data, size_t length, const uint8_t key[WSC_MASKING_KEY_LEN],
                       unsigned off) {
  for (size_t i = 0; i < length; i++) {
    data[i] = (uint8_t)((unsigned)data[i] ^ key[(off + i) & (WSC_MASKING_KEY_LEN - 1U)]);
  }
}

static size_t header_size(size_t payload_len, bool masked) {
  size_t header_length = WSC_HDR_BASE;
  if (payload_len > UINT16_MAX) {
    header_length += WSC_LEN64_EXT;
  } else if (payload_len > WSC_LEN7_MAX) {
    header_length += WSC_LEN16_EXT;
  }
  if (masked) {
    header_length += WSC_MASKING_KEY_LEN;
  }
  return header_length;
}

static size_t header_length(unsigned byte1) {
  size_t header_length = WSC_HDR_BASE;
  unsigned len7 = byte1 & WSC_LEN7_MASK;
  if (len7 == WSC_LEN16) {
    header_length += WSC_LEN16_EXT;
  } else if (len7 == WSC_LEN64) {
    header_length += WSC_LEN64_EXT;
  }
  if ((byte1 & WSC_MASK_BIT) != 0) {
    header_length += WSC_MASKING_KEY_LEN;
  }
  return header_length;
}

static void require_frame(const struct wsc_frame *frame) {
  if (frame == nullptr) {
    wsc_trap();
  }
  if (frame->payload_len > 0 && frame->payload == nullptr) {
    wsc_trap();
  }
  if (frame->opcode > WSC_OPCODE_MASK) {
    wsc_trap();
  }
  if ((uint64_t)frame->payload_len & WSC_LEN64_MSB) {
    wsc_trap();
  }
}

static size_t encoded_length(const struct wsc_frame *frame) {
  size_t header_length = 0;
  require_frame(frame);
  header_length = header_size(frame->payload_len, frame->masked);
  if (frame->payload_len > ((size_t)-1) - header_length) {
    wsc_trap();
  }
  return header_length + frame->payload_len;
}

static size_t write_frame(uint8_t *dst, const struct wsc_frame *frame) {
  uint8_t hdr[WSC_HDR_MAX];
  size_t header_length = WSC_HDR_BASE;

  hdr[0] = (uint8_t)((frame->fin ? (unsigned)WSC_FIN_BIT : 0U) |
                     (frame->rsv1 ? (unsigned)WSC_RSV1_BIT : 0U) |
                     (frame->rsv2 ? (unsigned)WSC_RSV2_BIT : 0U) |
                     (frame->rsv3 ? (unsigned)WSC_RSV3_BIT : 0U) |
                     ((unsigned)frame->opcode & (unsigned)WSC_OPCODE_MASK));
  if (frame->payload_len <= WSC_LEN7_MAX) {
    hdr[1] = (uint8_t)frame->payload_len;
  } else if (frame->payload_len <= UINT16_MAX) {
    hdr[1] = WSC_LEN16;
    wr16(hdr + WSC_HDR_BASE, (uint16_t)frame->payload_len);
    header_length = WSC_HDR_BASE + WSC_LEN16_EXT;
  } else {
    hdr[1] = WSC_LEN64;
    wr64(hdr + WSC_HDR_BASE, (uint64_t)frame->payload_len);
    header_length = WSC_HDR_BASE + WSC_LEN64_EXT;
  }
  if (frame->masked) {
    hdr[1] = (uint8_t)((unsigned)hdr[1] | WSC_MASK_BIT);
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
  if (dst == nullptr) {
    wsc_trap();
  }
  if (dst_cap < total) {
    wsc_trap();
  }
  return write_frame(dst, frame);
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
  dec->state = WSC_ST_DEAD;
  return err;
}

static int frames_push(struct wsc_decoder *dec, struct wsc_frame frame) {
  if (dec->frames_count == dec->frames_cap) {
    size_t cap = dec->frames_cap ? dec->frames_cap * 2 : WSC_FRAMES_INIT;
    if (wsc_frames_reserve(dec, cap) != 0) {
      return -1;
    }
  }
  dec->frames[dec->frames_count] = frame;
  dec->frames_count++;
  return 0;
}

static enum wsc_err emit(struct wsc_decoder *dec) {
  struct wsc_frame frame;
  enum wsc_err err = WSC_OK;

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
    err = wsc_attach_payload(dec, &frame);
    if (err != WSC_OK) {
      return fail(dec, err);
    }
  }
  if (frames_push(dec, frame) != 0) {
    wsc_discard_payload(&frame);
    return fail(dec, WSC_ERR_NO_MEMORY);
  }
  wsc_payload_emitted(dec);
  dec->payload.length = 0;
  return WSC_OK;
}

static void reset_header(struct wsc_decoder *dec) {
  dec->state = WSC_ST_HDR;
  dec->hdr_got = 0;
  dec->hdr_need = WSC_HDR_BASE;
  dec->payload_got = 0;
  dec->mask_off = 0;
}

static enum wsc_err on_header(struct wsc_decoder *dec) {
  unsigned byte0 = dec->hdr[0];
  unsigned byte1 = dec->hdr[1];
  uint64_t plen = 0;
  unsigned len7 = byte1 & WSC_LEN7_MASK;
  size_t off = WSC_HDR_BASE;

  dec->fin = (byte0 & WSC_FIN_BIT) != 0;
  dec->rsv1 = (byte0 & WSC_RSV1_BIT) != 0;
  dec->rsv2 = (byte0 & WSC_RSV2_BIT) != 0;
  dec->rsv3 = (byte0 & WSC_RSV3_BIT) != 0;
  dec->opcode = (uint8_t)(byte0 & WSC_OPCODE_MASK);
  dec->masked = (byte1 & WSC_MASK_BIT) != 0;

  if (len7 == WSC_LEN16) {
    plen = rd16(dec->hdr + WSC_HDR_BASE);
    off = WSC_HDR_BASE + WSC_LEN16_EXT;
    if (plen <= WSC_LEN7_MAX) {
      return fail(dec, WSC_ERR_LENGTH_NOT_MINIMAL);
    }
  } else if (len7 == WSC_LEN64) {
    plen = rd64(dec->hdr + WSC_HDR_BASE);
    off = WSC_HDR_BASE + WSC_LEN64_EXT;
    if ((plen & WSC_LEN64_MSB) != 0) {
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

  if (wsc_buf_reserve(dec, &dec->payload, (size_t)plen) != 0) {
    return fail(dec, WSC_ERR_NO_MEMORY);
  }
  dec->state = WSC_ST_PAYLOAD;
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
  if (dec->hdr_got < WSC_HDR_BASE) {
    dec->hdr_need = WSC_HDR_BASE;
  }
  take = dec->hdr_need - dec->hdr_got;
  if (take > length) {
    take = length;
  }
  memcpy(dec->hdr + dec->hdr_got, src, take);
  dec->hdr_got += take;
  *used = take;
  if (dec->hdr_got >= WSC_HDR_BASE) {
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
  if (dec->payload.data == nullptr) {
    wsc_trap();
  }
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

void wsc_decoder_state_init(struct wsc_decoder *dec) {
  dec->state = WSC_ST_HDR;
  dec->hdr_need = WSC_HDR_BASE;
}

void wsc_decoder_destroy(struct wsc_decoder *decoder) {
  if (decoder == nullptr) {
    return;
  }
  wsc_decoder_free(decoder);
}

struct wsc_decoding_result wsc_decoder_feed(struct wsc_decoder *decoder, const uint8_t *src,
                                            size_t length) {
  size_t off = 0;
  if (decoder == nullptr) {
    wsc_trap();
  }
  if (length > 0 && src == nullptr) {
    wsc_trap();
  }
  wsc_clear_frames(decoder);
  if (decoder->state == WSC_ST_DEAD) {
    return make_result(decoder);
  }
  while (off < length && decoder->state != WSC_ST_DEAD) {
    size_t used = 0;
    enum wsc_err err = WSC_OK;
    if (decoder->state == WSC_ST_HDR) {
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
