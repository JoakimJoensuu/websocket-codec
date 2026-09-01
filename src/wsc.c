#include "wsc.h"

#include "wsc_internal.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

static uint16_t read_uint16(const uint8_t *src) {
  return (uint16_t)(((unsigned)src[0] << WSC_BYTE_BITS) | (unsigned)src[1]);
}

static uint64_t read_uint64(const uint8_t *src) {
  uint64_t value = 0;
  for (int i = 0; i < (int)sizeof(uint64_t); i++) {
    value = (value << WSC_BYTE_BITS) | (uint64_t)src[i];
  }
  return value;
}

static void write_uint16(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)((unsigned)value >> WSC_BYTE_BITS);
  dst[1] = (uint8_t)value;
}

static void write_uint64(uint8_t *dst, uint64_t value) {
  for (int i = (int)sizeof(uint64_t) - 1; i >= 0; i--) {
    dst[i] = (uint8_t)value;
    value >>= WSC_BYTE_BITS;
  }
}

static void apply_mask(uint8_t *data, size_t length, const uint8_t key[WSC_MASKING_KEY_LEN],
                       unsigned offset) {
  for (size_t i = 0; i < length; i++) {
    data[i] = (uint8_t)((unsigned)data[i] ^ key[(offset + i) & (WSC_MASKING_KEY_LEN - 1U)]);
  }
}

static size_t header_size(size_t payload_len, bool masked) {
  size_t header_length = WSC_HEADER_BASE;
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
  size_t header_length = WSC_HEADER_BASE;
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
  uint8_t header[WSC_HEADER_MAX];
  size_t header_length = WSC_HEADER_BASE;

  header[0] = (uint8_t)((frame->fin ? (unsigned)WSC_FIN_BIT : 0U) |
                        (frame->rsv1 ? (unsigned)WSC_RSV1_BIT : 0U) |
                        (frame->rsv2 ? (unsigned)WSC_RSV2_BIT : 0U) |
                        (frame->rsv3 ? (unsigned)WSC_RSV3_BIT : 0U) |
                        ((unsigned)frame->opcode & (unsigned)WSC_OPCODE_MASK));
  if (frame->payload_len <= WSC_LEN7_MAX) {
    header[1] = (uint8_t)frame->payload_len;
  } else if (frame->payload_len <= UINT16_MAX) {
    header[1] = WSC_LEN16;
    write_uint16(header + WSC_HEADER_BASE, (uint16_t)frame->payload_len);
    header_length = WSC_HEADER_BASE + WSC_LEN16_EXT;
  } else {
    header[1] = WSC_LEN64;
    write_uint64(header + WSC_HEADER_BASE, (uint64_t)frame->payload_len);
    header_length = WSC_HEADER_BASE + WSC_LEN64_EXT;
  }
  if (frame->masked) {
    header[1] = (uint8_t)((unsigned)header[1] | WSC_MASK_BIT);
    memcpy(header + header_length, frame->masking_key, WSC_MASKING_KEY_LEN);
    header_length += WSC_MASKING_KEY_LEN;
  }

  memcpy(dst, header, header_length);
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

size_t wsc_encode_into(uint8_t *dst, size_t dst_capacity, const struct wsc_frame *frame) {
  size_t total = encoded_length(frame);
  if (dst == nullptr) {
    wsc_trap();
  }
  if (dst_capacity < total) {
    wsc_trap();
  }
  return write_frame(dst, frame);
}

static struct wsc_decoding_result make_result(struct wsc_decoder *decoder) {
  struct wsc_decoding_result result;
  result.err = decoder->last_err;
  result.frames = decoder->frames_count ? decoder->frames : nullptr;
  result.frames_count = decoder->frames_count;
  return result;
}

static enum wsc_err fail(struct wsc_decoder *decoder, enum wsc_err err) {
  decoder->last_err = err;
  decoder->state = WSC_ST_DEAD;
  return err;
}

static int frames_push(struct wsc_decoder *decoder, struct wsc_frame frame) {
  if (decoder->frames_count == decoder->frames_capacity) {
    size_t capacity = decoder->frames_capacity ? decoder->frames_capacity * 2 : WSC_FRAMES_INIT;
    if (wsc_frames_reserve(decoder, capacity) != 0) {
      return -1;
    }
  }
  decoder->frames[decoder->frames_count] = frame;
  decoder->frames_count++;
  return 0;
}

static enum wsc_err emit(struct wsc_decoder *decoder) {
  struct wsc_frame frame;
  enum wsc_err err = WSC_OK;

  frame.payload = nullptr;
  frame.payload_len = (size_t)decoder->payload_len;
  memcpy(frame.masking_key, decoder->masking_key, WSC_MASKING_KEY_LEN);
  frame.opcode = decoder->opcode;
  frame.fin = decoder->fin;
  frame.rsv1 = decoder->rsv1;
  frame.rsv2 = decoder->rsv2;
  frame.rsv3 = decoder->rsv3;
  frame.masked = decoder->masked;

  if (frame.payload_len > 0) {
    err = wsc_attach_payload(decoder, &frame);
    if (err != WSC_OK) {
      return fail(decoder, err);
    }
  }
  if (frames_push(decoder, frame) != 0) {
    wsc_discard_payload(&frame);
    return fail(decoder, WSC_ERR_NO_MEMORY);
  }
  wsc_payload_emitted(decoder);
  decoder->payload.length = 0;
  return WSC_OK;
}

static void reset_header(struct wsc_decoder *decoder) {
  decoder->state = WSC_ST_HEADER;
  decoder->header_received = 0;
  decoder->header_total = WSC_HEADER_BASE;
  decoder->payload_received = 0;
  decoder->mask_offset = 0;
}

static enum wsc_err on_header(struct wsc_decoder *decoder) {
  unsigned byte0 = decoder->header[0];
  unsigned byte1 = decoder->header[1];
  uint64_t payload_length = 0;
  unsigned len7 = byte1 & WSC_LEN7_MASK;
  size_t offset = WSC_HEADER_BASE;

  decoder->fin = (byte0 & WSC_FIN_BIT) != 0;
  decoder->rsv1 = (byte0 & WSC_RSV1_BIT) != 0;
  decoder->rsv2 = (byte0 & WSC_RSV2_BIT) != 0;
  decoder->rsv3 = (byte0 & WSC_RSV3_BIT) != 0;
  decoder->opcode = (uint8_t)(byte0 & WSC_OPCODE_MASK);
  decoder->masked = (byte1 & WSC_MASK_BIT) != 0;

  if (len7 == WSC_LEN16) {
    payload_length = read_uint16(decoder->header + WSC_HEADER_BASE);
    offset = WSC_HEADER_BASE + WSC_LEN16_EXT;
    if (payload_length <= WSC_LEN7_MAX) {
      return fail(decoder, WSC_ERR_LENGTH_NOT_MINIMAL);
    }
  } else if (len7 == WSC_LEN64) {
    payload_length = read_uint64(decoder->header + WSC_HEADER_BASE);
    offset = WSC_HEADER_BASE + WSC_LEN64_EXT;
    if ((payload_length & WSC_LEN64_MSB) != 0) {
      return fail(decoder, WSC_ERR_LEN64_MSB);
    }
    if (payload_length <= UINT16_MAX) {
      return fail(decoder, WSC_ERR_LENGTH_NOT_MINIMAL);
    }
  } else {
    payload_length = (uint64_t)len7;
  }

  if (decoder->masked) {
    memcpy(decoder->masking_key, decoder->header + offset, WSC_MASKING_KEY_LEN);
  } else {
    memset(decoder->masking_key, 0, WSC_MASKING_KEY_LEN);
  }

  if (payload_length > (uint64_t)(size_t)-1) {
    return fail(decoder, WSC_ERR_NO_MEMORY);
  }

  decoder->payload_len = payload_length;
  decoder->payload_received = 0;
  decoder->mask_offset = 0;
  decoder->payload.length = 0;

  if (payload_length == 0) {
    enum wsc_err err = emit(decoder);
    if (err != WSC_OK) {
      return err;
    }
    reset_header(decoder);
    return WSC_OK;
  }

  if (wsc_buffer_reserve(decoder, &decoder->payload, (size_t)payload_length) != 0) {
    return fail(decoder, WSC_ERR_NO_MEMORY);
  }
  decoder->state = WSC_ST_PAYLOAD;
  return WSC_OK;
}

static enum wsc_err on_payload_done(struct wsc_decoder *decoder) {
  enum wsc_err err = emit(decoder);
  if (err != WSC_OK) {
    return err;
  }
  reset_header(decoder);
  return WSC_OK;
}

static enum wsc_err feed_header(struct wsc_decoder *decoder, const uint8_t *src, size_t length,
                                size_t *used) {
  size_t take = 0;
  *used = 0;
  if (decoder->header_received < WSC_HEADER_BASE) {
    decoder->header_total = WSC_HEADER_BASE;
  }
  take = decoder->header_total - decoder->header_received;
  if (take > length) {
    take = length;
  }
  memcpy(decoder->header + decoder->header_received, src, take);
  decoder->header_received += take;
  *used = take;
  if (decoder->header_received >= WSC_HEADER_BASE) {
    decoder->header_total = header_length(decoder->header[1]);
  }
  if (decoder->header_received < decoder->header_total) {
    return WSC_OK;
  }
  return on_header(decoder);
}

static enum wsc_err feed_payload(struct wsc_decoder *decoder, const uint8_t *src, size_t length,
                                 size_t *used) {
  uint64_t left = decoder->payload_len - decoder->payload_received;
  size_t take = length;
  if ((uint64_t)take > left) {
    take = (size_t)left;
  }
  if (take == 0) {
    *used = 0;
    return WSC_OK;
  }
  if (decoder->payload.data == nullptr) {
    wsc_trap();
  }
  memcpy(decoder->payload.data + decoder->payload.length, src, take);
  if (decoder->masked) {
    apply_mask(decoder->payload.data + decoder->payload.length, take, decoder->masking_key,
               decoder->mask_offset);
  }
  decoder->mask_offset = (decoder->mask_offset + (unsigned)take) & (WSC_MASKING_KEY_LEN - 1U);
  decoder->payload.length += take;
  decoder->payload_received += take;
  *used = take;
  if (decoder->payload_received >= decoder->payload_len) {
    return on_payload_done(decoder);
  }
  return WSC_OK;
}

void wsc_decoder_state_init(struct wsc_decoder *decoder) {
  decoder->state = WSC_ST_HEADER;
  decoder->header_total = WSC_HEADER_BASE;
}

void wsc_decoder_destroy(struct wsc_decoder *decoder) {
  if (decoder == nullptr) {
    return;
  }
  wsc_decoder_free(decoder);
}

struct wsc_decoding_result wsc_decoder_feed(struct wsc_decoder *decoder, const uint8_t *src,
                                            size_t length) {
  size_t offset = 0;
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
  while (offset < length && decoder->state != WSC_ST_DEAD) {
    size_t used = 0;
    enum wsc_err err = WSC_OK;
    if (decoder->state == WSC_ST_HEADER) {
      err = feed_header(decoder, src + offset, length - offset, &used);
    } else {
      err = feed_payload(decoder, src + offset, length - offset, &used);
    }
    offset += used;
    if (err != WSC_OK) {
      break;
    }
    if (used == 0) {
      break;
    }
  }
  return make_result(decoder);
}
