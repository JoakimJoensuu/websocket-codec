#include "swsc.h"
#include "rng.h"
#include "utf8.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum : unsigned {
  HDR_BASE = 2,
  LEN16_EXT = 2,
  LEN64_EXT = 8,
  MASK_LEN = 4,
  HDR_MAX = HDR_BASE + LEN64_EXT + MASK_LEN,
};

enum : unsigned {
  LEN16 = 126,
  LEN64 = 127,
};

enum : uint8_t {
  FIN_BIT = 0x80,
  RSV_MASK = 0x70,
  OPCODE_MASK = 0x0F,
  MASK_BIT = 0x80,
  LEN7_MASK = 0x7F,
  CTRL_BIT = 0x08,
};

enum : uint64_t { LEN64_MSB = 0x8000000000000000 };

enum : unsigned {
  CLOSE_APP_MIN = 3000,
  CLOSE_APP_MAX = 4999,
  CLOSE_STD_MAX = 1014,
  CLOSE_RESERVED = 1004,
};

enum : unsigned {
  BUF_INIT = 256,
  EV_INIT = 8,
  PAYLOAD_CHUNK = 512,
};

enum : unsigned { BYTE_BITS = CHAR_BIT };

enum opcode : unsigned {
  OP_CONT = 0x0,
  OP_TEXT = 0x1,
  OP_BIN = 0x2,
  OP_CLOSE = 0x8,
  OP_PING = 0x9,
  OP_PONG = 0xA,
};

enum parse_st { ST_HDR = 0, ST_PAYLOAD, ST_DEAD };

struct buf {
  uint8_t *data;
  size_t length;
  size_t cap;
};

struct fail {
  enum swsc_err err;
  uint16_t code;
  const char *reason;
};

static const struct fail oom = {
    .err = SWSC_ERR_NOMEM,
    .code = SWSC_CLOSE_INTERNAL,
    .reason = "oom",
};

struct swsc {
  uint32_t (*rng)(void *);
  void *rng_ctx;
  size_t hdr_got;
  size_t hdr_need;
  uint64_t payload_len;
  uint64_t payload_got;
  struct buf msg;
  size_t ctrl_len;
  struct buf input;
  struct buf enc;
  struct swsc_event *evs;
  size_t evs_cnt;
  size_t evs_cap;
  uint32_t rng_state;
  enum parse_st state;
  enum opcode opcode;
  enum opcode send_opcode;
  unsigned mask_off;
  enum opcode msg_opcode;
  enum swsc_err last_err;
  struct utf8 utf8;
  struct utf8 send_utf8;
  uint16_t close_code;
  bool fin;
  bool masked;
  bool client;
  bool close_sent;
  bool close_recv;
  uint8_t mask_key[MASK_LEN];
  uint8_t hdr[HDR_MAX];
  uint8_t ctrl[SWSC_CTRL_MAX];
};

bool swsc_close_code_valid(uint16_t code) {
  if (code >= CLOSE_APP_MIN && code <= CLOSE_APP_MAX) {
    return true;
  }
  if (code >= SWSC_CLOSE_NORMAL && code <= CLOSE_STD_MAX && code != CLOSE_RESERVED &&
      code != SWSC_CLOSE_NO_STATUS && code != SWSC_CLOSE_ABNORMAL) {
    return true;
  }
  return false;
}

static bool is_control(enum opcode opcode) { return (opcode & CTRL_BIT) != 0; }

static bool is_known_opcode(enum opcode opcode) {
  return opcode == OP_CONT || opcode == OP_TEXT || opcode == OP_BIN || opcode == OP_CLOSE ||
         opcode == OP_PING || opcode == OP_PONG;
}

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

static void in_consume(struct swsc *ws, size_t length) {
  if (length >= ws->input.length) {
    ws->input.length = 0;
    return;
  }
  memmove(ws->input.data, ws->input.data + length, ws->input.length - length);
  ws->input.length -= length;
}

static void clear_events(struct swsc *ws) {
  for (size_t i = 0; i < ws->evs_cnt; i++) {
    free((void *)ws->evs[i].data);
    ws->evs[i].data = nullptr;
  }
  ws->evs_cnt = 0;
}

static int ev_push(struct swsc *ws, struct swsc_event event) {
  uint8_t *copy = nullptr;
  if (ws->evs_cnt == ws->evs_cap) {
    size_t ncap = ws->evs_cap ? ws->evs_cap * 2 : EV_INIT;
    struct swsc_event *nbuf = nullptr;
    if (ncap <= ws->evs_cap) {
      return -1;
    }
    nbuf = (struct swsc_event *)realloc(ws->evs, ncap * sizeof *nbuf);
    if (nbuf == nullptr) {
      return -1;
    }
    ws->evs = nbuf;
    ws->evs_cap = ncap;
  }
  if (event.length > 0) {
    if (event.data == nullptr) abort();

    copy = (uint8_t *)malloc(event.length);
    if (copy == nullptr) {
      return -1;
    }
    memcpy(copy, event.data, event.length);
  }
  ws->evs[ws->evs_cnt] = event;
  ws->evs[ws->evs_cnt].data = copy;
  ws->evs_cnt++;
  return 0;
}

static uint32_t next_rng(struct swsc *ws) {
  if (ws->rng != nullptr) {
    return ws->rng(ws->rng_ctx);
  }
  return rng_next(&ws->rng_state);
}

static void fill_mask(struct swsc *ws, uint8_t key[MASK_LEN]) {
  uint32_t word = next_rng(ws);
  key[0] = (uint8_t)word;
  key[1] = (uint8_t)(word >> BYTE_BITS);
  key[2] = (uint8_t)(word >> (2U * BYTE_BITS));
  key[3] = (uint8_t)(word >> (3U * BYTE_BITS));
}

static void apply_mask(uint8_t *data, size_t length, const uint8_t key[MASK_LEN]) {
  for (size_t i = 0; i < length; i++) {
    data[i] = (uint8_t)((unsigned)data[i] ^ key[i & (MASK_LEN - 1U)]);
  }
}

static int encode_frame(struct swsc *ws, bool fin, enum opcode opcode, const uint8_t *data,
                        size_t length, struct buf *out, bool append) {
  uint8_t hdr[HDR_MAX];
  size_t hlen = HDR_BASE;
  bool mask = ws->client;
  uint8_t key[MASK_LEN];
  size_t total = 0;
  size_t off = 0;

  if (ws == nullptr) abort();
  if (opcode != OP_PONG && ws->close_sent) abort();
  if (!is_known_opcode(opcode)) abort();
  if (is_control(opcode) && (!fin || length > SWSC_CTRL_MAX)) abort();
  if (length && data == nullptr) abort();

  hdr[0] = (uint8_t)((fin ? (unsigned)FIN_BIT : 0U) | (opcode & OPCODE_MASK));
  if (length <= SWSC_CTRL_MAX) {
    hdr[1] = (uint8_t)length;
  } else if (length <= UINT16_MAX) {
    hdr[1] = LEN16;
    wr16(hdr + HDR_BASE, (uint16_t)length);
    hlen = HDR_BASE + LEN16_EXT;
  } else {
    hdr[1] = LEN64;
    wr64(hdr + HDR_BASE, (uint64_t)length);
    hlen = HDR_BASE + LEN64_EXT;
  }
  if (mask) {
    hdr[1] = (uint8_t)((unsigned)hdr[1] | MASK_BIT);
    fill_mask(ws, key);
    memcpy(hdr + hlen, key, MASK_LEN);
    hlen += MASK_LEN;
  }

  total = hlen + length;
  off = append ? out->length : 0;
  if (buf_reserve(out, off + total) != 0) {
    return SWSC_ERR_NOMEM;
  }
  if (!append) {
    out->length = 0;
    off = 0;
  }
  memcpy(out->data + off, hdr, hlen);
  if (length) {
    memcpy(out->data + off + hlen, data, length);
    if (mask) {
      apply_mask(out->data + off + hlen, length, key);
    }
  }
  out->length = off + total;
  if (opcode == OP_CLOSE) {
    ws->close_sent = true;
  }
  return SWSC_OK;
}

static struct swsc_enc enc_fail(enum swsc_err err) {
  return (struct swsc_enc){
      .err = err,
      .bytes = {.data = nullptr, .length = 0},
  };
}

static struct swsc_enc encode_app(struct swsc *ws, bool fin, enum opcode opcode,
                                  const uint8_t *data, size_t length) {
  int status = encode_frame(ws, fin, opcode, data, length, &ws->enc, false);
  if (status != SWSC_OK) {
    return enc_fail(SWSC_ERR_NOMEM);
  }
  return (struct swsc_enc){
      .err = SWSC_OK,
      .bytes = {.data = ws->enc.data, .length = ws->enc.length},
  };
}

static int fail(struct swsc *ws, struct fail why) {
  size_t rlen = 0;

  if (ws->last_err == SWSC_OK) {
    ws->last_err = why.err;
  }
  ws->state = ST_DEAD;
  ws->close_code = why.code;
  ws->input.length = 0;

  if (why.reason != nullptr) {
    rlen = strlen(why.reason);
    if (rlen > SWSC_REASON_MAX) {
      rlen = SWSC_REASON_MAX;
    }
  }
  ev_push(ws, (struct swsc_event){
                  .kind = SWSC_EV_ERROR,
                  .data = (const uint8_t *)why.reason,
                  .length = rlen,
                  .close_code = why.code,
              });
  return why.err;
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
    hlen += MASK_LEN;
  }
  return hlen;
}

static int finish_message(struct swsc *ws) {
  enum swsc_event_kind kind = SWSC_EV_BIN;
  if (ws->msg_opcode == OP_TEXT) {
    if (utf8_finish(&ws->utf8) != 0) {
      return fail(ws, (struct fail){
                          .err = SWSC_ERR_UTF8,
                          .code = SWSC_CLOSE_INVALID_DATA,
                          .reason = "invalid utf-8",
                      });
    }
    kind = SWSC_EV_TEXT;
  }
  if (ev_push(ws, (struct swsc_event){
                      .kind = kind,
                      .data = ws->msg.data,
                      .length = ws->msg.length,
                  }) != 0) {
    return fail(ws, oom);
  }
  ws->msg.length = 0;
  return SWSC_OK;
}

static int on_control(struct swsc *ws) {
  if (ws->opcode == OP_PING) {
    if (ev_push(ws, (struct swsc_event){
                        .kind = SWSC_EV_PING,
                        .data = ws->ctrl,
                        .length = ws->ctrl_len,
                    }) != 0) {
      return fail(ws, oom);
    }
    return SWSC_OK;
  }
  if (ws->opcode == OP_PONG) {
    if (ev_push(ws, (struct swsc_event){
                        .kind = SWSC_EV_PONG,
                        .data = ws->ctrl,
                        .length = ws->ctrl_len,
                    }) != 0) {
      return fail(ws, oom);
    }
    return SWSC_OK;
  }

  if (ws->ctrl_len == 0) {
    ws->close_code = SWSC_CLOSE_NO_STATUS;
    ws->close_recv = true;
    if (ev_push(ws, (struct swsc_event){
                        .kind = SWSC_EV_CLOSE,
                        .close_code = SWSC_CLOSE_NO_STATUS,
                    }) != 0) {
      return fail(ws, oom);
    }
    ws->state = ST_DEAD;
    return SWSC_OK;
  }
  if (ws->ctrl_len < SWSC_CLOSE_CODE_LEN) {
    return fail(ws, (struct fail){
                        .err = SWSC_ERR_PROTOCOL,
                        .code = SWSC_CLOSE_PROTOCOL,
                        .reason = "bad close payload",
                    });
  }
  {
    uint16_t code = rd16(ws->ctrl);
    const uint8_t *reason = ws->ctrl + SWSC_CLOSE_CODE_LEN;
    size_t rlen = ws->ctrl_len - SWSC_CLOSE_CODE_LEN;
    struct utf8 state;
    if (!swsc_close_code_valid(code)) {
      return fail(ws, (struct fail){
                          .err = SWSC_ERR_PROTOCOL,
                          .code = SWSC_CLOSE_PROTOCOL,
                          .reason = "bad close code",
                      });
    }
    utf8_init(&state);
    if (utf8_feed(&state, reason, rlen) != 0 || utf8_finish(&state) != 0) {
      return fail(ws, (struct fail){
                          .err = SWSC_ERR_UTF8,
                          .code = SWSC_CLOSE_INVALID_DATA,
                          .reason = "bad close reason",
                      });
    }
    ws->close_code = code;
    ws->close_recv = true;
    if (ev_push(ws, (struct swsc_event){
                        .kind = SWSC_EV_CLOSE,
                        .data = reason,
                        .length = rlen,
                        .close_code = code,
                    }) != 0) {
      return fail(ws, oom);
    }
    ws->state = ST_DEAD;
    return SWSC_OK;
  }
}

static int dispatch_empty_or_start(struct swsc *ws) {
  if (is_control(ws->opcode)) {
    ws->ctrl_len = 0;
    return on_control(ws);
  }
  if (ws->opcode != OP_CONT) {
    ws->msg_opcode = ws->opcode;
    ws->msg.length = 0;
    utf8_init(&ws->utf8);
  }
  if (ws->fin) {
    int status = finish_message(ws);
    ws->msg_opcode = 0;
    return status;
  }
  return SWSC_OK;
}

static int on_frame_header(struct swsc *ws) {
  unsigned byte0 = ws->hdr[0];
  unsigned byte1 = ws->hdr[1];
  uint64_t plen = 0;
  unsigned len7 = byte1 & LEN7_MASK;
  size_t off = HDR_BASE;

  ws->fin = (byte0 & FIN_BIT) != 0;
  ws->opcode = (enum opcode)(byte0 & OPCODE_MASK);
  ws->masked = (byte1 & MASK_BIT) != 0;

  if ((byte0 & RSV_MASK) != 0) {
    return fail(ws, (struct fail){
                        .err = SWSC_ERR_PROTOCOL,
                        .code = SWSC_CLOSE_PROTOCOL,
                        .reason = "rsv nonzero",
                    });
  }
  if (!is_known_opcode(ws->opcode)) {
    return fail(ws, (struct fail){
                        .err = SWSC_ERR_PROTOCOL,
                        .code = SWSC_CLOSE_PROTOCOL,
                        .reason = "bad opcode",
                    });
  }
  if (!ws->client) {
    if (!ws->masked) {
      return fail(ws, (struct fail){
                          .err = SWSC_ERR_PROTOCOL,
                          .code = SWSC_CLOSE_PROTOCOL,
                          .reason = "unmasked client frame",
                      });
    }
  } else if (ws->masked) {
    return fail(ws, (struct fail){
                        .err = SWSC_ERR_PROTOCOL,
                        .code = SWSC_CLOSE_PROTOCOL,
                        .reason = "masked server frame",
                    });
  }

  if (len7 == LEN16) {
    plen = rd16(ws->hdr + HDR_BASE);
    off = HDR_BASE + LEN16_EXT;
    if (plen <= SWSC_CTRL_MAX) {
      return fail(ws, (struct fail){
                          .err = SWSC_ERR_PROTOCOL,
                          .code = SWSC_CLOSE_PROTOCOL,
                          .reason = "non-minimal length",
                      });
    }
  } else if (len7 == LEN64) {
    plen = rd64(ws->hdr + HDR_BASE);
    off = HDR_BASE + LEN64_EXT;
    if (plen & LEN64_MSB) {
      return fail(ws, (struct fail){
                          .err = SWSC_ERR_PROTOCOL,
                          .code = SWSC_CLOSE_PROTOCOL,
                          .reason = "length msb",
                      });
    }
    if (plen <= UINT16_MAX) {
      return fail(ws, (struct fail){
                          .err = SWSC_ERR_PROTOCOL,
                          .code = SWSC_CLOSE_PROTOCOL,
                          .reason = "non-minimal length",
                      });
    }
  } else {
    plen = (uint64_t)len7;
  }

  if (ws->masked) {
    memcpy(ws->mask_key, ws->hdr + off, MASK_LEN);
  }

  if (is_control(ws->opcode)) {
    if (!ws->fin) {
      return fail(ws, (struct fail){
                          .err = SWSC_ERR_PROTOCOL,
                          .code = SWSC_CLOSE_PROTOCOL,
                          .reason = "fragmented control",
                      });
    }
    if (plen > SWSC_CTRL_MAX) {
      return fail(ws, (struct fail){
                          .err = SWSC_ERR_PROTOCOL,
                          .code = SWSC_CLOSE_PROTOCOL,
                          .reason = "control too long",
                      });
    }
  } else {
    if (ws->opcode == OP_CONT) {
      if (ws->msg_opcode == 0) {
        return fail(ws, (struct fail){
                            .err = SWSC_ERR_PROTOCOL,
                            .code = SWSC_CLOSE_PROTOCOL,
                            .reason = "orphan continuation",
                        });
      }
    } else {
      if (ws->msg_opcode != 0) {
        return fail(ws, (struct fail){
                            .err = SWSC_ERR_PROTOCOL,
                            .code = SWSC_CLOSE_PROTOCOL,
                            .reason = "new data while fragmented",
                        });
      }
    }
    if (plen > (uint64_t)(size_t)-1 || (uint64_t)ws->msg.length > (uint64_t)(size_t)-1 - plen) {
      return fail(ws, oom);
    }
  }

  ws->payload_len = plen;
  ws->payload_got = 0;
  ws->mask_off = 0;
  ws->ctrl_len = 0;

  if (plen == 0) {
    ws->state = ST_HDR;
    ws->hdr_got = 0;
    ws->hdr_need = HDR_BASE;
    return dispatch_empty_or_start(ws);
  }

  ws->state = ST_PAYLOAD;
  if (!is_control(ws->opcode) && ws->opcode != OP_CONT) {
    ws->msg_opcode = ws->opcode;
    ws->msg.length = 0;
    utf8_init(&ws->utf8);
  }
  return SWSC_OK;
}

static int on_payload_bytes(struct swsc *ws, const uint8_t *src, size_t length) {
  uint8_t tmp[PAYLOAD_CHUNK];
  size_t off = 0;

  while (off < length) {
    size_t chunk = length - off;
    if (chunk > sizeof tmp) {
      chunk = sizeof tmp;
    }
    memcpy(tmp, src + off, chunk);
    if (ws->masked) {
      for (size_t i = 0; i < chunk; i++) {
        tmp[i] = (uint8_t)((unsigned)tmp[i] ^ ws->mask_key[(ws->mask_off + i) & (MASK_LEN - 1U)]);
      }
    }
    ws->mask_off = (ws->mask_off + (unsigned)chunk) & (MASK_LEN - 1U);

    if (is_control(ws->opcode)) {
      memcpy(ws->ctrl + ws->ctrl_len, tmp, chunk);
      ws->ctrl_len += chunk;
    } else {
      if (buf_reserve(&ws->msg, ws->msg.length + chunk) != 0) {
        return fail(ws, oom);
      }
      memcpy(ws->msg.data + ws->msg.length, tmp, chunk);
      if (ws->msg_opcode == OP_TEXT &&
          utf8_feed(&ws->utf8, ws->msg.data + ws->msg.length, chunk) != 0) {
        return fail(ws, (struct fail){
                            .err = SWSC_ERR_UTF8,
                            .code = SWSC_CLOSE_INVALID_DATA,
                            .reason = "invalid utf-8",
                        });
      }
      ws->msg.length += chunk;
    }
    off += chunk;
  }
  return SWSC_OK;
}

static int on_payload_done(struct swsc *ws) {
  ws->state = ST_HDR;
  ws->hdr_got = 0;
  ws->hdr_need = HDR_BASE;
  if (is_control(ws->opcode)) {
    return on_control(ws);
  }
  if (ws->fin) {
    int status = finish_message(ws);
    ws->msg_opcode = 0;
    return status;
  }
  return SWSC_OK;
}

static int parse_in(struct swsc *ws) {
  while (ws->input.length > 0 && ws->state != ST_DEAD && ws->last_err == SWSC_OK) {
    if (ws->state == ST_HDR) {
      size_t need = 0;
      size_t take = 0;
      int status = SWSC_OK;
      if (ws->hdr_got < HDR_BASE) {
        ws->hdr_need = HDR_BASE;
      }
      need = ws->hdr_need;
      take = need - ws->hdr_got;
      if (take > ws->input.length) {
        take = ws->input.length;
      }
      memcpy(ws->hdr + ws->hdr_got, ws->input.data, take);
      ws->hdr_got += take;
      in_consume(ws, take);
      if (ws->hdr_got >= HDR_BASE) {
        ws->hdr_need = header_len(ws->hdr[1]);
      }
      if (ws->hdr_got < ws->hdr_need) {
        if (ws->input.length == 0) {
          break;
        }
        continue;
      }
      status = on_frame_header(ws);
      if (status < 0) {
        return status;
      }
      continue;
    }

    if (ws->state == ST_PAYLOAD) {
      uint64_t left = ws->payload_len - ws->payload_got;
      size_t take = ws->input.length;
      int status = SWSC_OK;
      if ((uint64_t)take > left) {
        take = (size_t)left;
      }
      status = on_payload_bytes(ws, ws->input.data, take);
      if (status < 0) {
        return status;
      }
      in_consume(ws, take);
      ws->payload_got += take;
      if (ws->payload_got >= ws->payload_len) {
        status = on_payload_done(ws);
        if (status < 0) {
          return status;
        }
      }
      continue;
    }
    break;
  }
  return ws->last_err == SWSC_OK ? SWSC_OK : (int)ws->last_err;
}

static struct swsc *create(bool client, uint32_t (*rng)(void *), void *rng_ctx) {
  struct swsc *ws = (struct swsc *)calloc(1, sizeof *ws);
  if (ws == nullptr) {
    return nullptr;
  }
  ws->client = client;
  ws->rng = rng;
  ws->rng_ctx = rng_ctx;
  ws->rng_state = RNG_SEED ^ (uint32_t)(uintptr_t)ws;
  ws->state = ST_HDR;
  ws->hdr_need = HDR_BASE;
  ws->close_code = SWSC_CLOSE_NO_STATUS;
  return ws;
}

struct swsc *swsc_create_client(uint32_t (*rng)(void *ctx), void *rng_ctx) {
  return create(true, rng, rng_ctx);
}

struct swsc *swsc_create_server() { return create(false, nullptr, nullptr); }

void swsc_destroy(struct swsc *ws) {
  if (ws == nullptr) {
    return;
  }
  clear_events(ws);
  free(ws->evs);
  free(ws->msg.data);
  free(ws->input.data);
  free(ws->enc.data);
  free(ws);
}

static struct swsc_result make_result(struct swsc *ws, enum swsc_err err) {
  struct swsc_result result;
  result.err = err;
  result.events = ws->evs_cnt ? ws->evs : nullptr;
  result.events_cnt = ws->evs_cnt;
  return result;
}

struct swsc_result swsc_feed(struct swsc *ws, const uint8_t *src, size_t length) {
  if (ws == nullptr) abort();
  if (length && src == nullptr) abort();
  clear_events(ws);
  if (ws->state == ST_DEAD) {
    return make_result(ws, ws->last_err ? ws->last_err : SWSC_ERR_CLOSED);
  }
  if (length) {
    if (buf_reserve(&ws->input, ws->input.length + length) != 0) {
      return make_result(ws, (enum swsc_err)fail(ws, oom));
    }
    memcpy(ws->input.data + ws->input.length, src, length);
    ws->input.length += length;
  }
  return make_result(ws, (enum swsc_err)parse_in(ws));
}

static void require_send_idle(const struct swsc *ws) {
  if (ws->send_opcode != 0) abort();
}

static enum swsc_err feed_send_text(struct utf8 *state, const uint8_t *data, size_t length,
                                    bool finish) {
  struct utf8 next = *state;
  if (length && utf8_feed(&next, data, length) != 0) {
    return SWSC_ERR_UTF8;
  }
  if (finish && utf8_finish(&next) != 0) {
    return SWSC_ERR_UTF8;
  }
  *state = next;
  return SWSC_OK;
}

struct swsc_enc swsc_text_frame(struct swsc *ws, const uint8_t *data, size_t length) {
  struct utf8 state;
  if (ws == nullptr) abort();
  if (length && data == nullptr) abort();
  if (ws->close_sent) abort();
  require_send_idle(ws);
  utf8_init(&state);
  if (feed_send_text(&state, data, length, true) != SWSC_OK) {
    return enc_fail(SWSC_ERR_UTF8);
  }
  return encode_app(ws, true, OP_TEXT, data, length);
}

struct swsc_enc swsc_bin_frame(struct swsc *ws, const uint8_t *data, size_t length) {
  if (ws == nullptr) abort();
  if (length && data == nullptr) abort();
  if (ws->close_sent) abort();
  require_send_idle(ws);
  return encode_app(ws, true, OP_BIN, data, length);
}

struct swsc_enc swsc_ping_frame(struct swsc *ws, const uint8_t *data, size_t length) {
  if (ws == nullptr) abort();
  if (length && data == nullptr) abort();
  if (ws->close_sent) abort();
  return encode_app(ws, true, OP_PING, data, length);
}

struct swsc_enc swsc_pong_frame(struct swsc *ws, const uint8_t *data, size_t length) {
  if (ws == nullptr) abort();
  if (length && data == nullptr) abort();
  return encode_app(ws, true, OP_PONG, data, length);
}

struct swsc_enc swsc_close_frame(struct swsc *ws, uint16_t code, const uint8_t *reason,
                                 size_t reason_len) {
  uint8_t payload[SWSC_CTRL_MAX];
  size_t plen = SWSC_CLOSE_CODE_LEN;
  struct utf8 state;
  if (ws == nullptr) abort();
  if (ws->close_sent) abort();
  if (code == 0 || code == SWSC_CLOSE_NO_STATUS) {
    if (reason_len != 0) abort();
    return encode_app(ws, true, OP_CLOSE, nullptr, 0);
  }
  if (!swsc_close_code_valid(code)) abort();
  if (reason_len > SWSC_REASON_MAX) abort();
  wr16(payload, code);
  if (reason_len) {
    utf8_init(&state);
    if (feed_send_text(&state, reason, reason_len, true) != SWSC_OK) {
      return enc_fail(SWSC_ERR_UTF8);
    }
    memcpy(payload + SWSC_CLOSE_CODE_LEN, reason, reason_len);
    plen = SWSC_CLOSE_CODE_LEN + reason_len;
  }
  return encode_app(ws, true, OP_CLOSE, payload, plen);
}

struct swsc_enc swsc_text_fragment(struct swsc *ws, const uint8_t *data, size_t length) {
  struct swsc_enc enc;
  struct utf8 next;
  enum opcode opcode = OP_TEXT;
  if (ws == nullptr) abort();
  if (length && data == nullptr) abort();
  if (ws->close_sent) abort();
  if (ws->send_opcode == 0) {
    opcode = OP_TEXT;
    utf8_init(&next);
  } else if (ws->send_opcode == OP_TEXT) {
    opcode = OP_CONT;
    next = ws->send_utf8;
  } else {
    abort();
  }
  if (feed_send_text(&next, data, length, false) != SWSC_OK) {
    return enc_fail(SWSC_ERR_UTF8);
  }
  enc = encode_app(ws, false, opcode, data, length);
  if (enc.err == SWSC_OK) {
    ws->send_opcode = OP_TEXT;
    ws->send_utf8 = next;
  }
  return enc;
}

struct swsc_enc swsc_text_fragment_end(struct swsc *ws, const uint8_t *data, size_t length) {
  struct swsc_enc enc;
  struct utf8 next;
  if (ws == nullptr) abort();
  if (length && data == nullptr) abort();
  if (ws->close_sent) abort();
  if (ws->send_opcode != OP_TEXT) abort();
  next = ws->send_utf8;
  if (feed_send_text(&next, data, length, true) != SWSC_OK) {
    return enc_fail(SWSC_ERR_UTF8);
  }
  enc = encode_app(ws, true, OP_CONT, data, length);
  if (enc.err == SWSC_OK) {
    ws->send_utf8 = next;
    ws->send_opcode = 0;
  }
  return enc;
}

struct swsc_enc swsc_bin_fragment(struct swsc *ws, const uint8_t *data, size_t length) {
  struct swsc_enc enc;
  enum opcode opcode = OP_BIN;
  if (ws == nullptr) abort();
  if (length && data == nullptr) abort();
  if (ws->close_sent) abort();
  if (ws->send_opcode == 0) {
    opcode = OP_BIN;
  } else if (ws->send_opcode == OP_BIN) {
    opcode = OP_CONT;
  } else {
    abort();
  }
  enc = encode_app(ws, false, opcode, data, length);
  if (enc.err == SWSC_OK) {
    ws->send_opcode = OP_BIN;
  }
  return enc;
}

struct swsc_enc swsc_bin_fragment_end(struct swsc *ws, const uint8_t *data, size_t length) {
  struct swsc_enc enc;
  if (ws == nullptr) abort();
  if (length && data == nullptr) abort();
  if (ws->close_sent) abort();
  if (ws->send_opcode != OP_BIN) abort();
  enc = encode_app(ws, true, OP_CONT, data, length);
  if (enc.err == SWSC_OK) {
    ws->send_opcode = 0;
  }
  return enc;
}

bool swsc_closing(const struct swsc *ws) {
  if (ws == nullptr) abort();
  return ws->close_sent || ws->close_recv;
}

bool swsc_closed(const struct swsc *ws) {
  if (ws == nullptr) abort();
  return ws->close_sent && ws->close_recv;
}

enum swsc_err swsc_error(const struct swsc *ws) {
  if (ws == nullptr) abort();
  return ws->last_err;
}

uint16_t swsc_last_close(const struct swsc *ws) {
  if (ws == nullptr) abort();
  return ws->close_code;
}
