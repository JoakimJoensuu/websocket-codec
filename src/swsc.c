#include "swsc.h"
#include "bug.h"
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

typedef enum { ST_HDR = 0, ST_PAYLOAD, ST_DEAD } parse_st;

struct buf {
  uint8_t *p;
  size_t n;
  size_t cap;
};

struct fail {
  swsc_err err;
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
  struct buf in;
  struct buf reply;
  struct buf enc;
  swsc_event *evs;
  size_t ev_n;
  size_t ev_cap;
  uint32_t rng_state;
  parse_st st;
  swsc_opcode opcode;
  swsc_opcode send_opcode;
  unsigned mask_off;
  swsc_opcode msg_opcode;
  swsc_err last_err;
  utf8 utf8;
  utf8 send_utf8;
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
  if (code >= SWSC_CLOSE_NORMAL && code <= CLOSE_STD_MAX &&
      code != CLOSE_RESERVED && code != SWSC_CLOSE_NO_STATUS &&
      code != SWSC_CLOSE_ABNORMAL) {
    return true;
  }
  return false;
}

static bool is_control(swsc_opcode opcode) { return (opcode & CTRL_BIT) != 0; }

static bool is_known_opcode(swsc_opcode opcode) {
  return opcode == SWSC_OP_CONT || opcode == SWSC_OP_TEXT ||
         opcode == SWSC_OP_BIN || opcode == SWSC_OP_CLOSE ||
         opcode == SWSC_OP_PING || opcode == SWSC_OP_PONG;
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
  nbuf = (uint8_t *)realloc(buf->p, ncap);
  if (!nbuf) {
    return -1;
  }
  buf->p = nbuf;
  buf->cap = ncap;
  return 0;
}

static void in_consume(swsc *ws, size_t len) {
  if (len >= ws->in.n) {
    ws->in.n = 0;
    return;
  }
  memmove(ws->in.p, ws->in.p + len, ws->in.n - len);
  ws->in.n -= len;
}

static void clear_events(swsc *ws) {
  for (size_t i = 0; i < ws->ev_n; i++) {
    free((void *)ws->evs[i].data);
    ws->evs[i].data = nullptr;
  }
  ws->ev_n = 0;
}

static int ev_push(swsc *ws, swsc_event event) {
  uint8_t *copy = nullptr;
  if (ws->ev_n == ws->ev_cap) {
    size_t ncap = ws->ev_cap ? ws->ev_cap * 2 : EV_INIT;
    swsc_event *nbuf = nullptr;
    if (ncap <= ws->ev_cap) {
      return -1;
    }
    nbuf = (swsc_event *)realloc(ws->evs, ncap * sizeof *nbuf);
    if (!nbuf) {
      return -1;
    }
    ws->evs = nbuf;
    ws->ev_cap = ncap;
  }
  if (event.len > 0) {
    bug(event.data != nullptr);
    copy = (uint8_t *)malloc(event.len);
    if (!copy) {
      return -1;
    }
    memcpy(copy, event.data, event.len);
  }
  ws->evs[ws->ev_n] = event;
  ws->evs[ws->ev_n].data = copy;
  ws->ev_n++;
  return 0;
}

static uint32_t next_rng(swsc *ws) {
  if (ws->rng) {
    return ws->rng(ws->rng_ctx);
  }
  return rng_next(&ws->rng_state);
}

static void fill_mask(swsc *ws, uint8_t key[MASK_LEN]) {
  uint32_t word = next_rng(ws);
  key[0] = (uint8_t)word;
  key[1] = (uint8_t)(word >> BYTE_BITS);
  key[2] = (uint8_t)(word >> (2U * BYTE_BITS));
  key[3] = (uint8_t)(word >> (3U * BYTE_BITS));
}

static void apply_mask(uint8_t *data, size_t len, const uint8_t key[MASK_LEN]) {
  for (size_t i = 0; i < len; i++) {
    data[i] = (uint8_t)((unsigned)data[i] ^ key[i & (MASK_LEN - 1U)]);
  }
}

static int encode_frame(swsc *ws, bool fin, swsc_opcode opcode,
                        const uint8_t *data, size_t len, struct buf *out,
                        bool append) {
  uint8_t hdr[HDR_MAX];
  size_t hlen = HDR_BASE;
  bool mask = ws->client;
  uint8_t key[MASK_LEN];
  size_t total = 0;
  size_t off = 0;

  bug(ws != nullptr);
  bug(opcode == SWSC_OP_PONG || !ws->close_sent);
  bug(is_known_opcode(opcode));
  bug(!is_control(opcode) || (fin && len <= SWSC_CTRL_MAX));
  bug(!(len && !data));

  hdr[0] = (uint8_t)((fin ? (unsigned)FIN_BIT : 0U) | (opcode & OPCODE_MASK));
  if (len <= SWSC_CTRL_MAX) {
    hdr[1] = (uint8_t)len;
  } else if (len <= UINT16_MAX) {
    hdr[1] = LEN16;
    wr16(hdr + HDR_BASE, (uint16_t)len);
    hlen = HDR_BASE + LEN16_EXT;
  } else {
    hdr[1] = LEN64;
    wr64(hdr + HDR_BASE, (uint64_t)len);
    hlen = HDR_BASE + LEN64_EXT;
  }
  if (mask) {
    hdr[1] = (uint8_t)((unsigned)hdr[1] | MASK_BIT);
    fill_mask(ws, key);
    memcpy(hdr + hlen, key, MASK_LEN);
    hlen += MASK_LEN;
  }

  total = hlen + len;
  off = append ? out->n : 0;
  if (buf_reserve(out, off + total) != 0) {
    return SWSC_ERR_NOMEM;
  }
  if (!append) {
    out->n = 0;
    off = 0;
  }
  memcpy(out->p + off, hdr, hlen);
  if (len) {
    memcpy(out->p + off + hlen, data, len);
    if (mask) {
      apply_mask(out->p + off + hlen, len, key);
    }
  }
  out->n = off + total;
  if (opcode == SWSC_OP_CLOSE) {
    ws->close_sent = true;
  }
  return SWSC_OK;
}

static int reply_frame(swsc *ws, bool fin, swsc_opcode opcode,
                       const uint8_t *data, size_t len) {
  return encode_frame(ws, fin, opcode, data, len, &ws->reply, true);
}

static swsc_bytes enc_bytes(const swsc *ws, int status) {
  swsc_bytes frame;
  if (status != SWSC_OK || ws->enc.n == 0) {
    frame.p = nullptr;
    frame.n = 0;
    return frame;
  }
  frame.p = ws->enc.p;
  frame.n = ws->enc.n;
  return frame;
}

static swsc_bytes encode_app(swsc *ws, bool fin, swsc_opcode opcode,
                             const uint8_t *data, size_t len) {
  int status = encode_frame(ws, fin, opcode, data, len, &ws->enc, false);
  return enc_bytes(ws, status);
}

static int fail(swsc *ws, struct fail why) {
  uint8_t payload[SWSC_CTRL_MAX];
  size_t rlen = 0;
  size_t plen = SWSC_CLOSE_CODE_LEN;

  if (ws->last_err == SWSC_OK) {
    ws->last_err = why.err;
  }
  ws->st = ST_DEAD;
  ws->close_code = why.code;
  ws->in.n = 0;

  if (!ws->close_sent) {
    wr16(payload, why.code);
    if (why.reason) {
      rlen = strlen(why.reason);
      if (rlen > SWSC_REASON_MAX) {
        rlen = SWSC_REASON_MAX;
      }
      memcpy(payload + SWSC_CLOSE_CODE_LEN, why.reason, rlen);
      plen = SWSC_CLOSE_CODE_LEN + rlen;
    }
    encode_frame(ws, true, SWSC_OP_CLOSE, payload, plen, &ws->reply, true);
  }
  ev_push(ws, (swsc_event){
                  .kind = SWSC_EV_ERROR,
                  .data = (const uint8_t *)why.reason,
                  .len = rlen,
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

static int finish_message(swsc *ws) {
  swsc_event_kind kind = SWSC_EV_NONE;
  if (ws->msg_opcode == SWSC_OP_TEXT) {
    if (utf8_finish(&ws->utf8) != 0) {
      return fail(ws, (struct fail){.err = SWSC_ERR_UTF8,
                                    .code = SWSC_CLOSE_INVALID_DATA,
                                    .reason = "invalid utf-8"});
    }
    kind = SWSC_EV_TEXT;
  } else {
    kind = SWSC_EV_BIN;
  }
  if (ev_push(ws, (swsc_event){.kind = kind,
                               .data = ws->msg.p,
                               .len = ws->msg.n}) != 0) {
    return fail(ws, oom);
  }
  ws->msg.n = 0;
  return SWSC_OK;
}

static int on_control(swsc *ws) {
  if (ws->opcode == SWSC_OP_PING) {
    if (reply_frame(ws, true, SWSC_OP_PONG, ws->ctrl, ws->ctrl_len) !=
        SWSC_OK) {
      return fail(ws, oom);
    }
    if (ev_push(ws, (swsc_event){.kind = SWSC_EV_PING,
                                 .data = ws->ctrl,
                                 .len = ws->ctrl_len}) != 0) {
      return fail(ws, oom);
    }
    return SWSC_OK;
  }
  if (ws->opcode == SWSC_OP_PONG) {
    if (ev_push(ws, (swsc_event){.kind = SWSC_EV_PONG,
                                 .data = ws->ctrl,
                                 .len = ws->ctrl_len}) != 0) {
      return fail(ws, oom);
    }
    return SWSC_OK;
  }

  ws->close_recv = true;
  if (ws->ctrl_len == 0) {
    ws->close_code = SWSC_CLOSE_NO_STATUS;
    if (!ws->close_sent &&
        reply_frame(ws, true, SWSC_OP_CLOSE, nullptr, 0) != SWSC_OK) {
      return fail(ws, oom);
    }
    if (ev_push(ws, (swsc_event){.kind = SWSC_EV_CLOSE,
                                 .close_code = SWSC_CLOSE_NO_STATUS}) != 0) {
      return fail(ws, oom);
    }
    ws->st = ST_DEAD;
    return SWSC_OK;
  }
  if (ws->ctrl_len < SWSC_CLOSE_CODE_LEN) {
    return fail(ws, (struct fail){.err = SWSC_ERR_PROTOCOL,
                                  .code = SWSC_CLOSE_PROTOCOL,
                                  .reason = "bad close payload"});
  }
  {
    uint16_t code = rd16(ws->ctrl);
    const uint8_t *reason = ws->ctrl + SWSC_CLOSE_CODE_LEN;
    size_t rlen = ws->ctrl_len - SWSC_CLOSE_CODE_LEN;
    utf8 state;
    if (!swsc_close_code_valid(code)) {
      return fail(ws, (struct fail){.err = SWSC_ERR_PROTOCOL,
                                    .code = SWSC_CLOSE_PROTOCOL,
                                    .reason = "bad close code"});
    }
    utf8_init(&state);
    if (utf8_feed(&state, reason, rlen) != 0 || utf8_finish(&state) != 0) {
      return fail(ws, (struct fail){.err = SWSC_ERR_UTF8,
                                    .code = SWSC_CLOSE_INVALID_DATA,
                                    .reason = "bad close reason"});
    }
    ws->close_code = code;
    if (!ws->close_sent && reply_frame(ws, true, SWSC_OP_CLOSE, ws->ctrl,
                                       ws->ctrl_len) != SWSC_OK) {
      return fail(ws, oom);
    }
    if (ev_push(ws, (swsc_event){.kind = SWSC_EV_CLOSE,
                                 .data = reason,
                                 .len = rlen,
                                 .close_code = code}) != 0) {
      return fail(ws, oom);
    }
    ws->st = ST_DEAD;
    return SWSC_OK;
  }
}

static int dispatch_empty_or_start(swsc *ws) {
  if (is_control(ws->opcode)) {
    ws->ctrl_len = 0;
    return on_control(ws);
  }
  if (ws->opcode != SWSC_OP_CONT) {
    ws->msg_opcode = ws->opcode;
    ws->msg.n = 0;
    utf8_init(&ws->utf8);
  }
  if (ws->fin) {
    int status = finish_message(ws);
    ws->msg_opcode = 0;
    return status;
  }
  return SWSC_OK;
}

static int on_frame_header(swsc *ws) {
  unsigned byte0 = ws->hdr[0];
  unsigned byte1 = ws->hdr[1];
  uint64_t plen = 0;
  unsigned len7 = byte1 & LEN7_MASK;
  size_t off = HDR_BASE;

  ws->fin = (byte0 & FIN_BIT) != 0;
  ws->opcode = (swsc_opcode)(byte0 & OPCODE_MASK);
  ws->masked = (byte1 & MASK_BIT) != 0;

  if ((byte0 & RSV_MASK) != 0) {
    return fail(ws, (struct fail){.err = SWSC_ERR_PROTOCOL,
                                  .code = SWSC_CLOSE_PROTOCOL,
                                  .reason = "rsv nonzero"});
  }
  if (!is_known_opcode(ws->opcode)) {
    return fail(ws, (struct fail){.err = SWSC_ERR_PROTOCOL,
                                  .code = SWSC_CLOSE_PROTOCOL,
                                  .reason = "bad opcode"});
  }
  if (!ws->client) {
    if (!ws->masked) {
      return fail(ws, (struct fail){.err = SWSC_ERR_PROTOCOL,
                                    .code = SWSC_CLOSE_PROTOCOL,
                                    .reason = "unmasked client frame"});
    }
  } else if (ws->masked) {
    return fail(ws, (struct fail){.err = SWSC_ERR_PROTOCOL,
                                  .code = SWSC_CLOSE_PROTOCOL,
                                  .reason = "masked server frame"});
  }

  if (len7 == LEN16) {
    plen = rd16(ws->hdr + HDR_BASE);
    off = HDR_BASE + LEN16_EXT;
    if (plen <= SWSC_CTRL_MAX) {
      return fail(ws, (struct fail){.err = SWSC_ERR_PROTOCOL,
                                    .code = SWSC_CLOSE_PROTOCOL,
                                    .reason = "non-minimal length"});
    }
  } else if (len7 == LEN64) {
    plen = rd64(ws->hdr + HDR_BASE);
    off = HDR_BASE + LEN64_EXT;
    if (plen & LEN64_MSB) {
      return fail(ws, (struct fail){.err = SWSC_ERR_PROTOCOL,
                                    .code = SWSC_CLOSE_PROTOCOL,
                                    .reason = "length msb"});
    }
    if (plen <= UINT16_MAX) {
      return fail(ws, (struct fail){.err = SWSC_ERR_PROTOCOL,
                                    .code = SWSC_CLOSE_PROTOCOL,
                                    .reason = "non-minimal length"});
    }
  } else {
    plen = (uint64_t)len7;
  }

  if (ws->masked) {
    memcpy(ws->mask_key, ws->hdr + off, MASK_LEN);
  }

  if (is_control(ws->opcode)) {
    if (!ws->fin) {
      return fail(ws, (struct fail){.err = SWSC_ERR_PROTOCOL,
                                    .code = SWSC_CLOSE_PROTOCOL,
                                    .reason = "fragmented control"});
    }
    if (plen > SWSC_CTRL_MAX) {
      return fail(ws, (struct fail){.err = SWSC_ERR_PROTOCOL,
                                    .code = SWSC_CLOSE_PROTOCOL,
                                    .reason = "control too long"});
    }
  } else {
    if (ws->opcode == SWSC_OP_CONT) {
      if (ws->msg_opcode == 0) {
        return fail(ws, (struct fail){.err = SWSC_ERR_PROTOCOL,
                                      .code = SWSC_CLOSE_PROTOCOL,
                                      .reason = "orphan continuation"});
      }
    } else {
      if (ws->msg_opcode != 0) {
        return fail(ws, (struct fail){.err = SWSC_ERR_PROTOCOL,
                                      .code = SWSC_CLOSE_PROTOCOL,
                                      .reason = "new data while fragmented"});
      }
    }
    if (plen > (uint64_t)(size_t)-1 ||
        (uint64_t)ws->msg.n > (uint64_t)(size_t)-1 - plen) {
      return fail(ws, oom);
    }
  }

  ws->payload_len = plen;
  ws->payload_got = 0;
  ws->mask_off = 0;
  ws->ctrl_len = 0;

  if (plen == 0) {
    ws->st = ST_HDR;
    ws->hdr_got = 0;
    ws->hdr_need = HDR_BASE;
    return dispatch_empty_or_start(ws);
  }

  ws->st = ST_PAYLOAD;
  if (!is_control(ws->opcode) && ws->opcode != SWSC_OP_CONT) {
    ws->msg_opcode = ws->opcode;
    ws->msg.n = 0;
    utf8_init(&ws->utf8);
  }
  return SWSC_OK;
}

static int on_payload_bytes(swsc *ws, const uint8_t *src, size_t len) {
  uint8_t tmp[PAYLOAD_CHUNK];
  size_t off = 0;

  while (off < len) {
    size_t chunk = len - off;
    if (chunk > sizeof tmp) {
      chunk = sizeof tmp;
    }
    memcpy(tmp, src + off, chunk);
    if (ws->masked) {
      for (size_t i = 0; i < chunk; i++) {
        tmp[i] = (uint8_t)((unsigned)tmp[i] ^
                           ws->mask_key[(ws->mask_off + i) & (MASK_LEN - 1U)]);
      }
    }
    ws->mask_off = (ws->mask_off + (unsigned)chunk) & (MASK_LEN - 1U);

    if (is_control(ws->opcode)) {
      memcpy(ws->ctrl + ws->ctrl_len, tmp, chunk);
      ws->ctrl_len += chunk;
    } else {
      if (buf_reserve(&ws->msg, ws->msg.n + chunk) != 0) {
        return fail(ws, oom);
      }
      memcpy(ws->msg.p + ws->msg.n, tmp, chunk);
      if (ws->msg_opcode == SWSC_OP_TEXT &&
          utf8_feed(&ws->utf8, ws->msg.p + ws->msg.n, chunk) != 0) {
        return fail(ws, (struct fail){.err = SWSC_ERR_UTF8,
                                      .code = SWSC_CLOSE_INVALID_DATA,
                                      .reason = "invalid utf-8"});
      }
      ws->msg.n += chunk;
    }
    off += chunk;
  }
  return SWSC_OK;
}

static int on_payload_done(swsc *ws) {
  ws->st = ST_HDR;
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

static int parse_in(swsc *ws) {
  while (ws->in.n > 0 && ws->st != ST_DEAD && ws->last_err == SWSC_OK) {
    if (ws->st == ST_HDR) {
      size_t need = 0;
      size_t take = 0;
      int status = SWSC_OK;
      if (ws->hdr_got < HDR_BASE) {
        ws->hdr_need = HDR_BASE;
      }
      need = ws->hdr_need;
      take = need - ws->hdr_got;
      if (take > ws->in.n) {
        take = ws->in.n;
      }
      memcpy(ws->hdr + ws->hdr_got, ws->in.p, take);
      ws->hdr_got += take;
      in_consume(ws, take);
      if (ws->hdr_got >= HDR_BASE) {
        ws->hdr_need = header_len(ws->hdr[1]);
      }
      if (ws->hdr_got < ws->hdr_need) {
        if (ws->in.n == 0) {
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

    if (ws->st == ST_PAYLOAD) {
      uint64_t left = ws->payload_len - ws->payload_got;
      size_t take = ws->in.n;
      int status = SWSC_OK;
      if ((uint64_t)take > left) {
        take = (size_t)left;
      }
      status = on_payload_bytes(ws, ws->in.p, take);
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

static swsc *create(bool client, uint32_t (*rng)(void *), void *rng_ctx) {
  swsc *ws = (swsc *)calloc(1, sizeof *ws);
  if (!ws) {
    return nullptr;
  }
  ws->client = client;
  ws->rng = rng;
  ws->rng_ctx = rng_ctx;
  ws->rng_state = RNG_SEED ^ (uint32_t)(uintptr_t)ws;
  ws->st = ST_HDR;
  ws->hdr_need = HDR_BASE;
  ws->close_code = SWSC_CLOSE_NO_STATUS;
  return ws;
}

swsc *swsc_create_client(uint32_t (*rng)(void *ctx), void *rng_ctx) {
  return create(true, rng, rng_ctx);
}

swsc *swsc_create_server() { return create(false, nullptr, nullptr); }

void swsc_destroy(swsc *ws) {
  if (!ws) {
    return;
  }
  clear_events(ws);
  free(ws->evs);
  free(ws->msg.p);
  free(ws->in.p);
  free(ws->reply.p);
  free(ws->enc.p);
  free(ws);
}

static swsc_result make_result(swsc *ws, swsc_err err) {
  swsc_result result;
  result.err = err;
  result.evs = ws->ev_n ? ws->evs : nullptr;
  result.n = ws->ev_n;
  result.out.p = ws->reply.n ? ws->reply.p : nullptr;
  result.out.n = ws->reply.n;
  return result;
}

swsc_result swsc_feed(swsc *ws, const uint8_t *src, size_t len) {
  bug(ws != nullptr);
  bug(!(len && !src));
  clear_events(ws);
  ws->reply.n = 0;
  if (ws->st == ST_DEAD) {
    return make_result(ws, ws->last_err ? ws->last_err : SWSC_ERR_CLOSED);
  }
  if (len) {
    if (buf_reserve(&ws->in, ws->in.n + len) != 0) {
      return make_result(ws, (swsc_err)fail(ws, oom));
    }
    memcpy(ws->in.p + ws->in.n, src, len);
    ws->in.n += len;
  }
  return make_result(ws, (swsc_err)parse_in(ws));
}

static void require_send_idle(const swsc *ws) { bug(ws->send_opcode == 0); }

static void check_text(const uint8_t *data, size_t len) {
  utf8 state;
  utf8_init(&state);
  if (len) {
    bug(utf8_feed(&state, data, len) == 0);
  }
  bug(utf8_finish(&state) == 0);
}

static utf8 check_send_text(utf8 state, const uint8_t *data, size_t len,
                            bool finish) {
  if (len) {
    bug(utf8_feed(&state, data, len) == 0);
  }
  if (finish) {
    bug(utf8_finish(&state) == 0);
  }
  return state;
}

swsc_bytes swsc_text_frame(swsc *ws, const uint8_t *data, size_t len) {
  bug(ws != nullptr);
  bug(!(len && !data));
  bug(!ws->close_sent);
  require_send_idle(ws);
  check_text(data, len);
  return encode_app(ws, true, SWSC_OP_TEXT, data, len);
}

swsc_bytes swsc_bin_frame(swsc *ws, const uint8_t *data, size_t len) {
  bug(ws != nullptr);
  bug(!(len && !data));
  bug(!ws->close_sent);
  require_send_idle(ws);
  return encode_app(ws, true, SWSC_OP_BIN, data, len);
}

swsc_bytes swsc_ping_frame(swsc *ws, const uint8_t *data, size_t len) {
  bug(ws != nullptr);
  bug(!(len && !data));
  bug(!ws->close_sent);
  return encode_app(ws, true, SWSC_OP_PING, data, len);
}

swsc_bytes swsc_pong_frame(swsc *ws, const uint8_t *data, size_t len) {
  bug(ws != nullptr);
  bug(!(len && !data));
  return encode_app(ws, true, SWSC_OP_PONG, data, len);
}

swsc_bytes swsc_close_frame(swsc *ws, uint16_t code, const uint8_t *reason,
                            size_t reason_len) {
  uint8_t payload[SWSC_CTRL_MAX];
  size_t plen = SWSC_CLOSE_CODE_LEN;
  bug(ws != nullptr);
  bug(!ws->close_sent);
  if (code == 0) {
    bug(reason_len == 0);
    return encode_app(ws, true, SWSC_OP_CLOSE, nullptr, 0);
  }
  bug(swsc_close_code_valid(code));
  bug(reason_len <= SWSC_REASON_MAX);
  wr16(payload, code);
  if (reason_len) {
    check_text(reason, reason_len);
    memcpy(payload + SWSC_CLOSE_CODE_LEN, reason, reason_len);
    plen = SWSC_CLOSE_CODE_LEN + reason_len;
  }
  return encode_app(ws, true, SWSC_OP_CLOSE, payload, plen);
}

swsc_bytes swsc_fragment(swsc *ws, swsc_opcode opcode, const uint8_t *data,
                         size_t len) {
  swsc_bytes frame;
  utf8 next;
  bool text = false;
  bug(ws != nullptr);
  bug(!(len && !data));
  bug(!ws->close_sent);
  if (opcode == SWSC_OP_CONT) {
    bug(ws->send_opcode == SWSC_OP_TEXT || ws->send_opcode == SWSC_OP_BIN);
  } else {
    bug(opcode == SWSC_OP_TEXT || opcode == SWSC_OP_BIN);
    require_send_idle(ws);
  }
  text = (opcode == SWSC_OP_TEXT) ||
         (opcode == SWSC_OP_CONT && ws->send_opcode == SWSC_OP_TEXT);
  if (text) {
    if (opcode == SWSC_OP_TEXT) {
      utf8_init(&next);
    } else {
      next = ws->send_utf8;
    }
    next = check_send_text(next, data, len, false);
  }
  frame = encode_app(ws, false, opcode, data, len);
  if (frame.p) {
    if (opcode != SWSC_OP_CONT) {
      ws->send_opcode = opcode;
    }
    if (text) {
      ws->send_utf8 = next;
    }
  }
  return frame;
}

swsc_bytes swsc_fragment_end(swsc *ws, const uint8_t *data, size_t len) {
  swsc_bytes frame;
  utf8 next;
  bool text = false;
  bug(ws != nullptr);
  bug(!(len && !data));
  bug(!ws->close_sent);
  bug(ws->send_opcode == SWSC_OP_TEXT || ws->send_opcode == SWSC_OP_BIN);
  text = (ws->send_opcode == SWSC_OP_TEXT);
  if (text) {
    next = check_send_text(ws->send_utf8, data, len, true);
  }
  frame = encode_app(ws, true, SWSC_OP_CONT, data, len);
  if (frame.p) {
    if (text) {
      ws->send_utf8 = next;
    }
    ws->send_opcode = 0;
  }
  return frame;
}

bool swsc_closing(const swsc *ws) {
  bug(ws != nullptr);
  return ws->close_sent || ws->close_recv;
}

bool swsc_closed(const swsc *ws) {
  bug(ws != nullptr);
  return ws->close_sent && ws->close_recv;
}

swsc_err swsc_error(const swsc *ws) {
  bug(ws != nullptr);
  return ws->last_err;
}

uint16_t swsc_last_close(const swsc *ws) {
  bug(ws != nullptr);
  return ws->close_code;
}
