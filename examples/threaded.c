/**
 * Client and server threads on a socketpair. No HTTP.
 *
 * Frame helpers return a view that the next encode invalidates, and send()
 * may take only part of it. Copy into an application buffer and drain that.
 *
 * The client reads slowly so the server cannot push a whole frame in one send.
 */

#define _POSIX_C_SOURCE 200809L

#include "sws.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static void pause_ms(unsigned ms)
{
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = (long)ms * 1000000L;
    nanosleep(&ts, NULL);
}

enum { NMSG = 40, MSGLEN = 200, SLOW_READ = 8 };

typedef struct {
    uint8_t *p;
    size_t len;
    size_t cap;
} outbuf;

static int out_append(outbuf *o, const uint8_t *p, size_t n)
{
    uint8_t *np;
    size_t cap;
    if (!n) {
        return 0;
    }
    cap = o->cap ? o->cap : 256;
    while (cap < o->len + n) {
        if (cap > ((size_t)-1) / 2) {
            return -1;
        }
        cap *= 2;
    }
    np = (uint8_t *)realloc(o->p, cap);
    if (!np) {
        return -1;
    }
    memcpy(np + o->len, p, n);
    o->p = np;
    o->cap = cap;
    o->len += n;
    return 0;
}

static int out_copy(outbuf *o, sws_bytes b)
{
    if (!b.p && b.n) {
        return -1;
    }
    return out_append(o, b.p, b.n);
}

static int out_flush(int fd, outbuf *o, int *short_sends)
{
    while (o->len) {
        ssize_t w = send(fd, o->p, o->len, MSG_DONTWAIT);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            return -1;
        }
        if (w == 0) {
            return -1;
        }
        if ((size_t)w < o->len && short_sends) {
            (*short_sends)++;
        }
        memmove(o->p, o->p + (size_t)w, o->len - (size_t)w);
        o->len -= (size_t)w;
    }
    return 0;
}

static void out_free(outbuf *o)
{
    free(o->p);
    o->p = NULL;
    o->len = 0;
    o->cap = 0;
}

typedef struct {
    int fd;
    int short_sends;
    int texts;
    int rc;
} thread_arg;

static void *server_fn(void *argp)
{
    thread_arg *arg = (thread_arg *)argp;
    sws *ws = sws_create_server();
    outbuf out = {0};
    uint8_t payload[MSGLEN];
    uint8_t in[256];
    int i;
    int snd = 1024;

    arg->rc = 1;
    if (!ws) {
        return NULL;
    }
    setsockopt(arg->fd, SOL_SOCKET, SO_SNDBUF, &snd, sizeof snd);
    memset(payload, 'x', sizeof payload);

    for (i = 0; i < NMSG; i++) {
        sws_bytes b = sws_text_frame(ws, payload, sizeof payload);
        if (out_copy(&out, b) != 0 || out_flush(arg->fd, &out, &arg->short_sends) != 0) {
            goto done;
        }
    }

    if (out_copy(&out, sws_close_frame(ws, SWS_CLOSE_NORMAL, NULL, 0)) != 0) {
        goto done;
    }

    for (;;) {
        ssize_t n;
        sws_result r;
        if (out_flush(arg->fd, &out, &arg->short_sends) != 0) {
            goto done;
        }
        n = recv(arg->fd, in, sizeof in, out.len ? MSG_DONTWAIT : 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if ((errno == EAGAIN || errno == EWOULDBLOCK) && out.len) {
                pause_ms(1);
                continue;
            }
            goto done;
        }
        if (n == 0) {
            goto done;
        }
        r = sws_feed(ws, in, (size_t)n);
        if (out_copy(&out, r.out) != 0) {
            goto done;
        }
        if (r.err != SWS_OK || sws_closed(ws)) {
            while (out.len) {
                if (out_flush(arg->fd, &out, &arg->short_sends) != 0) {
                    goto done;
                }
                if (out.len) {
                    pause_ms(1);
                }
            }
            arg->rc = (r.err == SWS_OK) ? 0 : 1;
            goto done;
        }
    }

done:
    out_free(&out);
    sws_destroy(ws);
    return NULL;
}

static void *client_fn(void *argp)
{
    thread_arg *arg = (thread_arg *)argp;
    sws *ws = sws_create_client(NULL, NULL);
    outbuf out = {0};
    uint8_t in[SLOW_READ];

    arg->rc = 1;
    if (!ws) {
        return NULL;
    }

    for (;;) {
        ssize_t n;
        sws_result r;
        size_t i;
        pause_ms(2);
        n = recv(arg->fd, in, sizeof in, 0);
        if (n <= 0) {
            goto done;
        }
        r = sws_feed(ws, in, (size_t)n);
        if (out_copy(&out, r.out) != 0) {
            goto done;
        }
        while (out.len) {
            ssize_t w = send(arg->fd, out.p, out.len, 0);
            if (w < 0) {
                if (errno == EINTR) {
                    continue;
                }
                goto done;
            }
            memmove(out.p, out.p + (size_t)w, out.len - (size_t)w);
            out.len -= (size_t)w;
        }
        for (i = 0; i < r.n; i++) {
            if (r.evs[i].kind == SWS_EV_TEXT) {
                arg->texts++;
            }
        }
        if (r.err != SWS_OK || sws_closed(ws)) {
            arg->rc = (r.err == SWS_OK && arg->texts == NMSG) ? 0 : 1;
            goto done;
        }
    }

done:
    out_free(&out);
    sws_destroy(ws);
    return NULL;
}

int main(void)
{
    int fd[2];
    pthread_t th_srv, th_cli;
    thread_arg srv = {0};
    thread_arg cli = {0};

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) != 0) {
        perror("socketpair");
        return 1;
    }
    srv.fd = fd[0];
    cli.fd = fd[1];
    if (pthread_create(&th_srv, NULL, server_fn, &srv) != 0 ||
        pthread_create(&th_cli, NULL, client_fn, &cli) != 0) {
        return 1;
    }
    pthread_join(th_srv, NULL);
    pthread_join(th_cli, NULL);
    close(fd[0]);
    close(fd[1]);

    printf("client got %d/%d texts; server short sends: %d\n", cli.texts, NMSG,
           srv.short_sends);
    return (srv.rc || cli.rc || srv.short_sends == 0) ? 1 : 0;
}
