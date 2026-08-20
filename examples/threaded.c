/**
 * Client and server threads on a socketpair. No HTTP.
 *
 * Copy each encoded frame (or feed.out chunk) into a list. Control
 * (Pong, Close, Ping) is a separate list from data so a Pong can go out
 * before leftover TEXT. Finish the in-flight frame first; never splice
 * into the middle of a frame.
 *
 * The client reads slowly and sends a Ping while the server still has
 * TEXT queued.
 */

#define _POSIX_C_SOURCE 200809L

#include "swsf.h"

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

enum { NMSG = 12, MSGLEN = 3000, SLOW_READ = 16 };

typedef struct frame {
    uint8_t *p;
    size_t len;
    size_t off;
    struct frame *next;
} frame;

typedef struct {
    frame *head;
    frame *tail;
} flist;

typedef struct {
    flist ctrl;
    flist data;
    frame *cur;
} txq;

static int flist_push(flist *l, swsf_bytes b)
{
    frame *f;
    if (!b.n) {
        return 0;
    }
    if (!b.p) {
        return -1;
    }
    f = (frame *)calloc(1, sizeof *f);
    if (!f) {
        return -1;
    }
    f->p = (uint8_t *)malloc(b.n);
    if (!f->p) {
        free(f);
        return -1;
    }
    memcpy(f->p, b.p, b.n);
    f->len = b.n;
    if (l->tail) {
        l->tail->next = f;
    } else {
        l->head = f;
    }
    l->tail = f;
    return 0;
}

static frame *flist_pop(flist *l)
{
    frame *f = l->head;
    if (!f) {
        return NULL;
    }
    l->head = f->next;
    if (!l->head) {
        l->tail = NULL;
    }
    f->next = NULL;
    return f;
}

static void frame_free(frame *f)
{
    if (!f) {
        return;
    }
    free(f->p);
    free(f);
}

static void tx_free(txq *tx)
{
    frame *f;
    frame_free(tx->cur);
    tx->cur = NULL;
    while ((f = flist_pop(&tx->ctrl))) {
        frame_free(f);
    }
    while ((f = flist_pop(&tx->data))) {
        frame_free(f);
    }
}

static int tx_idle(const txq *tx)
{
    return !tx->cur && !tx->ctrl.head && !tx->data.head;
}

static int tx_push_ctrl(txq *tx, swsf_bytes b, int *preempt)
{
    if (b.n && preempt && (tx->data.head || tx->cur)) {
        (*preempt)++;
    }
    return flist_push(&tx->ctrl, b);
}

static int tx_push_data(txq *tx, swsf_bytes b)
{
    return flist_push(&tx->data, b);
}

static int tx_flush(int fd, txq *tx, int send_flags, int *short_sends)
{
    for (;;) {
        size_t left;
        ssize_t w;
        if (!tx->cur) {
            tx->cur = flist_pop(&tx->ctrl);
            if (!tx->cur) {
                tx->cur = flist_pop(&tx->data);
            }
            if (!tx->cur) {
                return 0;
            }
        }
        left = tx->cur->len - tx->cur->off;
        w = send(fd, tx->cur->p + tx->cur->off, left, send_flags);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            if ((send_flags & MSG_DONTWAIT) && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                return 0;
            }
            return -1;
        }
        if (w == 0) {
            return -1;
        }
        if ((size_t)w < left && short_sends) {
            (*short_sends)++;
        }
        tx->cur->off += (size_t)w;
        if (tx->cur->off >= tx->cur->len) {
            frame_free(tx->cur);
            tx->cur = NULL;
        }
    }
}

typedef struct {
    int fd;
    int short_sends;
    int texts;
    int pongs;
    int preempt;
    int rc;
} thread_arg;

static void *server_fn(void *argp)
{
    thread_arg *arg = (thread_arg *)argp;
    swsf *ws = swsf_create_server();
    txq tx = {0};
    uint8_t payload[MSGLEN];
    uint8_t in[256];
    int i = 0;
    int close_queued = 0;
    int snd = 1024;

    arg->rc = 1;
    if (!ws) {
        return NULL;
    }
    setsockopt(arg->fd, SOL_SOCKET, SO_SNDBUF, &snd, sizeof snd);
    memset(payload, 'x', sizeof payload);

    for (;;) {
        ssize_t n;
        swsf_result r;
        if (i < NMSG) {
            if (tx_push_data(&tx, swsf_text_frame(ws, payload, sizeof payload)) != 0) {
                goto done;
            }
            i++;
        }
        if (i >= NMSG && !close_queued && !tx.data.head && !tx.cur) {
            if (tx_push_ctrl(&tx, swsf_close_frame(ws, SWSF_CLOSE_NORMAL, NULL, 0), NULL) != 0) {
                goto done;
            }
            close_queued = 1;
        }
        if (tx_flush(arg->fd, &tx, MSG_DONTWAIT, &arg->short_sends) != 0) {
            goto done;
        }
        n = recv(arg->fd, in, sizeof in,
                 (i >= NMSG && close_queued && tx_idle(&tx)) ? 0 : MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (i < NMSG || !close_queued || !tx_idle(&tx)) {
                    if (!tx_idle(&tx)) {
                        pause_ms(1);
                    }
                    continue;
                }
            }
            goto done;
        }
        if (n == 0) {
            goto done;
        }
        r = swsf_feed(ws, in, (size_t)n);
        if (tx_push_ctrl(&tx, r.out, &arg->preempt) != 0) {
            goto done;
        }
        if (r.err != SWSF_OK) {
            goto done;
        }
        if (swsf_closed(ws) && tx_idle(&tx)) {
            arg->rc = 0;
            goto done;
        }
    }

done:
    tx_free(&tx);
    swsf_destroy(ws);
    return NULL;
}

static void *client_fn(void *argp)
{
    thread_arg *arg = (thread_arg *)argp;
    swsf *ws = swsf_create_client(NULL, NULL);
    txq tx = {0};
    uint8_t in[SLOW_READ];
    int pinged = 0;

    arg->rc = 1;
    if (!ws) {
        return NULL;
    }

    for (;;) {
        ssize_t n;
        swsf_result r;
        size_t i;
        pause_ms(2);
        n = recv(arg->fd, in, sizeof in, 0);
        if (n <= 0) {
            goto done;
        }
        r = swsf_feed(ws, in, (size_t)n);
        if (tx_push_ctrl(&tx, r.out, NULL) != 0) {
            goto done;
        }
        if (!pinged && arg->texts > 0) {
            if (tx_push_ctrl(&tx, swsf_ping_frame(ws, (const uint8_t *)"?", 1), NULL) != 0) {
                goto done;
            }
            pinged = 1;
        }
        if (tx_flush(arg->fd, &tx, 0, NULL) != 0) {
            goto done;
        }
        for (i = 0; i < r.n; i++) {
            if (r.evs[i].kind == SWSF_EV_TEXT) {
                arg->texts++;
            } else if (r.evs[i].kind == SWSF_EV_PONG) {
                arg->pongs++;
            }
        }
        if (r.err != SWSF_OK) {
            goto done;
        }
        if (swsf_closed(ws) && tx_idle(&tx)) {
            arg->rc = (arg->texts == NMSG && arg->pongs >= 1) ? 0 : 1;
            goto done;
        }
    }

done:
    tx_free(&tx);
    swsf_destroy(ws);
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

    printf("client got %d/%d texts, %d pongs; server short sends: %d, preempt: %d\n",
           cli.texts, NMSG, cli.pongs, srv.short_sends, srv.preempt);
    return (srv.rc || cli.rc || srv.short_sends == 0 || srv.preempt == 0) ? 1 : 0;
}
