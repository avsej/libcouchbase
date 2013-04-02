/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011-2012 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

/**
 * This file contains IO operations that use libevent
 *
 * @author Trond Norbye
 * @todo add more documentation
 */

#include "config.h"
#include <event.h>
#include "libevent_io_opts.h"
#include "plugins/io/common.h"
#include <errno.h>

struct lcb_libevent_st {
    struct event_base *base;
    int allocated;
};
typedef struct lcb_libevent_st lcb_libevent_t;

struct event_cookie_st {
    lcb_common_context_t *ctx;
    lcb_io_plugin_event_cb handler;
    void *data;
};
typedef struct event_cookie_st event_cookie_t;

#ifndef HAVE_LIBEVENT2
/* libevent 1.x compatibility layer */
#ifndef evutil_socket_t
#define evutil_socket_t int
#endif

typedef void (*event_callback_fn)(evutil_socket_t, short, void *);

static int
event_assign(struct event *ev,
             struct event_base *base,
             evutil_socket_t fd,
             short events,
             event_callback_fn callback,
             void *arg)
{
    ev->ev_callback = callback;
    ev->ev_arg = arg;
    ev->ev_fd = fd;
    ev->ev_events = events;
    ev->ev_res = 0;
    ev->ev_flags = EVLIST_INIT;
    ev->ev_ncalls = 0;
    ev->ev_pncalls = NULL;
    event_base_set(base, ev);

    return 0;
}

static struct event *
event_new(struct event_base *base,
          evutil_socket_t fd,
          short events,
          event_callback_fn cb,
          void *arg) {
    struct event *ev;
    ev = malloc(sizeof(struct event));
    if (ev == NULL) {
        return NULL;
    }
    if (event_assign(ev, base, fd, events, cb, arg) < 0) {
        free(ev);
        return NULL;
    }
    return ev;
}

static void
event_free(struct event *ev)
{
    /* make sure that this event won't be coming back to haunt us. */
    free(ev);

}
static short
event_get_events(const struct event *ev)
{
    return ev->ev_events;
}

static event_callback_fn
event_get_callback(const struct event *ev)
{
    return ev->ev_callback;
}
#endif

static void *lcb_io_create_event(lcb_io_opt_t io)
{
    lcb_libevent_t *libevent = io->v.v0.cookie;
    struct event *ev;
    event_cookie_t *cookie;

    cookie = calloc(1, sizeof(event_cookie_t));
    if (cookie == NULL) {
        return NULL;
    }
    ev = event_new(libevent->base, INVALID_SOCKET, 0, NULL, cookie);
    if (ev == NULL) {
        free(cookie);
        return NULL;
    }
    return ev;
}

static void handler_thunk(int sock, short which, void *data)
{
    event_cookie_t *cookie = data;
    cookie->handler(to_socket(cookie->ctx), which, cookie->data);
    (void)sock;
}

static int lcb_io_update_event(lcb_io_opt_t io,
                               lcb_socket_t sock,
                               void *event,
                               short flags,
                               void *cb_data,
                               void (*handler)(lcb_socket_t sock,
                                               short which,
                                               void *cb_data))
{
    lcb_libevent_t *libevent = io->v.v0.cookie;
    event_cookie_t *cookie = event_get_callback_arg(event);
    lcb_common_context_t *ctx = from_socket(sock);

    flags |= EV_PERSIST;
    if (flags == event_get_events(event) &&
            handler == cookie->handler) {
        /* no change! */
        return 0;
    }

    if (event_pending(event, EV_READ | EV_WRITE, 0)) {
        event_del(event);
    }

    cookie->ctx = ctx;
    cookie->handler = handler;
    cookie->data = cb_data;
    event_assign(event, libevent->base, (evutil_socket_t)ctx->sock,
                 flags, handler_thunk, cookie);
    return event_add(event, NULL);
}


static void lcb_io_delete_timer(lcb_io_opt_t io,
                                void *event)
{
    lcb_libevent_t *libevent = io->v.v0.cookie;

    if (event_pending(event, EV_TIMEOUT, 0) != 0 && event_del(event) == -1) {
        io->v.v0.error = EINVAL;
    }
    event_assign(event, libevent->base, INVALID_SOCKET, 0, NULL,
                 event_get_callback_arg(event));
}

static int lcb_io_update_timer(lcb_io_opt_t io,
                               void *timer,
                               lcb_uint32_t usec,
                               void *cb_data,
                               lcb_io_plugin_event_cb handler)
{
    lcb_libevent_t *libevent = io->v.v0.cookie;
    event_cookie_t *cookie = event_get_callback_arg(timer);
    short flags = EV_TIMEOUT | EV_PERSIST;
    struct timeval tmo;

    if (flags == event_get_events(timer) &&
            handler == cookie->handler) {
        /* no change! */
        return 0;
    }

    if (event_pending(timer, EV_TIMEOUT, 0)) {
        event_del(timer);
    }

    cookie->ctx = from_socket(INVALID_SOCKET);
    cookie->handler = handler;
    cookie->data = cb_data;
    event_assign(timer, libevent->base, INVALID_SOCKET, flags,
                 handler_thunk, cookie);
    tmo.tv_sec = usec / 1000000;
    tmo.tv_usec = usec % 1000000;
    return event_add(timer, &tmo);
}

static void lcb_io_destroy_event(lcb_io_opt_t io,
                                 void *event)
{
    if (event_pending(event, EV_READ | EV_WRITE | EV_TIMEOUT, 0)) {
        event_del(event);
    }
    event_free(event);
    (void)io;
}

static void lcb_io_delete_event(lcb_io_opt_t io,
                                lcb_socket_t sock,
                                void *event)
{
    lcb_libevent_t *libevent = io->v.v0.cookie;

    if (event_del(event) == -1) {
        io->v.v0.error = EINVAL;
    }
    event_assign(event, libevent->base, INVALID_SOCKET, 0, NULL,
                 event_get_callback_arg(event));
    (void)sock;
}

static void lcb_io_stop_event_loop(lcb_io_opt_t io)
{
    lcb_libevent_t *libevent = io->v.v0.cookie;
    event_base_loopbreak(libevent->base);
}

static void lcb_io_run_event_loop(lcb_io_opt_t io)
{
    lcb_libevent_t *libevent = io->v.v0.cookie;
    event_base_loop(libevent->base, 0);
}

static void lcb_destroy_io_opts(lcb_io_opt_t io)
{
    lcb_libevent_t *libevent = io->v.v0.cookie;
    if (libevent->allocated) {
        event_base_free(libevent->base);
    }
    free(io->v.v0.cookie);
    free(io);
}

LIBCOUCHBASE_API
lcb_error_t lcb_create_libevent_io_opts(int version, lcb_io_opt_t *io, void *arg)
{
    struct event_base *base = arg;
    lcb_io_opt_t ret;
    struct lcb_libevent_st *cookie;
    if (version != 0) {
        return LCB_PLUGIN_VERSION_MISMATCH;
    }

    ret = calloc(1, sizeof(*ret));
    cookie = calloc(1, sizeof(*cookie));
    if (ret == NULL || cookie == NULL) {
        free(ret);
        free(cookie);
        return LCB_CLIENT_ENOMEM;
    }

    /* setup io io! */
    ret->version = 0;
    ret->dlhandle = NULL;
    ret->destructor = lcb_destroy_io_opts;
    /* consider that struct isn't allocated by the library,
     * `need_cleanup' flag might be set in lcb_create() */
    ret->v.v0.need_cleanup = 0;
    ret->v.v0.recv = lcb_io_common_recv;
    ret->v.v0.send = lcb_io_common_send;
    ret->v.v0.recvv = lcb_io_common_recvv;
    ret->v.v0.sendv = lcb_io_common_sendv;
    ret->v.v0.socket = lcb_io_common_socket;
    ret->v.v0.close = lcb_io_common_close;
    ret->v.v0.connect = lcb_io_common_connect;

    ret->v.v0.delete_event = lcb_io_delete_event;
    ret->v.v0.destroy_event = lcb_io_destroy_event;
    ret->v.v0.create_event = lcb_io_create_event;
    ret->v.v0.update_event = lcb_io_update_event;

    ret->v.v0.delete_timer = lcb_io_delete_timer;
    ret->v.v0.destroy_timer = lcb_io_destroy_event;
    ret->v.v0.create_timer = lcb_io_create_event;
    ret->v.v0.update_timer = lcb_io_update_timer;

    ret->v.v0.run_event_loop = lcb_io_run_event_loop;
    ret->v.v0.stop_event_loop = lcb_io_stop_event_loop;

    if (base == NULL) {
        if ((cookie->base = event_base_new()) == NULL) {
            free(ret);
            free(cookie);
            return LCB_CLIENT_ENOMEM;
        }
        cookie->allocated = 1;
    } else {
        cookie->base = base;
        cookie->allocated = 0;
    }
    ret->v.v0.cookie = cookie;

    *io = ret;
    return LCB_SUCCESS;
}
