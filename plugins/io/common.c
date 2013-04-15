/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2013 Couchbase, Inc.
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

#include "config.h"
#include "common.h"
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#undef NDEBUG
#include <assert.h>
#include "internal.h"

LIBCOUCHBASE_API
lcb_ssize_t lcb_io_common_recv(lcb_io_opt_t io,
                               lcb_socket_t sock,
                               void *buffer,
                               lcb_size_t len,
                               int flags)
{
    lcb_common_context_t *ctx = from_socket(sock);
    lcb_ssize_t ret = recv(ctx->sock, buffer, len, flags);
    if (ret < 0) {
        io->v.v0.error = errno;
    }
    return ret;
}

LIBCOUCHBASE_API
lcb_ssize_t lcb_io_common_recvv(lcb_io_opt_t io,
                                lcb_socket_t sock,
                                struct lcb_iovec_st *iov,
                                lcb_size_t niov)
{
    lcb_common_context_t *ctx = from_socket(sock);
    struct msghdr msg;
    struct iovec vec[2];
    lcb_ssize_t ret;

    if (niov != 2) {
        return -1;
    }
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = vec;
    msg.msg_iovlen = iov[1].iov_len ? (lcb_size_t)2 : (lcb_size_t)1;
    msg.msg_iov[0].iov_base = iov[0].iov_base;
    msg.msg_iov[0].iov_len = iov[0].iov_len;
    msg.msg_iov[1].iov_base = iov[1].iov_base;
    msg.msg_iov[1].iov_len = iov[1].iov_len;
    ret = recvmsg(ctx->sock, &msg, 0);

    if (ret < 0) {
        io->v.v0.error = errno;
    }

    return ret;
}

LIBCOUCHBASE_API
lcb_ssize_t lcb_io_common_send(lcb_io_opt_t io,
                               lcb_socket_t sock,
                               const void *msg,
                               lcb_size_t len,
                               int flags)
{
    lcb_common_context_t *ctx = from_socket(sock);
    lcb_ssize_t ret = send(ctx->sock, msg, len, flags);
    if (ret < 0) {
        io->v.v0.error = errno;
    }
    return ret;
}

LIBCOUCHBASE_API
lcb_ssize_t lcb_io_common_sendv(lcb_io_opt_t io,
                                lcb_socket_t sock,
                                struct lcb_iovec_st *iov,
                                lcb_size_t niov)
{
    lcb_common_context_t *ctx = from_socket(sock);
    struct msghdr msg;
    lcb_ssize_t ret;

    memset(&msg, 0, sizeof(msg));
    assert(sizeof(struct iovec) == sizeof(struct lcb_iovec_st));
    assert(offsetof(struct iovec, iov_base) == offsetof(struct lcb_iovec_st, iov_base));
    assert(offsetof(struct iovec, iov_len) == offsetof(struct lcb_iovec_st, iov_len));
    msg.msg_iov = (struct iovec *)iov;
    msg.msg_iovlen = niov;
    ret = sendmsg(ctx->sock, &msg, 0);

    if (ret < 0) {
        io->v.v0.error = errno;
    }
    return ret;
}

static int make_socket_nonblocking(lcb_common_context_t *ctx)
{
#ifdef _WIN32
    u_long nonblocking = 1;
    if (ioctlsocket(ctx->sock, FIONBIO, &nonblocking) == SOCKET_ERROR) {
        return -1;
    }
#else
    int flags;
    if ((flags = fcntl(ctx->sock, F_GETFL, NULL)) < 0) {
        return -1;
    }
    if (fcntl(ctx->sock, F_SETFL, flags | O_NONBLOCK) == -1) {
        return -1;
    }
#endif

    return 0;
}

/* XXX it should use instance-level setting somehow */
static int common_getaddrinfo(const char *hostname,
                              const char *servname,
                              struct addrinfo **res)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET;
    return getaddrinfo(hostname, servname, &hints, res);
}


LIBCOUCHBASE_API
lcb_socket_t lcb_io_common_socket(lcb_io_opt_t io,
                                  const char *hostname,
                                  const char *servname)
{
    lcb_common_context_t *ctx;
    int error;

    ctx = calloc(1, sizeof(lcb_common_context_t));
    if (ctx == NULL) {
        return to_socket(INVALID_SOCKET);
    }
    error = common_getaddrinfo(hostname, servname, &ctx->root_ai);
    if (error != 0) {
        /* FIXME */
/*            char errinfo[1024];*/
/*            lcb_error_t our_errno;*/
/*            lcb_sockconn_errinfo(instance->io->v.v0.error,*/
/*                                 instance->host,*/
/*                                 instance->port,*/
/*                                 instance->ai,*/
/*                                 errinfo,*/
/*                                 sizeof(errinfo),*/
/*                                 &our_errno);*/
/*            lcb_instance_connerr(instance, our_errno, errinfo);*/
/*            return ;*/

        return to_socket(INVALID_SOCKET);
    }
    ctx->curr_ai = ctx->root_ai;
    for (; ctx->curr_ai; ctx->curr_ai = ctx->curr_ai->ai_next) {
        ctx->sock = socket(ctx->curr_ai->ai_family,
                           ctx->curr_ai->ai_socktype,
                           ctx->curr_ai->ai_protocol);
        if (ctx->sock != INVALID_SOCKET) {
            break;
        }
    }
    if (ctx->sock == INVALID_SOCKET) {
        free(ctx);
        io->v.v0.error = errno;
    } else {
        if (make_socket_nonblocking(ctx) != 0) {
            error = errno;
            io->v.v0.close(io, to_socket(ctx));
            io->v.v0.error = error;
        }
    }

    return to_socket(ctx);
}

LIBCOUCHBASE_API
void lcb_io_common_close(lcb_io_opt_t io,
                         lcb_socket_t sock)
{
    lcb_common_context_t *ctx = from_socket(sock);

#ifdef _WIN32
    (void)closesocket(ctx->sock);
#else
    (void)close(ctx->sock);
#endif
    ctx->sock = INVALID_SOCKET;
    if (ctx->root_ai != NULL) {
        freeaddrinfo(ctx->root_ai);
    }
    free(ctx);

    (void)io;
}

LIBCOUCHBASE_API
int lcb_io_common_connect(lcb_io_opt_t io,
                          lcb_socket_t sock,
                          const struct sockaddr *name,
                          unsigned int namelen)
{
    lcb_common_context_t *ctx = from_socket(sock);
    int ret;

    ret = connect(ctx->sock, name, (socklen_t)namelen);
    if (ret < 0) {
        io->v.v0.error = errno;
    }
    return ret;
}

struct connect_cookie_st
{
    lcb_io_opt_t io;
    void *event;
    void *cb_data;
    lcb_io_plugin_connect_cb handler;
};
typedef struct connect_cookie_st connect_cookie_t;

static
void lcb_io_common_connect_thunk(lcb_socket_t sock, short which, void *arg)
{
    connect_cookie_t *cookie = arg;
    lcb_io_opt_t io = cookie->io;
    void *event = cookie->event;
    void *cb_data = cookie->cb_data;
    lcb_io_plugin_connect_cb handler = cookie->handler;

    free(cookie);
    lcb_io_common_connect_peer(io, sock, event, cb_data, handler);
    (void)which;
}

LIBCOUCHBASE_API
void lcb_io_common_connect_peer(lcb_io_opt_t io,
                                lcb_socket_t sock,
                                void *event,
                                void *cb_data,
                                lcb_io_plugin_connect_cb handler)
{
    lcb_common_context_t *ctx = from_socket(sock);
    int retry;

    do {
        if (ctx->sock == INVALID_SOCKET) {
            /* reset address info for future attempts */
            ctx->curr_ai = ctx->root_ai;
            handler(LCB_CONNECT_ERROR, cb_data);
            return;
        }

        retry = 0;
        if (io->v.v0.connect(io, sock, ctx->curr_ai->ai_addr,
                             (unsigned int)ctx->curr_ai->ai_addrlen) == 0) {
            handler(LCB_SUCCESS, cb_data);
            return ;
        } else {
            lcb_connect_status_t connstatus = lcb_connect_status(io->v.v0.error);
            connect_cookie_t *cookie;

            switch (connstatus) {
            case LCB_CONNECT_EINTR:
                retry = 1;
                break;
            case LCB_CONNECT_EISCONN:
                handler(LCB_SUCCESS, cb_data);
                return;
            case LCB_CONNECT_EINPROGRESS: /* first call to connect */
                cookie = malloc(sizeof(connect_cookie_t));
                cookie->io = io;
                cookie->event = event;
                cookie->cb_data = cb_data;
                cookie->handler = handler;
                io->v.v0.update_event(io, sock, event,
                                      LCB_WRITE_EVENT, cookie,
                                      lcb_io_common_connect_thunk);
                return ;
            case LCB_CONNECT_EALREADY: /* subsequent calls to connect */
                return ;

            case LCB_CONNECT_EFAIL:
                if (ctx->curr_ai->ai_next) {
                    retry = 1;
                    ctx->curr_ai = ctx->curr_ai->ai_next;
                    io->v.v0.delete_event(io, sock, event);
                    io->v.v0.close(io, sock);
                    break;
                } /* else, we fallthrough */

            default:
                /* reset address info for future attempts */
                ctx->curr_ai = ctx->root_ai;
                handler(LCB_CONNECT_ERROR, cb_data);
                return;
            }
        }
    } while (retry);

    /* not reached */
    return ;
}
