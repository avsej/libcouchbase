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

LIBCOUCHBASE_API
lcb_socket_t lcb_io_common_socket(lcb_io_opt_t io,
                                  int domain,
                                  int type,
                                  int protocol)
{
    lcb_common_context_t *ctx;

    ctx = calloc(1, sizeof(lcb_common_context_t));
    ctx->sock = socket(domain, type, protocol);

    if (ctx->sock == INVALID_SOCKET) {
        free(ctx);
        io->v.v0.error = errno;
    } else {
        if (make_socket_nonblocking(ctx) != 0) {
            int error = errno;
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
    free(ctx);

    (void)io;
}

LIBCOUCHBASE_API
lcb_socket_t lcb_io_common_ai2sock(lcb_io_opt_t io,
                                   struct addrinfo **ai)
{
    lcb_socket_t ret = INVALID_SOCKET;
    io->v.v0.error = 0;

    for (; *ai; *ai = (*ai)->ai_next) {
        ret = io->v.v0.socket(io,
                              (*ai)->ai_family,
                              (*ai)->ai_socktype,
                              (*ai)->ai_protocol);
        if (ret != INVALID_SOCKET) {
            return ret;
        }
    }
    return ret;
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
