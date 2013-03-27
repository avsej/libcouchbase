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
lcb_ssize_t lcb_io_common_recv(struct lcb_io_opt_st *iops,
                               lcb_socket_t sock,
                               void *buffer,
                               lcb_size_t len,
                               int flags)
{
    lcb_ssize_t ret = recv(to_socket(sock), buffer, len, flags);
    if (ret < 0) {
        iops->v.v0.error = errno;
    }
    return ret;
}

LIBCOUCHBASE_API
lcb_ssize_t lcb_io_common_recvv(struct lcb_io_opt_st *iops,
                                lcb_socket_t sock,
                                struct lcb_iovec_st *iov,
                                lcb_size_t niov)
{
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
    ret = recvmsg(to_socket(sock), &msg, 0);

    if (ret < 0) {
        iops->v.v0.error = errno;
    }

    return ret;
}

LIBCOUCHBASE_API
lcb_ssize_t lcb_io_common_send(struct lcb_io_opt_st *iops,
                               lcb_socket_t sock,
                               const void *msg,
                               lcb_size_t len,
                               int flags)
{
    lcb_ssize_t ret = send(to_socket(sock), msg, len, flags);
    if (ret < 0) {
        iops->v.v0.error = errno;
    }
    return ret;
}

LIBCOUCHBASE_API
lcb_ssize_t lcb_io_common_sendv(struct lcb_io_opt_st *iops,
                                lcb_socket_t sock,
                                struct lcb_iovec_st *iov,
                                lcb_size_t niov)
{
    struct msghdr msg;
    lcb_ssize_t ret;

    memset(&msg, 0, sizeof(msg));
    assert(sizeof(struct iovec) == sizeof(struct lcb_iovec_st));
    assert(offsetof(struct iovec, iov_base) == offsetof(struct lcb_iovec_st, iov_base));
    assert(offsetof(struct iovec, iov_len) == offsetof(struct lcb_iovec_st, iov_len));
    msg.msg_iov = (struct iovec *)iov;
    msg.msg_iovlen = niov;
    ret = sendmsg(to_socket(sock), &msg, 0);

    if (ret < 0) {
        iops->v.v0.error = errno;
    }
    return ret;
}

static int make_socket_nonblocking(lcb_socket_t sock)
{
#ifdef _WIN32
    u_long nonblocking = 1;
    if (ioctlsocket((SOCKET)sock, FIONBIO, &nonblocking) == SOCKET_ERROR) {
        return -1;
    }
#else
    int flags;
    if ((flags = fcntl((int)sock, F_GETFL, NULL)) < 0) {
        return -1;
    }
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
        return -1;
    }
#endif

    return 0;
}

LIBCOUCHBASE_API
lcb_socket_t lcb_io_common_socket(struct lcb_io_opt_st *iops,
                                  int domain,
                                  int type,
                                  int protocol)
{
    lcb_socket_t sock = socket(domain, type, protocol);
    if (sock == INVALID_SOCKET) {
        iops->v.v0.error = errno;
    } else {
        if (make_socket_nonblocking(sock) != 0) {
            int error = errno;
            iops->v.v0.close(iops, sock);
            iops->v.v0.error = error;
            sock = INVALID_SOCKET;
        }
    }

    return sock;
}

LIBCOUCHBASE_API
void lcb_io_common_close(struct lcb_io_opt_st *iops,
                         lcb_socket_t sock)
{
#ifdef _WIN32
    (void)closesocket((SOCKET)sock);
#else
    (void)close((int)sock);
#endif
    (void)iops;
}

LIBCOUCHBASE_API
lcb_socket_t lcb_io_common_ai2sock(struct lcb_io_opt_st *iops,
                                   struct addrinfo **ai)
{
    lcb_socket_t ret = INVALID_SOCKET;
    iops->v.v0.error = 0;

    for (; *ai; *ai = (*ai)->ai_next) {
        ret = iops->v.v0.socket(iops,
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
int lcb_io_common_connect(struct lcb_io_opt_st *iops,
                          lcb_socket_t sock,
                          const struct sockaddr *name,
                          unsigned int namelen)
{
    int ret = connect(to_socket(sock), name, (socklen_t)namelen);
    if (ret < 0) {
        iops->v.v0.error = errno;
    }
    return ret;
}
