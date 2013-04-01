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

#ifndef LIBCOUCHBASE_PLUGINS_IO_COMMON_H
#define LIBCOUCHBASE_PLUGINS_IO_COMMON_H 1

#include <libcouchbase/couchbase.h>

#ifdef __cplusplus
extern "C" {
#endif

    struct lcb_common_context_st {
#ifdef _WIN32
        SOCKET sock;
#else
        int sock;
#endif
        struct addrinfo *ai;
        struct addrinfo *curr_ai;
    };
    typedef struct lcb_common_context_st lcb_common_context_t;

#define to_socket(X)    ((lcb_socket_t)(intptr_t)(X))
#define from_socket(X)  ((lcb_common_context_t *)(intptr_t)(X))

    LIBCOUCHBASE_API
    lcb_ssize_t lcb_io_common_recv(lcb_io_opt_t iops,
                                   lcb_socket_t sock,
                                   void *buffer,
                                   lcb_size_t len,
                                   int flags);

    LIBCOUCHBASE_API
    lcb_ssize_t lcb_io_common_recvv(lcb_io_opt_t iops,
                                    lcb_socket_t sock,
                                    struct lcb_iovec_st *iov,
                                    lcb_size_t niov);

    LIBCOUCHBASE_API
    lcb_ssize_t lcb_io_common_send(lcb_io_opt_t iops,
                                   lcb_socket_t sock,
                                   const void *msg,
                                   lcb_size_t len,
                                   int flags);

    LIBCOUCHBASE_API
    lcb_ssize_t lcb_io_common_sendv(lcb_io_opt_t iops,
                                    lcb_socket_t sock,
                                    struct lcb_iovec_st *iov,
                                    lcb_size_t niov);

    LIBCOUCHBASE_API
    lcb_socket_t lcb_io_common_socket(lcb_io_opt_t iops,
                               int domain,
                               int type,
                               int protocol);

    LIBCOUCHBASE_API
    void lcb_io_common_close(lcb_io_opt_t iops,
                             lcb_socket_t sock);

    /**
     * This function will try to get a socket, and return it.
     * If there are no more sockets left, iops->v.v0.error is still 0, but
     * the return is INVALID_SOCKET.
     *
     * This function will 'advance' the current addrinfo structure, as well.
     */
    LIBCOUCHBASE_API
    lcb_socket_t lcb_io_common_ai2sock(lcb_io_opt_t iops,
                                       struct addrinfo **ai);

    LIBCOUCHBASE_API
    int lcb_io_common_connect(lcb_io_opt_t iops,
                              lcb_socket_t sock,
                              const struct sockaddr *name,
                              unsigned int namelen);

#ifdef __cplusplus
}
#endif

#endif
