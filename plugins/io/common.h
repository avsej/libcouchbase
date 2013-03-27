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

#ifdef _WIN32
#define to_socket(s) ((SOCKET)s)
#else
#define to_socket(s) ((int)s)
#endif

    LIBCOUCHBASE_API
    lcb_ssize_t lcb_io_common_recv(struct lcb_io_opt_st *iops,
                                   lcb_socket_t sock,
                                   void *buffer,
                                   lcb_size_t len,
                                   int flags);

    LIBCOUCHBASE_API
    lcb_ssize_t lcb_io_common_recvv(struct lcb_io_opt_st *iops,
                                    lcb_socket_t sock,
                                    struct lcb_iovec_st *iov,
                                    lcb_size_t niov);

    LIBCOUCHBASE_API
    lcb_ssize_t lcb_io_common_send(struct lcb_io_opt_st *iops,
                                   lcb_socket_t sock,
                                   const void *msg,
                                   lcb_size_t len,
                                   int flags);

    LIBCOUCHBASE_API
    lcb_ssize_t lcb_io_common_sendv(struct lcb_io_opt_st *iops,
                                    lcb_socket_t sock,
                                    struct lcb_iovec_st *iov,
                                    lcb_size_t niov);

    LIBCOUCHBASE_API
    lcb_socket_t lcb_io_common_socket(struct lcb_io_opt_st *iops,
                               int domain,
                               int type,
                               int protocol);

    LIBCOUCHBASE_API
    void lcb_io_common_close(struct lcb_io_opt_st *iops,
                             lcb_socket_t sock);

    /**
     * This function will try to get a socket, and return it.
     * If there are no more sockets left, iops->v.v0.error is still 0, but
     * the return is INVALID_SOCKET.
     *
     * This function will 'advance' the current addrinfo structure, as well.
     */
    LIBCOUCHBASE_API
    lcb_socket_t lcb_io_common_ai2sock(struct lcb_io_opt_st *iops,
                                       struct addrinfo **ai);

    LIBCOUCHBASE_API
    int lcb_io_common_connect(struct lcb_io_opt_st *iops,
                              lcb_socket_t sock,
                              const struct sockaddr *name,
                              unsigned int namelen);

#ifdef __cplusplus
}
#endif

#endif
