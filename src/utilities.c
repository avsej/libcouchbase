/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010-2012 Couchbase, Inc.
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

#include "internal.h"

/**
 * This file contains utility functions which don't have another place
 * to call home
 */

#if !defined(HAVE_HTONLL) && !defined(WORDS_BIGENDIAN)
extern lcb_uint64_t lcb_byteswap64(lcb_uint64_t val)
{
    lcb_size_t ii;
    lcb_uint64_t ret = 0;
    for (ii = 0; ii < sizeof(lcb_uint64_t); ii++) {
        ret <<= 8;
        ret |= val & 0xff;
        val >>= 8;
    }
    return ret;
}
#endif

/**
 * This function provides a convenient place to put and classify any
 * sort of weird network error we might receive upon connect(2).
 *
 * A connection may either be in progress (EAGAIN), already connected
 * (ISCONN), noop-like (EALREADY), temporarily failed (but likely to
 * work within a short retry interval (EINTR), failed (FFAIL) or just
 * plain down screwy (UNHANDLED).
 *
 * The idea is that for multiple DNS lookups there is no point to
 * abort when the first lookup fails, because we possibly have
 * multiple RR entries.
 *
 */
lcb_connect_status_t lcb_connect_status(int err)
{
    switch (err) {
    case 0:
        return LCB_CONNECT_OK;

    case EINTR:
        return LCB_CONNECT_EINTR;

    case EWOULDBLOCK:
#ifdef USE_EAGAIN
    case EAGAIN:
#endif
    case EINPROGRESS:
        return LCB_CONNECT_EINPROGRESS;

    case EALREADY:
        return LCB_CONNECT_EALREADY;

    case EISCONN:
        return LCB_CONNECT_EISCONN;

        /* Possible to get these from a bad dns lookup */
    case EAFNOSUPPORT:
    case EINVAL:

    case ECONNREFUSED:

    case ENETUNREACH:
    case ENETRESET:
    case ENETDOWN:

    case ETIMEDOUT:
    case ECONNABORTED:

    case EHOSTDOWN:
    case EHOSTUNREACH:
        return LCB_CONNECT_EFAIL;

    default:
        /* We should really fail, as I think this should cover it */
        return LCB_CONNECT_EUNHANDLED;
    }
}

/**
 * Hello. My name is Dr. Socket, and I will diagnose your connection issue.
 * Give me a few parameters and I will figure out what
 * is wrong with your connection.
 *
 * I will give a human readable description in buf, and give a LCB_*
 * error number in uerr
 */
void lcb_sockconn_errinfo(int connerr,
                          const char *hostname,
                          const char *port,
                          const struct addrinfo *root_ai,
                          char *buf,
                          lcb_size_t nbuf,
                          lcb_error_t *uerr)
{
    char *errextra = NULL;

    /* First, check and see if the error is not a success */
    if (connerr != 0) {
        errextra = strerror(connerr);
        *uerr = LCB_CONNECT_ERROR;
    } else {
        int naddrs = 0;
        struct addrinfo *curr_ai = (struct addrinfo *)root_ai;

        for (; curr_ai; curr_ai = curr_ai->ai_next) {
            naddrs++;
        }

        if (naddrs) {
            /* unknown network error: */
            errextra = "Network error(s)";
            *uerr = LCB_CONNECT_ERROR;
        } else {
            errextra = "Lookup failed";
            *uerr = LCB_UNKNOWN_HOST;
        }
    }

    if (errextra == NULL) {
        errextra = "Unknown error";
    }

    snprintf(buf, nbuf, "Failed to connect to \"%s:%s\": %s",
             hostname, port, errextra);
}
