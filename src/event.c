/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010-2013 Couchbase, Inc.
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
 * This file contains the callback functions used by libevent.
 *
 * @author Trond Norbye
 * @todo add more documentation
 */
#include "internal.h"
#include <ctype.h>

static int do_fill_input_buffer(lcb_server_t c)
{
    struct lcb_iovec_st iov[2];
    lcb_ssize_t nr;

    if (!ringbuffer_ensure_capacity(&c->input, 8192)) {
        lcb_error_handler(c->instance, LCB_CLIENT_ENOMEM, NULL);
        return -1;
    }

    ringbuffer_get_iov(&c->input, RINGBUFFER_WRITE, iov);

    c->instance->io->v.v0.error = 0;
    nr = c->instance->io->v.v0.recvv(c->instance->io, c->sock, iov, 2);
    if (nr == -1) {
        switch (c->instance->io->v.v0.error) {
        case EINTR:
            break;
        case EWOULDBLOCK:
#ifdef USE_EAGAIN
        case EAGAIN:
#endif
            return 0;
        default:
            lcb_failout_server(c, LCB_NETWORK_ERROR);
            return -1;
        }
    } else if (nr == 0) {
        assert((iov[0].iov_len + iov[1].iov_len) != 0);
        /* TODO stash error message somewhere
         * "Connection closed... we should resend to other nodes or reconnect!!" */
        lcb_failout_server(c, LCB_NETWORK_ERROR);
        return -1;
    } else {
        ringbuffer_produced(&c->input, (lcb_size_t)nr);
        lcb_update_server_timer(c);
    }

    return 1;
}

static int parse_single(lcb_server_t c, hrtime_t stop)
{
    protocol_binary_response_header header;
    lcb_size_t nr;
    char *bytes;
    lcb_size_t nbytes;
    lcb_packet_t pkt;
    lcb_t instance = c->instance;

    if (ringbuffer_ensure_alignment(&c->input) != 0) {
        lcb_error_handler(instance, LCB_EINTERNAL, NULL);
        return -1;
    }

    nr = ringbuffer_peek(&c->input, header.bytes, sizeof(header));
    if (nr < sizeof(header)) {
        return 0; /* need more data */
    }

    nbytes = ntohl(header.response.bodylen) + (lcb_uint32_t)sizeof(header);
    if (c->input.nbytes < nbytes) {
        return 0; /* need more data */
    }

    if (lcb_server_purge_implicit_responses(c, header.response.opaque, stop) != 0) {
        return -1;
    }
    pkt = lcb_packet_queue_peek(c->log);
    if (header.response.opaque < pkt->opaque &&
            header.response.opaque > 0) { /* sasl comes with zero opaque */
        ringbuffer_consumed(&c->input, nbytes);
        return 1; /* already processed. */
    }

    /* now we have everything! */

    /* assume that the respose bytes is continuous chunk of memory */
    bytes = c->input.read_head;

    if (!ringbuffer_is_continous(&c->input, RINGBUFFER_READ, nbytes)) {
        /* The buffer isn't continuous.. for now just copy it out and
         * operate on the copy ;) */
        if ((bytes = malloc(nbytes)) == NULL) {
            lcb_error_handler(instance, LCB_CLIENT_ENOMEM, NULL);
            return -1;
        }
        nr = ringbuffer_read(&c->input, bytes, nbytes);
        if (nr != nbytes) {
            lcb_error_handler(instance, LCB_EINTERNAL, NULL);
            free(bytes);
            return -1;
        }
    }

    switch (header.response.magic) {
    case PROTOCOL_BINARY_REQ:
        /*
         * The only way to get request packets is if someone started
         * to send us TAP requests, and we don't support that anymore
         */
        lcb_error_handler(c->instance, LCB_EINTERNAL,
                          "Protocol error. someone sent us a command!");
        return -1;
        break;
    case PROTOCOL_BINARY_RES: {
        int was_connected = c->connected;

        if (instance->histogram) {
            lcb_record_metrics(instance, stop - pkt->start, header.response.opcode);
        }

        if (ntohs(header.response.status) != PROTOCOL_BINARY_RESPONSE_NOT_MY_VBUCKET
                || header.response.opcode == CMD_GET_REPLICA
                || header.response.opcode == CMD_OBSERVE) {
            if (lcb_dispatch_response(c, pkt, (protocol_binary_response_header *)bytes) == -1) {
                /*
                 * Internal error.. we received an unsupported response
                 * id. This should _ONLY_ happen at development time because
                 * we won't receive response packets with other opcodes
                 * than we send. Let's abort here to make it easy for
                 * the developer to know what happened..
                 */
                lcb_error_handler(c->instance, LCB_EINTERNAL,
                                  "Received unknown command response");
                abort();
                return -1;
            }

            /* keep packet until we get complete STAT response */
            if (was_connected && (header.response.opcode != PROTOCOL_BINARY_CMD_STAT || header.response.keylen == 0)) {
                lcb_packet_queue_remove(pkt);
                pkt = NULL;
            }
        } else {
            int idx;
            lcb_server_t new_srv;
            idx = vbucket_found_incorrect_master(instance->vbucket_config,
                                                 pkt->vbucket, (int)c->index);
            assert((lcb_size_t)idx < instance->nservers);
            new_srv = instance->servers + idx;
            lcb_packet_retry(new_srv, pkt);
        }
        break;
    }

    default:
        lcb_error_handler(instance, LCB_PROTOCOL_ERROR, NULL);
        if (bytes != c->input.read_head) {
            free(bytes);
        }
        return -1;
    }

    if (bytes != c->input.read_head) {
        free(bytes);
    } else {
        ringbuffer_consumed(&c->input, nbytes);
    }
    return 1;
}


static int do_read_data(lcb_server_t c, int allow_read)
{
    /*
    ** Loop and try to parse the data... We don't want to lock up the
    ** event loop completely, so set a max number of packets to process
    ** before backing off..
    */
    lcb_size_t processed = 0;
    /* @todo Make the backoff number tunable from the instance */
    const lcb_size_t operations_per_call = 1000;
    int rv = 0;
    /*
    ** The timers isn't supposed to be _that_ accurate.. it's better
    ** to shave off system calls :)
    */
    hrtime_t stop = gethrtime();

    while (processed < operations_per_call) {
        rv = parse_single(c, stop);
        if (rv == -1) {
            return -1;
        } else if (rv == 0) {
            /* need more data */
            if (allow_read && (rv = do_fill_input_buffer(c)) < 1) {
                /* error or would block ;) */
                return rv;
            }
            break;
        } else {
            ++processed;
        }
    }

    return 0;
}

static int do_send_data(lcb_server_t c)
{
    while (lcb_packet_queue_not_empty(c->output)) {
        lcb_ssize_t nw;
        lcb_server_iov_fill(c);
        nw = c->instance->io->v.v0.sendv(c->instance->io, c->sock, c->iov, c->niov);
        if (nw == -1) {
            switch (c->instance->io->v.v0.error) {
            case EINTR:
                /* retry */
                break;
            case EWOULDBLOCK:
#ifdef USE_EAGAIN
            case EAGAIN:
#endif
                return 0;
            default:
                lcb_failout_server(c, LCB_NETWORK_ERROR);
                return -1;
            }
        } else if (nw > 0) {
            lcb_server_iov_consume(c, (lcb_size_t)nw);
            lcb_update_server_timer(c);
        }
    }

    return 0;
}

LIBCOUCHBASE_API
void lcb_flush_buffers(lcb_t instance, const void *cookie)
{
    lcb_size_t ii;
    for (ii = 0; ii < instance->nservers; ++ii) {
        lcb_server_t c = instance->servers + ii;
        if (c->connected) {
            lcb_server_event_handler(c->sock, LCB_READ_EVENT | LCB_WRITE_EVENT, c);
        }
    }
    (void)cookie;
}

void lcb_server_event_handler(lcb_socket_t sock, short which, void *arg)
{
    lcb_server_t c = arg;
    (void)sock;

    if (which & LCB_WRITE_EVENT) {
        if (do_send_data(c) != 0) {
            /* TODO stash error message somewhere
             * "Failed to send to the connection to \"%s:%s\"", c->hostname, c->port */
            lcb_failout_server(c, LCB_NETWORK_ERROR);
            return;
        }
    }

    if (which & LCB_READ_EVENT || c->input.nbytes) {
        if (do_read_data(c, which & LCB_READ_EVENT) != 0) {
            /* TODO stash error message somewhere
             * "Failed to read from connection to \"%s:%s\"", c->hostname, c->port */
            lcb_failout_server(c, LCB_NETWORK_ERROR);
            return;
        }
    }

    which = LCB_READ_EVENT;
    if (lcb_packet_queue_not_empty(c->output) || c->input.nbytes) {
        /**
         * If we have data in the read buffer, we need to make sure the event
         * still gets delivered despite nothing being in the actual TCP read
         * buffer. Since writes will typically not block, we hinge the next
         * read operation on write-ability
         */
        which |= LCB_WRITE_EVENT;
    }

    c->instance->io->v.v0.update_event(c->instance->io, c->sock,
                                       c->event, which, c,
                                       lcb_server_event_handler);

    lcb_maybe_breakout(c->instance);

    /* Make it known that this was a success. */
    lcb_error_handler(c->instance, LCB_SUCCESS, NULL);
}

int lcb_has_data_in_buffers(lcb_t instance)
{
    lcb_size_t ii;

    if (hashset_num_items(instance->http_requests)) {
        return 1;
    }
    for (ii = 0; ii < instance->nservers; ++ii) {
        lcb_server_t c = instance->servers + ii;
        if (lcb_packet_queue_not_empty(c->log) || c->input.nbytes
                || (c->http_requests && hashset_num_items(c->http_requests))) {
            return 1;
        } else {
            assert(lcb_packet_queue_not_empty(c->output) == 0);
            assert(lcb_packet_queue_not_empty(c->pending) == 0);
        }
    }
    return 0;
}

void lcb_maybe_breakout(lcb_t instance)
{
    if (instance->wait) {
        if (!lcb_has_data_in_buffers(instance)
                && hashset_num_items(instance->timers) == 0) {
            instance->wait = 0;
            instance->io->v.v0.stop_event_loop(instance->io);
        }
    }
}
