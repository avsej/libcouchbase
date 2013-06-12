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
 * This file contains the protocol handling and callback dispatching for
 * commands.
 *
 * @author Trond Norbye
 * @todo add more documentation
 */
#include "internal.h"

static void swallow_command(lcb_server_t *c,
                            protocol_binary_response_header *header,
                            int was_connected)
{
    lcb_size_t nr;
    protocol_binary_request_header req;
    if (was_connected &&
            (header->response.opcode != PROTOCOL_BINARY_CMD_STAT ||
             header->response.keylen == 0)) {
        nr = ringbuffer_read(&c->cmd_log, req.bytes, sizeof(req));
        assert(nr == sizeof(req));
        ringbuffer_consumed(&c->cmd_log, ntohl(req.request.bodylen));
        ringbuffer_consumed(&c->output_cookies,
                            sizeof(struct lcb_command_data_st));
    }
}

int lcb_proto_parse_single(lcb_server_t *c, hrtime_t stop)
{
    protocol_binary_request_header req;
    protocol_binary_response_header header;
    lcb_size_t nr;
    char *packet;
    lcb_size_t packetsize;
    struct lcb_command_data_st ct;

    if (ringbuffer_ensure_alignment(&c->input) != 0) {
        lcb_error_handler(c->instance, LCB_EINTERNAL,
                          NULL);
        return -1;
    }

    nr = ringbuffer_peek(&c->input, header.bytes, sizeof(header));
    if (nr < sizeof(header)) {
        return 0;
    }

    packetsize = ntohl(header.response.bodylen) + (lcb_uint32_t)sizeof(header);
    if (c->input.nbytes < packetsize) {
        return 0;
    }

    /* Is it already timed out? */
    nr = ringbuffer_peek(&c->cmd_log, req.bytes, sizeof(req));
    if (nr < sizeof(req) || /* the command log doesn't know about it */
            (header.response.opaque < req.request.opaque &&
             header.response.opaque > 0)) { /* sasl comes with zero opaque */
        /* already processed. */
        ringbuffer_consumed(&c->input, packetsize);
        return 1;
    }

    packet = c->input.read_head;
    /* we have everything! */

    if (!ringbuffer_is_continous(&c->input, RINGBUFFER_READ,
                                 packetsize)) {
        /* The buffer isn't continous.. for now just copy it out and
        ** operate on the copy ;)
        */
        if ((packet = malloc(packetsize)) == NULL) {
            lcb_error_handler(c->instance, LCB_CLIENT_ENOMEM, NULL);
            return -1;
        }
        nr = ringbuffer_read(&c->input, packet, packetsize);
        if (nr != packetsize) {
            lcb_error_handler(c->instance, LCB_EINTERNAL,
                              NULL);
            free(packet);
            return -1;
        }
    }

    nr = ringbuffer_peek(&c->output_cookies, &ct, sizeof(ct));
    if (nr != sizeof(ct)) {
        lcb_error_handler(c->instance, LCB_EINTERNAL,
                          NULL);
        if (packet != c->input.read_head) {
            free(packet);
        }
        return -1;
    }
    ct.vbucket = ntohs(req.request.vbucket);

    switch (header.response.magic) {
    case PROTOCOL_BINARY_REQ:
        /*
         * The only way to get request packets is if someone started
         * to send us TAP requests, and we don't support that anymore
         */
        lcb_error_handler(c->instance, LCB_EINTERNAL,
                          "Protocol error. someone sent us a command!");
        return -1;
    case PROTOCOL_BINARY_RES: {
        int was_connected = c->connection_ready;
        if (lcb_server_purge_implicit_responses(c, header.response.opaque, stop, 0) != 0) {
            if (packet != c->input.read_head) {
                free(packet);
            }
            return -1;
        }

        if (c->instance->histogram) {
            lcb_record_metrics(c->instance, stop - ct.start,
                               header.response.opcode);
        }

        if (ntohs(header.response.status) != PROTOCOL_BINARY_RESPONSE_NOT_MY_VBUCKET
                || header.response.opcode == CMD_GET_REPLICA
                || header.response.opcode == CMD_OBSERVE) {
            if (lcb_dispatch_response(c, &ct, (void *)packet) == -1) {
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

            /* keep command and cookie until we get complete STAT response */
            swallow_command(c, &header, was_connected);

        } else {
            int idx;
            char *body;
            lcb_size_t nbody;
            lcb_server_t *new_srv;

            if (c->instance->compat.type == LCB_CACHED_CONFIG) {
                lcb_schedule_config_cache_refresh(c->instance);
            }

            /* re-schedule command to new server */
            idx = vbucket_found_incorrect_master(c->instance->vbucket_config,
                                                 ntohs(req.request.vbucket),
                                                 (int)c->index);

            if (idx == -1) {
                swallow_command(c, &header, was_connected);
                break;
            }

            assert((lcb_size_t)idx < c->instance->nservers);
            new_srv = c->instance->servers + idx;

            nr = ringbuffer_read(&c->cmd_log, req.bytes, sizeof(req));
            assert(nr == sizeof(req));

            req.request.opaque = ++c->instance->seqno;
            nbody = ntohl(req.request.bodylen);
            body = malloc(nbody);
            if (body == NULL) {
                lcb_error_handler(c->instance, LCB_CLIENT_ENOMEM, NULL);
                return -1;
            }
            nr = ringbuffer_read(&c->cmd_log, body, nbody);
            assert(nr == nbody);
            nr = ringbuffer_read(&c->output_cookies, &ct, sizeof(ct));
            assert(nr == sizeof(ct));
            /* Preserve the cookie and reset timestamp for the command. This
             * means that the library will retry the command until it will
             * get code different from LCB_NOT_MY_VBUCKET */
            ct.start = gethrtime();
            lcb_server_retry_packet(new_srv, &ct, &req, sizeof(req));
            /* FIXME dtrace instrumentation */
            lcb_server_write_packet(new_srv, body, nbody);
            lcb_server_end_packet(new_srv);
            lcb_server_send_packets(new_srv);
            free(body);
        }
        break;
    }

    default:
        lcb_error_handler(c->instance,
                          LCB_PROTOCOL_ERROR,
                          NULL);
        if (packet != c->input.read_head) {
            free(packet);
        }
        return -1;
    }

    if (packet != c->input.read_head) {
        free(packet);
    } else {
        ringbuffer_consumed(&c->input, packetsize);
    }
    return 1;
}
