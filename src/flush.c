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

#include "internal.h"

LIBCOUCHBASE_API
lcb_error_t lcb_flush(lcb_t instance, const void *command_cookie,
                      lcb_size_t num, const lcb_flush_cmd_t *const *commands)
{
    lcb_size_t count;
    lcb_error_t rc;
    lcb_packet_t pkt = NULL;

    /* we need a vbucket config before we can start getting data.. */
    if (instance->vbucket_config == NULL) {
        switch (instance->type) {
        case LCB_TYPE_CLUSTER:
            return lcb_synchandler_return(instance, LCB_EBADHANDLE);
        case LCB_TYPE_BUCKET:
        default:
            return lcb_synchandler_return(instance, LCB_CLIENT_ETMPFAIL);
        }
    }

    for (count = 0; count < num; ++count) {
        lcb_server_t server;
        protocol_binary_request_no_extras req;
        lcb_size_t ii;

        if (commands[count]->version != 0) {
            return lcb_synchandler_return(instance, LCB_EINVAL);
        }

        memset(&req, 0, sizeof(req));
        req.message.header.request.magic = PROTOCOL_BINARY_REQ;
        req.message.header.request.opcode = PROTOCOL_BINARY_CMD_FLUSH;
        req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
        req.message.header.request.opaque = ++instance->seqno;

        for (ii = 0; ii < instance->nservers; ++ii) {
            server = instance->servers + ii;
            TRACE_FLUSH_BEGIN(&req, server->authority);
            rc = lcb_packet_start(server, &pkt, command_cookie,
                                  &req.message.header, req.bytes,
                                  sizeof(req.bytes));
            if (rc != LCB_SUCCESS) {
                return lcb_synchandler_return(instance, rc);
            }
            lcb_server_send_packets(server);
        }
    }
    return lcb_synchandler_return(instance, LCB_SUCCESS);
}
