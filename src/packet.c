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
 * This file contains the functions to operate on the packets
 */

#include "internal.h"

lcb_error_t lcb_packet_queue_create(lcb_packet_t *queue)
{
    lcb_error_t rc;
    lcb_packet_t qq;

    rc = lcb_packet_create(&qq);
    if (rc != LCB_SUCCESS) {
        return rc;
    }
    *queue = qq;
    return lcb_packet_queue_init(qq);
}

void lcb_packet_queue_destroy(lcb_packet_t queue)
{
    free(queue);
}

lcb_error_t lcb_packet_queue_init(lcb_packet_t queue)
{
    memset(queue, 0, sizeof(struct lcb_packet_st));
    queue->next = queue;
    queue->prev = queue;
    return LCB_SUCCESS;
}

int lcb_packet_queue_not_empty(lcb_packet_t queue)
{
    return queue != NULL && (queue->next != queue || queue->prev != queue);
}

lcb_error_t lcb_packet_queue_push(lcb_packet_t queue, lcb_packet_t operation)
{
    operation->next = queue;
    operation->prev = queue->prev;
    queue->prev->next = operation;
    queue->prev = operation;
    return LCB_SUCCESS;
}

lcb_packet_t lcb_packet_queue_peek(lcb_packet_t queue)
{
    return queue->next;
}

lcb_packet_t lcb_packet_queue_pop(lcb_packet_t queue)
{
    lcb_packet_t ret = NULL;

    if (lcb_packet_queue_not_empty(queue)) {
        ret = queue->next;
        queue->next = ret->next;
        ret->next->prev = ret->prev;
        ret->next = ret->prev = NULL;
    }
    return ret;
}

lcb_error_t lcb_packet_create(lcb_packet_t *packet)
{
    *packet = calloc(1, sizeof(struct lcb_packet_st));
    if (*packet == NULL) {
        return LCB_CLIENT_ENOMEM;
    }
    return LCB_SUCCESS;
}

void lcb_packet_destroy(lcb_packet_t packet)
{
    free(packet);
}

lcb_error_t lcb_packet_queue_remove(lcb_packet_t packet)
{
    if (packet->prev && packet->next) {
        packet->next->prev = packet->prev;
        packet->prev->next = packet->next;
        packet->next = packet->prev = NULL;
        buffer_destroy(packet->payload);
        lcb_packet_destroy(packet);
        return LCB_SUCCESS;
    } else {
        return LCB_EINVAL;
    }
}

lcb_error_t lcb_packet_write(lcb_packet_t packet,
                             const void *data,
                             lcb_size_t size)
{
    return buffer_write(packet->payload, data, size);
}

/* make shallow copy of the packet. this means that copy will share
 * the payload contents */
static
lcb_error_t lcb_packet_copy(lcb_packet_t *dst, lcb_packet_t src)
{
    lcb_error_t rc;
    lcb_packet_t pkt = NULL;

    rc = lcb_packet_create(&pkt);
    if (rc != LCB_SUCCESS) {
        return rc;
    }
    memcpy(pkt, src, sizeof(struct lcb_packet_st));
    pkt->payload->refcount++;
    *dst = pkt;
    return LCB_SUCCESS;
}

/* register packet in the server log and also push it to outgoing
 * queue. the packet copies will share the same payload buffer */
lcb_error_t lcb_packet_push(lcb_server_t server, lcb_packet_t packet)
{
    lcb_error_t rc;
    lcb_packet_t copy = NULL;

    rc = lcb_packet_copy(&copy, packet);
    if (rc != LCB_SUCCESS) {
        return rc;
    }
    rc = lcb_packet_queue_push(server->log, copy);
    if (rc != LCB_SUCCESS) {
        free(copy);
        return rc;
    }
    if (server->connected) {
        return lcb_packet_queue_push(server->output, packet);
    } else {
        return lcb_packet_queue_push(server->pending, packet);
    }
}

/* create packet structure and prepare it for sending over the wires
 *
 * this function store pointer to the newly created struct to
 * `packet`. Also it the `packet` points to not-NULL value it will use
 * it as a template and will copy `timestamp` from it instead of doing
 * syscall. You are free to inspect/change any fields after.
 */
lcb_error_t lcb_packet_start(lcb_server_t server,
                             lcb_packet_t *packet,
                             const void *cookie,
                             const protocol_binary_request_header *header,
                             const void *data,
                             lcb_size_t size)
{
    lcb_packet_t pkt = NULL;
    lcb_error_t rc;

    rc = lcb_packet_create(&pkt);
    if (rc != LCB_SUCCESS) {
        return rc;
    }
    pkt->payload = calloc(1, sizeof(buffer_t));
    if (pkt->payload == NULL) {
        free(pkt);
        return LCB_CLIENT_ENOMEM;
    }
    pkt->payload->refcount++;
    rc = lcb_packet_write(pkt, data, size);
    if (rc != LCB_SUCCESS) {
        free(pkt);
        return rc;
    }
    /* allow to use packet as template to reduce count of syscalls for
     * multi-ops for example */
    if (*packet == NULL) {
        pkt->start = gethrtime();
    } else {
        pkt->start = (*packet)->start;
    }
    pkt->cookie = cookie;
    pkt->opcode = header->request.opcode;
    pkt->opaque = header->request.opaque;
    pkt->vbucket = ntohs(header->request.vbucket);

    rc = lcb_packet_push(server, pkt);
    if (rc != LCB_SUCCESS) {
        free(pkt);
        return rc;
    }
    *packet = pkt;
    return LCB_SUCCESS;
}

lcb_error_t lcb_packet_retry(lcb_server_t server,
                             lcb_packet_t packet)
{
    protocol_binary_request_header *header = (void *)packet->payload->bytes;
    packet->opaque = ++server->instance->seqno;
    packet->start = gethrtime();
    header->request.opaque = packet->opaque;
    return lcb_packet_push(server, packet);
}
