/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011-2013 Couchbase, Inc.
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
 * This file contains the functions to operate on libembase_server objects
 *
 * @author Trond Norbye
 * @todo add more documentation
 */

#include "internal.h"

#if 0
void lcb_failout_observe_request(lcb_server_t server,
                                 struct lcb_command_data_st *command_data,
                                 const char *packet,
                                 lcb_size_t npacket,
                                 lcb_error_t err)
{
    lcb_t instance = server->instance;
    protocol_binary_request_header *req = (void *)packet;
    const char *ptr = packet + sizeof(req->bytes);
    const char *end = packet + npacket;
    lcb_observe_resp_t resp;

    memset(&resp, 0, sizeof(resp));
    resp.v.v0.status = LCB_OBSERVE_MAX;
    while (ptr < end) {
        lcb_uint16_t nkey;

        /* ignore vbucket */
        ptr += sizeof(lcb_uint16_t);
        nkey = ntohs(*(lcb_uint16_t *)ptr);

        ptr += sizeof(lcb_uint16_t);
        resp.v.v0.key = ptr;
        resp.v.v0.nkey = nkey;

        TRACE_OBSERVE_PROGRESS(req->request.opaque, ntohs(req->request.vbucket),
                               req->request.opcode, err, &resp);
        instance->callbacks.observe(instance, command_data->cookie,
                                    err, &resp);
        ptr += nkey;
    }
    if (lcb_lookup_server_with_command(instance, CMD_OBSERVE,
                                       req->request.opaque, server) < 0) {
        TRACE_OBSERVE_END(req->request.opaque, ntohs(req->request.vbucket),
                          req->request.opcode, err);
        resp.v.v0.key = NULL;
        resp.v.v0.nkey = 0;
        instance->callbacks.observe(instance, command_data->cookie, err, &resp);
    }
}
#endif

static lcb_storage_t map_store_cmd(protocol_binary_command cmd)
{
    switch (cmd) {
    case PROTOCOL_BINARY_CMD_ADD:
        return LCB_ADD;
    case PROTOCOL_BINARY_CMD_REPLACE:
        return LCB_REPLACE;
    case PROTOCOL_BINARY_CMD_SET:
        return LCB_SET;
    case PROTOCOL_BINARY_CMD_APPEND:
        return LCB_APPEND;
    case PROTOCOL_BINARY_CMD_PREPEND:
        return LCB_PREPEND;
    default:
        /* it must be impossible */
        abort();
    }
}

/* notify user that the command has been terminated with given error
 * code
 */
static lcb_error_t lcb_purge_packet(lcb_server_t server,
                                    lcb_packet_t packet,
                                    lcb_error_t error)
{
    lcb_t instance = server->instance;
    union {
        lcb_get_resp_t get;
        lcb_store_resp_t store;
        lcb_remove_resp_t remove;
        lcb_touch_resp_t touch;
        lcb_unlock_resp_t unlock;
        lcb_arithmetic_resp_t arithmetic;
        lcb_flush_resp_t flush;
        lcb_server_stat_resp_t stats;
        lcb_server_version_resp_t versions;
        lcb_verbosity_resp_t verbosity;
        lcb_observe_resp_t observe;
    } resp;
    char *key;
    lcb_size_t nkey;
    protocol_binary_request_header *req = (void *)packet->payload->bytes;

    nkey = ntohs(req->request.keylen);
    key = packet->payload->bytes + sizeof(req->bytes) + req->request.extlen;

    memset(&resp, 0, sizeof(resp));
    switch (packet->opcode) {
    case PROTOCOL_BINARY_CMD_NOOP:
        break;
    case PROTOCOL_BINARY_CMD_GAT:
    case PROTOCOL_BINARY_CMD_GATQ:
    case PROTOCOL_BINARY_CMD_GET:
    case PROTOCOL_BINARY_CMD_GETQ:
        resp.get.v.v0.key = key;
        resp.get.v.v0.nkey = nkey;
        TRACE_GET_END(packet->opaque, packet->vbucket, packet->opcode, error, &resp.get);
        instance->callbacks.get(instance, packet->cookie, error, &resp.get);
        break;
    case PROTOCOL_BINARY_CMD_ADD:
    case PROTOCOL_BINARY_CMD_REPLACE:
    case PROTOCOL_BINARY_CMD_SET:
    case PROTOCOL_BINARY_CMD_APPEND:
    case PROTOCOL_BINARY_CMD_PREPEND:
        resp.store.v.v0.key = key;
        resp.store.v.v0.nkey = nkey;
        TRACE_STORE_END(packet->opaque, packet->vbucket, packet->opcode, error, &resp.store);
        instance->callbacks.store(instance, packet->cookie, map_store_cmd(packet->opcode), error, &resp.store);
        break;
    case PROTOCOL_BINARY_CMD_DELETE:
        resp.remove.v.v0.key = key;
        resp.remove.v.v0.nkey = nkey;
        TRACE_REMOVE_END(packet->opaque, packet->vbucket, packet->opcode, error, &resp.remove);
        instance->callbacks.remove(instance, packet->cookie, error, &resp.remove);
        break;

    case PROTOCOL_BINARY_CMD_INCREMENT:
    case PROTOCOL_BINARY_CMD_DECREMENT:
        resp.arithmetic.v.v0.key = key;
        resp.arithmetic.v.v0.nkey = nkey;
        TRACE_ARITHMETIC_END(packet->opaque, packet->vbucket, packet->opcode, error, &resp.arithmetic);
        instance->callbacks.arithmetic(instance, packet->cookie, error, &resp.arithmetic);
        break;
    case PROTOCOL_BINARY_CMD_TOUCH:
        resp.touch.v.v0.key = key;
        resp.touch.v.v0.nkey = nkey;
        TRACE_TOUCH_END(packet->opaque, packet->vbucket, packet->opcode, error, &resp.touch);
        instance->callbacks.touch(instance, packet->cookie, error, &resp.touch);
        break;
    case PROTOCOL_BINARY_CMD_FLUSH:
        resp.flush.v.v0.server_endpoint = server->authority;
        TRACE_FLUSH_PROGRESS(packet->opaque, packet->vbucket, packet->opcode, error, &resp.flush);
        instance->callbacks.flush(instance, packet->cookie, error, &resp.flush);
        if (lcb_lookup_server_with_command(instance, PROTOCOL_BINARY_CMD_FLUSH, packet->opaque, server) < 0) {
            resp.flush.v.v0.server_endpoint = NULL;
            TRACE_FLUSH_END(packet->opaque, packet->vbucket, packet->opcode, error);
            instance->callbacks.flush(instance, packet->cookie, error, &resp.flush);
        }
        break;
    case PROTOCOL_BINARY_CMD_STAT:
        resp.stats.v.v0.server_endpoint = server->authority;
        TRACE_STATS_PROGRESS(packet->opaque, packet->vbucket, packet->opcode, error, &resp.stats);
        instance->callbacks.stat(instance, packet->cookie, error, &resp.stats);
        if (lcb_lookup_server_with_command(instance, PROTOCOL_BINARY_CMD_STAT, packet->opaque, server) < 0) {
            resp.stats.v.v0.server_endpoint = NULL;
            TRACE_STATS_END(packet->opaque, packet->vbucket, packet->opcode, error);
            instance->callbacks.stat(instance, packet->cookie, error, &resp.stats);
        }
        break;
    case PROTOCOL_BINARY_CMD_VERBOSITY:
        resp.verbosity.v.v0.server_endpoint = server->authority;
        TRACE_VERBOSITY_END(packet->opaque, packet->vbucket, packet->opcode, error, &resp.verbosity);
        instance->callbacks.verbosity(instance, packet->cookie, error, &resp.verbosity);
        if (lcb_lookup_server_with_command(instance, PROTOCOL_BINARY_CMD_VERBOSITY, packet->opaque, server) < 0) {
            resp.verbosity.v.v0.server_endpoint = NULL;
            TRACE_VERBOSITY_END(packet->opaque, packet->vbucket, packet->opcode, error, &resp.verbosity);
            instance->callbacks.verbosity(instance, packet->cookie, error, &resp.verbosity);
        }
        break;
    case PROTOCOL_BINARY_CMD_VERSION:
        resp.versions.v.v0.server_endpoint = server->authority;
        TRACE_VERSIONS_PROGRESS(packet->opaque, packet->vbucket, packet->opcode, error, &resp.versions);
        instance->callbacks.version(instance, packet->cookie, error, &resp.versions);
        if (lcb_lookup_server_with_command(instance, PROTOCOL_BINARY_CMD_VERSION, packet->opaque, server) < 0) {
            resp.versions.v.v0.server_endpoint = NULL;
            TRACE_VERSIONS_END(packet->opaque, packet->vbucket, packet->opcode, error);
            instance->callbacks.version(instance, packet->cookie, error, &resp.versions);
        }
        break;
    case CMD_OBSERVE:
        resp.observe.v.v0.status = LCB_OBSERVE_MAX;
        TRACE_OBSERVE_END(packet->opaque, packet->vbucket, packet->opcode, error);
        instance->callbacks.observe(instance, packet->cookie, error, &resp.observe);
        /* FIXME */
        /*            lcb_failout_observe_request(server, &ct, packet,*/
        /*                                        sizeof(req.bytes) + ntohl(req.request.bodylen),*/
        /*                                        error);*/
        break;
    case PROTOCOL_BINARY_CMD_SASL_LIST_MECHS:
    case PROTOCOL_BINARY_CMD_SASL_AUTH:
    case PROTOCOL_BINARY_CMD_SASL_STEP:
        /* no need to notify user about these commands */
        break;
    default:
        return LCB_CLIENT_UNKNOWN_COMMAND;
    }
    return LCB_SUCCESS;
}

/* release all packets leaving in the server log, and call user
 * callback with error code given to notify about premature
 * termination
 */
void lcb_purge_single_server(lcb_server_t server,
                             lcb_error_t error)
{
    lcb_t instance = server->instance;
    hrtime_t now = gethrtime();
    int should_switch_to_backup_node = 0;

    while (lcb_packet_queue_not_empty(server->output)) {
        lcb_packet_queue_remove(server->output->next);
    }
    while (lcb_packet_queue_not_empty(server->pending)) {
        lcb_packet_queue_remove(server->pending->next);
    }
    while (lcb_packet_queue_not_empty(server->log)) {
        lcb_packet_t pkt = server->log->next;

        if (server->instance->histogram) {
            lcb_record_metrics(server->instance, now - pkt->start, pkt->opcode);
        }
        lcb_purge_packet(server, pkt, error);
        lcb_packet_queue_remove(pkt);
        if (server->is_config_node) {
            instance->weird_things++;
            if (instance->weird_things >= instance->weird_things_threshold) {
                should_switch_to_backup_node = 1;
            }
        }
    }
    if (should_switch_to_backup_node) {
        lcb_switch_to_backup_node(instance, LCB_NETWORK_ERROR,
                                  "Config connection considered stale. "
                                  "Reconnection forced");
    }
    lcb_maybe_breakout(instance);
}

lcb_error_t lcb_failout_server(lcb_server_t server,
                               lcb_error_t error)
{
    lcb_purge_single_server(server, error);

    server->connected = 0;

    if (server->sock != INVALID_SOCKET) {
        server->instance->io->v.v0.delete_event(server->instance->io, server->sock,
                                                server->event);
        server->instance->io->v.v0.close(server->instance->io, server->sock);
        server->sock = INVALID_SOCKET;
    }

    return error;
}

static void purge_http_request(lcb_server_t server)
{
    lcb_size_t ii;
    lcb_http_request_t *htitems;
    lcb_size_t curix;
    lcb_size_t nitems = hashset_num_items(server->http_requests);
    htitems = malloc(nitems * sizeof(*htitems));

    for (curix = 0, ii = 0; ii < server->http_requests->capacity; ii++) {
        if (server->http_requests->items[ii] > 1) {
            htitems[curix] = (lcb_http_request_t)server->http_requests->items[ii];
            curix++;
        }
    }

    assert(curix);

    for (ii = 0; ii < curix; ii++) {
        lcb_http_request_finish(server->instance,
                                server,
                                htitems[ii],
                                LCB_CLIENT_ETMPFAIL);
    }

    free(htitems);
}

/**
 * Release all allocated resources for this server instance
 * @param server the server to destroy
 */
void lcb_server_destroy(lcb_server_t server)
{
    /* Cancel all pending commands */
    lcb_purge_single_server(server, LCB_CLIENT_ETMPFAIL);
    if (server->sasl_conn != NULL) {
        sasl_dispose(&server->sasl_conn);
        server->sasl_conn = NULL;
    }

    free(server->iov);
    server->iov = NULL;

    /* Delete the event structure itself */
    if (server->event) {
        server->instance->io->v.v0.destroy_event(server->instance->io,
                                                 server->event);
    }

    if (server->timer) {
        server->instance->io->v.v0.destroy_timer(server->instance->io,
                                                 server->timer);
    }

    if (server->sock != INVALID_SOCKET) {
        server->instance->io->v.v0.close(server->instance->io, server->sock);
    }

    free(server->rest_api_server);
    free(server->couch_api_base);
    free(server->hostname);
    free(server->authority);
    lcb_packet_queue_destroy(server->output);
    lcb_packet_queue_destroy(server->log);
    lcb_packet_queue_destroy(server->pending);
    ringbuffer_destruct(&server->input);

    if (server->http_requests) {
        if (hashset_num_items(server->http_requests)) {
            purge_http_request(server);
        }
        hashset_destroy(server->http_requests);
    }
    memset(server, 0xff, sizeof(*server));
}


/**
 * Get the name of the local endpoint
 * @param sock The socket to query the name for
 * @param buffer The destination buffer
 * @param buffz The size of the output buffer
 * @return 1 if success, 0 otherwise
 */
static int get_local_address(lcb_socket_t sock,
                             char *buffer,
                             lcb_size_t bufsz)
{
    char h[NI_MAXHOST];
    char p[NI_MAXSERV];
    struct sockaddr_storage saddr;
    socklen_t salen = sizeof(saddr);

    if ((getsockname(sock, (struct sockaddr *)&saddr, &salen) < 0) ||
            (getnameinfo((struct sockaddr *)&saddr, salen, h, sizeof(h),
                         p, sizeof(p), NI_NUMERICHOST | NI_NUMERICSERV) < 0) ||
            (snprintf(buffer, bufsz, "%s;%s", h, p) < 0)) {
        return 0;
    }

    return 1;
}

/**
 * Get the name of the remote enpoint
 * @param sock The socket to query the name for
 * @param buffer The destination buffer
 * @param buffz The size of the output buffer
 * @return 1 if success, 0 otherwise
 */
static int get_remote_address(lcb_socket_t sock,
                              char *buffer,
                              lcb_size_t bufsz)
{
    char h[NI_MAXHOST];
    char p[NI_MAXSERV];
    struct sockaddr_storage saddr;
    socklen_t salen = sizeof(saddr);

    if ((getpeername(sock, (struct sockaddr *)&saddr, &salen) < 0) ||
            (getnameinfo((struct sockaddr *)&saddr, salen, h, sizeof(h),
                         p, sizeof(p), NI_NUMERICHOST | NI_NUMERICSERV) < 0) ||
            (snprintf(buffer, bufsz, "%s;%s", h, p) < 0)) {
        return 0;
    }

    return 1;
}

/**
 * Start the SASL auth for a given server.
 *
 * Neither the server or the client supports anything else than
 * plain SASL authentication, so lets just try it. If someone change
 * the list of supported SASL mechanisms they need to update the client
 * anyway.
 *
 * @param server the server object to auth agains
 */
static void start_sasl_auth_server(lcb_server_t server)
{
    /* There is no point of calling sasl_list_mechs on the server
     * because we know that the server will reply with "PLAIN"
     * it means it's just an extra ping-pong to the server
     * adding latency.. Let's do the SASL_AUTH immediately
     */
    const char *data;
    const char *chosenmech;
    char *mechlist;
    unsigned int len;
    lcb_packet_t pkt = NULL;
    lcb_error_t rc;
    protocol_binary_request_no_extras req;
    lcb_size_t keylen;
    lcb_size_t bodysize;

    mechlist = strdup("PLAIN");
    if (mechlist == NULL) {
        lcb_error_handler(server->instance, LCB_CLIENT_ENOMEM, NULL);
        return;
    }
    if (sasl_client_start(server->sasl_conn, mechlist,
                          NULL, &data, &len, &chosenmech) != SASL_OK) {
        free(mechlist);
        lcb_error_handler(server->instance, LCB_AUTH_ERROR,
                          "Unable to start sasl client");
        return;
    }
    free(mechlist);

    keylen = strlen(chosenmech);
    bodysize = keylen + len;

    memset(&req, 0, sizeof(req));
    req.message.header.request.magic = PROTOCOL_BINARY_REQ;
    req.message.header.request.opcode = PROTOCOL_BINARY_CMD_SASL_AUTH;
    req.message.header.request.keylen = ntohs((lcb_uint16_t)keylen);
    req.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    req.message.header.request.bodylen = ntohl((lcb_uint32_t)(bodysize));

    server->connected = 1; /* HACK write packet into output buffer */
    rc = lcb_packet_start(server, &pkt, NULL, &req.message.header,
                          req.bytes, sizeof(req.bytes));
    if (rc != LCB_SUCCESS) {
        server->connected = 0;
        lcb_error_handler(server->instance, LCB_CLIENT_ENOMEM,
                          "cannot schedule SASL packet");
        /* FIXME handle error condition in caller */
        return;
    }
    rc = lcb_packet_write(pkt, chosenmech, keylen);
    if (rc != LCB_SUCCESS) {
        server->connected = 0;
        lcb_error_handler(server->instance, LCB_CLIENT_ENOMEM,
                          "cannot schedule SASL packet");
        /* FIXME handle error condition in caller */
        return;
    }
    rc = lcb_packet_write(pkt, data, len);
    if (rc != LCB_SUCCESS) {
        server->connected = 0;
        lcb_error_handler(server->instance, LCB_CLIENT_ENOMEM,
                          "cannot schedule SASL packet");
        /* FIXME handle error condition in caller */
        return;
    }
    server->connected = 0;

    /* put data in the buffer and subscribe to write event.. */
    server->instance->io->v.v0.update_event(server->instance->io, server->sock,
                                            server->event, LCB_WRITE_EVENT,
                                            server, lcb_server_event_handler);
}

void lcb_server_connected(lcb_server_t server)
{
    server->connected = 1;

    while (lcb_packet_queue_not_empty(server->pending)) {
        lcb_packet_queue_push(server->output,
                              lcb_packet_queue_pop(server->pending));
    }
    /* we are going to send data to the server */
    server->instance->io->v.v0.update_event(server->instance->io, server->sock,
                                            server->event, LCB_WRITE_EVENT,
                                            server, lcb_server_event_handler);
    /* FIXME previous implementation was setting READ event handler in
     * case it hasn't pending data */
}

static void socket_connected(lcb_server_t server)
{
    char local[NI_MAXHOST + NI_MAXSERV + 2];
    char remote[NI_MAXHOST + NI_MAXSERV + 2];
    int sasl_in_progress = (server->sasl_conn != NULL);

    get_local_address(server->sock, local, sizeof(local));
    get_remote_address(server->sock, remote, sizeof(remote));

    if (!sasl_in_progress) {
        assert(sasl_client_new("couchbase", server->hostname, local, remote,
                               server->instance->sasl.callbacks, 0,
                               &server->sasl_conn) == SASL_OK);
    }

    if (vbucket_config_get_user(server->instance->vbucket_config) == NULL) {
        /* No SASL AUTH needed */
        lcb_server_connected(server);
    } else {
        if (!sasl_in_progress) {
            start_sasl_auth_server(server);
        }
    }
}

lcb_error_t lcb_server_initialize(lcb_server_t server, int servernum)
{
    /* Initialize all members */
    char *p;
    lcb_error_t rc;
    const char *n = vbucket_config_get_server(server->instance->vbucket_config,
                                              servernum);
    server->index = servernum;
    server->authority = strdup(n);
    server->hostname = strdup(n);
    if (server->authority == NULL || server->hostname == NULL) {
        lcb_server_destroy(server);
        return LCB_CLIENT_ENOMEM;
    }
    p = strchr(server->hostname, ':');
    *p = '\0';
    server->port = p + 1;

    server->is_config_node = vbucket_config_is_config_node(server->instance->vbucket_config,
                                                           servernum);
    n = vbucket_config_get_couch_api_base(server->instance->vbucket_config,
                                          servernum);
    if (n != NULL) {
        server->couch_api_base = strdup(n);
        if (server->couch_api_base == NULL) {
            lcb_server_destroy(server);
            return LCB_CLIENT_ENOMEM;
        }
    }
    server->http_requests = hashset_create();
    if (server->http_requests == NULL) {
        lcb_server_destroy(server);
        return LCB_CLIENT_ENOMEM;
    }
    n = vbucket_config_get_rest_api_server(server->instance->vbucket_config,
                                           servernum);
    server->rest_api_server = strdup(n);
    if (server->rest_api_server == NULL) {
        lcb_server_destroy(server);
        return LCB_CLIENT_ENOMEM;
    }
    server->event = server->instance->io->v.v0.create_event(server->instance->io);
    if (server->event == NULL) {
        lcb_server_destroy(server);
        return LCB_CLIENT_ENOMEM;
    }
    server->timer = server->instance->io->v.v0.create_timer(server->instance->io);
    if (server->timer == NULL) {
        lcb_server_destroy(server);
        return LCB_CLIENT_ENOMEM;
    }
    rc = lcb_packet_queue_create(&server->log);
    if (rc != LCB_SUCCESS) {
        lcb_server_destroy(server);
        return rc;
    }
    rc = lcb_packet_queue_create(&server->pending);
    if (rc != LCB_SUCCESS) {
        lcb_server_destroy(server);
        return rc;
    }
    rc = lcb_packet_queue_create(&server->output);
    if (rc != LCB_SUCCESS) {
        lcb_server_destroy(server);
        return rc;
    }

    server->niov = 0;
    /* FIXME move IOV_MAX to the plugin */
    server->iov = calloc(IOV_MAX, sizeof(struct lcb_iovec_st));
    if (server->iov == NULL) {
        lcb_server_destroy(server);
        return LCB_CLIENT_ENOMEM;
    }
    server->sock = INVALID_SOCKET;
    server->sasl_conn = NULL;
    return LCB_SUCCESS;
}

lcb_error_t lcb_server_iov_fill(lcb_server_t server)
{
    lcb_packet_t root = server->output;
    lcb_packet_t pkt = root->next;

    server->niov = 0;
    while (pkt != root && server->niov < IOV_MAX) {
        struct lcb_iovec_st *io = server->iov + server->niov;
        io->iov_base = pkt->payload->bytes + pkt->payload->nread;
        io->iov_len = pkt->payload->nbytes - pkt->payload->nread;
        server->niov++;
        pkt = pkt->next;
    }
    return LCB_SUCCESS;
}

lcb_error_t lcb_server_iov_consume(lcb_server_t server, lcb_size_t nbytes)
{
    lcb_packet_t root = server->output;
    lcb_packet_t pkt;

    while (nbytes && lcb_packet_queue_not_empty(root)) {
        pkt = root->next;
        if (nbytes >= pkt->payload->nbytes) {
            nbytes -= pkt->payload->nbytes;
            lcb_packet_queue_remove(server->output->next);
        } else {
            /* partially sent packet */
            pkt->payload->nread = nbytes;
        }
    }
    return LCB_SUCCESS;
}

static void lcb_server_connect_handler(lcb_error_t status, void *arg)
{
    lcb_server_t server = arg;
    lcb_io_opt_t io = server->instance->io;

    io->v.v0.update_event(io, server->sock, server->event,
                          LCB_RW_EVENT, server,
                          lcb_server_event_handler);

    if (status == LCB_SUCCESS) {
        socket_connected(server);
    } else {
        lcb_failout_server(server, LCB_CONNECT_ERROR);
    }
}

void lcb_server_send_packets(lcb_server_t server)
{
    lcb_io_opt_t io = server->instance->io;

    if (lcb_packet_queue_not_empty(server->pending) || lcb_packet_queue_not_empty(server->output)) {
        if (server->connected) {
            io->v.v0.update_event(io, server->sock, server->event,
                                  LCB_RW_EVENT, server,
                                  lcb_server_event_handler);
        } else {
            if (server->sock == INVALID_SOCKET) {
                /* Try to get a socket.. */
                server->sock = io->v.v0.socket(io, server->hostname, server->port);
            }
            if (server->sock == INVALID_SOCKET) {
                lcb_failout_server(server, LCB_NETWORK_ERROR);
                return;
            }
            io->v.v0.connect_peer(io, server->sock, server->event,
                                  server, lcb_server_connect_handler);
        }
    }
}

/*
 * Drop all packets with sequence number less than specified.
 *
 * The packets are considered as stale and the caller will receive
 * appropriate error code in the operation callback.
 *
 * Returns 0 on success
 */
int lcb_server_purge_implicit_responses(lcb_server_t server,
                                        lcb_uint32_t seqno,
                                        hrtime_t end)
{
    lcb_packet_t root = server->log;
    lcb_packet_t pkt = root->next;

    while (pkt != root && pkt->opaque < seqno) {
        if (server->instance->histogram) {
            lcb_record_metrics(server->instance, end - pkt->start, pkt->opcode);
        }
        switch (pkt->opcode) {
        case PROTOCOL_BINARY_CMD_GATQ:
        case PROTOCOL_BINARY_CMD_GETQ:
            lcb_purge_packet(server, pkt, LCB_KEY_ENOENT);
            break;
        case PROTOCOL_BINARY_CMD_NOOP:
        case PROTOCOL_BINARY_CMD_SASL_AUTH:
            break;
        case CMD_OBSERVE:
            lcb_purge_packet(server, pkt, LCB_SERVER_BUG);
            /*            lcb_failout_observe_request(c, &ct, packet,*/
            /*                                        sizeof(req.bytes) + ntohl(req.request.bodylen),*/
            /*                                        LCB_SERVER_BUG);*/
        default: {
            char errinfo[128] = { '\0' };
            snprintf(errinfo, 128, "Unknown implicit send message op=0x%02x", pkt->opcode);
            lcb_error_handler(server->instance, LCB_EINTERNAL, errinfo);
            return -1;
        }
        }
        lcb_packet_queue_remove(pkt);
        pkt = root->next;
    }

    return 0;
}
