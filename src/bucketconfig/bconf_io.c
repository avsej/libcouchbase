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

/**
 * This file contains connection routines for the instance
 *
 * @author Mark Nunberg
 */

#include "internal.h"

static void config_v0_handler(lcb_socket_t sock, short which, void *arg);
static void config_v1_read_handler(lcb_sockdata_t *sockptr,
                                            lcb_ssize_t nr);
static void config_v1_write_handler(lcb_sockdata_t *sockptr,
                                            lcb_io_writebuf_t *wbuf,
                                            int status);
static void config_v1_error_handler(lcb_sockdata_t *sockptr);

static void lcb_instance_reset_stream_state(lcb_t instance)
{
    free(instance->vbucket_stream.input.data);
    free(instance->vbucket_stream.chunk.data);
    free(instance->vbucket_stream.header);
    memset(&instance->vbucket_stream, 0, sizeof(instance->vbucket_stream));

    ringbuffer_reset(instance->connection.input);
    ringbuffer_reset(instance->connection.output);
}


void lcb_instance_connerr(lcb_t instance,
                                 lcb_error_t err,
                                 const char *errinfo)
{
    lcb_connection_close(&instance->connection);
    /* We try and see if the connection attempt can be relegated to another
     * REST API entry point. If we can, the following should return something
     * other than -1...
     */

    if (lcb_switch_to_backup_node(instance, err, errinfo) != -1) {
        return;
    }

    /* ..otherwise, we have a currently irrecoverable error. bail out all the
     * pending commands, if applicable and/or deliver a final failure for
     * initial connect attempts.
     */

    if (!instance->vbucket_config) {
        /* Initial connection, no pending commands, and connect timer */
        lcb_connection_delete_timer(&instance->connection);
    } else {
        lcb_size_t ii;
        for (ii = 0; ii < instance->nservers; ++ii) {
            lcb_failout_server(instance->servers + ii, err);
        }
    }

    /* check to see if we can breakout of the event loop. don't hang on REST
     * API connection attempts.
     */
    lcb_maybe_breakout(instance);
}


static void instance_connect_done_handler(lcb_connection_t conn,
                                          lcb_error_t err)
{
    lcb_t instance = conn->instance;

    if (err == LCB_SUCCESS) {
        instance->backup_idx = 0;
        /**
         * Print the URI to the ringbuffer
         */
        ringbuffer_strcat(conn->output, instance->http_uri);
        assert(conn->output->nbytes > 0);

        conn->evinfo.handler = config_v0_handler;
        conn->completion.read = config_v1_read_handler;
        conn->completion.write = config_v1_write_handler;
        conn->completion.error = config_v1_error_handler;

        lcb_sockrw_set_want(conn, LCB_RW_EVENT, 0);
        lcb_sockrw_apply_want(conn);

    } else if (err == LCB_ETIMEDOUT) {
        lcb_error_handler(instance,
                          LCB_CONNECT_ERROR,
                          "Could not connect to server within allotted time");
        instance->timeout.next = 0;
        lcb_maybe_breakout(instance);

    } else {
        lcb_instance_connerr(instance, err, "Couldn't connect");
    }
}

static void setup_current_host(lcb_t instance, const char *host)
{
    char *ptr;
    lcb_connection_t conn = &instance->connection;
    snprintf(conn->host, sizeof(conn->host), "%s", host);
    if ((ptr = strchr(conn->host, ':')) == NULL) {
        strcpy(conn->port, "8091");
    } else {
        *ptr = '\0';
        snprintf(conn->port, sizeof(conn->port), "%s", ptr + 1);
    }
}

lcb_error_t lcb_instance_start_connection(lcb_t instance)
{
    int error;
    char *ptr;
    lcb_connection_t conn = &instance->connection;
    lcb_connection_result_t connres;

    /**
     * First, close the connection, if there's an open socket from a previous
     * one.
     */
    lcb_connection_close(&instance->connection);
    lcb_instance_reset_stream_state(instance);

    conn->on_connect_complete = instance_connect_done_handler;

    do {
        setup_current_host(instance,
                           instance->backup_nodes[instance->backup_idx++]);
        error = lcb_connection_getaddrinfo(conn, 1);

        if (error != 0) {
            /* Ok, we failed to look up that server.. look up the next
             * in the list
             */
            if (instance->backup_nodes[instance->backup_idx] == NULL) {
                char errinfo[1024];
                snprintf(errinfo, sizeof(errinfo),
                         "Failed to look up \"%s:%s\"",
                         conn->host, conn->port);
                return lcb_error_handler(instance,
                                         LCB_UNKNOWN_HOST,
                                         errinfo);
            }
        }
    } while (error != 0);

    instance->last_error = LCB_SUCCESS;

    /* We need to fix the host part... */
    ptr = strstr(instance->http_uri, LCB_LAST_HTTP_HEADER);
    assert(ptr);
    ptr += strlen(LCB_LAST_HTTP_HEADER);
    sprintf(ptr, "Host: %s:%s\r\n\r\n", conn->host, conn->port);

    connres = lcb_connection_start(conn, 1, instance->timeout.usec);
    if (connres == LCB_CONN_ERROR) {
        return lcb_error_handler(instance, LCB_CONNECT_ERROR,
                                 "Couldn't schedule connection");
    }

    if (instance->syncmode == LCB_SYNCHRONOUS) {
        lcb_wait(instance);
    }

    return instance->last_error;
}

/**
 * Callback from libevent when we read from the REST socket
 * @param sock the readable socket
 * @param which what kind of events we may do
 * @param arg pointer to the libcouchbase instance
 */
static void config_v0_handler(lcb_socket_t sock, short which, void *arg)
{
    lcb_t instance = arg;
    lcb_connection_t conn = &instance->connection;
    assert(sock != INVALID_SOCKET);
    lcb_sockrw_status_t status;

    if ((which & LCB_WRITE_EVENT) == LCB_WRITE_EVENT) {

        status = lcb_sockrw_v0_write(conn, conn->output);
        if (status != LCB_SOCKRW_WROTE && status != LCB_SOCKRW_WOULDBLOCK) {
            lcb_error_handler(instance, LCB_NETWORK_ERROR,
                              "Failed to send data to REST server");
            lcb_instance_connerr(instance,
                                 LCB_NETWORK_ERROR,
                                 "Problem with sending data");
            return;
        }

        if (lcb_sockrw_flushed(conn)) {
            lcb_sockrw_set_want(conn, LCB_READ_EVENT, 1);
        }

    }

    if ((which & LCB_READ_EVENT) == 0) {
        return;
    }

    status = lcb_sockrw_v0_slurp(conn, conn->input);
    if (status != LCB_SOCKRW_READ && status != LCB_SOCKRW_WOULDBLOCK) {
        lcb_error_handler(instance, LCB_NETWORK_ERROR,
                          "Failed to send read data from REST server");
        lcb_instance_connerr(instance,
                             LCB_NETWORK_ERROR,
                             "Problem with reading data");
        return;
    }
    lcb_parse_vbucket_stream(instance);
    lcb_sockrw_set_want(conn, LCB_READ_EVENT, 0);
    lcb_sockrw_apply_want(conn);
}

static void v1_error_common(lcb_t instance)
{
    lcb_instance_connerr(instance, LCB_NETWORK_ERROR,
                         "Problem with sending data");
}

static void config_v1_read_handler(lcb_sockdata_t *sockptr, lcb_ssize_t nr)
{
    lcb_t instance;
    if (!lcb_sockrw_v1_cb_common(sockptr, NULL, (void**)&instance)) {
        return;
    }

    lcb_sockrw_v1_onread_common(sockptr, &instance->connection.input, nr);

    if (nr < 1) {
        v1_error_common(instance);
        return;
    }

    lcb_parse_vbucket_stream(instance);
    lcb_sockrw_set_want(&instance->connection, LCB_READ_EVENT, 1);
    lcb_sockrw_apply_want(&instance->connection);
}

static void config_v1_write_handler(lcb_sockdata_t *sockptr,
                                    lcb_io_writebuf_t *wbuf,
                                    int status)
{
    lcb_t instance;
    if (!lcb_sockrw_v1_cb_common(sockptr, wbuf, (void**)&instance)) {
        return;
    }

    lcb_sockrw_v1_onwrite_common(sockptr, wbuf, &instance->connection.output);

    if (status) {
        v1_error_common(instance);
    }

    lcb_sockrw_set_want(&instance->connection, LCB_READ_EVENT, 1);
    lcb_sockrw_apply_want(&instance->connection);
}

static void config_v1_error_handler(lcb_sockdata_t *sockptr)
{
    lcb_t instance;
    if (!lcb_sockrw_v1_cb_common(sockptr, NULL, (void**)&instance)) {
        return;
    }

    v1_error_common(instance);
}
