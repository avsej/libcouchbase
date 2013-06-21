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
#ifndef LIBCOUCHBASE_INTERNAL_H
#define LIBCOUCHBASE_INTERNAL_H 1

/* We're currently doing a lot of logic inside our asserts, causing the
 * library to behave "weird" if you try to build with -DNDEBUG
 */
#undef NDEBUG

#include "config.h"
#include "trace.h"

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <memcached/protocol_binary.h>
#include <ep-engine/command_ids.h>
#include <libvbucket/vbucket.h>
#include <libcouchbase/couchbase.h>
#ifdef HAVE_SYSTEM_LIBSASL
#include <sasl/sasl.h>
#else
#include "isasl.h"
#endif

#include "http_parser/http_parser.h"
#include "ringbuffer.h"
#include "url_encoding.h"
#include "hashset.h"
#include "debug.h"
#include "handler.h"
#include "io/lcbio.h"

#define LCB_DEFAULT_TIMEOUT 2500000
#define LCB_DEFAULT_CONFIG_ERRORS_THRESHOLD 100
#define LCB_LAST_HTTP_HEADER "X-Libcouchbase: \r\n"

#ifdef __cplusplus
extern "C" {
#endif
    struct lcb_server_st;
    typedef struct lcb_server_st lcb_server_t;

    typedef struct {
        char *bytes;
        lcb_size_t size;
        lcb_size_t nbytes;
        lcb_size_t nread;
        int refcount;
    } buffer_t;

    lcb_error_t buffer_ensure_capacity(buffer_t *buffer, lcb_size_t size);
    lcb_error_t buffer_write(buffer_t *buffer, const void *src, lcb_size_t nb);
    void buffer_destroy(buffer_t *buffer);

    typedef struct lcb_packet_st *lcb_packet_t;

    struct lcb_packet_st {
        lcb_packet_t prev;
        lcb_packet_t next;
        lcb_uint8_t opcode;
        lcb_uint16_t vbucket;
        lcb_uint32_t opaque;
        int replica;
        hrtime_t start;
        const void *cookie;
        buffer_t *payload; /* pointer to shared buffer */
    };

    lcb_error_t lcb_packet_queue_create(lcb_packet_t *queue);
    void lcb_packet_queue_destroy(lcb_packet_t queue);
    lcb_error_t lcb_packet_queue_init(lcb_packet_t queue);
    int lcb_packet_queue_not_empty(lcb_packet_t queue);
    lcb_error_t lcb_packet_queue_push(lcb_packet_t queue, lcb_packet_t operation);
    lcb_packet_t lcb_packet_queue_peek(lcb_packet_t queue);
    lcb_packet_t lcb_packet_queue_pop(lcb_packet_t queue);
    lcb_error_t lcb_packet_queue_remove(lcb_packet_t operation);

    lcb_error_t lcb_packet_create(lcb_packet_t *packet);
    void lcb_packet_destroy(lcb_packet_t packet);
    lcb_error_t lcb_packet_start(lcb_server_t server,
                                 lcb_packet_t *packet,
                                 const void *cookie,
                                 const protocol_binary_request_header *header,
                                 const void *data,
                                 lcb_size_t size);
    lcb_error_t lcb_packet_push(lcb_server_t server,
                                lcb_packet_t packet);
    lcb_error_t lcb_packet_retry(lcb_server_t server,
                                 lcb_packet_t packet);
    lcb_error_t lcb_packet_write(lcb_packet_t packet,
                                 const void *data,
                                 lcb_size_t size);


    /**
     * Define constants for connection attemptts
     */
    typedef enum {
        LCB_CONNECT_OK = 0,
        LCB_CONNECT_EINPROGRESS,
        LCB_CONNECT_EALREADY,
        LCB_CONNECT_EISCONN,
        LCB_CONNECT_EINTR,
        LCB_CONNECT_EFAIL,
        LCB_CONNECT_EINVAL,
        LCB_CONNECT_EUNHANDLED
    } lcb_connect_status_t;

    typedef struct {
        char *data;
        lcb_size_t size;
        lcb_size_t avail;
    } http_buffer_t;
    int grow_buffer(http_buffer_t *buffer, lcb_size_t min_free);

    struct lcb_histogram_st;

    typedef void (*vbucket_state_listener_t)(lcb_server_t *server);

    struct lcb_callback_st {
        lcb_get_callback get;
        lcb_store_callback store;
        lcb_arithmetic_callback arithmetic;
        lcb_observe_callback observe;
        lcb_remove_callback remove;
        lcb_stat_callback stat;
        lcb_version_callback version;
        lcb_touch_callback touch;
        lcb_flush_callback flush;
        lcb_error_callback error;
        lcb_http_complete_callback http_complete;
        lcb_http_data_callback http_data;
        lcb_unlock_callback unlock;
        lcb_configuration_callback configuration;
        lcb_verbosity_callback verbosity;
    };

    struct lcb_st {
        /**
         * the type of the connection:
         * * LCB_TYPE_BUCKET
         *      NULL for bucket means "default" bucket
         * * LCB_TYPE_CLUSTER
         *      the bucket argument ignored and all data commands will
         *      return LCB_EBADHANDLE
         */
        lcb_type_t type;

        /** The URL request to send to the server */
        char *http_uri;

        /** The current vbucket config handle */
        VBUCKET_CONFIG_HANDLE vbucket_config;

        struct {
            char *header;
            buffer_t input;
            lcb_size_t chunk_size;
            buffer_t chunk;
        } vbucket_stream;

        struct lcb_io_opt_st *io;

        /** The number of weird things happened with config node
         *  This counter reflects event on memcached port (default 11210),
         *  but used to make decisions about healthiness of the
         *  configuration port (default 8091).
         */
        lcb_size_t weird_things;
        lcb_size_t weird_things_threshold;

        /* The current synchronous mode */
        lcb_syncmode_t syncmode;

        struct lcb_connection_st connection;

        /** Indicates whether the instance is configured */
        int connection_ready;

        /** The number of couchbase server in the configuration */
        lcb_size_t nservers;
        /** The array of the couchbase servers */
        lcb_server_t *servers;

        /** if non-zero, backup_nodes entries should be freed before
            freeing the pointer itself */
        int should_free_backup_nodes;
        /** The array of last known nodes as hostname:port */
        char **backup_nodes;
        /** The current connect index */
        int backup_idx;

        /** The type of the key distribution */
        VBUCKET_DISTRIBUTION_TYPE dist_type;
        /** The number of replicas */
        lcb_uint16_t nreplicas;
        /** The number of vbuckets */
        lcb_uint16_t nvbuckets;
        /** A map from the vbucket to the server hosting the vbucket */
        lcb_vbucket_t *vb_server_map;

        vbucket_state_listener_t vbucket_state_listener;

        /* credentials needed to operate cluster via REST API */
        char *username;
        char *password;

        struct {
            const char *name;
            union {
                sasl_secret_t secret;
                char buffer[256];
            } password;
            sasl_callback_t callbacks[4];
        } sasl;

        /** The set of the timers */
        hashset_t timers;
        /** The set of the pointers to HTTP requests to Cluster */
        hashset_t http_requests;

        struct lcb_callback_st callbacks;
        struct lcb_histogram_st *histogram;

        lcb_uint32_t seqno;
        int wait;
        /** Is IPv6 enabled */
        lcb_ipv6_t ipv6;
        const void *cookie;

        lcb_error_t last_error;

        struct {
            hrtime_t next;
            lcb_uint32_t usec;
        } timeout;

        struct {
            lcb_compat_t type;
            union {
                struct {
                    time_t mtime;
                    char *cachefile;
                    int updating;
                    int needs_update;
                } cached;
            } value;
        } compat;

#ifdef LCB_DEBUG
        lcb_debug_st debug;
#endif
    };

    /**
     * The structure representing each couchbase server
     */
    struct lcb_server_st {
        /** The server index in the list */
        int index;
        /** Non-zero for node is using for configuration */
        int is_config_node;
        /** The server endpoint as hostname:port */
        char *authority;
        /** The Couchbase Views API endpoint base */
        char *couch_api_base;
        /** The REST API server as hostname:port */
        char *rest_api_server;
        /** The sent buffer for this server so that we can resend the
         * command to another server if the bucket is moved... */
        ringbuffer_t cmd_log;
        ringbuffer_t output_cookies;
        /**
         * The pending buffer where we write data until we're in a
         * connected state;
         */
        ringbuffer_t pending;
        ringbuffer_t pending_cookies;

        /** The set of the pointers to HTTP requests to couchbase (Views and
         * Management API) */
        hashset_t http_requests;

        /** The SASL object used for this server */
        sasl_conn_t *sasl_conn;
        /** Is this server in a connected state (done with sasl auth) */
        int connection_ready;

        /**
         * This flag is for use by server_send_packets. By default, this
         * function calls apply_want, but this is unsafe if we are already
         * inside the handler, because at this point the read buffer may not
         * have been owned by us, while a read event may still be requested.
         *
         * If this is the case, apply_want will not be called from send_packets
         * but it will be called when the event handler regains control.
         */
        int inside_handler;

        /* Pointer back to the instance */
        lcb_t instance;
        struct lcb_connection_st connection;
    };

    struct lcb_timer_st {
        lcb_uint32_t usec;
        int periodic;
        void *event;
        const void *cookie;
        lcb_timer_callback callback;
        lcb_t instance;
    };

    struct lcb_http_header_st {
        struct lcb_http_header_st *next;
        char *data;
    };

    struct lcb_http_request_st {
        /** The socket to the server */
        /** The origin node */
        lcb_server_t *server;
        /** Short ref to instance (server->instance) */
        lcb_t instance;
        /** The URL buffer */
        char *url;
        lcb_size_t nurl;
        /** The URL info */
        struct http_parser_url url_info;
        /** The requested path (without couch api endpoint) */
        char *path;
        lcb_size_t npath;
        /** The password. It is here to simplify memory management */
        char *password;
        /** The type of HTTP request */
        lcb_http_method_t method;
        /** The HTTP response parser */
        http_parser *parser;
        http_parser_settings parser_settings;

        /** Non-zero if caller would like to receive response in chunks */
        int chunked;
        /** This callback will be executed when the whole response will be
         * transferred */
        lcb_http_complete_callback on_complete;
        /** This callback will be executed for each chunk of the response */
        lcb_http_data_callback on_data;
        /** The accumulator for result (when chunked mode disabled) */
        ringbuffer_t result;
        /** The cookie belonging to this request */
        const void *command_cookie;
        int cancelled;
        /** Is HTTP parser completed its work */
        int completed;
        /** Linked list of headers */
        struct lcb_http_header_st *headers_list;
        /** Headers array for passing to callbacks */
        const char **headers;
        /** Number of headers **/
        lcb_size_t nheaders;

        lcb_io_opt_t io;

        struct lcb_connection_st connection;

    };

    void lcb_http_request_finish(lcb_t instance,
                                 lcb_server_t *server,
                                 lcb_http_request_t req,
                                 lcb_error_t error);

    lcb_error_t lcb_synchandler_return(lcb_t instance, lcb_error_t retcode);

    lcb_error_t lcb_error_handler(lcb_t instance,
                                  lcb_error_t error,
                                  const char *errinfo);
    int lcb_switch_to_backup_node(lcb_t instance,
                                  lcb_error_t error,
                                  const char *reason);
    int lcb_server_purge_implicit_responses(lcb_server_t *c,
                                            lcb_uint32_t seqno,
                                            hrtime_t delta,
                                            int all);
    void lcb_server_destroy(lcb_server_t *server);
    void lcb_server_connected(lcb_server_t *server);

    void lcb_server_initialize(lcb_server_t *server,
                               int servernum);

    int lcb_dispatch_response(lcb_server_t server,
                              lcb_packet_t packet,
                              protocol_binary_response_header *res);

    /**
     * Start sending packets
     * @param server the server to start send data to
     */
    void lcb_server_send_packets(lcb_server_t *server);


    void lcb_server_v0_event_handler(lcb_socket_t sock, short which, void *arg);

    void lcb_initialize_packet_handlers(lcb_t instance);

    int lcb_base64_encode(const char *src, char *dst, lcb_size_t sz);

    void lcb_record_metrics(lcb_t instance,
                            hrtime_t delta,
                            lcb_uint8_t opcode);

    void lcb_purge_timedout(lcb_t instance);


    int lcb_lookup_server_with_command(lcb_t instance,
                                       lcb_uint8_t opcode,
                                       lcb_uint32_t opaque,
                                       lcb_server_t *exc);

    void lcb_update_server_timer(lcb_server_t *server);

    void lcb_purge_single_server(lcb_server_t *server,
                                 lcb_error_t error);

    lcb_error_t lcb_failout_server(lcb_server_t *server,
                                   lcb_error_t error);

    void lcb_maybe_breakout(lcb_t instance);

    lcb_connect_status_t lcb_connect_status(int err);

    void lcb_sockconn_errinfo(int connerr,
                              const char *hostname,
                              const char *port,
                              const struct addrinfo *root_ai,
                              char *buf,
                              lcb_size_t nbuf,
                              lcb_error_t *uerr);

    lcb_socket_t lcb_gai2sock(lcb_t instance,
                              struct addrinfo **curr_ai,
                              int *connerr);

    lcb_sockdata_t *lcb_gai2sock_v1(lcb_t instance,
                                struct addrinfo **ai,
                                int *connerr);

    lcb_error_t lcb_apply_vbucket_config(lcb_t instance,
                                         VBUCKET_CONFIG_HANDLE config);



    int lcb_getaddrinfo(lcb_t instance, const char *hostname,
                        const char *servname, struct addrinfo **res);

    void lcb_failout_observe_request(lcb_server_t *server,
                                     struct lcb_command_data_st *command_data,
                                     const char *packet,
                                     lcb_size_t npacket,
                                     lcb_error_t err);

    int lcb_load_config_cache(lcb_t instance);
    void lcb_refresh_config_cache(lcb_t instance);
    void lcb_schedule_config_cache_refresh(lcb_t instance);
    void lcb_update_vbconfig(lcb_t instance,
                             VBUCKET_CONFIG_HANDLE next_config);

    void lcb_instance_connerr(lcb_t instance,
                                     lcb_error_t err,
                                     const char *errinfo);

    lcb_error_t lcb_instance_start_connection(lcb_t instance);

    void lcb_vbucket_stream_v0_handler(lcb_socket_t sock, short which, void *arg);

    void lcb_server_connect(lcb_server_t *server);

    int lcb_proto_parse_single(lcb_server_t *c, hrtime_t stop);

    int lcb_http_request_valid(lcb_t instance, lcb_http_request_t req);
    lcb_error_t lcb_http_parse_setup(lcb_http_request_t req);
    lcb_error_t lcb_http_request_connect(lcb_http_request_t req);
    int lcb_http_request_do_parse(lcb_http_request_t req);
    void lcb_setup_lcb_http_resp_t(lcb_http_resp_t *resp,
                                   lcb_http_status_t status,
                                   const char *path,
                                   lcb_size_t npath,
                                   const char * const *headers,
                                   const void *bytes,
                                   lcb_size_t nbytes);


    void lcb_server_v1_read_handler(lcb_sockdata_t *sockptr, lcb_ssize_t nr);
    void lcb_server_v1_write_handler(lcb_sockdata_t *sockptr,
                                     lcb_io_writebuf_t *wbuf,
                                     int status);
    void lcb_server_v1_error_handler(lcb_sockdata_t *sockptr);

    void lcb_parse_vbucket_stream(lcb_t instance);


#ifdef __cplusplus
}
#endif

#endif
