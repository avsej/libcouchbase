/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2019 Couchbase, Inc.
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

#ifndef LIBCOUCHBASE_CONNSTR_H
#define LIBCOUCHBASE_CONNSTR_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *key;
    size_t key_len;
    const char *value;
    size_t value_len;
} lcb_CONNSPEC_OPTION;

typedef enum {
    LCB_CONNSPEC_NODE_BOOTSTRAP_UNSPEC = 0,
    LCB_CONNSPEC_NODE_BOOTSTRAP_MCD,
    LCB_CONNSPEC_NODE_BOOTSTRAP_MCDS,
    LCB_CONNSPEC_NODE_BOOTSTRAP_HTTP,
    LCB_CONNSPEC_NODE_BOOTSTRAP_HTTPS
} lcb_CONNSPEC_NODE_BOOTSTRAP;

typedef enum {
    LCB_CONNSPEC_NODE_TYPE_UNSPEC = 0,
    LCB_CONNSPEC_NODE_TYPE_IPV4,
    LCB_CONNSPEC_NODE_TYPE_IPV6,
    LCB_CONNSPEC_NODE_TYPE_DNS
} lcb_CONNSPEC_NODE_TYPE;

typedef struct {
    const char *address;
    size_t address_len;
    const char *port;
    size_t port_len;
    lcb_CONNSPEC_NODE_BOOTSTRAP bootstrap;
    lcb_CONNSPEC_NODE_BOOTSTRAP type;
} lcb_CONNSPEC_NODE;

typedef struct {
    const char *scheme;
    size_t scheme_len;
    const char *bucket;
    size_t bucket_len;
    lcb_CONNSPEC_OPTION *options;
    size_t options_len;
} lcb_CONNSPEC;

/**
 * Parses connection string into specification object.
 *
 * The function does not copy values, all strings from the spec object point to source string.
 */
LIBCOUCHBASE_API lcb_STATUS lcb_connstr_parse(const char *connstr, size_t connstr_len, lcb_CONNSPEC **spec);

/**
 * Destroys connection specification object.
 */
LIBCOUCHBASE_API lcb_STATUS lcb_connstr_destroy(lcb_CONNSPEC *spec);

/**
 * Generates connection string from specification object.
 *
 * The function allocates string using standard malloc(3), therefore it must be deallocated using free(3)
 */
LIBCOUCHBASE_API lcb_STATUS lcb_connstr_build(lcb_CONNSPEC *spec, char **connstr, size_t *connstr_len);

#ifdef __cplusplus
}
#endif
#endif // LIBCOUCHBASE_CONNSTR_H
