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

#ifdef _WIN32
/*
 * For windows we're currently only supporting the single IO method
 * bundle.
 */
#include "winsock_io_opts.h"

LIBCOUCHBASE_API
lcb_error_t lcb_create_io_ops(lcb_io_opt_t *io,
                              const struct lcb_create_io_ops_st *options)
{
    lcb_error_t ret = LCB_SUCCESS;
    lcb_io_ops_type_t type = LCB_IO_OPS_DEFAULT;

    if (options != NULL) {
        if (options->version != 0) {
            return LCB_EINVAL;
        }
        type = options->v.v0.type;
    }

    if (type == LCB_IO_OPS_DEFAULT || type == LCB_IO_OPS_WINSOCK) {
        *io = lcb_create_winsock_io_opts();
        if (*io == NULL) {
            return LCB_CLIENT_ENOMEM;
        }
    } else {
        return LCB_NOT_SUPPORTED;
    }

    return LCB_SUCCESS;
}

LIBCOUCHBASE_API
lcb_error_t lcb_destroy_io_ops(lcb_io_opt_t io)
{
    if (io && io->destructor) {
        io->destructor(io);
    }
    return LCB_SUCCESS;
}
#else

#include "plugins/io/common.h"

typedef lcb_error_t (*create_func_t)(int version, lcb_io_opt_t *io, const void *cookie);

struct plugin_st {
    void *dlhandle;
    union {
        create_func_t create;
        void *voidptr;
    } func;
};

static lcb_error_t get_create_func(const char *image,
                                   const char *symbol,
                                   struct plugin_st *plugin)
{
    void *dlhandle;
    dlhandle = dlopen(image, RTLD_NOW | RTLD_LOCAL);
    if (dlhandle == NULL) {
        return LCB_DLOPEN_FAILED;
    }

    memset(plugin, 0, sizeof(*plugin));
    plugin->func.create = NULL;
    plugin->func.voidptr = dlsym(dlhandle, symbol);
    if (plugin->func.voidptr == NULL) {
        dlclose(dlhandle);
        dlhandle = NULL;
        return LCB_DLSYM_FAILED;
    } else {
        plugin->dlhandle = dlhandle;
    }
    return LCB_SUCCESS;
}

#ifdef __APPLE__
#define PLUGIN_SO(NAME) "libcouchbase_"NAME".dylib"
#else
#define PLUGIN_SO(NAME) "libcouchbase_"NAME".so"
#endif

#define PLUGIN_SYMBOL(NAME) "lcb_create_"NAME"_io_opts"

static lcb_error_t create_v0(lcb_io_opt_t *io,
                             const struct lcb_create_io_ops_st *options);

static lcb_error_t create_v1(lcb_io_opt_t *io,
                             const struct lcb_create_io_ops_st *options);

static lcb_error_t create_v2(lcb_io_opt_t *io,
                             const struct lcb_create_io_ops_st *options);

#define USE_PLUGIN(OPTS, PLUGIN_NAME, PLUGIN_CONST)             \
        switch (OPTS->version) {                                \
        case 0:                                                 \
            OPTS->v.v0.type = PLUGIN_CONST;                     \
            break;                                              \
        case 1:                                                 \
            OPTS->v.v1.sofile = PLUGIN_SO(PLUGIN_NAME);         \
            OPTS->v.v1.symbol = PLUGIN_SYMBOL(PLUGIN_NAME);     \
            break;                                              \
        }

static void override_from_env(struct lcb_create_io_ops_st *options)
{
    char *plugin = getenv("LIBCOUCHBASE_EVENT_PLUGIN_NAME");
    if (plugin != NULL && *plugin != '\0') {
        if (strncmp("libevent", plugin, 8) == 0) {
            USE_PLUGIN(options, "libevent", LCB_IO_OPS_LIBEVENT);
        } else if (strncmp("libev", plugin, 5) == 0) {
            USE_PLUGIN(options, "libev", LCB_IO_OPS_LIBEV);
        } else if (options->version == 1) {
            char *symbol = getenv("LIBCOUCHBASE_EVENT_PLUGIN_SYMBOL");
            if (symbol == NULL || *symbol == '\0') {
                options->v.v1.sofile = plugin;
                options->v.v1.symbol = symbol;
            }
        }
    }
}

#undef USE_PLUGIN

LIBCOUCHBASE_API
lcb_error_t lcb_destroy_io_ops(lcb_io_opt_t io)
{
    if (io) {
        void *dlhandle = io->dlhandle;
        if (io->destructor) {
            io->destructor(io);
        }
        if (dlhandle) {
            dlclose(dlhandle);
        }
    }

    return LCB_SUCCESS;
}

LIBCOUCHBASE_API
lcb_error_t lcb_create_io_ops(lcb_io_opt_t *io,
                              const struct lcb_create_io_ops_st *io_opts)
{
    struct lcb_create_io_ops_st options;

    memset(&options, 0, sizeof(struct lcb_create_io_ops_st));
    if (io_opts == NULL) {
        options.version = 0;
        options.v.v0.type = LCB_IO_OPS_DEFAULT;
    } else {
        memcpy(&options, io_opts, sizeof(struct lcb_create_io_ops_st));
    }
    override_from_env(&options);
    switch (options.version) {
    case 0:
        return create_v0(io, &options);
    case 1:
        return create_v1(io, &options);
    case 2:
        return create_v2(io, &options);
    default:
        return LCB_NOT_SUPPORTED;
    }
}

static lcb_error_t create_v0(lcb_io_opt_t *io,
                             const struct lcb_create_io_ops_st *options)
{
    lcb_io_ops_type_t type;
    struct lcb_create_io_ops_st opts;

    memset(&opts, 0, sizeof(struct lcb_create_io_ops_st));
    opts.version = 1;
    opts.v.v1.cookie = options->v.v0.cookie;
    type = options->v.v0.type;
    switch (type) {
    case LCB_IO_OPS_LIBEVENT:
        opts.v.v1.sofile = PLUGIN_SO("libevent");
        opts.v.v1.symbol = PLUGIN_SYMBOL("libevent");
        return create_v1(io, &opts);
    case LCB_IO_OPS_LIBEV:
        opts.v.v1.sofile = PLUGIN_SO("libev");
        opts.v.v1.symbol = PLUGIN_SYMBOL("libev");
        return create_v1(io, &opts);
    case LCB_IO_OPS_DEFAULT:
        opts.v.v1.sofile = PLUGIN_SO("libevent");
        opts.v.v1.symbol = PLUGIN_SYMBOL("libevent");
        if (create_v1(io, &opts) != LCB_SUCCESS) {
            opts.v.v1.sofile = PLUGIN_SO("libev");
            opts.v.v1.symbol = PLUGIN_SYMBOL("libev");
            return create_v1(io, &opts);
        } else {
            return LCB_SUCCESS;
        }
    default:
        return LCB_NOT_SUPPORTED;
    }

}
#undef PLUGIN_SO

static void apply_io_defaults(lcb_io_opt_t io) {
    /* allow to reuse common functions */
    if (io->v.v0.recv == NULL) {
        io->v.v0.recv = lcb_io_common_recv;
    }
    if (io->v.v0.send == NULL) {
        io->v.v0.send = lcb_io_common_send;
    }
    if (io->v.v0.recvv == NULL) {
        io->v.v0.recvv = lcb_io_common_recvv;
    }
    if (io->v.v0.sendv == NULL) {
        io->v.v0.sendv = lcb_io_common_sendv;
    }
    if (io->v.v0.socket == NULL) {
        io->v.v0.socket = lcb_io_common_socket;
    }
    if (io->v.v0.close == NULL) {
        io->v.v0.close = lcb_io_common_close;
    }
    if (io->v.v0.ai2sock == NULL) {
        io->v.v0.ai2sock = lcb_io_common_ai2sock;
    }
    if (io->v.v0.connect == NULL) {
        io->v.v0.connect = lcb_io_common_connect;
    }
}

static lcb_error_t create_v1(lcb_io_opt_t *io,
                             const struct lcb_create_io_ops_st *options)
{
    struct plugin_st plugin;
    lcb_error_t ret = get_create_func(options->v.v1.sofile,
                                      options->v.v1.symbol,
                                      &plugin);
    if (ret != LCB_SUCCESS) {
        /* try to look up the symbol in the current image */
        lcb_error_t ret2 = get_create_func(NULL, options->v.v1.symbol, &plugin);
        if (ret2 != LCB_SUCCESS) {
            /* return original error to allow caller to fix it */
            return ret;
        }
    }

    ret = plugin.func.create(0, io, options->v.v1.cookie);
    if (ret != LCB_SUCCESS) {
        if (options->v.v1.sofile != NULL) {
            dlclose(plugin.dlhandle);
        }
        return LCB_CLIENT_ENOMEM;
    } else {
        lcb_io_opt_t iop = *io;
        iop->dlhandle = plugin.dlhandle;
        /* check if plugin select compatible version */
        if (iop->version < 0 || iop->version > 0) {
            lcb_destroy_io_ops(iop);
            return LCB_PLUGIN_VERSION_MISMATCH;
        }
        apply_io_defaults(iop);
    }

    return LCB_SUCCESS;
}

static lcb_error_t create_v2(lcb_io_opt_t *io,
                             const struct lcb_create_io_ops_st *options)
{
    lcb_error_t ret;

    ret = options->v.v2.create(0, io, options->v.v2.cookie);
    if (ret != LCB_SUCCESS) {
        return ret;
    } else {
        lcb_io_opt_t iop = *io;
        /* check if plugin select compatible version */
        if (iop->version < 0 || iop->version > 0) {
            lcb_destroy_io_ops(iop);
            return LCB_PLUGIN_VERSION_MISMATCH;
        }
        apply_io_defaults(iop);
    }

    return LCB_SUCCESS;
}

#endif
