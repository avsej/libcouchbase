/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011-2019 Couchbase, Inc.
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

#ifndef LCB_UTILS_H
#define LCB_UTILS_H

/**
 * @file
 * Various utility functions
 *
 * @uncommitted
 */

#ifdef __cplusplus
extern "C" {
#endif

#define LCB_CONFIG_MCD_PORT 11210
#define LCB_CONFIG_MCD_SSL_PORT 11207
#define LCB_CONFIG_HTTP_PORT 8091
#define LCB_CONFIG_HTTP_SSL_PORT 18091
#define LCB_CONFIG_MCCOMPAT_PORT 11211

/**
 * Set the key for the command.
 * @param cmd A command derived from lcb_CMDBASE
 * @param keybuf the buffer for the key
 * @param keylen the length of the key.
 *
 * @code{.c}
 * lcb_CMDGET cmd = { 0 };
 * LCB_CMD_SET_KEY(&cmd, "key", strlen("key"));
 * @endcode
 *
 * The storage for `keybuf` may be released or modified after the command has
 * been spooled.
 */
#define LCB_CMD_SET_KEY(cmd, keybuf, keylen) LCB_KREQ_SIMPLE(&(cmd)->key, keybuf, keylen)

/**
 * @name Creating Commands
 * @details
 *
 * Issuing a command to the Cluster involves selecting the correct command
 * structure, populating it with the data relevant for the command, optionally
 * associating the command with your own application data, issuing the command
 * to a spooling function, and finally receiving the response.
 *
 * Command structures all derive from the common @ref lcb_CMDBASE structure. This
 * structure defines the common fields for all commands.
 *
 * Almost all commands need to contain a key, which should be assigned using
 * the LCB_CMD_SET_KEY() macro.
 *
 * @{*/

#define LCB_CMD_BASE                                                                                                   \
    /**Common flags for the command. These modify the command itself. Currently                                        \
     the lower 16 bits of this field are reserved, and the higher 16 bits are                                          \
     used for individual commands.*/                                                                                   \
    lcb_U32 cmdflags;                                                                                                  \
                                                                                                                       \
    /**Specify the expiration time. This is either an absolute Unix time stamp                                         \
     or a relative offset from now, in seconds. If the value of this number                                            \
     is greater than the value of thirty days in seconds, then it is a Unix                                            \
     timestamp.                                                                                                        \
                                                                                                                       \
     This field is used in mutation operations (lcb_store3()) to indicate                                              \
     the lifetime of the item. It is used in lcb_get3() with the lcb_CMDGET::lock                                      \
     option to indicate the lock expiration itself. */                                                                 \
    lcb_U32 exptime;                                                                                                   \
                                                                                                                       \
    /**The known CAS of the item. This is passed to mutation to commands to                                            \
     ensure the item is only changed if the server-side CAS value matches the                                          \
     one specified here. For other operations (such as lcb_CMDENDURE) this                                             \
     is used to ensure that the item has been persisted/replicated to a number                                         \
     of servers with the value specified here. */                                                                      \
    lcb_U64 cas;                                                                                                       \
                                                                                                                       \
    /**< Collection ID */                                                                                              \
    lcb_U32 cid;                                                                                                       \
    const char *scope;                                                                                                 \
    size_t nscope;                                                                                                     \
    const char *collection;                                                                                            \
    size_t ncollection;                                                                                                \
    /**The key for the document itself. This should be set via LCB_CMD_SET_KEY() */                                    \
    lcb_KEYBUF key;                                                                                                    \
                                                                                                                       \
    /** Operation timeout (in microseconds). When zero, the library will use default value. */                         \
    lcb_U32 timeout;                                                                                                   \
    /** Parent tracing span */                                                                                         \
    lcbtrace_SPAN *pspan

/**
 * @name Receiving Responses
 * @details
 *
 * This section describes the APIs used in receiving responses.
 *
 * Each command will have a callback invoked (typically once, for some commands
 * this may be more than once) with a response structure. The response structure
 * will be of a type that extends lcb_RESPBASE. The response structure should
 * not be modified and any of its fields should be considered to point to memory
 * which will be released after the callback exits.
 *
 * The common response header contains the lcb_RESPBASE::cookie field which
 * is the pointer to your application context (passed as the second argument
 * to the spooling function) and allows you to associate a specific command
 * with a specific response.
 *
 * The header will also contain the key (lcb_RESPBASE::key) field which can
 * also help identify the specific command. This is useful if you maintain a
 * single _cookie_ for multiple commands, and have per-item specific data
 * you wish to associate within the _cookie_ itself.
 *
 * Success or failure of the operation is signalled through the lcb_RESPBASE::rc
 * field. Note that even in the case of failure, the lcb_RESPBASE::cookie and
 * lcb_RESPBASE::key fields will _always_ be populated.
 *
 * Most commands also return the CAS of the item (as it exists on the server)
 * and this is placed inside the lcb_RESPBASE::cas field, however it is
 * only valid in the case where lcb_RESPBASE::rc is LCB_SUCCESS.
 *
 * @{
 */

#define LCB_RESP_BASE                                                                                                  \
    /**                                                                                                                \
     Application-defined pointer passed as the `cookie` parameter when                                                 \
     scheduling the command.                                                                                           \
     */                                                                                                                \
    void *cookie;                                                                                                      \
    const void *key; /**< Key for request */                                                                           \
    lcb_SIZE nkey;   /**< Size of key */                                                                               \
    lcb_CAS cas;     /**< CAS for response (if applicable) */                                                          \
    lcb_STATUS rc;   /**< Status code */                                                                               \
    lcb_U16 version; /**< ABI version for response */                                                                  \
    /** Response specific flags. see ::lcb_RESPFLAGS */                                                                \
    lcb_U16 rflags;

#define LCB_RESP_SERVER_FIELDS                                                                                         \
    /** String containing the `host:port` of the server which sent this response */                                    \
    const char *server;

/**
 * @brief Base structure for informational commands from servers
 * This contains an additional lcb_RESPSERVERBASE::server field containing the
 * server which emitted this response.
 */
typedef struct {
    LCB_RESP_BASE
    LCB_RESP_SERVER_FIELDS
} lcb_RESPSERVERBASE;

/**
 * Retrieves the mutation token from the response structure
 * @param cbtype the type of callback invoked
 * @param rb the pointer to the response
 * @return The embedded mutation token, or NULL if the response does not have a
 *         mutation token. This may be either because the command does not support
 *         mutation tokens, or because they have been disabled at the connection
 *         level.
 */
LIBCOUCHBASE_API
const lcb_MUTATION_TOKEN *lcb_resp_get_mutation_token(int cbtype, const lcb_RESPBASE *rb);

/**
 * @volatile
 *
 * Retrieves the last mutation token for a given key.
 * This relies on the @ref LCB_CNTL_DURABILITY_MUTATION_TOKENS option, and will
 * check the instance-level log to determine the latest MUTATION_TOKEN for
 * the given vBucket ID which the key maps to.
 *
 * @param instance the instance
 * @param kb The buffer representing the key. The type of the buffer (see
 * lcb_KEYBUF::type) may either be ::LCB_KV_COPY or ::LCB_KV_VBID
 * @param[out] errp Set to an error if this function returns NULL
 * @return The mutation token if successful, otherwise NULL.
 *
 * Getting the latest mutation token for a key:
 *
 * @code{.c}
 * lcb_KEYBUF kb;
 * kb.type = LCB_KV_COPY;
 * kb.contig.bytes = "Hello";
 * kv.config.nbytes = 5;
 * mt = lcb_get_mutation_token(instance, &kb, &rc);
 * @endcode
 *
 * Getting the latest mutation token for a vbucket:
 * @code{.c}
 * lcb_KEYBUF kb;
 * kv.type = LCB_KV_VBID;
 * kv.contig.nbytes = 543;
 * kv.config.bytes = NULL;
 * mt = lcb_get_mutation_token(instance, &kb, &rc);
 * @endcode
 *
 * Getting the mutation token for each vbucket
 * @code{.c}
 * size_t ii, nvb;
 * lcbvb_CONFIG *vbc;
 * lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_VBCONFIG, &vbc);
 * nvb = vbucket_get_num_vbuckets(vbc);
 * for (ii = 0; ii < nvb; ii++) {
 *   lcb_KEYBUF kb;
 *   const lcb_MUTATION_TOKEN *mt;
 *   kb.type = LCB_KV_VBID;
 *   kb.contig.nbytes = ii;
 *   kb.config.bytes = NULL;
 *   mt = lcb_get_mutation_token(instance, &kb, &rc);
 * }
 * @endcode
 */
LIBCOUCHBASE_API
const lcb_MUTATION_TOKEN *lcb_get_mutation_token(lcb_INSTANCE *instance, const lcb_KEYBUF *kb, lcb_STATUS *errp);

/**@} (Group: Durability) */

/**@ingroup lcb-public-api
 * @defgroup lcb-misc-cmds Miscellaneous Commands
 * @brief Additional miscellaneous commands which can be executed on the server.
 *
 * @addtogroup lcb-misc-cmds
 * @{
 */

/**
 * @name Server Statistics
 * @{
 */

/**
 * @brief Command structure for stats request
 * The lcb_CMDSTATS::key field should contain the statistics key, or be empty
 * if the default statistics are desired.
 * The #cmdflags field may contain the @ref LCB_CMDSTATS_F_KV flag.
 */
typedef struct {
    LCB_CMD_BASE;
} lcb_CMDSTATS;

/**
 * The key is a stored item for which statistics should be retrieved. This
 * invokes the 'keystats' semantics. Note that when using _keystats_, a key
 * must be present, and must not have any spaces in it.
 */
#define LCB_CMDSTATS_F_KV (1 << 16)

/**@brief Response structure for cluster statistics.
 * The lcb_RESPSTATS::key field contains the statistic name (_not_ the same
 * as was passed in lcb_CMDSTATS::key which is the name of the statistical
 * _group_).*/
typedef struct {
    LCB_RESP_BASE
    LCB_RESP_SERVER_FIELDS
    const char *value; /**< The value, if any, for the given statistic */
    lcb_SIZE nvalue;   /**< Length of value */
} lcb_RESPSTATS;

/**@committed
 * @brief Schedule a request for statistics from the cluster.
 * @param instance the instance
 * @param cookie pointer to associate with the request
 * @param cmd the command
 * @return LCB_SUCCESS on success, other error code on failure.
 *
 * Note that the callback for this command is invoked an indeterminate amount
 * of times. The callback is invoked once for each statistic for each server.
 * When all the servers have responded with their statistics, a final callback
 * is delivered to the application with the LCB_RESP_F_FINAL flag set in the
 * lcb_RESPSTATS::rflags field. When this response is received no more callbacks
 * for this command shall be invoked.
 *
 * @par Request
 * @code{.c}
 * lcb_CMDSTATS cmd = { 0 };
 * // Using default stats, no further initialization
 * lcb_stats3(instance, fp, &cmd);
 * lcb_wait(instance);
 * @endcode
 *
 * @par Response
 * @code{.c}
 * lcb_install_callback3(instance, LCB_CALLBACK_STATS, stats_callback);
 * void stats_callback(lcb_INSTANCE, int, const lcb_RESPBASE *rb)
 * {
 *     const lcb_RESPSTATS *resp = (const lcb_RESPSTATS*)rb;
 *     if (resp->key) {
 *         printf("Server %s: %.*s = %.*s\n", resp->server,
 *            (int)resp->nkey, resp->key,
 *            (int)resp->nvalue, resp->value);
 *     }
 *     if (resp->rflags & LCB_RESP_F_FINAL) {
 *       printf("No more replies remaining!\n");
 *     }
 * }
 * @endcode
 */
LIBCOUCHBASE_API
lcb_STATUS lcb_stats3(lcb_INSTANCE *instance, const void *cookie, const lcb_CMDSTATS *cmd);

LIBCOUCHBASE_API lcb_CMDSTATS *lcb_cmdstats_alloc(void);
LIBCOUCHBASE_API void lcb_cmdstats_dispose(lcb_CMDSTATS *cmd);
/**@} (Name: Stats) */

/**@name Server Versions
 * @warning This does not return the actual _Couchbase_ version but rather
 * the internal version of the memcached server.
 * @{
 */

typedef struct {
    LCB_CMD_BASE;
} lcb_CMDVERSIONS;

/**@brief Response structure for the version command */
typedef struct {
    LCB_RESP_BASE
    LCB_RESP_SERVER_FIELDS
    const char *mcversion; /**< The version string */
    lcb_SIZE nversion;     /**< Length of the version string */
} lcb_RESPMCVERSION;

/**
 * @volatile
 */
LIBCOUCHBASE_API
lcb_STATUS lcb_server_versions3(lcb_INSTANCE *instance, const void *cookie, const lcb_CMDVERSIONS *cmd);

LIBCOUCHBASE_API lcb_CMDVERSIONS *lcb_cmdversions_alloc(void);
LIBCOUCHBASE_API void lcb_cmdversions_dispose(lcb_CMDVERSIONS *cmd);
/**@} (Name: MCversion) */

/**
 * @name Server Log Verbosity
 * @{
 */

/** @brief `level` field for lcb_server_verbosity3 () */
typedef enum {
    LCB_VERBOSITY_DETAIL = 0x00,
    LCB_VERBOSITY_DEBUG = 0x01,
    LCB_VERBOSITY_INFO = 0x02,
    LCB_VERBOSITY_WARNING = 0x03
} lcb_verbosity_level_t;

typedef struct {
    /* unused */
    LCB_CMD_BASE;
    const char *server;
    lcb_verbosity_level_t level;
} lcb_CMDVERBOSITY;
typedef lcb_RESPSERVERBASE lcb_RESPVERBOSITY;
/**@volatile*/
LIBCOUCHBASE_API
lcb_STATUS lcb_server_verbosity3(lcb_INSTANCE *instance, const void *cookie, const lcb_CMDVERBOSITY *cmd);

LIBCOUCHBASE_API lcb_CMDVERBOSITY *lcb_cmdverbosity_alloc(void);
LIBCOUCHBASE_API void lcb_cmdverbosity_dispose(lcb_CMDVERBOSITY *cmd);
/**@} (Name: Verbosity) */
/**@} (Group: Misc) */

/**
 * @ingroup lcb-public-api
 * @defgroup lcb-flush Flush
 * @brief Clear the contents of a bucket
 *
 * Flush is useful for development environments (for example clearing a bucket
 * before running tests).
 *
 * @addtogroup lcb-flush
 * @{
 */
typedef struct {
    LCB_CMD_BASE;
} lcb_CMDCBFLUSH;

typedef struct {
    LCB_RESP_BASE
} lcb_RESPCBFLUSH;

/**
 * @uncommitted
 *
 * Flush a bucket
 * This function will properly flush any type of bucket using the REST API
 * via HTTP.
 *
 * The callback invoked under ::LCB_CALLBACK_CBFLUSH will be invoked with either
 * a success or failure status depending on the outcome of the operation. Note
 * that in order for lcb_cbflush3() to succeed, flush must already be enabled
 * on the bucket via the administrative interface.
 *
 * @param instance the library handle
 * @param cookie the cookie passed in the callback
 * @param cmd empty command structure. Currently there are no options for this
 *  command.
 * @return status code for scheduling.
 *
 * @attention
 * Because this command is built using HTTP, this is not subject to operation
 * pipeline calls such as lcb_sched_enter()/lcb_sched_leave()
 */
LIBCOUCHBASE_API
lcb_STATUS lcb_cbflush3(lcb_INSTANCE *instance, void *cookie, const lcb_CMDCBFLUSH *cmd);

LIBCOUCHBASE_API lcb_CMDCBFLUSH *lcb_cmdcbflush_alloc(void);
LIBCOUCHBASE_API void lcb_cmdcbflush_dispose(lcb_CMDCBFLUSH *cmd);

typedef struct {
    LCB_CMD_BASE;
} lcb_CMDFLUSH;
typedef lcb_RESPSERVERBASE lcb_RESPFLUSH;
/**@} (Group: Flush) */

/**
 * @ingroup lcb-public-api
 * @defgroup lcb-noop NOOP
 * @brief Send NOOP command to server
 *
 * @addtogroup lcb-noop
 * @{
 */
typedef struct {
    LCB_CMD_BASE;
} lcb_CMDNOOP;
typedef lcb_RESPSERVERBASE lcb_RESPNOOP;

/**
 * @committed
 *
 * Send NOOP to the node
 *
 * @param instance the library handle
 * @param cookie the cookie passed in the callback
 * @param cmd empty command structure.
 * @return status code for scheduling.
 */
LIBCOUCHBASE_API
lcb_STATUS lcb_noop3(lcb_INSTANCE *instance, const void *cookie, const lcb_CMDNOOP *cmd);

LIBCOUCHBASE_API lcb_CMDNOOP *lcb_cmdnoop_alloc(void);
LIBCOUCHBASE_API void lcb_cmdnoop_dispose(lcb_CMDNOOP *cmd);
/**@} (Group: NOOP) */

/**
 * @ingroup lcb-public-api
 * @defgroup lcb-timings Timings
 * @brief Determine how long operations are taking to be completed
 *
 * libcouchbase provides a simple form of per-command timings you may use
 * to figure out the current lantency for the request-response cycle as
 * generated by your application. Please note that these numbers are not
 * necessarily accurate as you may affect the timing recorded by doing
 * work in the event loop.
 *
 * The time recorded with this library is the time elapsed from the
 * command being called, and the response packet being received from the
 * server.  Everything the application does before driving the event loop
 * will affect the timers.
 *
 * The function lcb_enable_timings() is used to enable the timings for
 * the given instance, and lcb_disable_timings is used to disable the
 * timings. The overhead of using the timers should be negligible.
 *
 * The function lcb_get_timings is used to retrieve the current timing.
 * values from the given instance. The cookie is passed transparently to
 * the callback function.
 *
 * Here is an example of the usage of this module:
 *
 * @code{.c}
 * #include <libcouchbase/couchbase.h>
 *
 * static void callback(
 *  lcb_INSTANCE *instance, const void *cookie, lcb_timeunit_t timeunit, lcb_U32 min,
 *  lcb_U32 max, lcb_U32 total, lcb_U32 maxtotal)
 * {
 *   FILE* out = (void*)cookie;
 *   int num = (float)10.0 * (float)total / ((float)maxtotal);
 *   fprintf(out, "[%3u - %3u]", min, max);
 *   switch (timeunit) {
 *   case LCB_TIMEUNIT_NSEC:
 *      fprintf(out, "ns");
 *      break;
 *   case LCB_TIMEUNIT_USEC:
 *      fprintf(out, "us");
 *      break;
 *   case LCB_TIMEUNIT_MSEC:
 *      fsprintf(out, "ms");
 *      break;
 *   case LCB_TIMEUNIT_SEC:
 *      fprintf(out, "s ");
 *      break;
 *   default:
 *      ;
 *   }
 *
 *   fprintf(out, " |");
 *   for (int ii = 0; ii < num; ++ii) {
 *      fprintf(out, "#");
 *   }
 *   fprintf(out, " - %u\n", total);
 * }
 *
 *
 * lcb_enable_timings(instance);
 * ... do a lot of operations ...
 * fprintf(stderr, "              +---------+\n"
 * lcb_get_timings(instance, stderr, callback);
 * fprintf(stderr, "              +---------+\n"
 * lcb_disable_timings(instance);
 * @endcode
 *
 * @addtogroup lcb-timings
 * @{
 */

/**
 * @brief Time units reported by lcb_get_timings()
 */
enum lcb_timeunit_t {
    LCB_TIMEUNIT_NSEC = 0, /**< @brief Time is in nanoseconds */
    LCB_TIMEUNIT_USEC = 1, /**< @brief Time is in microseconds */
    LCB_TIMEUNIT_MSEC = 2, /**< @brief Time is in milliseconds */
    LCB_TIMEUNIT_SEC = 3   /**< @brief Time is in seconds */
};
typedef enum lcb_timeunit_t lcb_timeunit_t;

/**
 * Start recording timing metrics for the different operations.
 * The timer is started when the command is called (and the data
 * spooled to the server), and the execution time is the time until
 * we parse the response packets. This means that you can affect
 * the timers by doing a lot of other stuff before checking if
 * there is any results available..
 *
 * @param instance the handle to lcb
 * @return Status of the operation.
 * @committed
 */
LIBCOUCHBASE_API
lcb_STATUS lcb_enable_timings(lcb_INSTANCE *instance);

/**
 * Stop recording (and release all resources from previous measurements)
 * timing metrics.
 *
 * @param instance the handle to lcb
 * @return Status of the operation.
 * @committed
 */
LIBCOUCHBASE_API
lcb_STATUS lcb_disable_timings(lcb_INSTANCE *instance);

/**
 * The following function is called for each bucket in the timings
 * histogram when you call lcb_get_timings.
 * You are guaranteed that the callback will be called with the
 * lowest [min,max] range first.
 *
 * @param instance the handle to lcb
 * @param cookie the cookie you provided that allows you to pass
 *               arbitrary user data to the callback
 * @param timeunit the "scale" for the values
 * @param min The lower bound for this histogram bucket
 * @param max The upper bound for this histogram bucket
 * @param total The number of hits in this histogram bucket
 * @param maxtotal The highest value in all of the buckets
 */
typedef void (*lcb_timings_callback)(lcb_INSTANCE *instance, const void *cookie, lcb_timeunit_t timeunit, lcb_U32 min,
                                     lcb_U32 max, lcb_U32 total, lcb_U32 maxtotal);

/**
 * Get the timings histogram
 *
 * @param instance the handle to lcb
 * @param cookie a cookie that will be present in all of the callbacks
 * @param callback Callback to invoke which will handle the timings
 * @return Status of the operation.
 * @committed
 */
LIBCOUCHBASE_API
lcb_STATUS lcb_get_timings(lcb_INSTANCE *instance, const void *cookie, lcb_timings_callback callback);
/**@} (Group: Timings) */

typedef enum {
    /** Dump the raw vbucket configuration */
    LCB_DUMP_VBCONFIG = 0x01,
    /** Dump information about each packet */
    LCB_DUMP_PKTINFO = 0x02,
    /** Dump memory usage/reservation information about buffers */
    LCB_DUMP_BUFINFO = 0x04,
    /** Dump various metrics information */
    LCB_DUMP_METRICS = 0x08,
    /** Dump everything */
    LCB_DUMP_ALL = 0xff
} lcb_DUMPFLAGS;

/**
 * @volatile
 * @brief Write a textual dump to a file.
 *
 * This function will inspect the various internal structures of the current
 * client handle (indicated by `instance`) and write the state information
 * to the file indicated by `fp`.
 * @param instance the handle to dump
 * @param fp the file to which the dump should be written
 * @param flags a set of modifiers (of @ref lcb_DUMPFLAGS) indicating what
 * information to dump. Note that a standard set of information is always
 * dumped, but by default more verbose information is hidden, and may be
 * enabled with these flags.
 */
LIBCOUCHBASE_API
void lcb_dump(lcb_INSTANCE *instance, FILE *fp, lcb_U32 flags);

/** Volatile histogram APIs, used by pillowfight and others */
struct lcb_histogram_st;
typedef struct lcb_histogram_st lcb_HISTOGRAM;

/**
 * @volatile
 * Create a histogram structure
 * @return a new histogram structure
 */
LIBCOUCHBASE_API
lcb_HISTOGRAM *lcb_histogram_create(void);

/**
 * @volatile free a histogram structure
 * @param hg the histogram
 */
LIBCOUCHBASE_API
void lcb_histogram_destroy(lcb_HISTOGRAM *hg);

/**
 * @volatile
 * Add an entry to a histogram structure
 * @param hg the histogram
 * @param duration the duration in nanoseconds
 */
LIBCOUCHBASE_API
void lcb_histogram_record(lcb_HISTOGRAM *hg, lcb_U64 duration);

typedef void (*lcb_HISTOGRAM_CALLBACK)(const void *cookie, lcb_timeunit_t timeunit, lcb_U32 min, lcb_U32 max,
                                       lcb_U32 total, lcb_U32 maxtotal);

/**
 * @volatile
 * Repeatedly invoke a callback for all entries in the histogram
 * @param hg the histogram
 * @param cookie pointer passed to callback
 * @param cb callback to invoke
 */
LIBCOUCHBASE_API
void lcb_histogram_read(const lcb_HISTOGRAM *hg, const void *cookie, lcb_HISTOGRAM_CALLBACK cb);

/**
 * Print the histogram to the specified FILE.
 *
 * This essentially outputs the same raw information as lcb_histogram_read(),
 * except it prints in implementation-defined format. It's simpler to use
 * than lcb_histogram_read, but less flexible.
 *
 * @param hg the histogram
 * @param stream File to print the histogram to.
 */
LIBCOUCHBASE_API
void lcb_histogram_print(lcb_HISTOGRAM *hg, FILE *stream);

/**
 * @volatile
 *
 * Retrieves the extra error context from the response structure.
 *
 * This context does not duplicate information described by status
 * code rendered by lcb_strerror() function, and should be logged
 * if available.
 *
 * @return the pointer to string or NULL if context wasn't specified.
 */
LIBCOUCHBASE_API
const char *lcb_resp_get_error_context(int cbtype, const lcb_RESPBASE *rb);

/**
 * @uncommitted
 *
 * Retrieves the error reference id from the response structure.
 *
 * Error reference id (or event id) should be logged to allow
 * administrators match client-side events with cluster logs.
 *
 * @return the pointer to string or NULL if ref wasn't specified.
 */
LIBCOUCHBASE_API
const char *lcb_resp_get_error_ref(int cbtype, const lcb_RESPBASE *rb);

/**
 * @defgroup lcb-collections-api Collections Management
 * @brief Managing collections in the bucket
 */

/*
 * @addtogroup lcb-collection-api
 * @{
 */

typedef struct lcb_RESPGETMANIFEST_ lcb_RESPGETMANIFEST;

LIBCOUCHBASE_API lcb_STATUS lcb_respgetmanifest_status(const lcb_RESPGETMANIFEST *resp);
LIBCOUCHBASE_API lcb_STATUS lcb_respgetmanifest_cookie(const lcb_RESPGETMANIFEST *resp, void **cookie);
LIBCOUCHBASE_API lcb_STATUS lcb_respgetmanifest_value(const lcb_RESPGETMANIFEST *resp, const char **json,
                                                      size_t *json_len);

typedef struct lcb_CMDGETMANIFEST_ lcb_CMDGETMANIFEST;

LIBCOUCHBASE_API lcb_STATUS lcb_cmdgetmanifest_create(lcb_CMDGETMANIFEST **cmd);
LIBCOUCHBASE_API lcb_STATUS lcb_cmdgetmanifest_destroy(lcb_CMDGETMANIFEST *cmd);
LIBCOUCHBASE_API lcb_STATUS lcb_cmdgetmanifest_timeout(lcb_CMDGETMANIFEST *cmd, uint32_t timeout);
LIBCOUCHBASE_API lcb_STATUS lcb_getmanifest(lcb_INSTANCE *instance, void *cookie, const lcb_CMDGETMANIFEST *cmd);

typedef struct lcb_RESPGETCID_ lcb_RESPGETCID;

LIBCOUCHBASE_API lcb_STATUS lcb_respgetcid_status(const lcb_RESPGETCID *resp);
LIBCOUCHBASE_API lcb_STATUS lcb_respgetcid_cookie(const lcb_RESPGETCID *resp, void **cookie);
LIBCOUCHBASE_API lcb_STATUS lcb_respgetcid_manifest_id(const lcb_RESPGETCID *resp, uint64_t *id);
LIBCOUCHBASE_API lcb_STATUS lcb_respgetcid_collection_id(const lcb_RESPGETCID *resp, uint32_t *id);
LIBCOUCHBASE_API lcb_STATUS lcb_respgetcid_scoped_collection(const lcb_RESPGETCID *resp, const char **name,
                                                             size_t *name_len);

typedef struct lcb_CMDGETCID_ lcb_CMDGETCID;

LIBCOUCHBASE_API lcb_STATUS lcb_cmdgetcid_create(lcb_CMDGETCID **cmd);
LIBCOUCHBASE_API lcb_STATUS lcb_cmdgetcid_destroy(lcb_CMDGETCID *cmd);
LIBCOUCHBASE_API lcb_STATUS lcb_cmdgetcid_scope(lcb_CMDGETCID *cmd, const char *scope, size_t scope_len);
LIBCOUCHBASE_API lcb_STATUS lcb_cmdgetcid_collection(lcb_CMDGETCID *cmd, const char *collection, size_t collection_len);
LIBCOUCHBASE_API lcb_STATUS lcb_cmdgetcid_timeout(lcb_CMDGETCID *cmd, uint32_t timeout);

LIBCOUCHBASE_API lcb_STATUS lcb_getcid(lcb_INSTANCE *instance, void *cookie, const lcb_CMDGETCID *cmd);
/** @} */

/**
 * @ingroup lcb-public-api
 * @defgroup lcb-cluster-status Cluster Information
 * @brief These functions return status information about the handle, the current
 * connection, and the number of nodes found within the cluster.
 *
 * @see lcb_cntl() for more functions to retrieve status info
 *
 * @addtogroup lcb-cluster-status
 * @{
 */

/**@brief
 * Type of node to retrieve for the lcb_get_node() function
 */
typedef enum {
    /** Get an HTTP configuration (Rest API) node */
    LCB_NODE_HTCONFIG = 0x01,
    /** Get a data (memcached) node */
    LCB_NODE_DATA = 0x02,
    /** Get a view (CAPI) node */
    LCB_NODE_VIEWS = 0x04,
    /** Only return a node which is connected, or a node which is known to be up */
    LCB_NODE_CONNECTED = 0x08,

    /** Specifying this flag adds additional semantics which instruct the library
     * to search additional resources to return a host, and finally,
     * if no host can be found, return the string
     * constant @ref LCB_GETNODE_UNAVAILABLE. */
    LCB_NODE_NEVERNULL = 0x10,

    /** Equivalent to `LCB_NODE_HTCONFIG|LCB_NODE_CONNECTED` */
    LCB_NODE_HTCONFIG_CONNECTED = 0x09,

    /**Equivalent to `LCB_NODE_HTCONFIG|LCB_NODE_NEVERNULL`.
     * When this is passed, some additional attempts may be made by the library
     * to return any kind of host, including searching the initial list of hosts
     * passed to the lcb_create() function. */
    LCB_NODE_HTCONFIG_ANY = 0x11
} lcb_GETNODETYPE;

/** String constant returned by lcb_get_node() when the @ref LCB_NODE_NEVERNULL
 * flag is specified, and no node can be returned */
#define LCB_GETNODE_UNAVAILABLE "invalid_host:0"

/**
 * @brief Return a string of `host:port` for a node of the given type.
 *
 * @param instance the instance from which to retrieve the node
 * @param type the type of node to return
 * @param index the node number if index is out of bounds it will be wrapped
 * around, thus there is never an invalid value for this parameter
 *
 * @return a string in the form of `host:port`. If LCB_NODE_NEVERNULL was specified
 * as an option in `type` then the string constant LCB_GETNODE_UNAVAILABLE is
 * returned. Otherwise `NULL` is returned if the type is unrecognized or the
 * LCB_NODE_CONNECTED option was specified and no connected node could be found
 * or a memory allocation failed.
 *
 * @note The index parameter is _ignored_ if `type` is
 * LCB_NODE_HTCONFIG|LCB_NODE_CONNECTED as there will always be only a single
 * HTTP bootstrap node.
 *
 * @code{.c}
 * const char *viewnode = lcb_get_node(instance, LCB_NODE_VIEWS, 0);
 * // Get the connected REST endpoint:
 * const char *restnode = lcb_get_node(instance, LCB_NODE_HTCONFIG|LCB_NODE_CONNECTED, 0);
 * if (!restnode) {
 *   printf("Instance not connected via HTTP!\n");
 * }
 * @endcode
 *
 * Iterate over all the data nodes:
 * @code{.c}
 * unsigned ii;
 * for (ii = 0; ii < lcb_get_num_servers(instance); ii++) {
 *   const char *kvnode = lcb_get_node(instance, LCB_NODE_DATA, ii);
 *   if (kvnode) {
 *     printf("KV node %s exists at index %u\n", kvnode, ii);
 *   } else {
 *     printf("No node for index %u\n", ii);
 *   }
 * }
 * @endcode
 *
 * @committed
 */
LIBCOUCHBASE_API
const char *lcb_get_node(lcb_INSTANCE *instance, lcb_GETNODETYPE type, unsigned index);

/**
 * @committed
 *
 * @brief Get the target server for a given key.
 *
 * This is a convenience function wrapping around the vBucket API which allows
 * you to retrieve the target node (the node which will be contacted) when
 * performing KV operations involving the key.
 *
 * @param instance the instance
 * @param key the key to use
 * @param nkey the length of the key
 * @return a string containing the hostname, or NULL on error.
 *
 * Since this is a convenience function, error details are not contained here
 * in favor of brevity. Use the full vBucket API for more powerful functions.
 */
LIBCOUCHBASE_API
const char *lcb_get_keynode(lcb_INSTANCE *instance, const void *key, size_t nkey);

/**
 * @brief Get the number of the replicas in the cluster
 *
 * @param instance The handle to lcb
 * @return -1 if the cluster wasn't configured yet, and number of replicas
 * otherwise. This may be `0` if there are no replicas.
 * @committed
 */
LIBCOUCHBASE_API
lcb_S32 lcb_get_num_replicas(lcb_INSTANCE *instance);

/**
 * @brief Get the number of the nodes in the cluster
 * @param instance The handle to lcb
 * @return -1 if the cluster wasn't configured yet, and number of nodes otherwise.
 * @committed
 */
LIBCOUCHBASE_API
lcb_S32 lcb_get_num_nodes(lcb_INSTANCE *instance);

/**
 * @brief Get a list of nodes in the cluster
 *
 * @return a NULL-terminated list of 0-terminated strings consisting of
 * node hostnames:admin_ports for the entire cluster.
 * The storage duration of this list is only valid until the
 * next call to a libcouchbase function and/or when returning control to
 * libcouchbase' event loop.
 *
 * @code{.c}
 * const char * const * curp = lcb_get_server_list(instance);
 * for (; *curp; curp++) {
 *   printf("Have node %s\n", *curp);
 * }
 * @endcode
 * @committed
 */
LIBCOUCHBASE_API
const char *const *lcb_get_server_list(lcb_INSTANCE *instance);

/**@} (Group: Cluster Info) */

/**
 * Functions to allocate and free memory related to libcouchbase. This is
 * mainly for use on Windows where it is possible that the DLL and EXE
 * are using two different CRTs
 */
LIBCOUCHBASE_API
void *lcb_mem_alloc(lcb_SIZE size);

/** Use this to free memory allocated with lcb_mem_alloc */
LIBCOUCHBASE_API
void lcb_mem_free(void *ptr);

/**
 * @internal
 *
 * These two functions unconditionally start and stop the event loop. These
 * should be used _only_ when necessary. Use lcb_wait and lcb_breakout
 * for safer variants.
 *
 * Internally these proxy to the run_event_loop/stop_event_loop calls
 */
LCB_INTERNAL_API
void lcb_run_loop(lcb_INSTANCE *instance);

/** @internal */
LCB_INTERNAL_API
void lcb_stop_loop(lcb_INSTANCE *instance);

/** @internal */
/* This returns the library's idea of time */
LCB_INTERNAL_API
lcb_U64 lcb_nstime(void);

#ifdef __cplusplus
}
#endif
#endif /* LCB_UTILS_H */
