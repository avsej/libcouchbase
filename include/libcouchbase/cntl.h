/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2013 Couchbase, Inc.
 *
 *     This file is in the Public Domain. You may embed this file into your
 *     application and obtain the latest command codes.
 *
 */

/**
 * Command codes for libcouchbase.
 * These codes may be passed to 'lcb_cntl'.
 *
 * Note that the constant values are also public API; thus allowing forwards
 * and backwards compatibility.
 */

#ifndef LCB_CNTL_H
#define LCB_CNTL_H

#ifdef __cplusplus
extern "C" {
#endif

#define LCB_CNTL_SET 0x01
#define LCB_CNTL_GET 0x00

/**
 * Get/Set. Operation timeout.
 * Arg: lcb_uint32_t* (microseconds)
 *
 *      lcb_uint32_t tmo = 3500000;
 *      lcb_cntl(LCB_CNTL_SET, instance, LCB_CNTL_OP_TIMEOUT, &tmo);
 */
#define LCB_CNTL_OP_TIMEOUT             0x00

/**
 * Get/Set. Durability timeout
 * Arg: lcb_uint32_t* (microseconds)
 */
#define LCB_CNTL_DURABILITY_TIMEOUT     0x01

/**
 * Get/Set. Durability poll interval.
 * Arg: lcb_uint32_t* (microseconds)
 */
#define LCB_CNTL_DURABILITY_INTERVAL    0x02

/**
 * Get/Set. View timeout.
 * Arg: lcb_uint32_t* (microseconds)
 */
#define LCB_CNTL_VIEW_TIMEOUT           0x03

/**
 * Get/Set. Default read buffer size (this is not a socket option)
 * Arg: lcb_size_t*
 */
#define LCB_CNTL_RBUFSIZE               0x04

/**
 * Get/Set. Default write buffer size (this is not a socket option)
 * Arg: lcb_size_t*
 */
#define LCB_CNTL_WBUFSIZE               0x05

/**
 * Get the handle type.
 * Arg: lcb_type_t*
 */
#define LCB_CNTL_HANDLETYPE             0x06

/**
 * Get the vBucket handle
 * Arg: VBUCKET_CONFIG_HANDLE*
 */
#define LCB_CNTL_VBCONFIG               0x07


/**
 * Get the iops implementation instance
 * Arg: lcb_io_ops_t*
 */
#define LCB_CNTL_IOPS                   0x08

struct lcb_cntl_vbinfo_st {
    int version;

    union {
        struct {
            /** Input parameters */
            const void *key;
            lcb_size_t nkey;
            /** Output */
            int vbucket;
            int server_index;
        } v0;
    } v;
};
/**
 * Get the vBucket ID for a given key, based on the current configuration
 * Arg: A struct lcb_cntl_vbinfo_st*. The 'vbucket' field in he structure
 *      will be modified
 */
#define LCB_CNTL_VBMAP                  0x09


struct lcb_cntl_server_st {
    /** Structure version */
    int version;

    union {

        struct {
            /** Server index to query */
            int index;

            /** NUL-terminated string containing the address */
            const char *host;
            /** NUL-terminated string containing the port */
            const char *port;
            /** Whether the node is connected */
            int connected;

            /**
             * Socket information. If a v0 IO plugin is being used, the sockfd
             * is set to the socket descriptor. If a v1 plugin is being used, the
             * sockptr is set to point to the appropriate structure.
             *
             * Note that you *MAY* perform various 'setsockopt' calls on the
             * sockfd (though it is your responsibility to ensure those options
             * are valid); however the actual socket descriptor may change
             * in the case of a cluster configuration update.
             */
            union {
                lcb_socket_t sockfd;
                lcb_sockdata_t *sockptr;
            } sock;
        } v0;
    } v;
};

/**
 * Get information about a memcached node.
 * Arg: A struct lcb_cntl_server_st*. Note that all fields in this structure
 *      are ready only and are only valid until one of the following happens:
 *          1) Another libcouchbase API function is called
 *          2) The IOPS loop regains control
 */
#define LCB_CNTL_MEMDNODE_INFO          0x0a

/**
 * Get information about the configuration node.
 * Arg: A struct lcb_cntl_server_st*. Semantics of MEMDNODE_INFO apply here
 *      as well.
 */
#define LCB_CNTL_CONFIGNODE_INFO        0x0b

/**
 * Get/Set the "syncmode" behavior
 * Arg: lcb_syncmode_t*
 */
#define LCB_CNTL_SYNCMODE               0x0c

/**
 * Get/Set IPv4/IPv6 selection policy
 * Arg: lcb_ipv6_t*
 */
#define LCB_CNTL_IP6POLICY              0x0d

/**
 * Get/Set the configuration error threshold. This number indicates how many
 * network/mapping/not-my-vbucket errors are received before a configuration
 * update is requested again.
 *
 * Arg: lcb_size_t*
 */
#define LCB_CNTL_CONFERRTHRESH          0x0e

/** This is not a command, but rather an indicator of the last item */
#define LCB_CNTL__MAX                   0x0e


#ifdef __cplusplus
}
#endif
#endif /* LCB_CNTL_H */
