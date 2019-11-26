/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2014-2019 Couchbase, Inc.
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

#include "connspec.h"
#include "hostlist.h"
#include "strcodecs/strcodecs.h"
#include "internalstructs.h"
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>

#define SET_ERROR(msg) \
    *errmsg = msg; \
    return LCB_EINVAL;

#define F_HASBUCKET (1u << 0u)
#define F_HASPASSWD (1u << 1u)
#define F_HASUSER (1u << 2u)
#define F_SSLSCHEME (1u << 3u)
#define F_FILEONLY (1u << 4u)
#define F_DNSSRV (1u << 5u)
#define F_DNSSRV_EXPLICIT ((1u << 6u) | F_DNSSRV)

using namespace lcb;

lcb_STATUS Connspec::parse(const char *connstr, size_t connstr_len, const char **errmsg)
{
    const char *errmsg_s; /* stack based error message pointer */
    if (!errmsg) {
        errmsg = &errmsg_s;
    }

    if (!connstr || connstr_len == 0) {
        connstr = "couchbase://";
        connstr_len = strlen(connstr);
    }
    lcb_STATUS err = parse_connspec(connstr, connstr_len, *this);

    if (err) {
        return err;
    }

    if (m_scheme == LCB_SPECSCHEME_MCD_SSL) {
        m_implicit_port = LCB_CONFIG_MCD_SSL_PORT;
        m_sslopts |= LCB_SSL_ENABLED;
        m_flags |= F_SSLSCHEME;
    } else if (m_scheme == LCB_SPECSCHEME_HTTP_SSL) {
        m_implicit_port = LCB_CONFIG_HTTP_SSL_PORT;
        m_sslopts |= LCB_SSL_ENABLED;
        m_flags |= F_SSLSCHEME;
    } else if (m_scheme == LCB_SPECSCHEME_HTTP) {
        m_implicit_port = LCB_CONFIG_HTTP_PORT;
    } else if (m_scheme == LCB_SPECSCHEME_MCD) {
        m_implicit_port = LCB_CONFIG_MCD_PORT;
    } else if (m_scheme == LCB_SPECSCHEME_SRV) {
        m_implicit_port = LCB_CONFIG_MCD_PORT;
        m_flags |= F_DNSSRV_EXPLICIT;
    } else if (m_scheme == LCB_SPECSCHEME_SRV_SSL) {
        m_implicit_port = LCB_CONFIG_MCD_SSL_PORT;
        m_sslopts |= LCB_SSL_ENABLED;
        m_flags |= F_SSLSCHEME | F_DNSSRV_EXPLICIT;
    } else if (m_scheme == LCB_SPECSCHEME_RAW) {
        m_implicit_port = 0;
    } else if (m_scheme.empty()) {
        m_implicit_port = LCB_CONFIG_HTTP_PORT;
    } else {
        SET_ERROR("String must begin with 'couchbase://, 'couchbases://', or 'http://'");
    }

    if (m_hosts.empty()) {
        m_hosts.resize(1);
        m_hosts.back().hostname = "localhost";
    } else if (m_hosts.size() == 1 && m_hosts[0].isTypeless() &&
               (m_hosts[0].port == 0 || m_hosts[0].port == m_implicit_port)) {
        m_flags |= F_DNSSRV;
    }

    if ((m_flags & F_DNSSRV_EXPLICIT) == F_DNSSRV_EXPLICIT) {
        if (m_hosts.size() > 1) {
            SET_ERROR("Only a single host is allowed with DNS SRV");
        } else {
            for (auto &host : m_hosts) {
                if (host.port > 0) {
                    SET_ERROR("Port cannot be specified with DNS SRV");
                }
            }
        }
    }
    for (auto &host : m_hosts) {
        if (host.port) {
            if (host.port == LCB_CONFIG_HTTP_PORT && m_scheme == "couchbase") {
                SET_ERROR("Cannot use port 8091 with \"couchbase://\" protocol. Use \"http://\" or select binary port");
            }
            if (host.port == m_implicit_port) {
                /* skip type detection if post has been specified and is matching the schema */
                continue;
            }
            switch (host.btype) {
                case LCB_BOOTSTRAP_TYPE_HTTP:
                    host.type = LCB_CONFIG_HTTP_PORT;
                    break;
                case LCB_BOOTSTRAP_TYPE_HTTPS:
                    host.type = LCB_CONFIG_HTTP_SSL_PORT;
                    break;
                case LCB_BOOTSTRAP_TYPE_MCD:
                    host.type = LCB_CONFIG_MCD_PORT;
                    break;
                case LCB_BOOTSTRAP_TYPE_MCDS:
                    host.type = LCB_CONFIG_MCD_SSL_PORT;
                    break;
                case LCB_BOOTSTRAP_TYPE_UNSPEC:
                    host.type = m_implicit_port;
                    break;
            }
        }
    }
    std::vector< std::string > non_passthrough_options;
    for (auto &pair : m_ctlopts) {
        const std::string &key = pair.first;
        const std::string &value = pair.second;
        bool passthrough_option = false;
        if (key == "bootstrap_on") {
            m_transports.clear();
            if (value == "cccp") {
                m_transports.insert(LCB_CONFIG_TRANSPORT_CCCP);
            } else if (value == "http") {
                m_transports.insert(LCB_CONFIG_TRANSPORT_HTTP);
            } else if (value == "all") {
                m_transports.insert(LCB_CONFIG_TRANSPORT_CCCP);
                m_transports.insert(LCB_CONFIG_TRANSPORT_HTTP);
            } else if (value == "file_only") {
                m_flags |= LCB_CONNSPEC_F_FILEONLY;
            } else {
                SET_ERROR("Value for bootstrap_on must be 'cccp', 'http', or 'all'");
            }
        } else if (key == "ssl") {
            if (value == "off") {
                if (m_flags & F_SSLSCHEME) {
                    SET_ERROR("SSL scheme specified, but ssl=off found in options");
                }
                m_sslopts &= ~LCB_SSL_ENABLED;
            } else if (value == "on") {
                m_sslopts |= LCB_SSL_ENABLED;
            } else if (value == "no_verify") {
                m_sslopts |= LCB_SSL_ENABLED | LCB_SSL_NOVERIFY;
            } else if (value == "no_global_init") {
                m_sslopts |= LCB_SSL_NOGLOBALINIT;
            } else {
                SET_ERROR("Invalid value for 'ssl'. Choices are on, off, and no_verify");
            }
        } else if (key == "truststorepath") {
            if (!(m_flags & F_SSLSCHEME)) {
                SET_ERROR("Trust store path must be specified with SSL host or scheme");
            }
            m_truststorepath = value;
        } else if (key == "certpath") {
            if (!(m_flags & F_SSLSCHEME)) {
                SET_ERROR("Certificate path must be specified with SSL host or scheme");
            }
            m_certpath = value;
        } else if (key == "keypath") {
            if (!(m_flags & F_SSLSCHEME)) {
                SET_ERROR("Private key path must be specified with SSL host or scheme");
            }
            m_keypath = value;
        } else if (key == "console_log_level") {
            if (sscanf(value.c_str(), "%d", &m_loglevel) != 1) {
                SET_ERROR("console_log_level must be a numeric value");
            }
        } else if (key == "log_redaction") {
            int btmp = 0;
            if (value == "on" || value == "true") {
                btmp = 1;
            } else if (value == "off" || value == "false") {
                btmp = 0;
            } else if (sscanf(value.c_str(), "%d", &btmp) != 1) {
                SET_ERROR("log_redaction must have numeric (boolean) value");
            }
            m_logredact = btmp != 0;
        } else if (key == "dnssrv") {
            if ((m_flags & F_DNSSRV_EXPLICIT) == F_DNSSRV_EXPLICIT) {
                SET_ERROR("Cannot use dnssrv scheme with dnssrv option");
            }
            int btmp = 0;
            if (value == "on" || value == "true") {
                btmp = 1;
            } else if (value == "off" || value == "false") {
                btmp = 0;
            } else if (sscanf(value.c_str(), "%d", &btmp) != 1) {
                SET_ERROR("dnssrv must have numeric (boolean) value");
            }
            if (btmp) {
                m_flags |= F_DNSSRV;
            } else {
                m_flags &= ~F_DNSSRV_EXPLICIT;
            }
        } else if (key == "ipv6") {
            if (value == "only") {
                m_ipv6 = LCB_IPV6_ONLY;
            } else if (value == "disabled") {
                m_ipv6 = LCB_IPV6_DISABLED;
            } else if (value == "allow") {
                m_ipv6 = LCB_IPV6_ALLOW;
            } else {
                SET_ERROR("Value for ipv6 must be 'disabled', 'allow', or 'only'");
            }
        } else {
            passthrough_option = true;
        }
        if (!passthrough_option) {
            non_passthrough_options.push_back(key);
        }
    }
    for (auto &key : non_passthrough_options) {
        m_ctlopts.erase(key);
    }
    if (!m_keypath.empty() && m_certpath.empty()) {
        SET_ERROR("Private key path must be specified with certificate path");
    }
    return LCB_SUCCESS;
}

lcb_STATUS Connspec::load(const lcb_CREATEOPTS &opts)
{
    if (opts.bucket && opts.bucket_len) {
        m_flags |= F_HASBUCKET;
        m_bucket = std::string(opts.bucket, opts.bucket_len);
    }
    if (opts.username && opts.username_len) {
        m_flags |= F_HASUSER;
        m_username = std::string(opts.username, opts.username_len);
    }
    if (opts.password && opts.password_len) {
        m_flags |= F_HASPASSWD;
        m_password = std::string(opts.password, opts.password_len);
    }
    if (opts.logger) {
        m_logger = opts.logger;
    }
    return parse(opts.connstr, opts.connstr_len, NULL);
}

bool
Connspec::can_dnssrv() const {
    return m_flags & F_DNSSRV;
}

bool
Connspec::is_explicit_dnssrv() const {
    return (m_flags & F_DNSSRV_EXPLICIT) == F_DNSSRV_EXPLICIT;
}
