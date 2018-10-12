/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2018 Couchbase, Inc.
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
#include "settings.h"
#include "internal.h"
#include "mcserver/negotiate.h"

#include <string>
#include <sstream>

#define LOGARGS(instance, lvl) ()->m_instance->settings, "c9smgmt", LCB_LOG_##lvl, __FILE__, __LINE__

static std::string manifest_to_json(lcb_C9SMANIFEST *manifest)
{
    char uid[34] = {};

    Json::Value json;
    snprintf(uid, sizeof(uid), "%" PRIx32, manifest->uid);
    json["uid"] = uid;
    Json::Value scopes(Json::arrayValue);
    for (size_t ii = 0; ii < manifest->nscopes; ii++) {
        Json::Value scope;
        snprintf(uid, sizeof(uid), "%" PRIx32, manifest->scopes[ii].uid);
        scope["uid"] = uid;
        scope["name"] = std::string(manifest->scopes[ii].name, manifest->scopes[ii].nname);
        Json::Value collections(Json::arrayValue);
        for (size_t jj = 0; jj < manifest->scopes[ii].ncollections; jj++) {
            Json::Value collection;
            snprintf(uid, sizeof(uid), "%" PRIx32, manifest->scopes[ii].collections[jj].uid);
            collection["uid"] = uid;
            collection["name"] =
                std::string(manifest->scopes[ii].collections[jj].name, manifest->scopes[ii].collections[jj].nname);
            collections.append(collection);
        }
        scope["collections"] = collections;
        scopes.append(scope);
    }
    json["scopes"] = scopes;
    return Json::FastWriter().write(json);
}

LIBCOUCHBASE_API
lcb_error_t lcb_c9s_manifest_set(lcb_t instance, const void *cookie, const lcb_CMDC9SMGMT *cmd)
{
    mc_CMDQUEUE *cq = &instance->cmdq;
    if (cq->config == NULL) {
        return LCB_CLIENT_ETMPFAIL;
    }
    if (!LCBT_SETTING(instance, use_collections)) {
        return LCB_NOT_SUPPORTED;
    }
    if (cq->npipelines < 1) {
        return LCB_NO_MATCHING_SERVER;
    }
    mc_PIPELINE *pl = cq->pipelines[0];

    if (cmd->manifest == NULL && (cmd->value.vtype != LCB_KV_CONTIG || cmd->value.u_buf.contig.nbytes == 0)) {
        return LCB_EINVAL;
    }
    std::string payload = cmd->manifest ? manifest_to_json(cmd->manifest)
        : std::string((const char *)cmd->value.u_buf.contig.bytes, cmd->value.u_buf.contig.nbytes);

    mc_PACKET *pkt = mcreq_allocate_packet(pl);
    if (!pkt) {
        return LCB_CLIENT_ENOMEM;
    }
    mcreq_reserve_header(pl, pkt, MCREQ_PKT_BASESIZE);

    protocol_binary_request_header hdr = {0};
    hdr.request.magic = PROTOCOL_BINARY_REQ;
    hdr.request.opcode = PROTOCOL_BINARY_CMD_COLLECTIONS_SET_MANIFEST;
    hdr.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    hdr.request.opaque = pkt->opaque;
    hdr.request.bodylen = htonl(payload.size());
    memcpy(SPAN_BUFFER(&pkt->kh_span), hdr.bytes, sizeof(hdr.bytes));

    pkt->u_rdata.reqdata.cookie = cookie;
    pkt->u_rdata.reqdata.start = gethrtime();
    mcreq_reserve_value2(pl, pkt, payload.size());
    memcpy(SPAN_BUFFER(&pkt->u_value.single), payload.c_str(), payload.size());

    LCB_SCHED_ADD(instance, pl, pkt);
    return LCB_SUCCESS;
}

LIBCOUCHBASE_API
lcb_error_t lcb_c9s_manifest_get(lcb_t instance, const void *cookie, const lcb_CMDC9SMGMT *cmd)
{
    mc_CMDQUEUE *cq = &instance->cmdq;
    if (cq->config == NULL) {
        return LCB_CLIENT_ETMPFAIL;
    }
    if (!LCBT_SETTING(instance, use_collections)) {
        return LCB_NOT_SUPPORTED;
    }
    if (cq->npipelines < 1) {
        return LCB_NO_MATCHING_SERVER;
    }
    mc_PIPELINE *pl = cq->pipelines[0];

    mc_PACKET *pkt = mcreq_allocate_packet(pl);
    if (!pkt) {
        return LCB_CLIENT_ENOMEM;
    }
    mcreq_reserve_header(pl, pkt, MCREQ_PKT_BASESIZE);

    protocol_binary_request_header hdr = {0};
    hdr.request.magic = PROTOCOL_BINARY_REQ;
    hdr.request.opcode = PROTOCOL_BINARY_CMD_COLLECTIONS_GET_MANIFEST;
    hdr.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    hdr.request.opaque = pkt->opaque;
    memcpy(SPAN_BUFFER(&pkt->kh_span), hdr.bytes, sizeof(hdr.bytes));

    pkt->u_rdata.reqdata.cookie = cookie;
    pkt->u_rdata.reqdata.start = gethrtime();

    LCB_SCHED_ADD(instance, pl, pkt);
    (void)cmd;
    return LCB_SUCCESS;
}
