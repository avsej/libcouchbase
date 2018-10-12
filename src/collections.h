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
#ifndef LCB_COLLECTIONS_H
#define LCB_COLLECTIONS_H

#ifdef __cplusplus
#include <string>
#include <vector>

#include "contrib/lcb-jsoncpp/lcb-jsoncpp.h"

namespace lcb
{
namespace c9s
{

class Manifest
{
  public:
    enum ParseStatus {
        /** Couldn't parse JSON */
        PARSE_ERROR,
        /** Invalid JSON structure */
        INVALID,
        /** Valid manifest */
        SUCCESS
    };

    class Collection
    {
      public:
        uint32_t uid;
        std::string name;

        Collection(std::string name_, uint32_t uid_)
        {
            this->name = name_;
            this->uid = uid_;
        }
    };

    class Scope
    {
      public:
        uint32_t uid;
        std::string name;
        std::vector< Collection > collections;

        Scope(std::string name_, uint32_t uid_)
        {
            this->name = name_;
            this->uid = uid_;
        }

        Collection &addCollection(std::string collectionName, uint32_t collectionUid = 1)
        {
            collections.push_back(Collection(collectionName, collectionUid));
            return collections.back();
        }
    };

    Manifest() {}

    ParseStatus parse(const char *s, size_t n)
    {
        std::string tmp;
        return parse(s, n, tmp);
    }

    ParseStatus parse(const char *s, size_t n, std::string &errmsg)
    {
        Json::Value json;
        if (!Json::Reader().parse(s, s + n, json)) {
            errmsg = "Invalid JSON";
            return PARSE_ERROR;
        }

        if (json.empty() || !json["uid"].isString() || !json["scopes"].isArray()) {
            errmsg = "missing/invalid toplevel fields";
            return INVALID;
        }

        uid = std::strtoul(json["uid"].asCString(), NULL, 16);
        Json::Value jscopes = json["scopes"];
        scopes.clear();
        Json::ArrayIndex nscopes = jscopes.size();
        for (Json::ArrayIndex ii = 0; ii < nscopes; ii++) {
            Json::Value ss = jscopes[ii];
            if (!ss["name"].isString() || !ss["uid"].isString() || !(ss["collections"].isArray() || ss["collections"].isNull())) {
                errmsg = "invalid scope structure";
                return INVALID;
            }
            Scope &scope = addScope(ss["name"].asString(), std::strtoul(ss["uid"].asCString(), NULL, 16));
            Json::Value jcollections = json["collections"];
            Json::ArrayIndex ncollections = jcollections.size();
            for (Json::ArrayIndex jj = 0; jj < ncollections; jj++) {
                Json::Value cc = jcollections[jj];
                if (!cc["name"].isString() || !cc["uid"].isString()) {
                    errmsg = "invalid scope structure";
                    return INVALID;
                }
                scope.addCollection(cc["name"].asString(), std::strtoul(cc["uid"].asCString(), NULL, 16));
            }
        }
        return SUCCESS;
    }

    uint32_t uid;

  private:
    Scope &addScope(std::string scopeName, uint32_t scopeUid)
    {
        scopes.push_back(Scope(scopeName, scopeUid));
        return scopes.back();
    }

    std::vector< Scope > scopes;
};

} // namespace c9s
} // namespace lcb

typedef lcb::c9s::Manifest *lcb_pMANIFEST;
#else
typedef struct lcbc9s_MANIFEST *lcb_pMANIFEST;
#endif /* __cplusplus */

#endif /* LCB_COLLECTIONS_H */
