/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2012-2013 Couchbase, Inc.
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
#include "config.h"

#include "mock-unit-test.h"
#include "testutil.h"
#include <map>

/*
 * Helper functions
 */
extern "C" {
    static void storeKvoCallback(lcb_t, lcb_CALLBACKTYPE, lcb_RESPSTORE *resp)
    {
        KVOperation *kvo = (KVOperation *)resp->cookie;
        kvo->cbCommon(resp->rc);
        kvo->result.assignKC(resp);
        ASSERT_EQ(LCB_SET, resp->op);
    }

    static void getKvoCallback(lcb_t, lcb_CALLBACKTYPE, lcb_RESPGET *resp)
    {
        KVOperation *kvo = (KVOperation *)resp->cookie;
        kvo->cbCommon(resp->rc);
        kvo->result.assign(resp);
    }

    static void removeKvoCallback(lcb_t, lcb_CALLBACKTYPE, lcb_RESPREMOVE *resp)
    {
        KVOperation *kvo = (KVOperation *)resp->cookie;
        kvo->cbCommon(resp->rc);
        kvo->result.assignKC(resp);
    }
}

void KVOperation::handleInstanceError(lcb_t instance, lcb_error_t err,
                                      const char *)
{
    KVOperation *kvo = reinterpret_cast<KVOperation *>(
            const_cast<void*>(lcb_get_cookie(instance)));
    kvo->assertOk(err);
    kvo->globalErrors.insert(err);
}

void KVOperation::enter(lcb_t instance)
{
    callbacks.get = lcb_install_callback3(instance, LCB_CALLBACK_GET, (lcb_RESPCALLBACK)getKvoCallback);
    callbacks.rm = lcb_install_callback3(instance, LCB_CALLBACK_REMOVE, (lcb_RESPCALLBACK)removeKvoCallback);
    callbacks.store = lcb_install_callback3(instance, LCB_CALLBACK_STORE, (lcb_RESPCALLBACK)storeKvoCallback);
    oldCookie = lcb_get_cookie(instance);
    lcb_set_cookie(instance, this);
}

void KVOperation::leave(lcb_t instance)
{
    lcb_install_callback3(instance, LCB_CALLBACK_GET, callbacks.get);
    lcb_install_callback3(instance, LCB_CALLBACK_REMOVE, callbacks.rm);
    lcb_install_callback3(instance, LCB_CALLBACK_STORE, callbacks.store);
    lcb_set_cookie(instance, oldCookie);
}

void KVOperation::assertOk(lcb_error_t err)
{
    if (ignoreErrors) {
        return;
    }

    if (allowableErrors.empty()) {
        ASSERT_EQ(LCB_SUCCESS, err) << "Unexpected error: " << lcb_strerror_short(err);
        return;
    }
    ASSERT_TRUE(allowableErrors.find(err) != allowableErrors.end())
        << "Unable to find " << lcb_strerror_short(err) << " in allowable errors";
}

void KVOperation::store(lcb_t instance)
{
    lcb_CMDSTORE cmd = {0};
    LCB_CMD_SET_KEY(&cmd, request->key.data(), request->key.length());
    LCB_CMD_SET_VALUE(&cmd, request->val.data(), request->val.length());
    cmd.operation = LCB_SET;
    cmd.flags = request->flags;
    cmd.exptime = request->exp;
    cmd.cas = request->cas;
    cmd.datatype = request->datatype;

    enter(instance);
    EXPECT_EQ(LCB_SUCCESS, lcb_store3(instance, this, &cmd));
    EXPECT_EQ(LCB_SUCCESS, lcb_wait(instance));
    leave(instance);

    ASSERT_EQ(1, callCount);
}

void KVOperation::remove(lcb_t instance)
{
    lcb_CMDREMOVE cmd = {0};
    LCB_CMD_SET_KEY(&cmd, request->key.data(), request->key.length());

    enter(instance);
    EXPECT_EQ(LCB_SUCCESS, lcb_remove3(instance, this, &cmd));
    EXPECT_EQ(LCB_SUCCESS, lcb_wait(instance));
    leave(instance);

    ASSERT_EQ(1, callCount);

}

void KVOperation::get(lcb_t instance)
{
    lcb_CMDGET cmd = {0};
    LCB_CMD_SET_KEY(&cmd, request->key.data(), request->key.length());
    cmd.exptime = request->exp;

    enter(instance);
    EXPECT_EQ(LCB_SUCCESS, lcb_get3(instance, this, &cmd));
    EXPECT_EQ(LCB_SUCCESS, lcb_wait(instance));
    leave(instance);

    ASSERT_EQ(1, callCount);
}

void storeKey(lcb_t instance, const std::string &key, const std::string &value)
{
    Item req = Item(key, value);
    KVOperation kvo = KVOperation(&req);
    kvo.store(instance);
}

void removeKey(lcb_t instance, const std::string &key)
{
    Item req = Item();
    req.key = key;
    KVOperation kvo = KVOperation(&req);
    kvo.allowableErrors.insert(LCB_SUCCESS);
    kvo.allowableErrors.insert(LCB_KEY_ENOENT);
    kvo.remove(instance);
}

void getKey(lcb_t instance, const std::string &key, Item &item)
{
    Item req = Item();
    req.key = key;
    KVOperation kvo = KVOperation(&req);
    kvo.result.cas = 0xdeadbeef;

    kvo.get(instance);
    ASSERT_NE(0xdeadbeef, kvo.result.cas);
    item = kvo.result;
}

void genDistKeys(lcbvb_CONFIG *vbc, std::vector<std::string> &out)
{
    char buf[1024] = { '\0' };
    int servers_max = lcbvb_get_nservers(vbc);
    std::map<int, bool> found_servers;
    EXPECT_TRUE(servers_max > 0);

    for (int cur_num = 0; found_servers.size() != servers_max; cur_num++) {
        int ksize = sprintf(buf, "VBKEY_%d", cur_num);
        int vbid;
        int srvix;
        lcbvb_map_key(vbc, buf, ksize, &vbid, &srvix);

        if (!found_servers[srvix]) {
            out.push_back(std::string(buf));
            found_servers[srvix] = true;
        }
    }

    EXPECT_EQ(servers_max, out.size());
}

void genStoreCommands(const std::vector<std::string> &keys,
                      std::vector<lcb_CMDSTORE> &cmds)
{
    for (unsigned int ii = 0; ii < keys.size(); ii++) {
        lcb_CMDSTORE cmd = {0};
        LCB_CMD_SET_KEY(&cmd, keys[ii].c_str(), keys[ii].size());
        LCB_CMD_SET_VALUE(&cmd, keys[ii].c_str(), keys[ii].size());
        cmd.operation = LCB_SET;
        cmds.push_back(cmd);
    }
}

/**
 * This doesn't _actually_ attempt to make sense of an operation. It simply
 * will try to keep the event loop alive.
 */
void doDummyOp(lcb_t& instance)
{
    Item itm("foo", "bar");
    KVOperation kvo(&itm);
    kvo.ignoreErrors = true;
    kvo.store(instance);
}

/**
 * Dump the item object to a stream
 * @param out where to dump the object to
 * @param item the item to print
 * @return the stream
 */
std::ostream &operator<< (std::ostream &out, const Item &item)
{
    using namespace std;
    out << "Key: " << item.key << endl;
    if (item.val.length()) {
        out <<  "Value: " << item.val << endl;
    }

    out << ios::hex << "CAS: 0x" << item.cas << endl
        << "Flags: 0x" << item.flags << endl;

    if (item.err != LCB_SUCCESS) {
        out << "Error: " << item.err << endl;
    }

    return out;
}
