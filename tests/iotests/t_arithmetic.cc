/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2012 Couchbase, Inc.
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
#include "iotests.h"

class ArithmeticUnitTest : public MockUnitTest
{
};

static lcb_uint64_t arithm_val;

extern "C" {
    static void arithmetic_incr_callback(lcb_t, lcb_CALLBACKTYPE, const lcb_RESPCOUNTER *resp)
    {
        ASSERT_EQ(LCB_SUCCESS, resp->rc);
        ASSERT_EQ(7, resp->nkey);
        ASSERT_EQ(0, memcmp(resp->key, "counter", 7));
        ASSERT_EQ(arithm_val + 1, resp->value);
        arithm_val = resp->value;
    }

    static void arithmetic_decr_callback(lcb_t, lcb_CALLBACKTYPE, const lcb_RESPCOUNTER *resp)
    {
        ASSERT_EQ(LCB_SUCCESS, resp->rc);
        ASSERT_EQ(7, resp->nkey);
        ASSERT_EQ(0, memcmp(resp->key, "counter", 7));
        ASSERT_EQ(arithm_val - 1, resp->value);
        arithm_val = resp->value;
    }

    static void arithmetic_create_callback(lcb_t, lcb_CALLBACKTYPE, const lcb_RESPCOUNTER *resp)
    {
        ASSERT_EQ(LCB_SUCCESS, resp->rc);
        ASSERT_EQ(9, resp->nkey);
        ASSERT_EQ(0, memcmp(resp->key, "mycounter", 9));
        ASSERT_EQ(0xdeadbeef, resp->value);
    }
}

/**
 * Common function to bootstrap an arithmetic key and set the expected/last
 * value counter.
 */
static void initArithmeticKey(lcb_t instance, std::string key,
                              lcb_uint64_t value)
{
    std::stringstream ss;
    ss << value;
    storeKey(instance, key, ss.str());
    arithm_val = value;
}

/**
 * @test Arithmetic (incr)
 * @pre initialize a global variable @c arithm_val to 0.
 * Schedule 10 arithmetic operations. The arithmetic callback should check
 * that the current value is one greater than @c arithm_val. Then set
 * @c arithm_val to the current value.
 *
 * @post The callback's assertions succeed (see precondition)
 */
TEST_F(ArithmeticUnitTest, testIncr)
{
    lcb_t instance;
    HandleWrap hw;
    createConnection(hw, instance);
    (void)lcb_install_callback3(instance, LCB_CALLBACK_COUNTER, (lcb_RESPCALLBACK)arithmetic_incr_callback);

    initArithmeticKey(instance, "counter", 0);

    for (int ii = 0; ii < 10; ++ii) {
        lcb_CMDCOUNTER cmd = {0};
        LCB_KREQ_SIMPLE(&cmd.key, "counter", 7);
        cmd.delta = 1;
        lcb_counter3(instance, NULL, &cmd);
        lcb_wait(instance);
    }
}

/**
 * @test Arithmetic (Decr)
 *
 * @pre Initialize the @c arithm_val to @c 100. Decrement the key 10 times.
 *
 * @post See @ref testIncr for expectations
 */
TEST_F(ArithmeticUnitTest, testDecr)
{
    lcb_t instance;
    HandleWrap hw;
    createConnection(hw, instance);
    (void)lcb_install_callback3(instance, LCB_CALLBACK_COUNTER, (lcb_RESPCALLBACK)arithmetic_decr_callback);

    initArithmeticKey(instance, "counter", 100);

    for (int ii = 0; ii < 10; ++ii) {
        lcb_CMDCOUNTER cmd = {0};
        LCB_KREQ_SIMPLE(&cmd.key, "counter", 7);
        cmd.delta = -1;
        lcb_counter3(instance, NULL, &cmd);
        lcb_wait(instance);
    }

}

/**
 * @test Arithmetic (Creation)
 * @pre Perform an arithmetic operation on a non-existent key. The increment
 * offset is @c 0x77 and the default value is @c 0xdeadbeef
 *
 * @post Value upon getting the key is @c 0xdeadbeef
 */
TEST_F(ArithmeticUnitTest, testArithmeticCreate)
{
    lcb_t instance;
    HandleWrap hw;
    createConnection(hw, instance);

    removeKey(instance, "mycounter");
    (void)lcb_install_callback3(instance, LCB_CALLBACK_COUNTER, (lcb_RESPCALLBACK)arithmetic_create_callback);
    lcb_CMDCOUNTER cmd = {0};
    LCB_KREQ_SIMPLE(&cmd.key, "mycounter", 9);
    cmd.create = 1;
    cmd.initial = 0xdeadbeef;
    cmd.delta = 0x77;
    lcb_counter3(instance, NULL, &cmd);
    lcb_wait(instance);
}
