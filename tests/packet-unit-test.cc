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
#include <gtest/gtest.h>
#include <libcouchbase/couchbase.h>
#include "internal.h"

class Packet : public ::testing::Test
{
};

TEST_F(Packet, basicTests)
{
    struct lcb_packet_st queue;
    lcb_error_t rc;

    lcb_packet_queue_init(&queue);
    EXPECT_EQ(&queue, queue.next);
    EXPECT_EQ(&queue, queue.prev);

    {
        lcb_packet_t p1, p2, p3;

        rc = lcb_packet_create(&p1);
        EXPECT_EQ(LCB_SUCCESS, rc);
        rc = lcb_packet_create(&p2);
        EXPECT_EQ(LCB_SUCCESS, rc);
        rc = lcb_packet_create(&p3);
        EXPECT_EQ(LCB_SUCCESS, rc);

        p1->opaque = 1;
        p2->opaque = 2;
        p3->opaque = 3;

        EXPECT_EQ(LCB_SUCCESS, lcb_packet_queue_push(&queue, p1));
        EXPECT_EQ(LCB_SUCCESS, lcb_packet_queue_push(&queue, p2));
        EXPECT_EQ(LCB_SUCCESS, lcb_packet_queue_push(&queue, p3));

        lcb_packet_t tmp;

        tmp = lcb_packet_queue_pop(&queue);
        EXPECT_TRUE(tmp) << "result must not be NULL";
        EXPECT_EQ(1, tmp->opaque) << "must return first packet";
        tmp = lcb_packet_queue_pop(&queue);
        EXPECT_TRUE(tmp) << "result must not be NULL";
        EXPECT_EQ(2, tmp->opaque) << "must return second packet";
        tmp = lcb_packet_queue_pop(&queue);
        EXPECT_TRUE(tmp) << "result must not be NULL";
        EXPECT_EQ(3, tmp->opaque) << "must return second packet";
        EXPECT_FALSE(lcb_packet_queue_not_empty(&queue)) << "queue must be empty";
        tmp = lcb_packet_queue_pop(&queue);
        EXPECT_FALSE(tmp) << "result must be NULL";
        tmp = lcb_packet_queue_pop(&queue);
        EXPECT_FALSE(tmp) << "result must be remain NULL";

        EXPECT_EQ(LCB_SUCCESS, lcb_packet_queue_push(&queue, p1));
        EXPECT_EQ(LCB_SUCCESS, lcb_packet_queue_push(&queue, p2));
        EXPECT_EQ(LCB_SUCCESS, lcb_packet_queue_push(&queue, p3));
        EXPECT_EQ(queue.next, p1) << "next packet must be p1";
        EXPECT_EQ(LCB_SUCCESS, lcb_packet_queue_remove(queue.next));
        EXPECT_EQ(queue.next, p2) << "next packet must be p2";
        EXPECT_EQ(LCB_SUCCESS, lcb_packet_queue_remove(queue.next));
        EXPECT_EQ(queue.next, p3) << "next packet must be p3";
        EXPECT_EQ(LCB_SUCCESS, lcb_packet_queue_remove(queue.next));
        EXPECT_FALSE(lcb_packet_queue_not_empty(&queue)) << "queue must be empty";
    }
}

TEST_F(Packet, movingTests)
{
    struct lcb_packet_st src;
    struct lcb_packet_st dst;
    lcb_error_t rc;

    lcb_packet_queue_init(&src);
    lcb_packet_queue_init(&dst);

    lcb_packet_t p1, p2, p3;

    rc = lcb_packet_create(&p1);
    EXPECT_EQ(LCB_SUCCESS, rc);
    rc = lcb_packet_create(&p2);
    EXPECT_EQ(LCB_SUCCESS, rc);
    rc = lcb_packet_create(&p3);
    EXPECT_EQ(LCB_SUCCESS, rc);

    p1->opaque = 1;
    p2->opaque = 2;
    p3->opaque = 3;

    EXPECT_EQ(LCB_SUCCESS, lcb_packet_queue_push(&src, p1));
    EXPECT_EQ(LCB_SUCCESS, lcb_packet_queue_push(&src, p2));
    EXPECT_EQ(LCB_SUCCESS, lcb_packet_queue_push(&src, p3));

    EXPECT_FALSE(lcb_packet_queue_not_empty(&dst)) << "destination must be empty";
    while (lcb_packet_queue_not_empty(&src)) {
        lcb_packet_t cur = lcb_packet_queue_pop(&src);
        EXPECT_TRUE(cur) << "failed to pop packet from non-empty queue";
        EXPECT_EQ(LCB_SUCCESS, lcb_packet_queue_push(&dst, cur)) << "failed to push packet to destination queue";
    }
    EXPECT_FALSE(lcb_packet_queue_not_empty(&src)) << "destination must be empty";
    EXPECT_EQ(dst.next, p1) << "next packet of destination queue must be p1";
    EXPECT_EQ(LCB_SUCCESS, lcb_packet_queue_remove(dst.next));
    EXPECT_EQ(dst.next, p2) << "next packet of destination queue must be p2";
    EXPECT_EQ(LCB_SUCCESS, lcb_packet_queue_remove(dst.next));
    EXPECT_EQ(dst.next, p3) << "next packet of destination queue must be p3";
    EXPECT_EQ(LCB_SUCCESS, lcb_packet_queue_remove(dst.next));
    EXPECT_FALSE(lcb_packet_queue_not_empty(&dst)) << "destination must be empty";

}
