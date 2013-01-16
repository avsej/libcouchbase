/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011 Couchbase, Inc.
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

void buffer_destroy(buffer_t *buffer)
{
    if (buffer) {
        buffer->refcount--;
        if (buffer->refcount == 0) {
            free(buffer->bytes);
            memset(buffer, 0, sizeof(buffer_t));
        }
    }
}

lcb_error_t buffer_ensure_capacity(buffer_t *buffer, lcb_size_t size)
{
    char *new_root;
    lcb_size_t new_size;

    if (size < (buffer->size - buffer->nbytes)) {
        /* we've got capacity! */
        return LCB_SUCCESS;
    }

    /* determine the new buffer size... */
    new_size = buffer->size << 1;
    if (new_size == 0) {
        new_size = 128;
    }
    while ((new_size - buffer->nbytes) < size) {
        new_size <<= 1;
    }

    /* go ahead and allocate a bigger block */
    new_root = realloc(buffer->bytes, new_size + 1);
    if (new_root == NULL) {
        return LCB_CLIENT_ENOMEM;
    }
    buffer->bytes = new_root;
    buffer->size = new_size;
    return LCB_SUCCESS;
}

lcb_error_t buffer_write(buffer_t *buffer, const void *src, lcb_size_t nb)
{
    lcb_error_t rc;

    rc = buffer_ensure_capacity(buffer, nb);
    if (rc != LCB_SUCCESS) {
        return rc;
    }
    memcpy(buffer->bytes + buffer->nbytes, src, nb);
    buffer->nbytes += nb;
    return LCB_SUCCESS;
}
