/*
* krypt-core API - C version
*
* Copyright (C) 2011
* Hiroshi Nakamura <nahi@ruby-lang.org>
* Martin Bosslet <martin.bosslet@googlemail.com>
* All rights reserved.
*
* This software is distributed under the same license as Ruby.
* See the file 'LICENSE' for further details.
*/

#include "krypt_io_buffer.h"
#include "krypt_error.h"

krypt_byte_buffer *
krypt_buffer_new(void)
{
    krypt_byte_buffer *ret;
    ret = ALLOC(krypt_byte_buffer);
    memset(ret, 0, sizeof(krypt_byte_buffer));
    return ret;
}

krypt_byte_buffer *
krypt_buffer_new_size(size_t size)
{
    krypt_byte_buffer *ret;
    ret = krypt_buffer_new();
    ret->init_size = size;
    return ret;
}

krypt_byte_buffer *
krypt_buffer_new_prealloc(uint8_t *b, size_t len)
{
    krypt_byte_buffer *ret;
    ret = krypt_buffer_new();
    ret->data = b;
    ret->limit = len;
    ret->prealloc = 1;
    return ret;
}

static const size_t KRYPT_BUF_MAX = SIZE_MAX / KRYPT_BYTE_BUFFER_GROWTH_FACTOR;

static int
int_buffer_grow(krypt_byte_buffer *buffer, size_t cur_len)
{
    size_t new_size;

    if (buffer->prealloc) {
	krypt_error_add("Cannot grow preallocated buffer");
	return 0;
    }

    if (buffer->data == NULL) {
	size_t alloc_size = buffer->init_size > cur_len ? buffer->init_size : cur_len;
	buffer->data = ALLOC_N(uint8_t, alloc_size);
	buffer->limit = alloc_size;
	return 1;
    }

    /* avoid infinite loop for limit == 1 */
    new_size = buffer->limit == 1 ? 2 : buffer->limit;

    while (new_size - buffer->size < cur_len) {
	if (new_size >= KRYPT_BUF_MAX) {
	    krypt_error_add("Cannot grow buffer");
	    return 0;
	}
    	new_size *= KRYPT_BYTE_BUFFER_GROWTH_FACTOR;
    }

    REALLOC_N(buffer->data, uint8_t, new_size);
    buffer->limit = new_size; 
    return 1;
}

ssize_t
krypt_buffer_write(krypt_byte_buffer *buffer, uint8_t *b, size_t len)
{
    if (!b) return -1;
    if (len == 0) return 0;
    if (len > SSIZE_MAX) return -1;

    if (buffer->limit - buffer->size < len) {
	if (!int_buffer_grow(buffer, len))
	    return -1;
    }

    memcpy(buffer->data + buffer->size, b, len);
    buffer->size += len;
    return (ssize_t) len;
}

void
krypt_buffer_free_secure(krypt_byte_buffer *buffer)
{
    if (buffer && buffer->data) {
	memset(buffer->data, 0, buffer->limit);
    }
    krypt_buffer_free(buffer);
}

void
krypt_buffer_free(krypt_byte_buffer *buffer)
{
    if (!buffer) return;
    if (buffer->data && (!buffer->prealloc))
	xfree(buffer->data);
    xfree(buffer);
}

size_t
krypt_buffer_get_bytes_free(krypt_byte_buffer *buffer, uint8_t **out)
{
    size_t ret;

    if (!buffer) return 0;

    *out = buffer->data;
    ret = buffer->size;
    xfree(buffer);
    return ret;
}

