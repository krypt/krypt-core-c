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

#if !defined(_KRYPT_IO_BUFFER_H_)
#define _KRYPT_IO_BUFFER_H_

#include <ruby.h>

#define KRYPT_BYTE_BUFFER_GROWTH_FACTOR 2

typedef struct krypt_byte_buffer_st {
    size_t size;
    size_t limit;
    size_t init_size;
    int prealloc; /* whether the buffer was already preallocated */
    uint8_t *data;
} krypt_byte_buffer;
 
#define krypt_buffer_get_data(b)	(b)->data
#define krypt_buffer_get_size(b)	(b)->size
krypt_byte_buffer *krypt_buffer_new(void);
krypt_byte_buffer *krypt_buffer_new_size(size_t size);
krypt_byte_buffer *krypt_buffer_new_prealloc(uint8_t *b, size_t len);
ssize_t krypt_buffer_write(krypt_byte_buffer *buffer, uint8_t *b, size_t len);
void krypt_buffer_free_secure(krypt_byte_buffer *buffer);
void krypt_buffer_free(krypt_byte_buffer *buffer);

size_t krypt_buffer_get_bytes_free(krypt_byte_buffer *buffer, uint8_t **out);

#endif /* _KRYPT_IO_BUFFER_H_ */
