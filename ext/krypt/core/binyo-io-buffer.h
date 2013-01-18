/*
 * binyo - Fast binary IO for Ruby
 *
 * Copyright (c) 2012-2013
 * Martin Bosslet <martin.bosslet@gmail.com>
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#if !defined(_BINYO_IO_BUFFER_H_)
#define _BINYO_IO_BUFFER_H_

#include <ruby.h>

#define BINYO_BYTE_BUFFER_GROWTH_FACTOR 2

typedef struct binyo_byte_buffer_st {
    size_t size;
    size_t limit;
    size_t init_size;
    int prealloc; /* whether the buffer was already preallocated */
    uint8_t *data;
} binyo_byte_buffer;
 
#define binyo_buffer_get_data(b)	(b)->data
#define binyo_buffer_get_size(b)	(b)->size
binyo_byte_buffer *binyo_buffer_new(void);
binyo_byte_buffer *binyo_buffer_new_size(size_t size);
binyo_byte_buffer *binyo_buffer_new_prealloc(uint8_t *b, size_t len);
ssize_t binyo_buffer_write(binyo_byte_buffer *buffer, uint8_t *b, size_t len);
void binyo_buffer_free_secure(binyo_byte_buffer *buffer);
void binyo_buffer_free(binyo_byte_buffer *buffer);

size_t binyo_buffer_get_bytes_free(binyo_byte_buffer *buffer, uint8_t **out);

#endif /* _BINYO_IO_BUFFER_H_ */
