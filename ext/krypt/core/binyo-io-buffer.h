/*
* binyo - Fast binary IO for Ruby
*
* Copyright (C) 2012
* Martin Bosslet <martin.bosslet@googlemail.com>
* All rights reserved.
*
* See the file 'LICENSE' for further details about licensing.
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
