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

#include "krypt-core.h"
#include "krypt_asn1-internal.h"

enum krypt_chunked_state {
    NEW_HEADER = 0,
    PROCESS_TAG,
    PROCESS_LENGTH,
    PROCESS_VALUE,
    DONE
};

typedef struct krypt_instream_chunked {
    krypt_instream_interface *methods;
    krypt_instream *inner;
    int values_only;
    enum krypt_chunked_state state;
    krypt_asn1_header *cur_header;
    krypt_instream *cur_value_stream;
    size_t header_offset;
} krypt_instream_chunked;

#define int_safe_cast(out, in)		krypt_safe_cast_instream((out), (in), KRYPT_INSTREAM_TYPE_CHUNKED, krypt_instream_chunked)

static krypt_instream_chunked* int_chunked_alloc(void);
static ssize_t int_chunked_read(krypt_instream *in, uint8_t *buf, size_t len);
static int int_chunked_seek(krypt_instream *in, off_t offset, int whence);
static void int_chunked_mark(krypt_instream *in);
static void int_chunked_free(krypt_instream *in);

static krypt_instream_interface krypt_interface_chunked = {
    KRYPT_INSTREAM_TYPE_CHUNKED,
    int_chunked_read,
    NULL,
    NULL,
    int_chunked_seek,
    int_chunked_mark,
    int_chunked_free
};

krypt_instream *
krypt_instream_new_chunked(krypt_instream *original, int values_only)
{
    krypt_instream_chunked *in;

    in = int_chunked_alloc();
    in->inner = original;
    in->values_only = values_only;
    in->state = NEW_HEADER;
    return (krypt_instream *) in;
}

static krypt_instream_chunked*
int_chunked_alloc(void)
{
    krypt_instream_chunked *ret;
    ret = ALLOC(krypt_instream_chunked);
    memset(ret, 0, sizeof(krypt_instream_chunked));
    ret->methods = &krypt_interface_chunked;
    return ret;
}

static int
int_read_new_header(krypt_instream_chunked *in)
{
    int ret;
    krypt_asn1_header *next;

    ret = krypt_asn1_next_header(in->inner, &next);
    if (ret == 0) {
	krypt_error_add("Premature end of value detected");
	return 0;
    }

    if (in->cur_header)
	krypt_asn1_header_free(in->cur_header);
    in->cur_header = next;
    in->state = PROCESS_TAG;
    in->header_offset = 0;
    return 1;
}

static size_t
int_read_header_bytes(krypt_instream_chunked *in,
		      uint8_t * bytes, 
		      size_t bytes_len, 
		      enum krypt_chunked_state next_state,
		      uint8_t *buf,
		      size_t len)
{
    size_t to_read;
    size_t available = bytes_len - in->header_offset;
        
    if (len < available) {
	in->header_offset += len;
	to_read = len;
    }
    else {
	in->state = next_state;
	in->header_offset = 0;
	to_read = available;
    }
    
    memcpy(buf, bytes, to_read);
    return to_read;
}

static ssize_t
int_read_value(krypt_instream_chunked *in, uint8_t *buf, size_t len)
{
    ssize_t read;

    if (!in->cur_value_stream)
	in->cur_value_stream = krypt_asn1_get_value_stream(in->inner, in->cur_header, in->values_only);

    read = krypt_instream_read(in->cur_value_stream, buf, len);
    if (read < -1)
	return read;

    if (read == -1) {
	if (in->state != DONE)
	    in->state = NEW_HEADER;
	krypt_instream_free(in->cur_value_stream);
	in->cur_value_stream = NULL;
	read = 0;
    }

    return read;
}

/* If state is PROCESS_VALUE, this means that the tag bytes
 * have been consumed. As an EOC contains no value, we are
 * done.
 */
#define int_check_done(in)					\
do {								\
    if ((in)->cur_header->tag == TAGS_END_OF_CONTENTS &&	\
	(in)->cur_header->tag_class == TAG_CLASS_UNIVERSAL &&   \
	(in)->state == PROCESS_VALUE) {				\
	(in)->state = DONE;					\
    }								\
} while (0)

/* TODO: check overflow */
static ssize_t
int_read_single_element(krypt_instream_chunked *in, uint8_t *buf, size_t len)
{
    ssize_t read = 0;
    size_t total = 0;

#define add_header_bytes()			\
do {						\
   if (!in->values_only) {			\
      total += read;				\
      if (total == len || in->state == DONE)	\
          return (ssize_t) total;		\
      if (total > len) return -2;		\
      buf += read;				\
   }						\
} while (0)

    switch (in->state) {
	case NEW_HEADER:
	    if (!int_read_new_header(in))
	       return -2;
    	    /* fallthrough */
	case PROCESS_TAG: 
	    read = int_read_header_bytes(in,
		    			 in->cur_header->tag_bytes,
					 in->cur_header->tag_len,
					 PROCESS_LENGTH, 
					 buf,
					 len);
	    add_header_bytes();
	    /* fallthrough */
	case PROCESS_LENGTH:
	    read = int_read_header_bytes(in,
		    			 in->cur_header->length_bytes,
					 in->cur_header->length_len,
					 PROCESS_VALUE,
					 buf,
					 len);
	    int_check_done(in);
	    add_header_bytes();
	    /* fallthrough */
	case PROCESS_VALUE:
	    read = int_read_value(in, buf, len);
	    if (read < -1) return read;
	    total += read;
	    buf += read;
	    return (ssize_t) total;
	default:
	    krypt_error_add("Internal error");
	    return -2; /* dummy */
    }
}

static ssize_t
int_read(krypt_instream_chunked *in, uint8_t *buf, size_t len)
{
    ssize_t read = 0;
    size_t total = 0;

    while (total != len && in->state != DONE) {
	read = int_read_single_element(in, buf, len);
	if (read < -1) return -2;
	if (total > (size_t) (SSIZE_MAX - read)) {
	    krypt_error_add("Stream too large");
	    return -2;
	}
	total += read;
	buf += read;
    }
    return total;
}

static ssize_t
int_chunked_read(krypt_instream *instream, uint8_t *buf, size_t len)
{
    krypt_instream_chunked *in;
    
    int_safe_cast(in, instream);
    
    if (!buf) return -2;
    if (in->state == DONE)
	return -1;

    return int_read(in, buf, len);
}

static int
int_chunked_seek(krypt_instream *instream, off_t offset, int whence)
{
    /* int_instream_chunked *in;

    int_safe_cast(in, instream); */

    return 0;
    /* TODO */
}

static void
int_chunked_mark(krypt_instream *instream)
{
    krypt_instream_chunked *in;

    if (!instream) return;
    int_safe_cast(in, instream);
    krypt_instream_mark(in->inner);
}

static void
int_chunked_free(krypt_instream *instream)
{
    krypt_instream_chunked *in;

    if (!instream) return;
    int_safe_cast(in, instream);
    if (in->cur_header)
	krypt_asn1_header_free(in->cur_header);
}

