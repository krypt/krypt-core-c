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

struct krypt_byte_ary_st {
    uint8_t *p;
    size_t len;
};

typedef struct krypt_instream_bytes_st {
    krypt_instream_interface *methods;
    struct krypt_byte_ary_st *src;
    size_t num_read;
} krypt_instream_bytes;

#define int_safe_cast(out, in)		krypt_safe_cast_instream((out), (in), KRYPT_INSTREAM_TYPE_BYTES, krypt_instream_bytes)

static krypt_instream_bytes* int_bytes_alloc(void);
static ssize_t int_bytes_read(krypt_instream *in, uint8_t *buf, size_t len);
static ssize_t int_bytes_gets(krypt_instream *in, char *line, size_t len);
static int int_bytes_seek(krypt_instream *in, off_t offset, int whence);
static void int_bytes_free(krypt_instream *in);

static krypt_instream_interface krypt_interface_bytes = {
    KRYPT_INSTREAM_TYPE_BYTES,
    int_bytes_read,
    NULL,
    int_bytes_gets,
    int_bytes_seek,
    NULL,
    int_bytes_free
};

krypt_instream *
krypt_instream_new_bytes(uint8_t *bytes, size_t len)
{
    krypt_instream_bytes *in;
    struct krypt_byte_ary_st *byte_ary;

    in = int_bytes_alloc();
    byte_ary = ALLOC(struct krypt_byte_ary_st);
    byte_ary->p = bytes;
    byte_ary->len = len;
    in->src = byte_ary;
    return (krypt_instream *) in;
}

static krypt_instream_bytes*
int_bytes_alloc(void)
{
    krypt_instream_bytes *ret;
    ret = ALLOC(krypt_instream_bytes);
    memset(ret, 0, sizeof(krypt_instream_bytes));
    ret->methods = &krypt_interface_bytes;
    return ret;
}

static ssize_t
int_bytes_read(krypt_instream *instream, uint8_t *buf, size_t len)
{
    struct krypt_byte_ary_st *src;
    size_t to_read;
    krypt_instream_bytes *in;

    int_safe_cast(in, instream);

    if (!buf) return -2;

    src = in->src;

    if (in->num_read == src->len)
	return -1;

    to_read = src->len - in->num_read < len ? src->len - in->num_read : len;
    memcpy(buf, src->p, to_read);
    src->p += to_read;
    in->num_read += to_read;
    return to_read;
}

static ssize_t
int_bytes_gets(krypt_instream *instream, char *line, size_t len)
{
    struct krypt_byte_ary_st *src;
    krypt_instream_bytes *in;
    ssize_t ret = 0;
    size_t to_read;
    char *d;
    char *end;

    int_safe_cast(in, instream);
    src = in->src;

    if (in->num_read == src->len)
	return -1;

    d = line;
    to_read = src->len - in->num_read < len ? src->len - in->num_read : len;
    end = d + to_read;

    while (d < end) {
	*d = *(src->p);    
	src->p++;
	if (*d == '\n') {
            in->num_read++;
	    break;
        }
	d++;
	ret++;
    }
    in->num_read += ret;

    if (*d == '\n' && *(d - 1) == '\r')
	ret--;

    return ret;
}

static int
int_bytes_set_pos(krypt_instream_bytes *in, off_t offset, size_t num_read)
{
    struct krypt_byte_ary_st *src = in->src;

    if (src->len - offset <= num_read) {
	krypt_error_add("Unreachable seek position");
	return 0;
    }
    src->p += offset;
    in->num_read += offset;
    return 1;
}

/* TODO check overflow */
static int
int_bytes_seek(krypt_instream *instream, off_t offset, int whence)
{
    struct krypt_byte_ary_st *src;
    size_t num_read;
    krypt_instream_bytes *in;

    int_safe_cast(in, instream);

    src = in->src;
    num_read = in->num_read;

    switch (whence) {
	case SEEK_CUR:
	    return int_bytes_set_pos(in, offset, num_read);
	case SEEK_SET:
	    return int_bytes_set_pos(in, offset - num_read, num_read);
	case SEEK_END:
	    return int_bytes_set_pos(in, offset + src->len - num_read, num_read);
	default:
	    krypt_error_add("Unknown whence: %d", whence);
	    return 0;
    }
}

static void
int_bytes_free(krypt_instream *instream)
{
    krypt_instream_bytes *in;

    if (!instream) return;
    int_safe_cast(in, instream);

    xfree(in->src);
}

