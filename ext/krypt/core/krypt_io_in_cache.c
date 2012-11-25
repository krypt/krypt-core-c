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

typedef struct krypt_instream_cache_st {
    krypt_instream_interface *methods;
    krypt_instream *inner;
    krypt_outstream *bytes;
} krypt_instream_cache;

#define int_safe_cast(out, in)		krypt_safe_cast_instream((out), (in), KRYPT_INSTREAM_TYPE_CACHE, krypt_instream_cache)

static krypt_instream_cache* int_cache_alloc(void);
static ssize_t int_cache_read(krypt_instream *in, uint8_t *buf, size_t len);
static int int_cache_seek(krypt_instream *in, off_t offset, int whence);
static void int_cache_mark(krypt_instream *in);
static void int_cache_free(krypt_instream *in);

static krypt_instream_interface krypt_interface_cache = {
    KRYPT_INSTREAM_TYPE_CACHE,
    int_cache_read,
    NULL,
    NULL,
    int_cache_seek,
    int_cache_mark,
    int_cache_free
};

krypt_instream *
krypt_instream_new_cache(krypt_instream *original)
{
    krypt_instream_cache *in;

    in = int_cache_alloc();
    in->inner = original;
    in->bytes = krypt_outstream_new_bytes_size(1024);
    return (krypt_instream *) in;
}

size_t
krypt_instream_cache_get_bytes(krypt_instream *instream, uint8_t **out)
{
    krypt_instream_cache *in;
    size_t ret;

    int_safe_cast(in, instream);
    ret = krypt_outstream_bytes_get_bytes_free(in->bytes, out);
    in->bytes = krypt_outstream_new_bytes_size(1024);
    return ret;
}

static krypt_instream_cache*
int_cache_alloc(void)
{
    krypt_instream_cache *ret;
    ret = ALLOC(krypt_instream_cache);
    memset(ret, 0, sizeof(krypt_instream_cache));
    ret->methods = &krypt_interface_cache;
    return ret;
}

static ssize_t
int_cache_read(krypt_instream *instream, uint8_t *buf, size_t len)
{
    ssize_t read;
    krypt_instream_cache *in;

    int_safe_cast(in, instream);

    if (!buf) return -2;

    read = krypt_instream_read(in->inner, buf, len);
    if (read > 0)
	krypt_outstream_write(in->bytes, buf, read);
    return read;
}

static int
int_cache_seek(krypt_instream *instream, off_t offset, int whence)
{
    krypt_instream_cache *in;

    int_safe_cast(in, instream);
    return krypt_instream_seek(in->inner, offset, whence);
}

static void
int_cache_mark(krypt_instream *instream)
{
    krypt_instream_cache *in;

    int_safe_cast(in, instream);
    krypt_instream_mark(in->inner);
}

static void
int_cache_free(krypt_instream *instream)
{
    krypt_instream_cache *in;

    if (!instream) return;

    int_safe_cast(in, instream);
    krypt_instream_free(in->inner);
    krypt_outstream_free(in->bytes);
}

void 
krypt_instream_cache_free_wrapper(krypt_instream *instream)
{
    krypt_instream_cache *in;

    if (!instream) return;

    int_safe_cast(in, instream);
    krypt_outstream_free(in->bytes);
    xfree(in);
}

