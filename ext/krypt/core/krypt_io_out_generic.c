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

typedef struct krypt_outstream_io_st {
    krypt_outstream_interface *methods;
    VALUE io;
} krypt_outstream_io;

#define int_safe_cast(out, in)		krypt_safe_cast_outstream((out), (in), KRYPT_OUTSTREAM_TYPE_IO_GENERIC, krypt_outstream_io)

static krypt_outstream_io* int_io_alloc(void);
static ssize_t int_io_write(krypt_outstream *out, uint8_t *buf, size_t len);
static int int_io_rb_write(krypt_outstream *out, VALUE vbuf, VALUE *ret);
static void int_io_mark(krypt_outstream *out);
static void int_io_free(krypt_outstream *out);

static krypt_outstream_interface krypt_interface_io = {
    KRYPT_OUTSTREAM_TYPE_IO_GENERIC,
    int_io_write,
    int_io_rb_write,
    int_io_mark,
    int_io_free
};

krypt_outstream *
krypt_outstream_new_io_generic(VALUE io)
{
    krypt_outstream_io *out;

    out = int_io_alloc();
    out->io = io;
    return (krypt_outstream *) out;
}

static krypt_outstream_io *
int_io_alloc(void)
{
    krypt_outstream_io *ret;
    ret = ALLOC(krypt_outstream_io);
    memset(ret, 0, sizeof(krypt_outstream_io));
    ret->methods = &krypt_interface_io;
    return ret;
}

static ssize_t
int_io_write(krypt_outstream *outstream, uint8_t *buf, size_t len)
{
    VALUE vbuf, ret;
    int w;

    if (!buf) return -1;

    vbuf = rb_str_new((const char *)buf, len);
    w = int_io_rb_write(outstream, vbuf, &ret);
    if (!w) {
	krypt_error_add("Error while writing to IO");
	return -1;
    }
    return NUM2LONG(ret);
}

static VALUE
int_io_rb_protected_write(VALUE args)
{
    VALUE io, vbuf;
    io = rb_ary_entry(args, 0);
    vbuf = rb_ary_entry(args, 1);
    return rb_funcall(io, sKrypt_ID_WRITE, 1, vbuf);
}

static int
int_io_rb_write(krypt_outstream *outstream, VALUE vbuf, VALUE *ret)
{
    krypt_outstream_io *out;
    VALUE args;
    int state = 0;

    int_safe_cast(out, outstream);
    args = rb_ary_new();
    rb_ary_push(args, out->io);
    rb_ary_push(args, vbuf);
    *ret = rb_protect(int_io_rb_protected_write, args, &state);
    return state == 0;
}

static void
int_io_mark(krypt_outstream *outstream)
{
    krypt_outstream_io *out;

    if (!outstream) return;
    int_safe_cast(out, outstream);
    rb_gc_mark(out->io);
}

static void
int_io_free(krypt_outstream *outstream)
{
    /* do nothing */
}

