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

typedef struct krypt_instream_io_st {
    krypt_instream_interface *methods;
    VALUE io;
} krypt_instream_io;

#define int_safe_cast(out, in)		krypt_safe_cast_instream((out), (in), KRYPT_INSTREAM_TYPE_IO_GENERIC, krypt_instream_io)

static krypt_instream_io* int_io_alloc(void);
static ssize_t int_io_read(krypt_instream *in, uint8_t *buf, size_t len);
static int int_io_rb_read(krypt_instream *in, VALUE vlen, VALUE vbuf, VALUE *out);
static int int_io_seek(krypt_instream *in, off_t offset, int whence);
static void int_io_mark(krypt_instream *in);
static void int_io_free(krypt_instream *in);

static krypt_instream_interface krypt_interface_io_generic = {
    KRYPT_INSTREAM_TYPE_IO_GENERIC,
    int_io_read,
    int_io_rb_read,
    NULL,
    int_io_seek,
    int_io_mark,
    int_io_free
};

krypt_instream *
krypt_instream_new_io_generic(VALUE io)
{
    krypt_instream_io *in;

    in = int_io_alloc();
    in->io = io;
    return (krypt_instream *) in;
}

static krypt_instream_io*
int_io_alloc(void)
{
    krypt_instream_io *ret;
    ret = ALLOC(krypt_instream_io);
    memset(ret, 0, sizeof(krypt_instream_io));
    ret->methods = &krypt_interface_io_generic;
    return ret;
}

static VALUE
int_io_rb_protected_read(VALUE args)
{
    VALUE io, vbuf, vlen;
    io = rb_ary_entry(args, 0);
    vlen = rb_ary_entry(args, 1);
    vbuf = rb_ary_entry(args, 2);
    return rb_funcall(io, sKrypt_ID_READ, 2, vlen, vbuf);
}

static int
int_io_rb_read_impl(krypt_instream_io *in, VALUE vlen, VALUE vbuf, VALUE *out)
{
    VALUE args = rb_ary_new();
    int state = 0;
    rb_ary_push(args, in->io);
    rb_ary_push(args, vlen);
    rb_ary_push(args, vbuf);
    *out = rb_protect(int_io_rb_protected_read, args, &state);
    return state == 0;
}

static ssize_t
int_io_read(krypt_instream *instream, uint8_t *buf, size_t len)
{
    VALUE read, vlen, vbuf;
    krypt_instream_io *in;

    int_safe_cast(in, instream);

    if (!buf) return -2;

    vlen = LONG2NUM(len);
    vbuf = rb_str_new2("");
    rb_enc_associate(vbuf, rb_ascii8bit_encoding());

    if (!int_io_rb_read_impl(in, vlen, vbuf, &read)) {
	krypt_error_add("Error while reading from IO");
	return -2;
    }
    
    if (NIL_P(read)) {
	return -1;
    }
    else {
	ssize_t r = (ssize_t) RSTRING_LEN(read);
	memcpy(buf, RSTRING_PTR(read), r);
	return r;
    }
}

static int
int_io_rb_read(krypt_instream *instream, VALUE vlen, VALUE vbuf, VALUE *out)
{
    krypt_instream_io *in;

    int_safe_cast(in, instream);
    return int_io_rb_read_impl(in, vlen, vbuf, out);
}

static VALUE
int_whence_sym_for(int whence)
{
    switch (whence) {
	case SEEK_CUR:
	    return sKrypt_ID_SEEK_CUR;
	case SEEK_SET:
	    return sKrypt_ID_SEEK_SET;
	case SEEK_END:
	    return sKrypt_ID_SEEK_END;
	default:
	    krypt_error_add("Unknown whence: %d", whence);
	    return Qnil;
    }
}

/* TODO: rb_protect */
static int
int_io_seek(krypt_instream *instream, off_t offset, int whence)
{
    VALUE io, whencesym;
    krypt_instream_io *in;

    int_safe_cast(in, instream);

    io = in->io;
    whencesym = int_whence_sym_for(whence);
    if (NIL_P(whencesym)) return 0;
    rb_funcall(io, sKrypt_ID_SEEK, 2, LONG2NUM(offset), whencesym);
    return 1;
}

static void
int_io_mark(krypt_instream *instream)
{
    krypt_instream_io *in;

    if (!instream) return;
    int_safe_cast(in, instream);

    rb_gc_mark(in->io);
}

static void
int_io_free(krypt_instream *instream)
{
    /* do nothing */
}

