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

void
krypt_io_adapter_mark(krypt_io_adapter *adapter)
{
    if (!adapter) return;

    if (adapter->in)
	krypt_instream_mark(adapter->in);
    if (adapter->out)
	krypt_outstream_mark(adapter->out);
}

void
krypt_io_adapter_free(krypt_io_adapter *adapter)
{
    if (!adapter) return;

    if (adapter->in)
	krypt_instream_free(adapter->in);
    if (adapter->out)
	krypt_outstream_free(adapter->out);
    if (adapter->buf)
	xfree(adapter->buf);
    xfree(adapter);
}

static krypt_io_adapter *
krypt_io_adapter_alloc()
{
    krypt_io_adapter *adapter;

    adapter = ALLOC(krypt_io_adapter);
    memset(adapter, 0, sizeof(krypt_io_adapter));
    return adapter;
}

VALUE
krypt_io_adapter_new_instream(krypt_instream *in)
{
    VALUE obj;
    krypt_io_adapter *adapter = krypt_io_adapter_alloc();
    adapter->in = in;
    krypt_io_adapter_set(cKryptASN1Instream, obj, adapter);
    return obj;
}

VALUE
krypt_io_adapter_new_outstream(krypt_outstream *out)
{
    VALUE obj;
    krypt_io_adapter *adapter = krypt_io_adapter_alloc();
    adapter->out = out;
    krypt_io_adapter_set(cKryptASN1Instream, obj, adapter);
    return obj;
}

VALUE
krypt_io_adapter_new_instream_with_buffer(krypt_instream *in, size_t bufsize)
{
    VALUE obj;
    krypt_io_adapter *adapter = krypt_io_adapter_alloc();
    adapter->in = in;
    adapter->buf = ALLOC_N(uint8_t, bufsize);
    krypt_io_adapter_set(cKryptASN1Instream, obj, adapter);
    return obj;
}

VALUE
krypt_io_adapter_new_outstream_with_buffer(krypt_outstream *out, size_t bufsize)
{
    VALUE obj;
    krypt_io_adapter *adapter = krypt_io_adapter_alloc();
    adapter->out = out;
    adapter->buf = ALLOC_N(uint8_t, bufsize);
    krypt_io_adapter_set(cKryptASN1Instream, obj, adapter);
    return obj;
}

#define int_check_stream(io) 		if (!(io) || !(io)->methods) \
						    rb_raise(eKryptASN1ParseError, "Stream not initialized properly")

#define int_check_stream_has(io, m) 		if (!(io) || !(io)->methods || !(io)->methods->m) \
						    rb_raise(eKryptASN1ParseError, "Stream not initialized properly")

VALUE sKrypt_ID_SEEK_CUR, sKrypt_ID_SEEK_SET, sKrypt_ID_SEEK_END;
ID sKrypt_ID_READ, sKrypt_ID_SEEK, sKrypt_ID_WRITE, sKrypt_ID_CLOSE;
ID sKrypt_IV_IO, sKrypt_IV_IO_ADAPTER;

void
krypt_add_io_error(void)
{
    int err;
    err = krypt_last_sys_error();
    krypt_error_add("Error stream IO: %d", err);
}

/* instream */

static int
int_read_all(krypt_instream *in, VALUE vbuf, VALUE *out)
{
    uint8_t *buf;
    ssize_t r;

    buf = ALLOC_N(uint8_t, KRYPT_IO_BUF_SIZE);

    while ((r = krypt_instream_read(in, buf, KRYPT_IO_BUF_SIZE)) >= 0) {
	rb_str_buf_cat(vbuf, (const char *) buf, r);
    }

    xfree(buf);
    if (r < -1) return 0;
    *out = vbuf;
    return 1;
}

static int
int_rb_read_generic(krypt_instream *in, VALUE vlen, VALUE vbuf, VALUE *out)
{

    long len;
    size_t tlen;
    ssize_t r;
    uint8_t *buf;

    if (NIL_P(vbuf)) {
	vbuf = rb_str_new2("");
	rb_enc_associate(vbuf, rb_ascii8bit_encoding());
    }

    if (NIL_P(vlen))
	 return int_read_all(in, vbuf, out);

    len = NUM2LONG(vlen);
    if (len < 0) {
	krypt_error_add("Negative length given");
	return 0;
    }
    if ((size_t) len > SIZE_MAX) {
	krypt_error_add("Size too large: %ld", len);
	return 0;
    }

    tlen = (size_t) len;
    if (len == 0) {
	rb_str_resize(vbuf, 0);
	*out = vbuf;
	return 1;
    }

    buf = ALLOC_N(uint8_t, tlen);
    r = krypt_instream_read(in, buf, tlen);

    if (r == 0) {
	krypt_error_add("Error while reading from stream");
	xfree(buf);
	return 0;
    }
    else if (r == -1) {
	xfree(buf);
	rb_str_resize(vbuf, 0);
	*out = Qnil;
	return 1;
    }
    else {
	rb_str_buf_cat(vbuf, (const char *)buf, r);
	xfree(buf);
	*out = vbuf;
	return 1;
    }
}

int
krypt_instream_rb_read(krypt_instream *in, VALUE vlen, VALUE vbuf, VALUE *out)
{
    int_check_stream(in);

    if (in->methods->rb_read) {
	return in->methods->rb_read(in, vlen, vbuf, out);
    }
    else {
	return int_rb_read_generic(in, vlen, vbuf, out);
    }
}

ssize_t 
krypt_instream_read(krypt_instream *in, uint8_t *buf, size_t len)
{
    int_check_stream_has(in, read);

    if (len > SSIZE_MAX) {
	krypt_error_add("Size too large: %ld", len);
	return -2;
    }
    return in->methods->read(in, buf, len);
}

static ssize_t
int_gets_generic(krypt_instream *in, char *line, size_t len)
{
    ssize_t ret = 0, r = 0;
    char *p = line;
    char *end = line + len;

    if (!line) return -2;

    while (p < end) {
	if ((r = in->methods->read(in, (uint8_t *) p, 1)) < 0)
	    break;
	if (r == 1) {
	    if (*p == '\n')
		break;
	    p++;
	    ret++;
	}
    }

    if (r < -1) return -2;
    if (ret == 0 && r == -1)
	return -1;

    /* normalize CRLF */
    if (*p == '\n' && *(p - 1) == '\r')
       ret--;	

    return ret;
}

ssize_t
krypt_instream_gets(krypt_instream *in, char *line, size_t len)
{
    int_check_stream(in);
    if (len > SSIZE_MAX) {
	krypt_error_add("Size too large: %ld", len);
	return -2;
    }
    if (in->methods->gets) {
	return in->methods->gets(in, line, len);
    }
    else {
	return int_gets_generic(in, line, len);
    }
}

int
krypt_instream_seek(krypt_instream *in, off_t offset, int whence)
{
    int_check_stream_has(in, seek);
    return in->methods->seek(in, offset, whence);
}

void
krypt_instream_mark(krypt_instream *in)
{
    int_check_stream(in);
    if (in->methods->mark)
	in->methods->mark(in);
}

void
krypt_instream_free(krypt_instream *in)
{
    int_check_stream(in);
    if (in->methods->free)
	in->methods->free(in);
    xfree(in);
}

static krypt_instream *
int_instream_common_new(VALUE value)
{
    int type;

    type = TYPE(value);

    if (type == T_STRING) {
	return krypt_instream_new_bytes((uint8_t *)RSTRING_PTR(value), RSTRING_LEN(value));
    }
    else {
	if (type == T_FILE) {
	    return krypt_instream_new_fd_io(value);
	}
	else if (rb_respond_to(value, sKrypt_ID_READ)) {
	    return krypt_instream_new_io_generic(value);
	}
    }
    return NULL;
}

krypt_instream *
krypt_instream_new_value(VALUE value)
{
    return int_instream_common_new(value);
}

krypt_instream *
krypt_instream_new_value_der(VALUE value)
{
    krypt_instream *in;

    if (!(in = int_instream_common_new(value))) {
	value = krypt_to_der_if_possible(value);
	StringValue(value);
	in = krypt_instream_new_bytes((uint8_t *)RSTRING_PTR(value), RSTRING_LEN(value));
    }

    return in;
}

krypt_instream *
krypt_instream_new_value_pem(VALUE value)
{
    krypt_instream *in;

    if (!(in = int_instream_common_new(value))) {
	value = krypt_to_pem_if_possible(value);
	StringValue(value);
	in = krypt_instream_new_bytes((uint8_t *)RSTRING_PTR(value), RSTRING_LEN(value));
    }

    return in;
}
/* end instream */

/* outstream */

ssize_t 
krypt_outstream_write(krypt_outstream *out, uint8_t *buf, size_t len)
{
    int_check_stream_has(out, write);
    if (len > SSIZE_MAX) {
	krypt_error_add("Size too large: %ld", len);
	return -1;
    }
    return out->methods->write(out, buf, len);
}

int
krypt_outstream_rb_write(krypt_outstream *out, VALUE vbuf, VALUE *ret)
{
    int_check_stream(out);

    if (out->methods->rb_write) {
	return out->methods->rb_write(out, vbuf, ret);
    }
    else {
	ssize_t w;
	w = krypt_outstream_write(out, (uint8_t *) RSTRING_PTR(vbuf), RSTRING_LEN(vbuf));
	if (w < 0) {
	    krypt_error_add("Error while writing to stream");
	    return 0;
	}
	*ret = LONG2NUM(w);
	return 1;
    }
}

void
krypt_outstream_mark(krypt_outstream *out)
{
    int_check_stream(out);
    if (out->methods->mark)
	out->methods->mark(out);
}

void
krypt_outstream_free(krypt_outstream *out)
{
    int_check_stream(out);
    if (out->methods->free)
	out->methods->free(out);
    xfree(out);
}

krypt_outstream *
krypt_outstream_new_value(VALUE value)
{
    int type;

    type = TYPE(value);

    if (type == T_FILE)
	return krypt_outstream_new_fd_io(value);
    if (rb_respond_to(value, sKrypt_ID_WRITE))
	return krypt_outstream_new_io_generic(value);
    krypt_error_add("Value cannot be converted into a stream");
    return NULL;
}

/* end outstream */

void
Init_krypt_io(void)
{
    sKrypt_ID_SEEK = rb_intern("seek");
    sKrypt_ID_READ = rb_intern("read");
    sKrypt_ID_WRITE = rb_intern("write");
    sKrypt_ID_CLOSE = rb_intern("close");

    sKrypt_IV_IO = rb_intern("@io");
    sKrypt_IV_IO_ADAPTER = rb_intern("@io_adapter");
}

void
InitVM_krypt_io(void)
{
    sKrypt_ID_SEEK_CUR = rb_const_get(rb_cIO, rb_intern("SEEK_CUR"));
    sKrypt_ID_SEEK_SET = rb_const_get(rb_cIO, rb_intern("SEEK_SET"));
    sKrypt_ID_SEEK_END = rb_const_get(rb_cIO, rb_intern("SEEK_END"));

    Init_krypt_base64();
    Init_krypt_hex();
}

