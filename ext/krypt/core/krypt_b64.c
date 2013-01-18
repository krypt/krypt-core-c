/*
 * krypt-core API - C implementation
 *
 * Copyright (c) 2011-2013
 * Hiroshi Nakamura <nahi@ruby-lang.org>
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

#include "krypt-core.h"

VALUE mKryptBase64;
VALUE cKryptBase64Encoder;
VALUE cKryptBase64Decoder;
VALUE eKryptBase64Error;

static const char krypt_b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char krypt_b64_table_inv[] = {
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,-1,
0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,
-1,-1,-1,-1,-1,-1,
26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51};
static uint8_t krypt_b64_separator[] = { '\r', '\n' };

static uint8_t krypt_b64_out_buf[4];
static uint8_t krypt_b64_in_buf[3];

#define KRYPT_BASE64_INV_MAX 123
#define KRYPT_BASE64_DECODE 0
#define KRYPT_BASE64_ENCODE 1

#define int_compute_int(res, b, i)					\
do {									\
    (res) = ((b)[(i)] << 16) | ((b)[(i)+1] << 8) | ((b)[(i)+2]);	\
} while(0)

static inline void
int_encode_int(int n)
{
    krypt_b64_out_buf[0] = krypt_b64_table[(n >> 18) & 0x3f];
    krypt_b64_out_buf[1] = krypt_b64_table[(n >> 12) & 0x3f];
    krypt_b64_out_buf[2] = krypt_b64_table[(n >> 6) & 0x3f];
    krypt_b64_out_buf[3] = krypt_b64_table[n & 0x3f];
}

static int
int_write_int(binyo_outstream *out, int n)
{
    int_encode_int(n);
    if (binyo_outstream_write(out, krypt_b64_out_buf, 4) == BINYO_ERR)
	return KRYPT_ERR;
    return KRYPT_OK;
}

static int
int_write_update(binyo_outstream *out, uint8_t *bytes, size_t off, size_t len)
{
    size_t i;
    int n;

    for (i=0; i < len; i+=3) {
	int_compute_int(n, bytes, off + i);
	if (int_write_int(out, n) == KRYPT_ERR) return KRYPT_ERR;
    }	
    return KRYPT_OK;
}

static int
int_write_update_cols(binyo_outstream *out, uint8_t *bytes, size_t off, size_t len, int cols)
{
    size_t i;
    int n, linepos = 0;

    for (i=0; i < len; i+=3) {
	int_compute_int(n, bytes, off + i);
	if (int_write_int(out, n) == KRYPT_ERR) return KRYPT_ERR;
	linepos += 4;
	if (linepos >= cols) {
	    if (binyo_outstream_write(out, krypt_b64_separator, 2) == BINYO_ERR)
		return KRYPT_ERR;
	    linepos = 0;
	}
    }
    return KRYPT_OK;
}

static inline void
int_encode_final(uint8_t *bytes, int remainder)
{
    int n;
    
    n = (bytes[0] << 16) | (remainder == 2 ? bytes[1] << 8 : 0);
    krypt_b64_out_buf[0] = krypt_b64_table[(n >> 18) & 0x3f];
    krypt_b64_out_buf[1] = krypt_b64_table[(n >> 12) & 0x3f];
    krypt_b64_out_buf[2] = remainder == 2 ? krypt_b64_table[(n >> 6) & 0x3f] : '=';
    krypt_b64_out_buf[3] = '=';
}

static int
int_write_final(binyo_outstream *out, uint8_t *bytes, int remainder, int crlf)
{
    if (remainder) {
	int_encode_final(bytes, remainder);
	if (binyo_outstream_write(out, krypt_b64_out_buf, 4) == BINYO_ERR)
	    return KRYPT_ERR;
    }
    if (crlf) {
	if (binyo_outstream_write(out, krypt_b64_separator, 2) == BINYO_ERR)
	    return KRYPT_ERR;
    }
    return 1;
}

int
krypt_base64_buffer_encode_to(binyo_outstream *out, uint8_t *bytes, size_t off, size_t len, int cols)
{
    int remainder;

    if (!bytes || !out) return KRYPT_ERR;

    remainder = len % 3;
    if (cols < 0) {
	if (int_write_update(out, bytes, off, len - remainder) == KRYPT_ERR) return KRYPT_ERR;
    } else {
	if (int_write_update_cols(out, bytes, off, len - remainder, cols) == KRYPT_ERR) return KRYPT_ERR;
    }

    if (int_write_final(out, bytes + len - remainder, remainder, cols > 0) == KRYPT_ERR) return KRYPT_ERR;
    return KRYPT_OK;
}

int
krypt_base64_encode(uint8_t *bytes, size_t len, int cols, uint8_t **out, size_t *outlen)
{
    size_t retlen; 
    binyo_outstream *outstream;

    if (!bytes) return KRYPT_ERR;
    if ( (len / 3 + 1) > (SIZE_MAX / 4) ) {
	krypt_error_add("Buffer too large: %ld", len);
	return KRYPT_ERR;
    }

    /* this is the maximum value, no exactness needed, we'll resize anyway */
    retlen = 4 * (len / 3 + 1); 

    /* Add the number of new line characters */
    if (cols > 0) {
	if ( (len / cols * 2) > SIZE_MAX - retlen ) {
	    krypt_error_add("Buffer too large: %ld", len);
	    return KRYPT_ERR;
	}
	retlen += len / cols * 2;
    }

    outstream = binyo_outstream_new_bytes_size(retlen);
    if (krypt_base64_buffer_encode_to(outstream, bytes, 0, len, cols) == KRYPT_ERR) {
	binyo_outstream_free(outstream);
	return KRYPT_ERR;
    }
    retlen = binyo_outstream_bytes_get_bytes_free(outstream, out);

    if (retlen > SIZE_MAX) {
	krypt_error_add("Return value too large");
	xfree(*out);
	*out = NULL;
       	return KRYPT_ERR;
    }
    *outlen = retlen;
    return KRYPT_OK;
}

static inline void
int_decode_int(int n)
{
    krypt_b64_in_buf[0] = (n >> 16) & 0xff;
    krypt_b64_in_buf[1] = (n >> 8) & 0xff;
    krypt_b64_in_buf[2] = n & 0xff;
}

static int
int_read_int(binyo_outstream *out, int n)
{
    int_decode_int(n);
    if (binyo_outstream_write(out, krypt_b64_in_buf, 3) == BINYO_ERR)
	return KRYPT_ERR;
    return KRYPT_OK;
}

static inline void
int_decode_final(int n, int remainder)
{
    switch (remainder) {
	/* 2 of 4 bytes are to be discarded. 
	 * 2 bytes represent 12 bits of meaningful data -> 1 byte plus 4 bits to be dropped */ 
	case 2:
	    krypt_b64_in_buf[0] = (n >> 4) & 0xff;
	    break;
	/* 1 of 4 bytes are to be discarded.
	 * 3 bytes represent 18 bits of meaningful data -> 2 bytes plus 2 bits to be dropped */
	case 3:
	    n >>= 2;
	    krypt_b64_in_buf[0] = (n >> 8) & 0xff;
	    krypt_b64_in_buf[1] = n & 0xff;
	    break;
    }
}

static int
int_read_final(binyo_outstream *out, int n, int remainder)
{
    int_decode_final(n, remainder);
    if (remainder > 1) {
	if (binyo_outstream_write(out, krypt_b64_in_buf, remainder - 1) == BINYO_ERR) return KRYPT_ERR;
    }
    return KRYPT_OK;
}

int
krypt_base64_buffer_decode_to(binyo_outstream *out, uint8_t *bytes, size_t off, size_t len)
{
    size_t i;
    int n = 0;
    int remainder = 0;
    char inv;

    if (len > SIZE_MAX - off) {
	krypt_error_add("Buffer too large: %ld", len);
	return KRYPT_ERR;
    }

    for (i=0; i < len; i++) {
	uint8_t b = bytes[off + i];
	if (b == '=')
	   break;
	if (b > KRYPT_BASE64_INV_MAX)
	   continue;
	inv = krypt_b64_table_inv[b];
	if (inv < 0)
	    continue;
	n = (n << 6) | inv;
	remainder = (remainder + 1) % 4;
	if (remainder == 0) {
	    if (int_read_int(out, n) == KRYPT_ERR) return KRYPT_ERR;
	}
    }

    if (remainder && (int_read_final(out, n, remainder) == KRYPT_ERR)) return KRYPT_ERR;
    return KRYPT_OK;
}
	
int
krypt_base64_decode(uint8_t *bytes, size_t len, uint8_t **out, size_t *outlen)
{
    size_t retlen;
    binyo_outstream *outstream;

    if (!bytes) return KRYPT_ERR;

    /* Approximate, will resize anyway */
    retlen = len / 4 * 3;

    outstream = binyo_outstream_new_bytes_size(retlen);
    if (krypt_base64_buffer_decode_to(outstream, bytes, 0, len) == KRYPT_ERR) {
	binyo_outstream_free(outstream);
	return KRYPT_ERR;
    }
    retlen = binyo_outstream_bytes_get_bytes_free(outstream, out);
    if (retlen > SSIZE_MAX) {
	xfree(*out);
	*out = NULL;
       	return KRYPT_ERR;
    }
    *outlen = retlen;
    return KRYPT_OK;
}

/* Krypt::Base64 */

/**
 * call-seq:
 *    Krypt::Base64.decode(data) -> String
 *
 * Decodes a Base64-encoded string of +data+, which need not necessarily be
 * a String, but must allow a conversion with to_str.
 */
static VALUE
krypt_base64_module_decode(VALUE self, VALUE data)
{
    VALUE ret;
    size_t len;
    size_t result_len;
    uint8_t *bytes;
    uint8_t *result = NULL;

    StringValue(data);
    len = (size_t) RSTRING_LEN(data);
    bytes = (uint8_t *) RSTRING_PTR(data);

    if (krypt_base64_decode(bytes, len, &result, &result_len) == KRYPT_ERR)
	krypt_error_raise(eKryptBase64Error, "Processing the value failed.");

    ret = rb_str_new((const char *) result, result_len);
    xfree(result);
    return ret;
}

/**
 * call-seq:
 *    Krypt::Base64.encode(data, [cols=nil]) -> String
 *
 * Encodes a String, or an object allowing conversion with to_str, in Base64
 * encoding. The optional +cols+ is an Integer parameter that may be used to
 * specify the line length of the resulting Base64 string. As the result is
 * being constructed in chunks of 4 characters at a time, a value of +cols+
 * that is not a multiple of 4 will result in line feeds after the next higher
 * multiple of 4 - for example, if +cols+ is specified as 22, then the result
 * will have line feeds after every 24 characters of output.
 */
static VALUE
krypt_base64_module_encode(int argc, VALUE *argv, VALUE self)
{
    VALUE data;
    VALUE cols = Qnil;
    VALUE ret;
    int c;
    size_t len;
    size_t result_len;
    uint8_t *bytes;
    uint8_t *result = NULL;

    rb_scan_args(argc, argv, "11", &data, &cols);

    if (NIL_P(data))
	rb_raise(eKryptBase64Error, "Data must not be nil");
    if (NIL_P(cols))
	c = -1;
    else
	c = NUM2INT(cols);

    StringValue(data);
    len = (size_t) RSTRING_LEN(data);
    bytes = (uint8_t *) RSTRING_PTR(data);

    if (krypt_base64_encode(bytes, len, c, &result, &result_len) == KRYPT_ERR)
	krypt_error_raise(eKryptBase64Error, "Processing the value failed.");

    ret = rb_str_new((const char *) result, result_len);
    rb_enc_associate(ret, rb_ascii8bit_encoding());
    xfree(result);
    return ret;
}

/* End Krypt::Base64 */

void
Init_krypt_base64(void)
{
#if 0
    mKrypt = rb_define_module("Krypt"); /* Let RDoc know */
#endif

    mKryptBase64 = rb_define_module_under(mKrypt, "Base64");

    eKryptBase64Error = rb_define_class_under(mKryptBase64, "Base64Error", eKryptError);

    rb_define_module_function(mKryptBase64, "decode", krypt_base64_module_decode, 1);
    rb_define_module_function(mKryptBase64, "encode", krypt_base64_module_encode, -1);
}

