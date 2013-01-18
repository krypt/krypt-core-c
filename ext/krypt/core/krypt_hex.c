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

VALUE mKryptHex;
VALUE cKryptHexEncoder;
VALUE cKryptHexDecoder;
VALUE eKryptHexError;

static const char krypt_hex_table[] = "0123456789abcdef";
static const char krypt_hex_table_inv[] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,-1,-1,
    -1,-1,-1,-1,-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,10,11,12,
    13,14,15
};

#define KRYPT_HEX_INV_MAX 102
#define KRYPT_HEX_DECODE 0
#define KRYPT_HEX_ENCODE 1

static int
int_hex_encode(uint8_t *bytes, size_t len, uint8_t *out)
{
    size_t i;
    uint8_t b;
    size_t j;
   
    for (i=0; i < len; i++) {
	b = bytes[i];
	j = i * 2;
	out[j] = krypt_hex_table[b >> 4];
	out[j + 1] = krypt_hex_table[b & 0x0f];
    }
    return KRYPT_OK;
}

static int
int_hex_decode(uint8_t *bytes, size_t len, uint8_t *out)
{
    size_t i;
    char b;
    uint8_t c, d;

    for (i=0; i < len / 2; i++) {
	c = (uint8_t) bytes[i*2];
	d = (uint8_t) bytes[i*2+1];
	if (c > KRYPT_HEX_INV_MAX || d > KRYPT_HEX_INV_MAX) {
	    krypt_error_add("Illegal hex character detected: %x or %x", c, d);
	    return KRYPT_ERR;
	}
	b = krypt_hex_table_inv[c];
	if (b < 0) {
	    krypt_error_add("Illegal hex character detected: %x", c);
	    return KRYPT_ERR;
	}
	out[i] = b << 4;
	b = krypt_hex_table_inv[d];
	if (b < 0) {
	    krypt_error_add("Illegal hex character detected: %x", d);
	    return KRYPT_ERR;
	}
	out[i] |= b;
    }
    return KRYPT_OK;
}

#define int_hex_encode_tests(bytes, len, tmp)				\
do {									\
    if (!(bytes)) {							\
	(tmp) = KRYPT_ERR;						\
    }									\
    if ((len) > SSIZE_MAX / 2) {					\
	krypt_error_add("Buffer too large: %ld", (len));		\
	(tmp) = KRYPT_ERR;						\
    }									\
} while (0)

int
krypt_hex_encode(uint8_t *bytes, size_t len, uint8_t **out, size_t *outlen)
{
    size_t ret;
    uint8_t *retval;
    int tmp = 0;

    int_hex_encode_tests(bytes, len, tmp);
    if (tmp == KRYPT_ERR) return KRYPT_ERR;

    ret = 2 * len;
    retval = ALLOC_N(uint8_t, ret);
    if (int_hex_encode(bytes, len, retval) == KRYPT_ERR) {
	xfree(retval);
	return KRYPT_ERR;
    }

    *out = retval;
    *outlen = ret;
    return KRYPT_OK;
}

#define int_hex_decode_tests(bytes, len, tmp)				\
do {									\
    if (!(bytes)) {							\
	(tmp) = KRYPT_ERR;						\
    }									\
    if ((len) % 2) {							\
	krypt_error_add("Buffer length must be a multiple of 2");	\
	(tmp) = KRYPT_ERR;						\
    }									\
    if ((len) / 2 > SSIZE_MAX) {					\
	krypt_error_add("Buffer too large: %ld", (len));		\
	(tmp) = KRYPT_ERR;						\
    }									\
} while (0)

int
krypt_hex_decode(uint8_t *bytes, size_t len, uint8_t **out, size_t *outlen)
{
    size_t ret;
    uint8_t *retval;
    int tmp = 0;
    
    int_hex_decode_tests(bytes, len, tmp);
    if (tmp == KRYPT_ERR) return KRYPT_ERR;

    ret = len / 2;
    retval = ALLOC_N(uint8_t, ret);
    if (int_hex_decode(bytes, len, retval) == KRYPT_ERR) {
	xfree(retval);
	return KRYPT_ERR;
    }
    *out = retval;
    *outlen = ret;
    return KRYPT_OK;
}

/* Krypt::Hex */

#define int_hex_process(bytes, len, mode, ret)					\
do {										\
    ssize_t result_len;								\
    uint8_t *result;								\
    int tmp = 0;								\
    if (!(bytes))								\
        krypt_error_raise(eKryptHexError, "Bytes null");			\
    if ((mode) == KRYPT_HEX_DECODE) {						\
	int_hex_decode_tests((bytes), (len), tmp);				\
	if (tmp == KRYPT_ERR)							\
	    krypt_error_raise(eKryptHexError, "Decoding the value failed");	\
	result_len = (len) / 2;							\
    	result = ALLOCA_N(uint8_t, result_len);					\
	tmp = int_hex_decode((bytes), (len), result);				\
    } else if ((mode) == KRYPT_HEX_ENCODE) {					\
	int_hex_encode_tests((bytes), (len), tmp);				\
	if (tmp == KRYPT_ERR)							\
	    krypt_error_raise(eKryptHexError, "Encoding the value failed");	\
	result_len = (len) * 2;							\
	result = ALLOCA_N(uint8_t, result_len);					\
	tmp = int_hex_encode((bytes), (len), result);				\
    } else {									\
	krypt_error_raise(rb_eRuntimeError, "Internal error");			\
    }										\
    if (tmp == KRYPT_ERR)							\
	krypt_error_raise(eKryptHexError, "Processing the hex value failed."); 	\
    (ret) = rb_str_new((const char *) result, result_len);			\
} while (0)

/**
 * call-seq:
 *    Krypt::Hex.decode(data) -> String
 *
 * Decodes a hex-encoded string of +data+, which need not necessarily be
 * a String, but must allow a conversion with to_str.
 */
static VALUE
krypt_hex_module_decode(VALUE self, VALUE data)
{
    VALUE ret;
    uint8_t *bytes;
    size_t len;

    StringValue(data);
    len = (size_t) RSTRING_LEN((data));
    bytes = (uint8_t *) RSTRING_PTR((data));
    int_hex_process(bytes, len, KRYPT_HEX_DECODE, ret);
    return ret;
}

/**
 * call-seq:
 *    Krypt::Hex.encode(data) -> String
 *
 * Encodes +data+, a String, or an object allowing conversion with to_str,
 * in hex encoding. 
 */
static VALUE
krypt_hex_module_encode(VALUE self, VALUE data)
{
    VALUE ret;
    uint8_t *bytes;
    size_t len;

    StringValue(data);
    len = (size_t) RSTRING_LEN((data));
    bytes = (uint8_t *) RSTRING_PTR((data));
    int_hex_process(bytes, len, KRYPT_HEX_ENCODE, ret);
    rb_enc_associate(ret, rb_usascii_encoding());
    return ret;
}

/* End Krypt::Hex */

void
Init_krypt_hex(void)
{
#if 0
    mKrypt = rb_define_module("Krypt"); /* Let RDoc know */
#endif

    mKryptHex = rb_define_module_under(mKrypt, "Hex");

    eKryptHexError = rb_define_class_under(mKryptHex, "HexError", eKryptError);

    rb_define_module_function(mKryptHex, "decode", krypt_hex_module_decode, 1);
    rb_define_module_function(mKryptHex, "encode", krypt_hex_module_encode, 1);
}

