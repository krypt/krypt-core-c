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

VALUE cKryptASN1Instream;

typedef struct krypt_instream_adapter_st {
    binyo_instream *in;
} krypt_instream_adapter;

static void
int_instream_adapter_mark(krypt_instream_adapter *adapter)
{
    if (!adapter) return;

    binyo_instream_mark(adapter->in);
}

static void
int_instream_adapter_free(krypt_instream_adapter *adapter)
{
    if (!adapter) return;

    binyo_instream_free(adapter->in);
    xfree(adapter);
}

#define int_krypt_instream_adapter_set(klass, obj, adapter) 	\
do { 							    	\
    if (!(adapter)) { 					    	\
	rb_raise(eKryptError, "Uninitialized Adapter"); 	\
    } 								\
    (obj) = Data_Wrap_Struct((klass), int_instream_adapter_mark, int_instream_adapter_free, (adapter)); \
} while (0)

#define int_krypt_instream_adapter_get(obj, adapter) 		\
do { 								\
    Data_Get_Struct((obj), krypt_instream_adapter, (adapter));  \
    if (!(adapter)) { 						\
	rb_raise(eKryptError, "Uninitialized Adapter");		\
    } 								\
} while (0)

VALUE
krypt_instream_adapter_new(binyo_instream *in)
{
    VALUE obj;
    krypt_instream_adapter *adapter;

    adapter = ALLOC(krypt_instream_adapter);
    adapter->in = in;
    int_krypt_instream_adapter_set(cKryptASN1Instream, obj, adapter);
    return obj;
}

/**
 * call-seq:
 *    in.read([len=nil], [buf=nil]) -> String or nil
 *
 * Please see IO#read for details.
 */
static VALUE
krypt_instream_adapter_read(int argc, VALUE *argv, VALUE self)
{
    krypt_instream_adapter *adapter;
    VALUE ret;
    VALUE vlen = Qnil;
    VALUE vbuf = Qnil;

    rb_scan_args(argc, argv, "02", &vlen, &vbuf);

    int_krypt_instream_adapter_get(self, adapter);

    if (binyo_instream_rb_read(adapter->in, vlen, vbuf, &ret) == BINYO_ERR)
	rb_raise(eKryptError, "Error reading stream");
    return ret;
}

static int 
int_whence_for(VALUE vwhence)
{
    ID whence;
   
    if (!SYMBOL_P(vwhence))
	rb_raise(rb_eArgError, "whence must be a Symbol");

    whence = SYM2ID(vwhence);
    if (whence == sBinyo_ID_SEEK_CUR)
	return SEEK_CUR;
    else if (whence == sBinyo_ID_SEEK_SET)
	return SEEK_SET;
    else if (whence == sBinyo_ID_SEEK_END)
	return SEEK_END;
    else
	rb_raise(eKryptASN1ParseError, "Unknown whence");
    
    return Qnil; /* dummy */
}

/**
 * call-seq:
 *    in.seek(n, [whence=:SEEK_SET]) -> 0
 *
 * Please see IO#seek for details.
 */
static VALUE
krypt_instream_adapter_seek(int argc, VALUE *argv, VALUE self)
{
    VALUE n, vwhence = sBinyo_ID_SEEK_SET;
    int whence;
    krypt_instream_adapter *adapter;

    rb_scan_args(argc, argv, "11", &n, &whence);

    int_krypt_instream_adapter_get(self, adapter);
    whence = int_whence_for(vwhence);
    if (binyo_instream_seek(adapter->in, NUM2INT(n), whence) == BINYO_ERR)
        rb_raise(eKryptASN1ParseError, "Seek failed");

    return INT2FIX(0); /* same as rb_io_seek */
}

void
Init_krypt_instream_adapter(void)
{
#if 0
    mKrypt = rb_define_module("Krypt");
    mKryptASN1 = rb_define_module_under(mKrypt, "ASN1"); /* Let RDoc know */ 
#endif

    /**
     * Document-class: Krypt::ASN1::Instream
     *
     * Acts as a drop-in replacement for an IO. It cannot be instantiated on
     * its own, instances may be obtained by calling Header#value_io. Instream
     * supports a reduced subset of the interface defined by IO.
     *
     * == Example usage
     *
     * === Reading the contents of an Instream
     *   der_io = # some IO representing a DER-encoded ASN.1 value 
     *   parser = Krypt::ASN1::Parser.new
     *   token = parser.next(der_io)
     *   instream = token.value_io
     *   value = instream.read # contains the raw bytes of the token's value
     */
    cKryptASN1Instream = rb_define_class_under(mKryptASN1, "Instream", rb_cObject);
    rb_define_method(cKryptASN1Instream, "read", krypt_instream_adapter_read, -1);
    rb_define_method(cKryptASN1Instream, "seek", krypt_instream_adapter_seek, -1);
    rb_undef_method(CLASS_OF(cKryptASN1Instream), "new"); /* private constructor */	
}

