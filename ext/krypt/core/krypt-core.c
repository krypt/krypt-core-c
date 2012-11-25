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

VALUE mKrypt;
VALUE eKryptError;

ID sKrypt_ID_TO_DER, sKrypt_ID_TO_PEM;
ID sKrypt_ID_EACH;
ID sKrypt_ID_EQUALS;
ID sKrypt_ID_SORT_BANG, sKrypt_ID_SORT;

VALUE
krypt_to_der(VALUE obj)
{
    VALUE tmp;

    tmp = rb_funcall(obj, sKrypt_ID_TO_DER, 0);
    StringValue(tmp);

    return tmp;
}

VALUE
krypt_to_der_if_possible(VALUE obj)
{
    if(rb_respond_to(obj, sKrypt_ID_TO_DER))
	return krypt_to_der(obj);
    return obj;
}

VALUE
krypt_to_pem(VALUE obj)
{
    VALUE tmp;

    tmp = rb_funcall(obj, sKrypt_ID_TO_PEM, 0);
    StringValue(tmp);

    return tmp;
}

VALUE
krypt_to_pem_if_possible(VALUE obj)
{
    if(rb_respond_to(obj, sKrypt_ID_TO_PEM))
	return krypt_to_pem(obj);
    return obj;
}

void
krypt_compute_twos_complement(uint8_t *dest, uint8_t *src, size_t len)
{
    size_t i;

    for (i=0; i<len; ++i) {
	dest[i] = ~src[i];
    }
    while (dest[i - 1] == 0xff) {
	dest[i - 1] = 0x0;
	i--;
    }
    dest[i-1]++;
}

void 
Init_kryptcore(void)
{
    mKrypt = rb_path2class("Krypt");
    eKryptError = rb_path2class("Krypt::Error");

    sKrypt_ID_TO_DER = rb_intern("to_der");
    sKrypt_ID_TO_PEM = rb_intern("to_pem");
    sKrypt_ID_EACH = rb_intern("each");
    sKrypt_ID_EQUALS = rb_intern("==");
    sKrypt_ID_SORT_BANG = rb_intern("sort!");
    sKrypt_ID_SORT = rb_intern("sort");

    /* Init components */
    Init_krypt_io();
    Init_krypt_asn1();
    Init_krypt_native_provider();
    Init_krypt_digest();
}
