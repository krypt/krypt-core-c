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

ID sID_TO_DER;
ID sID_EACH;

VALUE
krypt_to_der(VALUE obj)
{
    VALUE tmp;

    tmp = rb_funcall(obj, sID_TO_DER, 0);
    StringValue(tmp);

    return tmp;
}

VALUE
krypt_to_der_if_possible(VALUE obj)
{
    if(rb_respond_to(obj, sID_TO_DER))
	return krypt_to_der(obj);
    return obj;
}

void 
Init_kryptcore(void)
{
    mKrypt = rb_define_module("Krypt");

    eKryptError = rb_define_class_under(mKrypt, "KryptError", rb_eStandardError);

    sID_TO_DER = rb_intern("to_der");
    sID_EACH = rb_intern("each");

    /* Init components */
    Init_krypt_io();
    Init_krypt_asn1();

    /* Init per VM */
    InitVM(kryptcore);
}

void
InitVM_kryptcore(void)
{
    InitVM_krypt_io();
}
