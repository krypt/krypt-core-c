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

VALUE mKryptProvider;
VALUE cKryptNativeProvider;

static ID sKrypt_ID_register, sKrypt_ID_new_service;

static void
int_krypt_native_provider_mark(krypt_provider *provider)
{
    if (!provider) return;

    /*TODO*/
}

static void
int_krypt_native_provider_free(krypt_provider *provider)
{
    if (!provider) return;

    /*TODO*/
}

#define int_krypt_native_provider_set(klass, obj, provider) 	\
do { 							    	\
    if (!(provider)) { 					    	\
	rb_raise(eKryptError, "Uninitialized Provider"); 	\
    } 								\
    (obj) = Data_Wrap_Struct((klass), int_krypt_native_provider_mark, int_krypt_native_provider_free, (provider)); \
} while (0)

#define int_krypt_native_provider_get(obj, provider) 		\
do { 								\
    Data_Get_Struct((obj), krypt_provider, (provider));  	\
    if (!(provider)) { 						\
	rb_raise(eKryptError, "Uninitialized Provider");	\
    } 								\
} while (0)

VALUE
krypt_native_provider_new(krypt_provider *provider)
{
    VALUE obj;
    int_krypt_native_provider_set(cKryptNativeProvider, obj, provider);
    return obj;
}

static VALUE
int_provider_digest_new(krypt_provider *provider, VALUE aryargs)
{
    VALUE vname_or_oid;
    const char *name_or_oid;
    krypt_md *md;

    if (NIL_P(aryargs)) return Qnil;
    vname_or_oid = rb_ary_entry(aryargs, 0);
    name_or_oid = StringValueCStr(vname_or_oid);
    if ((md = krypt_md_new(provider, name_or_oid))) {
	return krypt_digest_new(md);
    }
    return Qnil;
}

static VALUE
krypt_native_provider_new_service(int argc, VALUE *argv, VALUE self)
{
    VALUE service_class;
    VALUE rest = Qnil;
    krypt_provider *provider;

    rb_scan_args(argc, argv, "1*", &service_class, &rest);
    int_krypt_native_provider_get(self, provider);

    if (service_class == mKryptDigest) {
	return int_provider_digest_new(provider, rest);
    }

    return Qnil;
}

void
krypt_provider_register(krypt_provider *provider)
{
    VALUE rb_provider;
    if (!provider->name) rb_raise(eKryptError, "Provider must have a name");

    rb_provider = krypt_native_provider_new(provider);
    rb_funcall(mKryptProvider, sKrypt_ID_register, 2, rb_str_new2(provider->name), rb_provider);
}

void
Init_krypt_native_provider(void)
{
#if 0
    mKrypt = rb_define_module("Krypt"); /* Let RDoc know */
    mKryptProvider = rb_define_module_under(mKrypt, "Provider"); /* Let RDoc know */
#endif

    mKryptProvider = rb_path2class("Krypt::Provider");
    sKrypt_ID_register = rb_intern("register");
    sKrypt_ID_new_service = rb_intern("new_service");

    cKryptNativeProvider = rb_define_class_under(mKryptProvider, "NativeProvider", rb_cObject);

    rb_define_method(cKryptNativeProvider, "new_service", krypt_native_provider_new_service, -1);
    rb_undef_method(CLASS_OF(cKryptNativeProvider), "new"); /* private constructor */	
}

