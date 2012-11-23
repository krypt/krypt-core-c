/*
* krypt-core API - C version
*
* Copyright (C) 2011 - 2012
* Hiroshi Nakamura <nahi@ruby-lang.org>
* Martin Bosslet <martin.bosslet@googlemail.com>
* All rights reserved.
*
* This software is distributed under the same license as Ruby.
* See the file 'LICENSE' for further details.
*/
#ifndef _KRYPT_PROVIDER_INTERNAL_H_
#define _KRYPT_PROVIDER_INTERNAL_H_

extern VALUE mKryptProvider;
extern VALUE cKryptNativeProvider;

/* Implements the boilerplate to connect the native provider to Ruby world */
VALUE krypt_native_provider_new(krypt_provider *provider);

void Init_krypt_native_provider(void);

#endif /* _KRYPT_PROVIDER_INTERNAL_H_ */
