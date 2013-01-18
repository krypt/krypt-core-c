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

#ifndef _KRYPT_DIGEST_H_
#define _KRYPT_DIGEST_H_

extern VALUE mKryptDigest;
extern VALUE eKryptDigestError;

extern VALUE cKryptNativeDigest;

krypt_md *krypt_md_new(krypt_provider *provider, const char *name_or_oid);
krypt_md *krypt_md_oid_new(krypt_provider *provider, const char *oid);
krypt_md *krypt_md_name_new(krypt_provider *provider, const char *name);

int krypt_md_update(krypt_md *md, const void *data, size_t len);
int krypt_md_final(krypt_md *md, uint8_t **digest, size_t *len);
int krypt_md_digest(krypt_md *md, const uint8_t *data, size_t len, uint8_t **digest, size_t *digest_len);
void krypt_md_mark(krypt_md *md);
void krypt_md_free(krypt_md *md);

VALUE krypt_digest_new(krypt_md *md);

void Init_krypt_digest(void);

#endif /* _KRYPT_DIGEST_H_ */
