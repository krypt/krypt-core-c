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

#ifndef _KRYPT_PROVIDER_H_
#define _KRYPT_PROVIDER_H_


#ifndef _RSTRING_NOT_MODIFIED
#define RSTRING_NOT_MODIFIED 1
#endif

#ifndef RUBY_READONLY_STRING
#define RUBY_READONLY_STRING 1
#endif

#include <ruby.h>

#ifndef KRYPT_OK
#define KRYPT_OK 1
#endif
#ifndef KRYPT_ERR
#define KRYPT_ERR -1
#endif

typedef struct krypt_provider_st krypt_provider;

/* Message digest */
typedef struct krypt_interface_md_st krypt_interface_md;

typedef struct krypt_md_st {
    krypt_provider *provider;
    krypt_interface_md *methods;
} krypt_md;

struct krypt_interface_md_st {
    int (*md_reset)(krypt_md *md);
    int (*md_update)(krypt_md *md, const void *data, size_t len);
    int (*md_final)(krypt_md *md, uint8_t ** digest, size_t *len);
    int (*md_digest)(krypt_md *md, const uint8_t *data, size_t len, uint8_t **digest, size_t *digest_len);
    int (*md_digest_length)(krypt_md *md, size_t *len);
    int (*md_block_length)(krypt_md *md, size_t *block_len);
    int (*md_name)(krypt_md *md, const char **name);
    void (*mark)(krypt_md *md);
    void (*free)(krypt_md *md);
};

/* Provider */
struct krypt_provider_st {
    const char *name;
    krypt_md *(*md_new_oid)(krypt_provider *provider, const char *oid);
    krypt_md *(*md_new_name)(krypt_provider *provider, const char *name);
};

/* Can be called from within a provider implementation to indicate errors */
void krypt_error_add(const char * format, ...);

/* May be used to register a singleton provider upon initialization */
void krypt_provider_register(krypt_provider *provider);

#endif /* _KRYPT_PROVIDER_H_ */

