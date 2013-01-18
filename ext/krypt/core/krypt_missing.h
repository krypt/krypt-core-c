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

#ifndef _KRYPT_MISSING_H_
#define _KRYPT_MISSING_H_

#include RUBY_EXTCONF_H

#ifndef HAVE_RB_ENUMERATORIZE
#define KRYPT_RETURN_ENUMERATOR(enumerable, id)						\
do {											\
    if (!rb_block_given_p())								\
    	return rb_funcall((enumerable), rb_intern("enum_for"), 1, ID2SYM((id)));	\
} while (0) 
#else
#define KRYPT_RETURN_ENUMERATOR(enumerable, id)						\
do {											\
    if(!rb_block_given_p())								\
    	RETURN_ENUMERATOR((enumerable), 0, 0);						\
} while (0)
#endif

#ifndef HAVE_RB_STR_ENCODE
VALUE rb_str_encode(VALUE str, VALUE to, int ecflags, VALUE ecopts);
#endif

#ifndef HAVE_GMTIME_R
#include <time.h>
struct tm *krypt_gmtime_r(const time_t *tp, struct tm *result);
#define gmtime_r(t, tm)				krypt_gmtime_r((t), (tm))
#endif

int krypt_asn1_encode_bignum(VALUE bignum, uint8_t **out, size_t *len);
int krypt_asn1_decode_bignum(uint8_t *bytes, size_t len, VALUE *out);

#endif /* KRYPT_MISSING_H */

