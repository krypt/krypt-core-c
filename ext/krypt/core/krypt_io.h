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

#if !defined(_KRYPT_IO_H_)
#define _KRYPT_IO_H_

#include "binyo-error.h"
#include "binyo-io.h"
#include "binyo-io-buffer.h"

#include "krypt_hex.h"
#include "krypt_b64.h"

#define KRYPT_INSTREAM_TYPE_DEFINITE   	100
#define KRYPT_INSTREAM_TYPE_CHUNKED    	101
#define KRYPT_INSTREAM_TYPE_PEM	       	102

binyo_instream *krypt_instream_new_value_der(VALUE value);
binyo_instream *krypt_instream_new_value_pem(VALUE value);
binyo_instream *krypt_instream_new_chunked(binyo_instream *in, int values_only);
binyo_instream *krypt_instream_new_definite(binyo_instream *in, size_t length);
binyo_instream *krypt_instream_new_pem(binyo_instream *original);
void krypt_instream_pem_free_wrapper(binyo_instream *instream);

int krypt_pem_get_last_name(binyo_instream *instream, uint8_t **out, size_t *outlen);
void krypt_pem_continue_stream(binyo_instream *instream);

void Init_krypt_io(void);

#endif /* _KRYPT_IO_H_ */

