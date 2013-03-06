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

#if !defined(_KRYPT_CORE_H_)
#define _KRYPT_CORE_H_

#include RUBY_EXTCONF_H

#if defined(__cplusplus)
extern "C" {
#endif

#define RSTRING_NOT_MODIFIED 1
#define RUBY_READONLY_STRING 1

#include <ruby.h>

#if defined(HAVE_RUBY_IO_H)
#include <ruby/io.h>
#endif

/* This is just a precaution to take remind us of thread safety
 * issues in case there would be no GVL */ 
#ifndef InitVM
#define InitVM(ext) {void InitVM_##ext(void);InitVM_##ext();}
#endif

extern VALUE mKrypt;
extern VALUE eKryptError;

extern ID sKrypt_ID_TO_DER;
extern ID sKrypt_ID_TO_PEM;
extern ID sKrypt_ID_EACH;
extern ID sKrypt_ID_EQUALS;
extern ID sKrypt_ID_SORT_BANG;
extern ID sKrypt_ID_SORT;

/** krypt-core headers **/
#include "krypt_error.h"
#include "krypt_missing.h"
#include "krypt_io.h"
#include "krypt_asn1.h"
#include "krypt_asn1_template.h"

VALUE krypt_to_der_if_possible(VALUE obj);
VALUE krypt_to_der(VALUE obj);
VALUE krypt_to_pem_if_possible(VALUE obj);
VALUE krypt_to_pem(VALUE obj);

/* internal Base64 en-/decoder */
#include "krypt_b64-internal.h"

/* internal hex en-/decoder */
#include "krypt_hex-internal.h"

/* helper for integer encoding/decoding */
void krypt_compute_twos_complement(uint8_t *dest, uint8_t *src, size_t len);

void Init_kryptcore(void);

#if defined(__cplusplus)
}
#endif

#endif /* _KRYPT_CORE_H_ */


