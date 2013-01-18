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

#if !defined(_KRYPT_ASN1_TEMPLATE_H_)
#define _KRYPT_ASN1_TEMPLATE_H_

extern ID sKrypt_ID_OPTIONS, sKrypt_ID_NAME, sKrypt_ID_TYPE,
          sKrypt_ID_CODEC, sKrypt_ID_LAYOUT, sKrypt_ID_MIN_SIZE;

extern ID sKrypt_ID_DEFAULT,  sKrypt_ID_OPTIONAL, sKrypt_ID_TAG, sKrypt_ID_TAGGING;
 
extern ID sKrypt_ID_DEFAULT, sKrypt_ID_NAME, sKrypt_ID_TYPE,
	  sKrypt_ID_OPTIONAL, sKrypt_ID_TAG, sKrypt_ID_TAGGING,
   	  sKrypt_ID_LAYOUT, sKrypt_ID_MIN_SIZE, sKrypt_ID_CODEC;

extern ID sKrypt_ID_PRIMITIVE, sKrypt_ID_SEQUENCE, sKrypt_ID_SET, sKrypt_ID_TEMPLATE,
   	  sKrypt_ID_SEQUENCE_OF, sKrypt_ID_SET_OF, sKrypt_ID_CHOICE, sKrypt_ID_ANY;

extern ID sKrypt_IV_VALUE, sKrypt_IV_DEFINITION, sKrypt_IV_OPTIONS;

extern ID sKrypt_ID_MERGE;

extern VALUE mKryptASN1Template;

VALUE krypt_asn1_template_parse_der(VALUE klass, VALUE der);
VALUE krypt_asn1_template_to_der(VALUE templ);

void Init_krypt_asn1_template(void);

#endif /*_KRYPT_ASN1_TEMPLATE_H_ */

