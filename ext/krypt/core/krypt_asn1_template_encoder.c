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
#include "krypt_asn1-internal.h"
#include "krypt_asn1_template-internal.h"

int
int_template_encode_non_cached(VALUE self, krypt_asn1_template *template, VALUE *out)
{
    return KRYPT_ERR;
}

int
int_template_encode_cached(krypt_asn1_object *object, VALUE *value)
{
    binyo_outstream *out;
    uint8_t *bytes;
    size_t len;
    int ret;

    len = object->header->tag_len + object->header->length_len + object->bytes_len;
    bytes = ALLOCA_N(uint8_t, len);
    out = binyo_outstream_new_bytes_prealloc(bytes, len);

    ret = krypt_asn1_object_encode(out, object);
    binyo_outstream_free(out);
    if (ret == KRYPT_ERR) return KRYPT_ERR;
    *value = rb_str_new((const char *) bytes, len);
    return KRYPT_OK;
}

int
krypt_asn1_template_encode(VALUE self, VALUE *out)
{
    krypt_asn1_template *template;
    krypt_asn1_object *object;
    int has_cached_encoding;

    krypt_asn1_template_get(self, template);
    object = template->object;

    has_cached_encoding = object && (object->bytes || object->bytes_len == 0)
                                 && object->header->tag_bytes && object->header->length_bytes;
    
    if (has_cached_encoding)
	return int_template_encode_cached(object, out);
    else
	return int_template_encode_non_cached(self, template, out);
}

