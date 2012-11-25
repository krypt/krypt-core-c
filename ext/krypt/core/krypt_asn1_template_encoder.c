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
#include "krypt_asn1-internal.h"
#include "krypt_asn1_template-internal.h"

int
int_template_encode_non_cached(VALUE self, krypt_asn1_template *template, VALUE *out)
{
    return 0;
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

    if ((ret = krypt_asn1_object_encode(out, object))) {
	*value = rb_str_new((const char *) bytes, len);
    }

    binyo_outstream_free(out);
    return ret;
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

