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

binyo_instream *
krypt_instream_new_value_der(VALUE value)
{
    binyo_instream *in;

    if (!(in = binyo_instream_new_value(value))) {
	value = krypt_to_der_if_possible(value);
	StringValue(value);
	in = binyo_instream_new_bytes((uint8_t *)RSTRING_PTR(value), RSTRING_LEN(value));
    }

    return in;
}

binyo_instream *
krypt_instream_new_value_pem(VALUE value)
{
    binyo_instream *in;

    if (!(in = binyo_instream_new_value(value))) {
	value = krypt_to_pem_if_possible(value);
	StringValue(value);
	in = binyo_instream_new_bytes((uint8_t *)RSTRING_PTR(value), RSTRING_LEN(value));
    }

    return in;
}

void
Init_krypt_io(void)
{
    Init_krypt_base64();
    Init_krypt_hex();
}

