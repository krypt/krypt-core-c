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

size_t krypt_pem_get_last_name(binyo_instream *instream, uint8_t **out);
void krypt_pem_continue_stream(binyo_instream *instream);

void Init_krypt_io(void);

#endif /* _KRYPT_IO_H_ */

