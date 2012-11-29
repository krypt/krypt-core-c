/*
* krypt-core API - C version
*
* Copyright (C) 2012
* Hiroshi Nakamura <nahi@ruby-lang.org>
* Martin Bosslet <martin.bosslet@googlemail.com>
* All rights reserved.
*
* This software is distributed under the same license as Ruby.
* See the file 'LICENSE' for further details.
*/

#ifndef _KRYPT_B64_INTERNAL_H
#define _KRYPT_B64_INTERNAL_H_

int krypt_base64_encode(uint8_t *bytes, size_t len, int cols, uint8_t **out, size_t *outlen);
int krypt_base64_buffer_encode_to(binyo_outstream *out, uint8_t *bytes, size_t off, size_t len, int cols);
int krypt_base64_decode(uint8_t *bytes, size_t len, uint8_t **out, size_t *outlen);
int krypt_base64_buffer_decode_to(binyo_outstream *out, uint8_t *bytes, size_t off, size_t len);

#endif /* _KRYPT_B64_INTERNAL_H_ */

