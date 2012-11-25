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

#ifndef _KRYPT_HEX_INTERNAL_H
#define _KRYPT_HEX_INTERNAL_H_

ssize_t krypt_hex_encode(uint8_t *bytes, size_t len, uint8_t **out);
ssize_t krypt_hex_decode(uint8_t *bytes, size_t len, uint8_t **out);

#endif /* _KRYPT_HEX_INTERNAL_H_ */

