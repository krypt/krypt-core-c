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

#ifndef _KRYPT_ERROR_H_
#define _KRYPT_ERROR_H_

#define KRYPT_OK 1
#define KRYPT_ERR -1

#define KRYPT_ASN1_EOF -2

void krypt_error_add(const char *format, ...);

int krypt_has_errors(void);
int krypt_error_message(char *buf, int buf_len);
VALUE krypt_error_create(VALUE exception_class, const char *format, ...);
void krypt_error_raise(VALUE exception_class, const char *format, ...);
void krypt_error_clear(void);

#endif /* KRYPT_ERROR_H */

