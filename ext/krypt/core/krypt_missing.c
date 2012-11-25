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

#ifndef HAVE_RB_STR_ENCODE
VALUE
rb_str_encode(VALUE str, VALUE to, int ecflags, VALUE ecopts)
{
    rb_encoding *enc = rb_enc_get(to);
    rb_enc_associate(str, enc);
    return str;
}
#endif

#ifndef HAVE_GMTIME_R
struct tm *
krypt_gmtime_r(const time_t *tp, struct tm *result)
{
    struct tm *t = gmtime(tp);
    if (t) *result = *t;
    return t;
}
#endif

#ifdef HAVE_RB_BIG_PACK
int
krypt_asn1_encode_bignum(VALUE bignum, uint8_t **out, size_t *outlen)
{
    int len, i, j;
    long num_longs, biglen, divisor;
    unsigned long *longs;
    uint8_t *bytes;
    uint8_t *ptr;
    uint8_t msb;
    unsigned long l;

    biglen = RBIGNUM_LEN(bignum);
    divisor = SIZEOF_LONG / SIZEOF_BDIGITS;
    num_longs = (biglen % divisor) == 0 ? biglen / divisor : biglen / divisor + 1;
    longs = ALLOC_N(unsigned long, num_longs);
    rb_big_pack(bignum, longs, num_longs);
    msb = longs[num_longs - 1] >> (SIZEOF_LONG * CHAR_BIT - 1);

    if (RBIGNUM_SIGN(bignum) == ((msb & 1) == 1)) {
	/* We can't use int_encode_integer here because longs are unsigned */
	len = num_longs * SIZEOF_LONG + 1;
	bytes = ALLOC_N(uint8_t, len);
	ptr = bytes;
	*ptr++ = RBIGNUM_SIGN(bignum) ? 0x00 : 0xff;
    }
    else {
	uint8_t *buf;
	size_t encoded;

	encoded = krypt_asn1_encode_integer(longs[num_longs - 1], &buf);
	len = encoded + (num_longs - 1) * SIZEOF_LONG;
	bytes = ALLOC_N(uint8_t, len);
	ptr = bytes;
	memcpy(ptr, buf, encoded);
	ptr += encoded;
	--num_longs;
	xfree(buf);
    }
    for (i = num_longs - 1; i >= 0; --i) {
	l = longs[i];
	for (j = 0; j < SIZEOF_LONG; ++j) {
	    ptr[SIZEOF_LONG - j - 1] = l & 0xff;
	    l >>= CHAR_BIT;
	}
	ptr += SIZEOF_LONG;
    }
    xfree(longs);
    *out = bytes;
    *outlen = ptr - bytes;
    return 1;
}
#else
int
krypt_asn1_encode_bignum(VALUE bignum, uint8_t **out, size_t *outlen)
{
    VALUE hexstr;
    int sign;
    char *hexstrbytes;
    int free_hex = 0;
    long hexstrlen;
    uint8_t *numbytes;
    ssize_t numlen;

    sign = RBIGNUM_NEGATIVE_P(bignum);

    hexstr = rb_funcall(bignum, rb_intern("to_s"), 1, INT2NUM(16));
    hexstrbytes = (char *) RSTRING_PTR(hexstr);
    hexstrlen = RSTRING_LEN(hexstr);

    if (sign) {
	hexstrbytes++;
	hexstrlen--; /* discard '-' */
    }

    if (hexstrlen % 2) {
	/* pad with leading 0 */
	char *padded = ALLOC_N(char, hexstrlen + 1);
	padded[0] = '0';
	memcpy(padded +1, hexstrbytes, hexstrlen);
	hexstrbytes = padded;
	hexstrlen++;
	free_hex = 1;
    }

    if ((numlen = krypt_hex_decode(hexstrbytes, hexstrlen, &numbytes)) == -1) {
	if (free_hex) xfree(hexstrbytes);
	return 0;
    }
    if (sign) {
	krypt_compute_twos_complement(numbytes, numbytes, numlen);
    } else if (numbytes[0] & 0x80) {
	uint8_t *normalized = ALLOC_N(uint8_t, numlen + 1);
	normalized[0] = 0x0;
	memcpy(normalized + 1, numbytes, numlen);
	xfree(numbytes);
	numlen++;
	numbytes = normalized;
    }

    if (free_hex) xfree(hexstrbytes);
    *out = numbytes;
    *outlen = numlen;
    return 1;
}
#endif

#ifdef HAVE_RB_BIG_PACK
int
krypt_asn1_decode_bignum(uint8_t *bytes, size_t len, VALUE *out)
{
    long num_longs;
    int i, j, pos, sign;
    unsigned long *longs;
    long l;
    VALUE value;

    sign = bytes[0] & 0x80;
    num_longs = (len - 1) / SIZEOF_LONG + 1;
    longs = ALLOC_N(unsigned long, num_longs);
    for (i = 0; i < num_longs; ++i) {
	l = 0;
	for (j = 0; j < SIZEOF_LONG; ++j) {
	    pos = len - i * SIZEOF_LONG - j - 1;
	    if (pos >= 0) {
		l += ((long)(bytes[pos] & 0xff) << (j * CHAR_BIT));
	    }
	    else if (sign) {
		l |= ((long)0xff << (j * CHAR_BIT));
	    }
	}
	longs[i] = l;
    }
    value = rb_big_unpack(longs, num_longs);
    if (TYPE(value) == T_BIGNUM) {
	RBIGNUM_SET_SIGN(value, !sign);
    }
    xfree(longs);
    *out = value;
    return 1;
}
#else
int krypt_asn1_decode_bignum(uint8_t *bytes, size_t len, VALUE *out)
{
    int sign;
    ssize_t hexlen;
    uint8_t *absolute;
    int free_abs = 0;
    char *hexnum;
    char *chexnum;

    sign = bytes[0] & 0x80;
    if (sign) {
	absolute = ALLOC_N(uint8_t, len); 
	krypt_compute_twos_complement(absolute, bytes, len);
	free_abs = 1;
    } else {
	absolute = bytes;
	if (absolute[0] == 0x0) {
	    absolute++;
	    len--;
	}
    }

    if ((hexlen = krypt_hex_encode(absolute, len, &hexnum)) == -1) {
	if (free_abs) xfree(absolute);
	return 0;
    }
    
    if (sign) {
	chexnum = ALLOC_N(char, hexlen + 2);
	chexnum[0] = '-';
	memcpy(chexnum + 1, hexnum, hexlen);
	chexnum[hexlen + 1] = '\0';
    } else {
	chexnum = ALLOC_N(char, hexlen + 1);
	memcpy(chexnum, hexnum, hexlen);
	chexnum[hexlen] = '\0';
    }

    *out = rb_cstr2inum(chexnum, 16);
    if (free_abs) xfree(absolute);
    xfree(hexnum);
    xfree(chexnum);
    return 1;
}
#endif

