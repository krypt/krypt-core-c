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

#if !defined(_KRYPT_ASN1_H_)
#define _KRYPT_ASN1_H_

extern VALUE mKryptASN1;
extern VALUE cKryptASN1Parser;
extern VALUE cKryptASN1Header;
extern VALUE cKryptASN1Instream;

extern VALUE cKryptASN1Data;
extern VALUE cKryptASN1Primitive;
extern VALUE cKryptASN1Constructive;

/* PRIMITIVE */
extern VALUE cKryptASN1EndOfContents;
extern VALUE cKryptASN1Boolean;                           		/* BOOLEAN           */
extern VALUE cKryptASN1Integer, cKryptASN1Enumerated;          		/* INTEGER           */
extern VALUE cKryptASN1BitString;                         		/* BIT STRING        */
extern VALUE cKryptASN1OctetString, cKryptASN1UTF8String;		/* STRINGs           */
extern VALUE cKryptASN1NumericString, cKryptASN1PrintableString;
extern VALUE cKryptASN1T61String, cKryptASN1VideotexString;
extern VALUE cKryptASN1IA5String, cKryptASN1GraphicString;
extern VALUE cKryptASN1ISO64String, cKryptASN1GeneralString;
extern VALUE cKryptASN1UniversalString, cKryptASN1BMPString;
extern VALUE cKryptASN1Null;                              		/* NULL              */
extern VALUE cKryptASN1ObjectId;                          		/* OBJECT IDENTIFIER */
extern VALUE cKryptASN1UTCTime, cKryptASN1GeneralizedTime;     		/* TIME              */

/* CONSTRUCTIVE */
extern VALUE cKryptASN1Sequence, cKryptASN1Set;

extern VALUE eKryptASN1Error;
extern VALUE eKryptASN1ParseError;
extern VALUE eKryptASN1SerializeError;

extern VALUE mKryptPEM;
extern VALUE eKryptPEMError;

extern ID sKrypt_TC_UNIVERSAL;
extern ID sKrypt_TC_APPLICATION;
extern ID sKrypt_TC_CONTEXT_SPECIFIC;
extern ID sKrypt_TC_PRIVATE;
/* Not real tag classes, for convenience reasons */
extern ID sKrypt_TC_EXPLICIT;
extern ID sKrypt_TC_IMPLICIT;

extern ID sKrypt_IV_TAG, sKrypt_IV_TAG_CLASS, sKrypt_IV_INF_LEN, sKrypt_IV_VALUE, sKrypt_IV_UNUSED_BITS;

void Init_krypt_asn1(void);
void Init_krypt_asn1_parser(void);
void Init_krypt_instream_adapter(void);
void Init_krypt_pem(void);

size_t krypt_asn1_encode_integer(long num, uint8_t **out);
int krypt_asn1_decode_stream(krypt_instream *in, VALUE *out);

VALUE krypt_instream_adapter_new(krypt_instream *in);

#endif /* _KRYPT_ASN1_H_ */


