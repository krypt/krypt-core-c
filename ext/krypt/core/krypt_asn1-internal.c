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

#include <limits.h>
#include "krypt-core.h"
#include "krypt_asn1-internal.h"

static const int KRYPT_ASN1_TAG_LIMIT = INT_MAX >> CHAR_BIT_MINUS_ONE;
static const size_t KRYPT_ASN1_LENGTH_LIMIT = SIZE_MAX >> CHAR_BIT;

#define int_next_byte(in, b)				 	\
do {							  	\
    if (binyo_instream_read((in), &(b), 1) != BINYO_OK) {  	\
	krypt_error_add("Could not read byte from stream");	\
    	return KRYPT_ERR;					\
    }								\
} while (0)						  	\

static int int_parse_tag(uint8_t b, binyo_instream *in, krypt_asn1_header *out);
static int int_parse_complex_tag(uint8_t b, binyo_instream *in, krypt_asn1_header *out);
static void int_parse_primitive_tag(uint8_t b, krypt_asn1_header *out);
static int int_parse_length(binyo_instream *in, krypt_asn1_header *out);
static int int_parse_complex_definite_length(uint8_t b, binyo_instream *in, krypt_asn1_header *out);
static int int_parse_read_exactly(binyo_instream *in, size_t n, uint8_t **out, size_t *outlen);
static int int_consume_stream(binyo_instream *in, uint8_t **out, size_t *outlen);
static void int_compute_tag(krypt_asn1_header *header);
static void int_compute_length(krypt_asn1_header *header);

/**
 * Parses a krypt_asn1_header from the krypt_instream at its current
 * position. 
 *
 * @param in	The binyo_instream to be parsed from
 * @param out	On successful parsing, an instance of krypt_asn1_header
 * 		will be assigned
 * @return	KRYPT_OK if a new header was successfully parsed, KRYPT_ASN1_EOF if EOF
 * 		has been reached, KRYPT_ERR in case of errors
 */		
int
krypt_asn1_next_header(binyo_instream *in, krypt_asn1_header **out)
{
    ssize_t read;
    uint8_t b;
    krypt_asn1_header *header;

    if (!in) return KRYPT_ERR;

    read = binyo_instream_read(in, &b, 1);
    if (read == BINYO_IO_EOF) return KRYPT_ASN1_EOF;
    if (read == BINYO_ERR) {
       krypt_error_add("Error when parsing stream");
       return KRYPT_ERR;
    }

    header = krypt_asn1_header_new();
    
    if (int_parse_tag(b, in, header) == KRYPT_ERR) {
       krypt_error_add("Error when parsing tag");
       goto error;
    }
    if (int_parse_length(in, header) == KRYPT_ERR) {
	krypt_error_add("Error when parsing length");
	goto error;
    }
    if (header->is_infinite && !header->is_constructed) {
	krypt_error_add("Infinite length values must be constructed");
	goto error;
    }

    *out = header;
    return KRYPT_OK;
 error:
    krypt_asn1_header_free(header);
    return KRYPT_ERR;
}

/**
 * Based on the last header that was parsed, this function skips the bytes
 * that represent the value of the object represented by the header.
 *
 * @param in	The binyo_instream that the header was parsed from
 * @param last	The last header that was parsed from the stream
 * @return KRYPT_OK if successful, KRYPT_ERR otherwise
 */
int
krypt_asn1_skip_value(binyo_instream *in, krypt_asn1_header *last)
{
    if (!in) return KRYPT_ERR;
    if (!last) return KRYPT_ERR;
    if (binyo_instream_skip(in, last->length) == BINYO_OK)
	return KRYPT_OK;
    else
	return KRYPT_ERR;
}

/**
 * Based on the last header that was parsed, this function reads and returns
 * the bytes that represent the value of the object represented by the header.
 *
 * @param in		The binyo_instream that the header was parsed from
 * @param last		The last header that was parsed from the stream
 * @param out   	A pointer to the uint8_t* that shall receive the value
 * 			representing the currently parsed object
 * @param outlen        The length of the value that has been parsed
 * @return		KRYPT_OK if successful, or KRYPT_ERR otherwise 
 */
int
krypt_asn1_get_value(binyo_instream *in, krypt_asn1_header *last, uint8_t **out, size_t *outlen)
{
    if (!in) return KRYPT_ERR;
    if (!last) return KRYPT_ERR;

    if (!last->is_infinite) {
	if (int_parse_read_exactly(in, last->length, out, outlen) == KRYPT_ERR)
	    return KRYPT_ERR;
	*outlen = last->length;
	return KRYPT_OK;
    }
    else {
	int ret;
	binyo_instream *inf_stream = krypt_instream_new_chunked(in, 0);
	ret = int_consume_stream(inf_stream, out, outlen);
	binyo_instream_free(inf_stream);
	return ret;
    }
}

/**
 * Based on the last header that was parsed, this function returns a
 * krypt_instream that allows to read the bytes that represent the value of
 * the object represented by the header in streaming manner.
 *
 * @param in		The binyo_instream that the header was parsed from
 * @param last		The last header that was parsed from the stream
 * @param values_only	Only used for infinite length values. If 0, all subsequent 
 *                      value bytes including headers will be read from the returned
 *                      stream. If 1 (or generally non-0), only the raw values 
 *                      excluding the headers will be read from the value stream. 
 *                      This comes in handy e.g. when reading the chunked value of an
 *                      infinite-length octet string. For definite length values, the
 *                      returned stream will always read values including the
 *                      headers.
 * @return		A binyo_instream * allowing to read the bytes representing
 *  			the value of the currently parsed object or NULL if an error
 *  			occurred.
 */
binyo_instream *
krypt_asn1_get_value_stream(binyo_instream *in, krypt_asn1_header *last, int values_only)
{
    if (!in) return NULL;
    if (!last) return NULL;

    if (last->is_infinite) {
	return krypt_instream_new_chunked(in, values_only);
    }
    else {
	return krypt_instream_new_definite(in, last->length);
    }
}

/**
 * Writes the encoding of a header to the supplied krypt_outstream.
 *
 * @param out		The binyo_outstream where the header shall be encoded 
 * 			to
 * @param header	The header that shall be encoded
 * @return              KRYPT_OK if successful, KRYPT_ERR otherwise
 */
int
krypt_asn1_header_encode(binyo_outstream *out, krypt_asn1_header *header)
{
    uint8_t *buf;
    size_t hlen;

    if (!out) return KRYPT_ERR;
    if (!header) return KRYPT_ERR;

    if (!header->tag_bytes)
	int_compute_tag(header);

    if (!header->length_bytes)
	int_compute_length(header);

    hlen = header->tag_len + header->length_len;
    buf = ALLOCA_N(uint8_t, hlen);
    memcpy(buf, header->tag_bytes, header->tag_len);
    memcpy(buf + header->tag_len, header->length_bytes, header->length_len);
    if (binyo_outstream_write(out, buf, hlen) == BINYO_ERR) return KRYPT_ERR;
    return KRYPT_OK;
}

/**
 * Writes the encoding of an krypt_asn1_object (header + value) to the
 * supplied binyo_outstream.
 *
 * @param out		The binyo_outstream where the object shall be encoded 
 * 			to
 * @param object	The object that shall be encoded
 * @return 		KRYPT_OK if successful, KRYPT_ERR otherwise
 */
int
krypt_asn1_object_encode(binyo_outstream *out, krypt_asn1_object *object)
{
    if (!object) return KRYPT_ERR;
    if (krypt_asn1_header_encode(out, object->header) == KRYPT_ERR) return KRYPT_ERR;
    if (!object->bytes) return KRYPT_OK;	
    if (object->bytes_len == 0) return KRYPT_OK;
    if (binyo_outstream_write(out, object->bytes, object->bytes_len) == BINYO_ERR) return KRYPT_ERR;
    return KRYPT_OK;
}

/**
 * Creates a new krypt_asn1_header struct.
 * @return 	a newly allocated krypt_asn1_header
 */
krypt_asn1_header *
krypt_asn1_header_new(void)
{
    krypt_asn1_header *ret;

    ret = ALLOC(krypt_asn1_header);
    memset(ret, 0, sizeof(krypt_asn1_header));
    return ret;
}

/**
 * Frees a krypt_asn1_header and its members.
 *
 * @param header	The header to be freed
 */
void
krypt_asn1_header_free(krypt_asn1_header *header)
{
    if (!header) return;
    if (header->tag_bytes)
	xfree(header->tag_bytes);
    if (header->length_bytes)
	xfree(header->length_bytes);
    xfree(header);
}

/**
 * Allocates a new krypt_asn1_object given a header and the value encoding.
 * It does *not* copy value, so the value pointer shall only be freed by a
 * subsequent call to krypt_asn1_object_free.
 *
 * @param header	The header corresponding to the value
 * @param value		The raw byte encoding of the value
 * @param len		The length of the byte encoding
 */
krypt_asn1_object *
krypt_asn1_object_new_value(krypt_asn1_header *header, uint8_t *value, size_t len)
{
    krypt_asn1_object *obj;

    obj = krypt_asn1_object_new(header);
    obj->bytes = value;
    obj->bytes_len = len;

    return obj;
}

/**
 * Allocates a new krypt_asn1_object given a header. For succesful encoding
 * with krypt_asn1_object_encode it is expected that the value encoding will
 * be added at a later point.
 *
 * @param header	The header corresponding to the value
 * @return 		A new header or NULL if allocation fails
 */
krypt_asn1_object *
krypt_asn1_object_new(krypt_asn1_header *header)
{
    krypt_asn1_object *obj;

    if (!header) return NULL;

    obj = ALLOC(krypt_asn1_object);
    obj->header = header;
    obj->bytes = NULL;
    obj->bytes_len = 0;

    return obj;
}


/**
 * Frees a krypt_asn1_object by freeing the header and the
 * value bytes if present.
 *
 * @param object	The krypt_asn1_object to be freed
 */
void
krypt_asn1_object_free(krypt_asn1_object *object)
{
    if (!object) return;

    krypt_asn1_header_free(object->header);
    if (object->bytes)
	xfree(object->bytes);
    xfree(object);
}

int
krypt_asn1_cmp_set_of(uint8_t *s1, size_t len1, 
	              uint8_t *s2, size_t len2, int *result)
{
    size_t min, i;
    krypt_asn1_header *h1 = NULL, *h2 = NULL;
    binyo_instream *in1, *in2;

    in1 = binyo_instream_new_bytes(s1, len1);
    in2 = binyo_instream_new_bytes(s2, len2);
    if (krypt_asn1_next_header(in1, &h1) != KRYPT_OK) goto error;
    if (krypt_asn1_next_header(in2, &h2) != KRYPT_OK) goto error;

    if (h1->tag == TAGS_END_OF_CONTENTS && h1->tag_class == TAG_CLASS_UNIVERSAL) {
	*result = 1;
	goto cleanup;
    }
    if (h2->tag == TAGS_END_OF_CONTENTS && h2->tag_class == TAG_CLASS_UNIVERSAL) {
	*result = -1;
	goto cleanup;
    }
    if (h1->tag < h2->tag) {
	*result = -1;
	goto cleanup;
    }
    if (h1->tag > h2->tag) {
	*result = 1;
	goto cleanup;
    }

    min = len1 < len2 ? len1 : len2;

    for (i=0; i<min; ++i) {
	if (s1[i] != s2[i]) {
	    *result = s1[i] < s2[i] ? -1 : 1;
	    goto cleanup;
	}
    }

    if (len1 == len2) 
	*result = 0;
    else
    	*result = len1 < len2 ? -1 : 1;

cleanup:
    binyo_instream_free(in1);
    binyo_instream_free(in2);
    krypt_asn1_header_free(h1);
    krypt_asn1_header_free(h2);
    return KRYPT_OK;
error:
    binyo_instream_free(in1);
    binyo_instream_free(in2);
    if (h1) krypt_asn1_header_free(h1);
    if (h2) krypt_asn1_header_free(h2);
    krypt_error_add("Error while comparing values");
    return KRYPT_ERR;
}

static int
int_parse_tag(uint8_t b, binyo_instream *in, krypt_asn1_header *out)
{
    if ((b & COMPLEX_TAG_MASK) == COMPLEX_TAG_MASK) {
    	return int_parse_complex_tag(b, in, out);
    } else {
    	int_parse_primitive_tag(b, out);
	return KRYPT_OK;
    }
}

static void
int_parse_primitive_tag(uint8_t b, krypt_asn1_header *out)
{
    out->tag = b & COMPLEX_TAG_MASK;
    out->is_constructed = (b & CONSTRUCTED_MASK) == CONSTRUCTED_MASK;
    out->tag_class = b & TAG_CLASS_PRIVATE;
    out->tag_bytes = ALLOC(uint8_t);
    out->tag_bytes[0] = b;
    out->tag_len = 1;
}

#define int_buffer_add_byte(buf, b, out)			\
do {								\
    if (binyo_buffer_write((buf), &(b), 1) == KRYPT_ERR) {	\
	binyo_buffer_free((buf));				\
        return KRYPT_ERR;					\
    }								\
} while (0)

#define int_check_tag(t, buf)					\
do {								\
    if ((t) > KRYPT_ASN1_TAG_LIMIT) {				\
	binyo_buffer_free((buf));				\
	krypt_error_add("Complex tag too large");		\
	return KRYPT_ERR;					\
    }								\
} while (0)

static int
int_parse_complex_tag(uint8_t b, binyo_instream *in, krypt_asn1_header *out)
{
    binyo_byte_buffer *buffer;
    int tag = 0;

    out->is_constructed = (b & CONSTRUCTED_MASK) == CONSTRUCTED_MASK;
    out->tag_class = b & TAG_CLASS_PRIVATE;
    buffer = binyo_buffer_new();
    int_buffer_add_byte(buffer, b, out);

    int_next_byte(in, b);

    if (b == INFINITE_LENGTH_MASK) {
	krypt_error_add("Bits 7 to 1 of the first subsequent octet shall not be 0 for complex tag encoding");
	return KRYPT_ERR;
    }

    while ((b & INFINITE_LENGTH_MASK) == INFINITE_LENGTH_MASK) {
	int_check_tag(tag, buffer);
	int_buffer_add_byte(buffer, b, out);
	tag <<= CHAR_BIT_MINUS_ONE;
	tag |= (b & 0x7f);
	int_next_byte(in, b);
    }

    int_check_tag(tag, buffer);
    int_buffer_add_byte(buffer, b, out);
    tag <<= CHAR_BIT_MINUS_ONE;
    tag |= (b & 0x7f);
    out->tag = tag;
    out->tag_len = binyo_buffer_get_bytes_free(buffer, &(out->tag_bytes));
    return KRYPT_OK;
}

#define int_set_single_byte_length(h, b)	\
do {						\
    (h)->length_bytes = ALLOC(uint8_t); 	\
    (h)->length_bytes[0] = (b);			\
    (h)->length_len = 1;			\
} while (0)

static int
int_parse_length(binyo_instream *in, krypt_asn1_header *out)
{
    uint8_t b;

    int_next_byte(in, b);
    
    if (b == INFINITE_LENGTH_MASK) {
	out->is_infinite = 1;
	out->length = 0;
	int_set_single_byte_length(out, b);
    }
    else if ((b & INFINITE_LENGTH_MASK) == INFINITE_LENGTH_MASK) {
	out->is_infinite = 0;
	return int_parse_complex_definite_length(b, in, out);
    }
    else {
	out->is_infinite = 0;
	out->length = b;
	int_set_single_byte_length(out, b);
    }
    return KRYPT_OK;
}

#define int_check_length(l, buf)				\
do {								\
    if ((l) > KRYPT_ASN1_LENGTH_LIMIT) {			\
	xfree((buf));						\
	(buf) = NULL;						\
	krypt_error_add("Complex length too long");		\
	return KRYPT_ERR;					\
    }								\
} while (0)


static int
int_parse_complex_definite_length(uint8_t b, binyo_instream *in, krypt_asn1_header *out)
{
    size_t len = 0;
    size_t offset = 0;
    size_t i, num_bytes;

    if (b == 0xff) {
	krypt_error_add("Initial octet of complex definite length shall not be 0xFF");
	return KRYPT_ERR;
    }
    num_bytes = b & 0x7f;

    out->length_bytes = ALLOC_N(uint8_t, num_bytes + 1);
    out->length_bytes[offset++] = b;

    for (i = num_bytes; i > 0; i--) {
	int_check_length(len, out->length_bytes);
	int_next_byte(in, b);
	len <<= CHAR_BIT;
	len |= b;
	out->length_bytes[offset++] = b;
    }

    out->length = len;
    out->length_len = num_bytes + 1;
    return KRYPT_OK;
}


static int
int_parse_read_exactly(binyo_instream *in, size_t n, uint8_t **out, size_t *outlen)
{
    uint8_t *ret, *p;
    size_t offset = 0;
    ssize_t read;

    if (n == 0) {
	*out = NULL;
       	return KRYPT_OK;
    }

    ret = ALLOC_N(uint8_t, n);
    p = ret;
    while (offset != n) {
	read = binyo_instream_read(in, p, n - offset);
	if (read  == BINYO_IO_EOF || read == BINYO_ERR) {
	    xfree(ret);
	    *out = NULL;
	    if (read == BINYO_IO_EOF)
		krypt_error_add("Premature EOF detected");
	    else
		krypt_error_add("Error while reading from stream");
	    return KRYPT_ERR;
	}
	p += read;
	offset += read;
    }
    *out = ret;
    return KRYPT_OK;
}

static int 
int_consume_stream(binyo_instream *in, uint8_t **out, size_t *outlen)
{
    binyo_byte_buffer *out_buf;
    uint8_t *in_buf;
    ssize_t read;
    size_t size;

    in_buf = ALLOC_N(uint8_t, BINYO_IO_BUF_SIZE);
    out_buf = binyo_buffer_new_size(512);
    while ((read = binyo_instream_read(in, in_buf, BINYO_IO_BUF_SIZE)) >= 0) {
	if (binyo_buffer_write(out_buf, in_buf, read) == BINYO_ERR) goto error;
    }
    if (read == BINYO_ERR) goto error;

    size = binyo_buffer_get_bytes_free(out_buf, out);
    xfree(in_buf);
    *outlen = size;
    return KRYPT_OK;

error:
    xfree(in_buf);
    binyo_buffer_free(out_buf);
    return KRYPT_ERR;
}

#define int_determine_num_shifts(i, value, by)		\
do {							\
    size_t tmp = (value);				\
    for ((i) = 0; tmp > 0; (i)++) {			\
	tmp >>= (by);					\
    }							\
} while (0)


static void
int_compute_complex_tag(krypt_asn1_header *header)
{
    size_t num_shifts, i;
    int tmp_tag;
    uint8_t b;
   
    b = header->is_constructed ? CONSTRUCTED_MASK : 0x00;
    b |= header->tag_class & 0xff;
    b |= COMPLEX_TAG_MASK;

    int_determine_num_shifts(num_shifts, header->tag, CHAR_BIT_MINUS_ONE);
    header->tag_bytes = ALLOC_N(uint8_t, num_shifts + 1);
    header->tag_bytes[0] = b;

    tmp_tag = header->tag;

    for (i = num_shifts; i > 0; i--) {
	b = tmp_tag & 0x7f;
	if (i != num_shifts)
	    b |= INFINITE_LENGTH_MASK;
	header->tag_bytes[i] = b;
	tmp_tag >>= CHAR_BIT_MINUS_ONE;
    }

    header->tag_len = num_shifts + 1;
}

static void 
int_compute_tag(krypt_asn1_header *header)
{
    if (header->tag < 31) {
	uint8_t b;
	b = header->is_constructed ? CONSTRUCTED_MASK : 0x00;
	b |= (header->tag_class & 0xff);
	b |= (header->tag & 0xff);
	header->tag_bytes = ALLOC(uint8_t);
	*(header->tag_bytes) = b;
	header->tag_len = 1;
    } else {
	int_compute_complex_tag(header);
    }
}

static void
int_compute_complex_length(krypt_asn1_header *header)
{
    size_t num_shifts, tmp_len, i;

    int_determine_num_shifts(num_shifts, header->length, CHAR_BIT);
    tmp_len = header->length;
    header->length_bytes = ALLOC_N(uint8_t, num_shifts + 1);
    header->length_bytes[0] = num_shifts & 0xff;
    header->length_bytes[0] |= INFINITE_LENGTH_MASK;

    for (i = num_shifts; i > 0; i--) {
	header->length_bytes[i] = tmp_len & 0xff;
	tmp_len >>= CHAR_BIT;
    }

    header->length_len = num_shifts + 1;
}

static void
int_compute_length(krypt_asn1_header *header)
{
    if (header->is_infinite) {
	header->length_bytes = ALLOC(uint8_t);
	*(header->length_bytes) = INFINITE_LENGTH_MASK;
	header->length_len = 1;
    }
    else if (header->length <= 127) {
	header->length_bytes = ALLOC(uint8_t);
	*(header->length_bytes) = header->length & 0xFF;
	header->length_len = 1;
    }
    else {
	int_compute_complex_length(header);
    }
}

