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

VALUE cKryptASN1Parser;
VALUE cKryptASN1Header;

typedef struct krypt_asn1_parsed_header_st {
    binyo_instream *in;
    krypt_asn1_header *header;
    VALUE tag;
    VALUE tag_class;
    VALUE constructed;
    VALUE infinite;
    VALUE length;
    VALUE header_length;
    VALUE value;

    int consumed;
    VALUE cached_stream;
} krypt_asn1_parsed_header;

static void
int_parsed_header_mark(krypt_asn1_parsed_header *header)
{
    if (!header) return;

    binyo_instream_mark(header->in);

    rb_gc_mark(header->tag);
    rb_gc_mark(header->tag_class);
    rb_gc_mark(header->constructed);
    rb_gc_mark(header->infinite);
    rb_gc_mark(header->length);
    rb_gc_mark(header->header_length);
    if (header->value != Qnil)
	rb_gc_mark(header->value);
    if (header->cached_stream != Qnil)
	rb_gc_mark(header->cached_stream);
}

static void
int_parsed_header_free(krypt_asn1_parsed_header *header)
{
    if (!header) return;

    binyo_instream_free(header->in);
    krypt_asn1_header_free(header->header);
    xfree(header);
}

#define int_asn1_parsed_header_set(klass, obj, header) do { \
    if (!(header)) { \
	rb_raise(eKryptError, "Uninitialized header"); \
    } \
    (obj) = Data_Wrap_Struct((klass), int_parsed_header_mark, int_parsed_header_free, (header)); \
} while (0)

#define int_asn1_parsed_header_get(obj, header) do { \
    Data_Get_Struct((obj), krypt_asn1_parsed_header, (header)); \
    if (!(header)) { \
	rb_raise(eKryptError, "Uninitialized header"); \
    } \
} while (0)

/* Header code */

static VALUE
int_asn1_header_new(binyo_instream *in, krypt_asn1_header *header)
{
    VALUE obj;
    ID tag_class;
    krypt_asn1_parsed_header *parsed_header;

    parsed_header = ALLOC(krypt_asn1_parsed_header);
    parsed_header->tag = INT2NUM(header->tag);
    if (!(tag_class = krypt_asn1_tag_class_for_int(header->tag_class))) return Qnil; 
    parsed_header->tag_class = ID2SYM(tag_class);
    parsed_header->constructed = header->is_constructed ? Qtrue : Qfalse;
    parsed_header->infinite = header->is_infinite ? Qtrue : Qfalse;
    parsed_header->length = LONG2NUM(header->length);
    parsed_header->header_length = LONG2NUM(header->tag_len + header->length_len);
    parsed_header->in = in;
    parsed_header->header = header;
    parsed_header->value = Qnil;
    parsed_header->consumed = 0;
    parsed_header->cached_stream = Qnil;
    
    int_asn1_parsed_header_set(cKryptASN1Header, obj, parsed_header);
    return obj;
}

#define KRYPT_ASN1_HEADER_GET_DEFINE(attr)		\
static VALUE						\
krypt_asn1_header_get_##attr(VALUE self)		\
{							\
    krypt_asn1_parsed_header *header;			\
    int_asn1_parsed_header_get(self, header);		\
    return header->attr;				\
}

/**
 * Document-method: Krypt::ASN1::Header#tag
 * 
 * call-seq:
 *    header.tag -> Number
 *
 * A +Number+ representing the tag of this Header. Never +nil+.
 */
KRYPT_ASN1_HEADER_GET_DEFINE(tag)

/**
 * Document-method: Krypt::ASN1::Header#tag_class
 * 
 * call-seq:
 *    header.tag_class -> Symbol
 *
 * A +Symbol+ representing the tag class of this Header. Never +nil+.
 * See Krypt::ASN1::ASN1Data for possible values.
 */
KRYPT_ASN1_HEADER_GET_DEFINE(tag_class)

/**
 * Document-method: Krypt::ASN1::Header#constructed?
 * 
 * call-seq:
 *    header.constructed? -> true or false
 *
 * +true+ if the current Header belongs to a constructed value, +false+
 * otherwise.
 */
KRYPT_ASN1_HEADER_GET_DEFINE(constructed)

/**
 * Document-method: Krypt::ASN1::Header#infinite?
 * 
 * call-seq:
 *    header.infinite? -> true or false
 *
 * +true+ if the current Header is encoded using infinite length, +false+
 * otherwise. Note that an infinite length-encoded value is automatically
 * constructed, i.e. header.constructed? => header.infinite?
 */
KRYPT_ASN1_HEADER_GET_DEFINE(infinite)

/**
 * Document-method: Krypt::ASN1::Header#length
 * 
 * call-seq:
 *    header.length -> Number
 *
 * Returns a +Number+ representing the raw byte length of the associated value.
 * It is +0+ is the Header represents an infinite length-encoded value. Never
 * +nil+.
 */   
KRYPT_ASN1_HEADER_GET_DEFINE(length)

/**
 * Document-method: Krypt::ASN1::Header#header_length
 * 
 * call-seq:
 *    header.header_length -> Number
 *
 * Returns the byte size of the raw header encoding. Never +nil+.
 */
KRYPT_ASN1_HEADER_GET_DEFINE(header_length)

/**
 * call-seq:
 *    header.encode_to(io) -> self
 *
 * * +io+: an IO-like object supporting IO#write
 *
 * Writes the raw Header encoding to an IO-like object supporting IO#write.
 * May raise Krypt::ASN1::SerializeError if encoding fails.
 */
static VALUE
krypt_asn1_header_encode_to(VALUE self, VALUE io)
{
    krypt_asn1_parsed_header *header;
    binyo_outstream *out;
    int result;

    int_asn1_parsed_header_get(self, header);

    if (!(out = binyo_outstream_new_value(io))) 
	krypt_error_raise(eKryptASN1SerializeError, "Error while trying to access the stream");

    result = krypt_asn1_header_encode(out, header->header);
    binyo_outstream_free(out);
    if (result == KRYPT_ERR)
	krypt_error_raise(eKryptASN1SerializeError, "Error while encoding header");
    return self;
}

/**
 * call-seq:
 *    header.bytes -> String
 *
 * Returns a +String+ containing the raw byte encoding of this Header.
 */
static VALUE
krypt_asn1_header_bytes(VALUE self)
{
    krypt_asn1_parsed_header *header;
    uint8_t *bytes;
    size_t size;
    binyo_outstream *out;
    VALUE ret;

    int_asn1_parsed_header_get(self, header);

    out = binyo_outstream_new_bytes();
    if (krypt_asn1_header_encode(out, header->header) == KRYPT_ERR) {
	binyo_outstream_free(out);
	krypt_error_raise(eKryptASN1SerializeError, "Error while encoding ASN.1 header");
    }
    size = binyo_outstream_bytes_get_bytes_free(out, &bytes);
    ret = rb_str_new((const char *)bytes, size);
    rb_enc_associate(ret, rb_ascii8bit_encoding());
    xfree(bytes);
    return ret;
}

/**
 * call-seq:
 *    header.skip_value -> nil
 *
 * Simply moves the "cursor" on the underlying IO forward by skipping over
 * the bytes that represent the value associated with this Header. After
 * having called +skip_value+, the next Header can be parsed from the
 * underlying IO with Parser#next.
 */
static VALUE
krypt_asn1_header_skip_value(VALUE self)
{
    krypt_asn1_parsed_header *header;
    
    int_asn1_parsed_header_get(self, header);
    if (krypt_asn1_skip_value(header->in, header->header) == KRYPT_ERR)
        krypt_error_raise(eKryptASN1ParseError, "Skipping the value failed");
    return Qnil;
}

/**
 * call-seq:
 *    header.value -> String or nil
 *
 * Returns the raw byte encoding of the associated value. Also moves the
 * "cursor" on the underlying IO forward. After having called value, the
 * next Header can be parsed from the underlying IO with Parser#next.
 * Once read, the value will be cached and subsequent calls to #value will
 * have no effect on the underlying stream. 
 * 
 * If there is no value (indicated * by Header#length == 0), it returns
 * +nil+. 
 * 
 * May raise Krypt::ASN1::ParseError if an Instream was already obtained by
 * Header#value_io, because the underlying stream can only be consumed once. 
 */
static VALUE
krypt_asn1_header_value(VALUE self)
{
    krypt_asn1_parsed_header *header;
    
    int_asn1_parsed_header_get(self, header);

    if (header->consumed && header->cached_stream != Qnil)
	rb_raise(eKryptASN1ParseError, "The stream has already been consumed");

    /* TODO: sync */
    if (!header->consumed && header->value == Qnil) {
	uint8_t *value;
	size_t length;
	int tag;

	if (krypt_asn1_get_value(header->in, header->header, &value, &length) == KRYPT_ERR)
            rb_raise(eKryptASN1ParseError, "Parsing the value failed");
	tag = header->header->tag;

	if (length != 0 || (tag != TAGS_NULL && tag != TAGS_END_OF_CONTENTS)) {
	    header->value = rb_str_new((const char *)value, length);
	    rb_enc_associate(header->value, rb_ascii8bit_encoding());
	}

	header->consumed = 1;
	xfree(value);
    }

    return header->value;
}

static VALUE
int_header_cache_stream(binyo_instream *in, krypt_asn1_header *header, int values_only)
{
    binyo_instream *value_stream;

    value_stream = krypt_asn1_get_value_stream(in, header, values_only);
    return krypt_instream_adapter_new(value_stream);
}

/**
 * call-seq:
 *    header.value_io -> Instream
 *
 * Returns a Krypt::ASN1::Instream that allows consuming the value in
 * streaming manner rather than buffering it in a +String+ and consuming
 * it at once. Note that once an Instream was obtained in this way,
 * all calls to Header#value will raise a ParseError. Subsequent calls
 * to +value_io+ are possible, however, the Instream instance is cached. 
 *
 * May raise Krypt::ASN1::ParseError if the associated value was already
 * consumed by a call to Header#value.
 */
static VALUE
krypt_asn1_header_value_io(int argc, VALUE *argv, VALUE self)
{
    krypt_asn1_parsed_header *header;
    VALUE values_only;

    rb_scan_args(argc, argv, "01", &values_only);
    
    int_asn1_parsed_header_get(self, header);
    if (header->consumed && header->cached_stream == Qnil)
	rb_raise(eKryptASN1ParseError, "The stream has already been consumed");

    /*TODO: synchronization */
    if (header->cached_stream == Qnil) {
	if (NIL_P(values_only))
	    values_only = Qtrue;

	header->consumed = 1;
	header->cached_stream = int_header_cache_stream(header->in,
	       			       	     	        header->header,
							values_only == Qtrue);
    }

    return header->cached_stream;
}

/**
 * call-seq:
 *    header.to_s -> String
 *
 * Prints out the information about this Header in a human-readable format
 * without consuming (and therefore also not displaying) the associated
 * value.
 */
static VALUE
krypt_asn1_header_to_s(VALUE self)
{
    VALUE str;
    krypt_asn1_parsed_header *header;
    ID to_s;

    int_asn1_parsed_header_get(self, header);
    to_s = rb_intern("to_s");

    str = rb_str_new2("Tag: ");
    rb_str_append(str, rb_funcall(header->tag, to_s, 0));
    rb_str_append(str, rb_str_new2(" Tag Class: "));
    rb_str_append(str, rb_funcall(header->tag_class, to_s, 0));
    rb_str_append(str, rb_str_new2(" Length: "));
    rb_str_append(str, rb_funcall(header->length, to_s, 0));
    rb_str_append(str, rb_str_new2(" Header Length: "));
    rb_str_append(str, rb_funcall(header->header_length, to_s, 0));
    rb_str_append(str, rb_str_new2(" Constructed: "));
    rb_str_append(str, rb_funcall(header->constructed, to_s, 0));
    rb_str_append(str, rb_str_new2(" Infinite Length: "));
    rb_str_append(str, rb_funcall(header->infinite, to_s, 0));

    return str;
}

/* End Header code */

/**
 * call-seq:
 *    parser.next(io) -> Header or nil
 *
 * * +io+: an IO-like object supporting IO#read and IO#seek
 * Returns a Header if parsing was successful or nil if the end of the stream
 * has been reached. May raise ParseError in case an error occurred.
 */
static VALUE
krypt_asn1_parser_next(VALUE self, VALUE io)
{
    binyo_instream *in;
    krypt_asn1_header *header;
    int result;
    VALUE ret;
    int type = TYPE(io);

    if (type == T_STRING)
	rb_raise(rb_eArgError, "Argument for next must respond to read");

    if (!(in = binyo_instream_new_value(io)))
	rb_raise(rb_eArgError, "Argument for next must respond to read");

    result = krypt_asn1_next_header(in, &header);
    if (result == KRYPT_ERR) goto error;
    if (result == KRYPT_ASN1_EOF) {
	binyo_instream_free(in);
	return Qnil;
    }

    ret = int_asn1_header_new(in, header);
    if (NIL_P(ret)) {
        krypt_asn1_header_free(header);
        goto error;
    }
    
    return ret;
    
error:
    binyo_instream_free(in);
    rb_raise(eKryptASN1ParseError, "Error while parsing header");
}

/* End Parser code */

void
Init_krypt_asn1_parser(void)
{
#if 0
    mKrypt = rb_define_module("Krypt");
    mKryptASN1 = rb_define_module_under(mKrypt, "ASN1"); /* Let RDoc know */ 
#endif

    /**
     * Document-class: Krypt::ASN1::Parser
     *
     * Low-level interface that allows to parse DER-encoded ASN.1 structures
     * in a truly streaming fashion using a "Pull Parser" model. The Pull
     * Parser model for stream-based parsing is considered as more convenient
     * than an event-based model due to its similarity to an equivalent
     * non-streaming parsing model and the fact that the typical callback-based
     * implementation of an event-based model gets complicated very quickly.
     * 
     * Pull parsing can be imagined as moving a cursor forward on the stream
     * by deciding to parse a particular token at the current stream position,
     * thus "pulling" stream tokens on demand.
     *
     * The Parser itself is stateless (i.e. can be reused safely on different
     * streams) and operates on any IO-like object that supports IO#read and
     * IO#seek.
     *
     * Calling Parser#next on an IO will attempt to read a DER Header of
     * a DER-encoded object (cf. http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf).
     * DER, the Distinguished Encoding Rules, are an encoding scheme for
     * encoding ASN.1 data structures into a binary format. DER is a TLV
     * (Tag-Length-Value) encoding, that is the Header of a DER-encoded
     * object can be thought of as the combination of Tag and Length.
     *
     * Parser#next may either return a Header, +nil+ if the end of the stream
     * was reached or raise a ParseError if an error occured. Upon succesful
     * parsing of a Header, there are several choices on how to proceed. 
     *
     * If the current Header represents a primitive value (may be detected
     * by verifying that Header#constructed? is +false+), the ways to move
     * forward on the stream are:
     * * skipping over the Header's value (the V in TLV) using 
     *   Header#skip_value 
     * * reading the value in one pass using Header#value
     * * obtaining an Instream of the value in order to read it 
     *   streaming-based using Header#value_io
     * Please note that immediately calling Parser#next on a stream from
     * whom a Header of a primitive value was just read will fail because
     * the only option to proceed in that case is either skipping or
     * consuming the value first. For more details on primitive values,
     * please have a look at Krypt::ASN1::Primitive.
     *
     * If the current Header represents a constructed value 
     * (Header#constructed? is +true+), there is another option still.
     * First, you may interpret the value of the constructed value in
     * its entirety, using the methods described above for primitive
     * values. The value in such a case represents the raw encoding of the
     * <b>entire</b> sequence of inner elements of that constructed encoding.
     * For example, for a SEQUENCE with n elements, the value will be the
     * concatenated encodings of every single of the n elements in successive
     * order. But, if you wish to parse the inner elements, too, there is the
     * additional option of parsing another Header immediately, effectively
     * "descending" into the nested structure. Similarly to how constructed
     * values can be nested, one can recursively descend with Parser into
     * these nested structures by parsing another Header with Parser#next
     * instead of merely consuming the constructed Header's value. This is
     * best illustrated using an
     *
     * === Example: Reading all objects contained within a constructed DER
     *   io = # IO representing a DER-encoded ASN.1 structure
     *   parser = Krypt::ASN1::Parser.new
     *   while header = parser.next do
     *     unless header.constructed?
     *       # Primitive -> consume/skip value
     *       value = header.value
     *       # Process value
     *     end
     *     # Constructed -> parse another Header immediately
     *   end
     * 
     * in contrast to
     *
     * === Example: Reading the entire value of a constructed DER at once
     *   io = # IO representing a DER-encoded ASN.1 structure
     *   parser = Krypt::ASN1::Parser.new
     *   header = parser.next
     *   value = header.value # Reads the entire encodings of the nested elements
     *   puts parser.next == nil # -> true, since the header and value of the
     *                             outmost constructed value is the entire
     *                             content of the stream
     * 
     * More details on constructed values can be found in the documentation
     * of Krypt::ASN1::Constructive.
     */
    cKryptASN1Parser = rb_define_class_under(mKryptASN1, "Parser", rb_cObject);
    rb_define_method(cKryptASN1Parser, "next", krypt_asn1_parser_next, 1);

    /**
     * Document-class: Krypt::ASN1::Header
     *
     * These are the tokens returned by Parser#next and cannot be instantiated
     * on their own. A Header represents the Tag and Length part of a TLV
     * (Tag-Length-Value) DER encoding, and it also allows to move the "cursor"
     * on an IO forward by consuming or skipping the associated value (the V).
     *
     * The Header itself contains tag and length information of what was just
     * parsed:
     *
     * * tag number (Header#tag)
     * * tag class (Header#tag_class)
     * * whether the header is constructed or not (Header#constructed?)
     * * whether it is an infinite length value or not (Header#infinite?)
     * * the length in bytes of the associated value (Header#length/size)
     * * the length of the raw Header encoding (Header#header_length/header_size)
     *
     * In addition, there are three ways to consume the value that is associated
     * with a Header:
     *
     * * by skipping it (Header#skip_value)
     * * by reading the value in one single pass (Header#value)
     * * or by obtaining an Instream of the value bytes so that it can be consumed
     *   in a streaming fashion (Header#value_io)
     *
     * Access to the raw encoding of the Header is given by either retrieving
     * a String containing the encoding with Header#bytes or by encoding it to
     * an IO-like object supporting IO#write using Header#encode_to.
     */
    cKryptASN1Header = rb_define_class_under(mKryptASN1, "Header", rb_cObject);
    rb_define_method(cKryptASN1Header, "tag", krypt_asn1_header_get_tag, 0);
    rb_define_method(cKryptASN1Header, "tag_class", krypt_asn1_header_get_tag_class, 0);
    rb_define_method(cKryptASN1Header, "constructed?", krypt_asn1_header_get_constructed, 0);
    rb_define_method(cKryptASN1Header, "infinite?", krypt_asn1_header_get_infinite, 0);
    rb_define_method(cKryptASN1Header, "length", krypt_asn1_header_get_length, 0);
    rb_define_alias(cKryptASN1Header, "size", "length");
    rb_define_method(cKryptASN1Header, "header_length", krypt_asn1_header_get_header_length, 0);
    rb_define_alias(cKryptASN1Header, "header_size", "header_length");
    rb_define_method(cKryptASN1Header, "encode_to", krypt_asn1_header_encode_to, 1);
    rb_define_method(cKryptASN1Header, "bytes", krypt_asn1_header_bytes, 0);
    rb_define_method(cKryptASN1Header, "skip_value", krypt_asn1_header_skip_value, 0);
    rb_define_method(cKryptASN1Header, "value", krypt_asn1_header_value, 0);
    rb_define_method(cKryptASN1Header, "value_io", krypt_asn1_header_value_io, -1);
    rb_define_method(cKryptASN1Header, "to_s", krypt_asn1_header_to_s, 0);
    rb_undef_method(CLASS_OF(cKryptASN1Header), "new"); /* private constructor */	
}

