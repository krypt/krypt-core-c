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

VALUE mKryptASN1;
VALUE eKryptASN1Error, eKryptASN1ParseError, eKryptASN1SerializeError; 

VALUE cKryptASN1Data;
VALUE cKryptASN1Primitive;
VALUE cKryptASN1Constructive;

/* PRIMITIVE */
VALUE cKryptASN1EndOfContents;
VALUE cKryptASN1Boolean;                           		/* BOOLEAN           */
VALUE cKryptASN1Integer, cKryptASN1Enumerated;          	/* INTEGER           */
VALUE cKryptASN1BitString;                        	  	/* BIT STRING        */
VALUE cKryptASN1OctetString, cKryptASN1UTF8String;        	/* STRINGs           */
VALUE cKryptASN1NumericString, cKryptASN1PrintableString;
VALUE cKryptASN1T61String, cKryptASN1VideotexString;
VALUE cKryptASN1IA5String, cKryptASN1GraphicString;
VALUE cKryptASN1ISO64String, cKryptASN1GeneralString;
VALUE cKryptASN1UniversalString, cKryptASN1BMPString;
VALUE cKryptASN1Null;                              		/* NULL              */
VALUE cKryptASN1ObjectId;                          		/* OBJECT IDENTIFIER */
VALUE cKryptASN1UTCTime, cKryptASN1GeneralizedTime;     	/* TIME              */

/* CONSTRUCTIVE */
VALUE cKryptASN1Sequence, cKryptASN1Set;

ID sKrypt_TC_UNIVERSAL, sKrypt_TC_APPLICATION, sKrypt_TC_CONTEXT_SPECIFIC, sKrypt_TC_PRIVATE;
ID sKrypt_TC_EXPLICIT, sKrypt_TC_IMPLICIT;

ID sKrypt_IV_TAG, sKrypt_IV_TAG_CLASS, sKrypt_IV_INF_LEN, sKrypt_IV_UNUSED_BITS;
ID sKrypt_IV_VALUE;

typedef struct krypt_asn1_info_st {
    const char *name;
    VALUE *klass;
} krypt_asn1_info;

static krypt_asn1_info krypt_asn1_infos[] = {
    { "END_OF_CONTENTS",   &cKryptASN1EndOfContents,	},  /*  0 */
    { "BOOLEAN",           &cKryptASN1Boolean,         	},  /*  1 */
    { "INTEGER",           &cKryptASN1Integer,         	},  /*  2 */
    { "BIT_STRING",        &cKryptASN1BitString,	},  /*  3 */
    { "OCTET_STRING",      &cKryptASN1OctetString,  	},  /*  4 */
    { "NULL",              &cKryptASN1Null,         	},  /*  5 */
    { "OBJECT_ID",         &cKryptASN1ObjectId,     	},  /*  6 */
    { "OBJECT_DESCRIPTOR", NULL,                  	},  /*  7 */
    { "EXTERNAL",          NULL,                  	},  /*  8 */
    { "REAL",              NULL,                  	},  /*  9 */
    { "ENUMERATED",        &cKryptASN1Enumerated,   	},  /* 10 */
    { "EMBEDDED_PDV",      NULL,                  	},  /* 11 */
    { "UTF8_STRING",       &cKryptASN1UTF8String,   	},  /* 12 */
    { "RELATIVE_OID",      NULL,                  	},  /* 13 */
    { "[UNIVERSAL 14]",    NULL,                  	},  /* 14 */
    { "[UNIVERSAL 15]",    NULL,                  	},  /* 15 */
    { "SEQUENCE",          &cKryptASN1Sequence,        	},  /* 16 */
    { "SET",               &cKryptASN1Set,             	},  /* 17 */
    { "NUMERIC_STRING",    &cKryptASN1NumericString,   	},  /* 18 */
    { "PRINTABLE_STRING",  &cKryptASN1PrintableString, 	},  /* 19 */
    { "T61_STRING",        &cKryptASN1T61String,       	},  /* 20 */
    { "VIDEOTEX_STRING",   &cKryptASN1VideotexString,  	},  /* 21 */
    { "IA5_STRING",        &cKryptASN1IA5String,       	},  /* 22 */
    { "UTC_TIME",          &cKryptASN1UTCTime,         	},  /* 23 */
    { "GENERALIZED_TIME",  &cKryptASN1GeneralizedTime, 	},  /* 24 */
    { "GRAPHIC_STRING",    &cKryptASN1GraphicString,   	},  /* 25 */
    { "ISO64_STRING",      &cKryptASN1ISO64String,     	},  /* 26 */
    { "GENERAL_STRING",    &cKryptASN1GeneralString,   	},  /* 27 */
    { "UNIVERSAL_STRING",  &cKryptASN1UniversalString, 	},  /* 28 */
    { "CHARACTER_STRING",  NULL,                  	},  /* 29 */
    { "BMP_STRING",        &cKryptASN1BMPString,       	},  /* 30 */
};

static int krypt_asn1_infos_size = (sizeof(krypt_asn1_infos)/sizeof(krypt_asn1_infos[0]));

#define ASN1DATA_DECODED  (1 << 0)
#define ASN1DATA_EXPLICIT (1 << 1)
#define ASN1DATA_MODIFIED (1 << 2)

struct krypt_asn1_data_st;
typedef struct krypt_asn1_data_st krypt_asn1_data;
typedef void (*krypt_asn1_update_cb)(krypt_asn1_data *);

struct krypt_asn1_data_st {
    krypt_asn1_object *object;
    krypt_asn1_update_cb update_cb;
    krypt_asn1_codec *codec;
    int flags;
    int default_tag;
}; 

static krypt_asn1_codec *
int_codec_for(krypt_asn1_object *object)
{
    krypt_asn1_codec *codec = NULL;
    int tag = object->header->tag;

    if (tag < 31 && object->header->tag_class == TAG_CLASS_UNIVERSAL)
	codec = &krypt_asn1_codecs[tag];
    if (!codec)
	codec = &KRYPT_DEFAULT_CODEC;

    return codec;
}

static krypt_asn1_data *
int_asn1_data_new(krypt_asn1_object *object)
{
    krypt_asn1_data *ret;

    ret = ALLOC(krypt_asn1_data);
    ret->object = object;
    ret->update_cb = NULL;
    ret->codec = int_codec_for(object);
    ret->flags = ASN1DATA_DECODED; /* only overwritten by parsed values */
    ret->default_tag = -1;
    return ret;
}

static void
int_asn1_data_free(krypt_asn1_data *data)
{
    if (!data) return;
    krypt_asn1_object_free(data->object);
    xfree(data);
}

#define int_asn1_data_set(klass, obj, data)	 			\
do { 							    		\
    if (!(data)) { 					    		\
	rb_raise(eKryptError, "Uninitialized krypt_asn1_data");		\
    } 									\
    (obj) = Data_Wrap_Struct((klass), 0, int_asn1_data_free, (data)); 	\
} while (0)

#define int_asn1_data_get(obj, data)				\
do { 								\
    Data_Get_Struct((obj), krypt_asn1_data, (data));		\
    if (!(data)) { 						\
	rb_raise(eKryptError, "Uninitialized krypt_asn1_data");	\
    } 								\
} while (0)

#define int_asn1_data_get_tag(o)			rb_ivar_get((o), sKrypt_IV_TAG)
#define int_asn1_data_get_tag_class(o)			rb_ivar_get((o), sKrypt_IV_TAG_CLASS)
#define int_asn1_data_get_infinite_length(o)		rb_ivar_get((o), sKrypt_IV_INF_LEN)
#define int_asn1_data_get_value(o)			rb_ivar_get((o), sKrypt_IV_VALUE)

#define int_asn1_data_set_tag(o, v)			rb_ivar_set((o), sKrypt_IV_TAG, (v))
#define int_asn1_data_set_tag_class(o, v)		rb_ivar_set((o), sKrypt_IV_TAG_CLASS, (v))
#define int_asn1_data_set_infinite_length(o, v)		rb_ivar_set((o), sKrypt_IV_INF_LEN, (v))
#define int_asn1_data_set_value(o, v)			rb_ivar_set((o), sKrypt_IV_VALUE, (v))

#define int_asn1_data_is_decoded(o)			(((o)->flags & ASN1DATA_DECODED) == ASN1DATA_DECODED)
#define int_asn1_data_is_explicit(o)			(((o)->flags & ASN1DATA_EXPLICIT) == ASN1DATA_EXPLICIT)
#define int_asn1_data_is_modified(o)			(((o)->flags & ASN1DATA_MODIFIED) == ASN1DATA_MODIFIED)
#define int_asn1_data_set_decoded(o, b)		\
do {						\
    if (b) {					\
	(o)->flags |= ASN1DATA_DECODED;		\
    } else {					\
	(o)->flags &= ~ASN1DATA_DECODED;	\
    }						\
} while (0)
#define int_asn1_data_set_explicit(o, b)	\
do {						\
    if (b) {					\
	(o)->flags |= ASN1DATA_EXPLICIT;	\
    } else {					\
	(o)->flags &= ~ASN1DATA_EXPLICIT;	\
    }						\
} while (0)
#define int_asn1_data_set_modified(o, b)	\
do {						\
    if (b) {					\
	(o)->flags |= ASN1DATA_MODIFIED;	\
    } else {					\
	(o)->flags &= ~ASN1DATA_MODIFIED;	\
    }						\
} while (0)

/* Declaration of en-/decode callbacks */
static int int_asn1_data_value_decode(VALUE self, krypt_asn1_data *data, VALUE *out);
static int int_asn1_cons_value_decode(VALUE self, krypt_asn1_data *data, VALUE *out);
static int int_asn1_prim_value_decode(VALUE self, krypt_asn1_data *data, VALUE *out);

static int int_asn1_data_encode_to(VALUE self, binyo_outstream *out, VALUE value, krypt_asn1_data *data);
static int int_asn1_cons_encode_to(VALUE self, binyo_outstream *out, VALUE value, krypt_asn1_data *data);
static int int_asn1_prim_encode_to(VALUE self, binyo_outstream *out, VALUE value, krypt_asn1_data *data);

static void
int_handle_class_specifics(VALUE self, krypt_asn1_header *header)
{
    if (header->tag_class == TAG_CLASS_UNIVERSAL) {
	switch (header->tag) {
	    case TAGS_BIT_STRING:
		rb_ivar_set(self, sKrypt_IV_UNUSED_BITS, INT2NUM(0));
		break;
	    default:
		break;
	}
    }
}

static VALUE
int_determine_class_and_default_tag(krypt_asn1_data *data)
{
    krypt_asn1_header *header = data->object->header;

    if (header->tag_class == TAG_CLASS_UNIVERSAL) {
	if (header->tag > 30) {
	    krypt_error_add("Universal tag too large: %d", header->tag);
	    return Qnil;
	}
	if (!krypt_asn1_infos[header->tag].klass) {
	    if (header->is_constructed)
		return cKryptASN1Constructive;
	    else
		return cKryptASN1Data;
	}
	data->default_tag = header->tag;
	return *(krypt_asn1_infos[header->tag].klass);
    }
    else {
	return header->is_constructed ? cKryptASN1Constructive : cKryptASN1Data;
    }
}

/* This initializer is used with freshly parsed values */
static VALUE
krypt_asn1_data_new(binyo_instream *in, krypt_asn1_header *header)
{
    VALUE obj;
    VALUE klass;
    ID tag_class;
    krypt_asn1_data *data;
    krypt_asn1_object *encoding;
    uint8_t *value = NULL;
    size_t value_len;

    if (krypt_asn1_get_value(in, header, &value, &value_len) == KRYPT_ERR)
	return Qnil;
    
    encoding = krypt_asn1_object_new_value(header, value, value_len);
    data = int_asn1_data_new(encoding);
    int_asn1_data_set_decoded(data, 0);
    klass = int_determine_class_and_default_tag(data);
    if (NIL_P(klass)) goto error;
    int_asn1_data_set(klass, obj, data);

    int_asn1_data_set_tag(obj, INT2NUM(header->tag));
    if (!(tag_class = krypt_asn1_tag_class_for_int(header->tag_class))) goto error;
    int_asn1_data_set_tag_class(obj, ID2SYM(tag_class));
    int_asn1_data_set_infinite_length(obj, header->is_infinite ? Qtrue : Qfalse);

    int_handle_class_specifics(obj, header);

    return obj;

error:
    xfree(data->object->bytes);
    xfree(data->object);
    xfree(data); /*header will be freed by caller */
    return Qnil;
}

/* Initializer section for ASN1Data created from scratch */
static VALUE
krypt_asn1_data_alloc(VALUE klass)
{
    return Data_Wrap_Struct(klass, 0, int_asn1_data_free, 0);
}

/* Generic helper for initialization */
static void
int_asn1_data_initialize(VALUE self,
			 int tag, 
			 int tag_class, 
			 int is_constructed, 
			 int is_infinite)
{
    krypt_asn1_data *data;
    krypt_asn1_object *object;
    krypt_asn1_header *header;

    if (DATA_PTR(self))
	rb_raise(eKryptASN1Error, "ASN1Data already initialized");
    header = krypt_asn1_header_new();
    header->tag = tag;
    header->tag_class = tag_class;
    header->is_constructed = is_constructed;
    header->is_infinite = is_infinite;
    object = krypt_asn1_object_new(header);
    data = int_asn1_data_new(object);
    if (tag_class == TAG_CLASS_UNIVERSAL)
	data->codec = int_codec_for(object);
    DATA_PTR(self) = data;
}

#define int_validate_tag_and_class(t, tc)				\
do {									\
    if (!SYMBOL_P((tc)))						\
        rb_raise(eKryptASN1Error, "Tag class must be a Symbol");	\
    if (!FIXNUM_P((t)))							\
	rb_raise(eKryptASN1Error, "Tag must be a Number");		\
} while (0)

/** ASN1Data can dynamically change its codec while
 * ASN1Primitive and ASN1Constructive and its
 * sub classes can not.  */
static void
int_asn1_data_update_cb(krypt_asn1_data *data)
{
    if (!data->object->header->is_constructed)
	data->codec = int_codec_for(data->object);
}

/* Used by non-UNIVERSAL values */
/*
 * call-seq:
 *    ASN1Data.new(value, tag, tag_class) -> ASN1Data
 *
 * * +value+: the value to be associated. See Primitive for the mappings
 * between ASN.1 types and Ruby types.
 * * +tag+:   a +Number+ representing this value's tag.
 * * +tag_class+: a +Symbol+ representing one of the four valid tag classes
 * +:UNIVERSAL+, +:CONTEXT_SPECIFIC+, +:APPLICATION+ or +:PRIVATE+.
 *
 * Creates an ASN1Data from scratch.
 */ 
static VALUE
krypt_asn1_data_initialize(VALUE self, VALUE value, VALUE vtag, VALUE vtag_class)
{
    ID stag_class;
    int tag, tag_class, is_constructed;
    krypt_asn1_data *data;

    int_validate_tag_and_class(vtag, vtag_class);
    tag = NUM2INT(vtag);
    stag_class = SYM2ID(vtag_class);
    if (stag_class == sKrypt_TC_EXPLICIT)
	rb_raise(eKryptASN1Error, "Explicit tagging is only supported for explicit UNIVERSAL sub classes of ASN1Data");
    if (stag_class == sKrypt_TC_UNIVERSAL && tag > 30)
	rb_raise(eKryptASN1Error, "Tag too large for UNIVERSAL tag class");
    if ((tag_class = krypt_asn1_tag_class_for_id(stag_class)) == KRYPT_ERR)
        rb_raise(eKryptASN1Error, "Unknown tag class");
    is_constructed = rb_respond_to(value, sKrypt_ID_EACH);
    
    int_asn1_data_initialize(self, tag, tag_class, is_constructed, 0);

    int_asn1_data_get(self, data);
    data->update_cb = int_asn1_data_update_cb;

    int_asn1_data_set_tag(self, vtag);
    int_asn1_data_set_tag_class(self, vtag_class);
    int_asn1_data_set_infinite_length(self, Qfalse);
    int_asn1_data_set_value(self, value);

    int_asn1_data_set_modified(data, 1); /* newly created is modified by default */

    return self;
}

static VALUE int_asn1_default_initialize(VALUE self, VALUE value, VALUE vtag, int default_tag, VALUE vtag_class);

/* Default helper for all UNIVERSAL values */
static VALUE
int_asn1_default_initialize(VALUE self,
			    VALUE value,
			    VALUE vtag,
			    int default_tag,
			    VALUE vtag_class)
{
    ID stag_class;
    int tag, tag_class, is_constructed;
    krypt_asn1_data *data;

    int_validate_tag_and_class(vtag, vtag_class);
    tag = NUM2INT(vtag);
    stag_class = SYM2ID(vtag_class);
    if (stag_class == sKrypt_TC_UNIVERSAL && tag > 30)
	rb_raise(eKryptASN1Error, "Tag too large for UNIVERSAL tag class");
    if ((tag_class = krypt_asn1_tag_class_for_id(stag_class)) == KRYPT_ERR)
        rb_raise(eKryptASN1Error, "Unknown tag class");
    
    is_constructed = rb_respond_to(value, sKrypt_ID_EACH);

    int_asn1_data_initialize(self,
	                     tag,
			     tag_class,
			     is_constructed,
			     0);

    int_asn1_data_get(self, data);

    if (stag_class == sKrypt_TC_EXPLICIT)
	int_asn1_data_set_explicit(data, 1);

    /* Override default behavior to support tag classes other than UNIVERSAL */
    if (default_tag <= 30) {
	data->codec = &krypt_asn1_codecs[default_tag];
	data->default_tag = default_tag;
    }

    int_asn1_data_set_tag(self, vtag);
    int_asn1_data_set_tag_class(self, vtag_class);
    int_asn1_data_set_infinite_length(self, Qfalse);
    int_asn1_data_set_value(self, value);

    int_asn1_data_set_modified(data, 1); /* newly created is modified by default */

    return self;
}

#define int_validate_args(tag, tc, argc, defaulttag)				\
do {										\
    if (!NIL_P((tc))) {								\
        if (NIL_P((tag)))							\
	    rb_raise(eKryptASN1Error, "Tag must be specified if tag class is");	\
        if (!SYMBOL_P((tc)))							\
            rb_raise(eKryptASN1Error, "Tag class must be a Symbol");		\
    }										\
    if (NIL_P((tc))) {								\
	if ((argc) == 3)							\
	    rb_raise(eKryptASN1Error, "Tag class must be a Symbol");		\
	if (NIL_P((tag)))							\
	    (tc) = ID2SYM(sKrypt_TC_UNIVERSAL);					\
	else									\
	    (tc) = ID2SYM(sKrypt_TC_CONTEXT_SPECIFIC);				\
    }										\
    if (NIL_P((tag))) {								\
	(tag) = INT2NUM((defaulttag));						\
    }										\
    else {									\
        if (!FIXNUM_P((tag)))							\
	    rb_raise(eKryptASN1Error, "Tag must be a Number");			\
    }										\
} while (0)

/* Special treatment for EOC: no-arg constructor */
static VALUE
krypt_asn1_end_of_contents_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE value;
    VALUE tag;
    VALUE tag_class;

    if (argc == 0) {
	value = Qnil;
    }
    else {
	rb_scan_args(argc, argv, "10", &value);
	if(!NIL_P(value))
	    rb_raise(rb_eArgError, "Value must be nil for END_OF_CONTENTS");
    }

    tag = INT2NUM(TAGS_END_OF_CONTENTS);
    tag_class = ID2SYM(sKrypt_TC_UNIVERSAL);
    return int_asn1_default_initialize(self,
	    			       value,
				       tag,
				       TAGS_END_OF_CONTENTS,
				       tag_class);
}

static VALUE
int_asn1_end_of_contents_new_instance(void)
{
    VALUE eoc;

    eoc = rb_obj_alloc(cKryptASN1EndOfContents);
    return krypt_asn1_end_of_contents_initialize(0, NULL, eoc);
}
   
/* Special treatment for NULL: no-arg constructor */
static VALUE
krypt_asn1_null_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE value;
    VALUE tag;
    VALUE tag_class;
    if (argc == 0) {
	value = Qnil;
	tag = INT2NUM(TAGS_NULL);
	tag_class = ID2SYM(sKrypt_TC_UNIVERSAL);
    }
    else {
	rb_scan_args(argc, argv, "12", &value, &tag, &tag_class);
	int_validate_args(tag, tag_class, argc, TAGS_NULL);
	if (!NIL_P(value))
	    rb_raise(rb_eArgError, "Value must be nil for NULL");
    }

    return int_asn1_default_initialize(self,
	    			       value,
				       tag,
				       TAGS_NULL,
				       tag_class);
}

/* Special treatment for BIT_STRING: set @unused_bits */
static VALUE
krypt_asn1_bit_string_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE value;
    VALUE tag;
    VALUE tag_class;
    rb_scan_args(argc, argv, "12", &value, &tag, &tag_class);
    int_validate_args(tag, tag_class, argc, TAGS_BIT_STRING);

    self = int_asn1_default_initialize(self,
	    			       value,
				       tag,
				       TAGS_BIT_STRING,
				       tag_class);

    rb_ivar_set(self, sKrypt_IV_UNUSED_BITS, INT2NUM(0));

    return self;
}

#define KRYPT_ASN1_DEFINE_CTOR(klass, t)						\
static VALUE										\
krypt_asn1_##klass##_initialize(int argc, VALUE *argv, VALUE self)			\
{											\
    VALUE value, tag, tag_class;							\
    rb_scan_args(argc, argv, "12", &value, &tag, &tag_class);				\
    int_validate_args(tag, tag_class, argc, t);						\
    return int_asn1_default_initialize(self, value, tag, (t), tag_class);		\
}

KRYPT_ASN1_DEFINE_CTOR(boolean,    	 TAGS_BOOLEAN    	)
KRYPT_ASN1_DEFINE_CTOR(integer,    	 TAGS_INTEGER    	)
KRYPT_ASN1_DEFINE_CTOR(enumerated,    	 TAGS_ENUMERATED    	)
KRYPT_ASN1_DEFINE_CTOR(octet_string,     TAGS_OCTET_STRING 	)
KRYPT_ASN1_DEFINE_CTOR(utf8_string,      TAGS_UTF8_STRING 	)
KRYPT_ASN1_DEFINE_CTOR(numeric_string,   TAGS_NUMERIC_STRING 	)
KRYPT_ASN1_DEFINE_CTOR(printable_string, TAGS_PRINTABLE_STRING  )
KRYPT_ASN1_DEFINE_CTOR(t61_string, 	 TAGS_T61_STRING 	)
KRYPT_ASN1_DEFINE_CTOR(videotex_string,  TAGS_VIDEOTEX_STRING   )
KRYPT_ASN1_DEFINE_CTOR(ia5_string, 	 TAGS_IA5_STRING 	)
KRYPT_ASN1_DEFINE_CTOR(graphic_string, 	 TAGS_GRAPHIC_STRING 	)
KRYPT_ASN1_DEFINE_CTOR(iso64_string, 	 TAGS_ISO64_STRING 	)
KRYPT_ASN1_DEFINE_CTOR(general_string,   TAGS_GENERAL_STRING 	)
KRYPT_ASN1_DEFINE_CTOR(universal_string, TAGS_UNIVERSAL_STRING  )
KRYPT_ASN1_DEFINE_CTOR(bmp_string, 	 TAGS_BMP_STRING 	)
KRYPT_ASN1_DEFINE_CTOR(object_id, 	 TAGS_OBJECT_ID	 	)
KRYPT_ASN1_DEFINE_CTOR(utc_time, 	 TAGS_UTC_TIME 	 	)
KRYPT_ASN1_DEFINE_CTOR(generalized_time, TAGS_GENERALIZED_TIME  )

KRYPT_ASN1_DEFINE_CTOR(sequence, 	 TAGS_SEQUENCE 	 	)
KRYPT_ASN1_DEFINE_CTOR(set, 		 TAGS_SET 	 	)

/* End initializer section for ASN1Data created from scratch */

/* ASN1Data methods */

#define int_invalidate_tag(h)				\
do {							\
    if ((h)->tag_bytes)					\
        xfree((h)->tag_bytes);				\
    (h)->tag_bytes = NULL;				\
    (h)->tag_len = 0;					\
} while (0)

#define int_invalidate_length(h)			\
do {							\
    if ((h)->length_bytes)				\
        xfree((h)->length_bytes);			\
    (h)->length_bytes = NULL;				\
    (h)->length_len = 0;				\
    (h)->length = 0;					\
} while (0)

#define int_invalidate_value(o)				\
do {							\
    if ((o)->bytes)					\
        xfree((o)->bytes);				\
    (o)->bytes = NULL;					\
    (o)->bytes_len = 0;					\
    int_invalidate_length((o)->header);			\
} while (0)

/*
 * call-seq:
 *    asn1.tag -> Number
 *
 * Returns a +Number+ representing the tag number of this ASN1Data. 
 * Never +nil+.
 */
static VALUE
krypt_asn1_data_get_tag(VALUE self)
{
    return int_asn1_data_get_tag(self);
}

/*
 * call-seq:
 *    asn1.tag=(number) -> Number
 *
 * * +number+: a +Number+ representing the tag number of this ASN1Data. 
 * Must not be +nil+.
 */
static VALUE
krypt_asn1_data_set_tag(VALUE self, VALUE tag)
{
    krypt_asn1_data *data;
    krypt_asn1_header *header;
    int new_tag;

    int_asn1_data_get(self, data);

    header = data->object->header;
    new_tag = NUM2INT(tag);
    if (header->tag == new_tag)
	return tag;

    header->tag = new_tag;
    int_invalidate_tag(header);
    if (data->update_cb)
	data->update_cb(data);

    int_asn1_data_set_modified(data, 1);
    int_asn1_data_set_tag(self, tag);

    return tag;
}

/*
 * call-seq:
 *    asn1.tag_class -> Symbol
 *
 * Returns a +Symbol+ representing the tag class of this ASN1Data.
 * Never +nil+. See ASN1Data for possible values.
 */
static VALUE
krypt_asn1_data_get_tag_class(VALUE self)
{
    return int_asn1_data_get_tag_class(self);
}

static int int_asn1_decode_value(VALUE self);

static int
int_asn1_handle_explicit_tagging(VALUE self, krypt_asn1_data *data, ID new_tc)
{
    int old_explicit;
    int invalidate_value = 0;

    old_explicit = int_asn1_data_is_explicit(data);
    if (new_tc == sKrypt_TC_EXPLICIT && old_explicit == 0) {
	invalidate_value = 1;
	int_asn1_data_set_explicit(data, 1);
    }
    if (new_tc != sKrypt_TC_EXPLICIT && old_explicit == 1) {
	invalidate_value = 1;
	int_asn1_data_set_explicit(data, 0);
    }

    if (invalidate_value) {
	if (!int_asn1_data_is_decoded(data)) {
	    if(int_asn1_decode_value(self) == KRYPT_ERR) return KRYPT_ERR;
	}
	int_invalidate_value(data->object);
    }
    return KRYPT_OK;
}

/*
 * call-seq:
 *    asn1.tag_class=(sym) -> Symbol
 *
 * * +sym+: A +Symbol+ representing the tag class of this ASN1Data.
 * Must not be +nil+. See ASN1Data for possible values.
 */
static VALUE
krypt_asn1_data_set_tag_class(VALUE self, VALUE tag_class)
{
    krypt_asn1_data *data;
    krypt_asn1_header *header;
    int new_tag_class;
    ID new_tc, old_tc;

    int_asn1_data_get(self, data);

    new_tc = SYM2ID(tag_class);
    old_tc = SYM2ID(int_asn1_data_get_tag_class(self));
    if (new_tc == old_tc)
	return tag_class;
    if (new_tc == sKrypt_TC_EXPLICIT && data->default_tag == -1)
	rb_raise(eKryptASN1Error, "Cannot explicitly tag value with unknown default tag");

    header = data->object->header;
    if ((new_tag_class = krypt_asn1_tag_class_for_id(new_tc)) == KRYPT_ERR)
        rb_raise(eKryptASN1Error, "Cannot set tag class");

    header->tag_class = new_tag_class;
    int_invalidate_tag(header);

    if (data->update_cb)
	data->update_cb(data);

    if (int_asn1_handle_explicit_tagging(self, data, new_tc) == KRYPT_ERR)
	rb_raise(eKryptASN1Error, "Tagging explicitly failed");

    int_asn1_data_set_modified(data, 1);
    int_asn1_data_set_tag_class(self, tag_class);

    return tag_class;
}

/*
 * call-seq:
 *    asn1.infinite_length -> bool
 *
 * Returns either true or false, depending on whether the value
 * is to be or was encoded using infinite length. See
 * ASN1Data#infinite_length= for details.
 */
static VALUE
krypt_asn1_data_get_inf_length(VALUE self)
{
    return int_asn1_data_get_infinite_length(self);
}

/*
 * call-seq:
 *    asn1.infinite_length=(bool) -> bool
 *
 * * +bool+: either true or false, depending on whether the value shall be
 * encoded using infinite length encoding or not
 *
 * Set a +Boolean+ indicating whether the encoding shall be infinite
 * length or not.
 * In DER, every value has a finite length associated with it. But in
 * scenarios where large amounts of data need to be transferred, it
 * might be desirable to have some kind of streaming support available.
 * For example, huge OCTET STRINGs are preferably sent in smaller-sized
 * chunks, each at a time.
 * This is possible in BER by setting the length bytes of an encoding
 * to zero and thus indicating that the following value will be
 * sent in chunks. Infinite length encodings are always constructed.
 * The end of such a stream of chunks is indicated by sending a 
 * EndOfContents value. SETs and SEQUENCEs may use an infinite length
 * encoding, but also primitive types such as e.g. OCTET STRINGS or
 * BIT STRINGS may leverage this functionality (cf. ITU-T X.690).
 */
static VALUE
krypt_asn1_data_set_inf_length(VALUE self, VALUE inf_length)
{
    krypt_asn1_data *data;
    krypt_asn1_header *header;
    int new_inf;

    int_asn1_data_get(self, data);

    header = data->object->header;
    new_inf = RTEST(inf_length) ? 1 : 0;
    if (header->is_infinite == new_inf)
	return inf_length;

    header->is_infinite = new_inf;
    int_invalidate_length(header);
    
    int_asn1_data_set_modified(data, 1);
    int_asn1_data_set_infinite_length(self, new_inf ? Qtrue : Qfalse);

    return inf_length;
}

static int
int_asn1_data_value_decode(VALUE self, krypt_asn1_data *data, VALUE *out)
{
    if (data->object->header->is_constructed) {
	int result;
	krypt_asn1_object *object = data->object;

	result = int_asn1_cons_value_decode(self, data, out);
	/* Invalidate the cached byte encoding */
	xfree(object->bytes);
	object->bytes = NULL;
	object->bytes_len = 0;
	return result;
    } else {
	return int_asn1_prim_value_decode(self, data, out);
    }
}

static int
int_asn1_decode_value(VALUE self)
{
    krypt_asn1_data *data;

    int_asn1_data_get(self, data);
    /* TODO: sync */
    if (!int_asn1_data_is_decoded(data)) {
	VALUE value;
	if (int_asn1_data_value_decode(self, data, &value) == KRYPT_ERR) return KRYPT_ERR;
	int_asn1_data_set_value(self, value);
	int_asn1_data_set_decoded(data, 1);
    }
    return KRYPT_OK;
}

/*
 * call-seq:
 *    asn1.value -> value
 *
 * Obtain the value of an ASN1Data.
 * Please see Constructive and Primitive docs for the mappings between
 * ASN.1 data types and Ruby classes.
 */
static VALUE
krypt_asn1_data_get_value(VALUE self)
{
    if (int_asn1_decode_value(self) == KRYPT_ERR)
	krypt_error_raise(eKryptASN1Error, "Error while decoding value");
    return int_asn1_data_get_value(self);
}

/*
 * call-seq:
 *    asn1.value=(value) -> value
 *
 * Set the value of an ASN1Data.
 * Please see Constructive and Primitive docs for the mappings between
 * ASN.1 data types and Ruby classes.
 */
static VALUE
krypt_asn1_data_set_value(VALUE self, VALUE value)
{
    krypt_asn1_data *data;
    krypt_asn1_object *object;
    int is_constructed;

    int_asn1_data_get(self, data);
    int_asn1_data_set_value(self, value);

    /* Free data that is now stale */
    object = data->object;
    int_invalidate_value(object);    
    is_constructed = rb_respond_to(value, sKrypt_ID_EACH);
    if (object->header->is_constructed != is_constructed) {
	object->header->is_constructed = is_constructed;
	int_invalidate_tag(object->header);
	data->codec = int_codec_for(data->object);
    }

    int_asn1_data_set_modified(data, 1);

    return value;
}

static int 
int_asn1_data_encode_to(VALUE self, binyo_outstream *out, VALUE value, krypt_asn1_data *data)
{
    int ret;

    if (data->object->header->is_constructed)
	ret = int_asn1_cons_encode_to(self, out, value, data);
    else
	ret = int_asn1_prim_encode_to(self, out, value, data);
    int_asn1_data_set_modified(data, 0); /* once encoded, modified status is reset */
    return ret;
}

static int
int_asn1_make_explicit(VALUE value, int default_tag, VALUE *out)
{
    VALUE universal;
    VALUE klass;
    VALUE ary;
    krypt_asn1_data *data;

    if (default_tag == -1) {
	krypt_error_add("Cannot encode value with explicit tagging");
	return KRYPT_ERR;
    }

    if (!krypt_asn1_infos[default_tag].klass) {
	krypt_error_add("Unsupported tag: %d", default_tag);
	return KRYPT_ERR;
    }

    ary = rb_ary_new();

    klass = *(krypt_asn1_infos[default_tag].klass);
    universal = rb_obj_alloc(klass);
    universal = int_asn1_default_initialize(
	    universal,
	    value,
	    INT2NUM(default_tag),
	    default_tag,
	    ID2SYM(sKrypt_TC_UNIVERSAL)
    );
    int_asn1_data_get(universal, data);
    int_handle_class_specifics(universal, data->object->header);
    rb_ary_push(ary, universal);

    *out = ary;
    return KRYPT_OK;
}

static int
int_asn1_encode_to(binyo_outstream *out, krypt_asn1_data *data, VALUE self)
{
    krypt_asn1_object *object = data->object;

    /* TODO: sync */
    if (!object->bytes) {
	VALUE value;
	value = int_asn1_data_get_value(self);
	if (int_asn1_data_is_explicit(data)) {
	    if (int_asn1_make_explicit(value, data->default_tag, &value) == KRYPT_ERR) return KRYPT_ERR;
	    data->object->header->is_constructed = 1; /* explicitly tagged values are always constructed */
	}
	return int_asn1_data_encode_to(self, out, value, data);
    }
    else {
	if (krypt_asn1_object_encode(out, object) == KRYPT_ERR)
            return KRYPT_ERR;
        return KRYPT_OK;
    }
}

/*
 * call-seq:
 *    asn1.encode_to(io) -> self
 *
 * * +io+: an IO-like object supporting IO#write
 *
 * Encodes this ASN1Data into a DER-encoded String value by writing the
 * contents to an IO-like object.
 * Newly created ASN1Data are DER-encoded except for the possibility of
 * infinite length encodings. If a value with BER encoding was parsed and
 * is not modified, the BER encoding will be preserved when encoding it
 * again.
 */
static VALUE
krypt_asn1_data_encode_to(VALUE self, VALUE io)
{
    binyo_outstream *out;
    krypt_asn1_data *data;
    int result;

    int_asn1_data_get(self, data);

    out = binyo_outstream_new_value(io);
    result = int_asn1_encode_to(out, data, self);
    binyo_outstream_free(out);
    if (result == KRYPT_ERR)
	krypt_error_raise(eKryptASN1Error, "Error while encoding value");
    return self;
}

static VALUE
int_asn1_data_to_der_cached(krypt_asn1_object *object)
{
    binyo_outstream *out;
    VALUE ret;
    uint8_t *bytes;
    size_t len;

    len = object->header->tag_len + object->header->length_len + object->bytes_len;
    bytes = ALLOCA_N(uint8_t, len);
    out = binyo_outstream_new_bytes_prealloc(bytes, len);

    if (krypt_asn1_object_encode(out, object) == KRYPT_ERR) {
	binyo_outstream_free(out);
	krypt_error_raise(eKryptASN1Error, "Error while encoding value");
    }

    ret = rb_str_new((const char *) bytes, len);
    binyo_outstream_free(out);
    return ret;
}

static VALUE
int_asn1_data_to_der_non_cached(krypt_asn1_data *data, VALUE self)
{
    VALUE string;
    binyo_outstream *out;
    uint8_t *bytes;
    size_t len;

    out = binyo_outstream_new_bytes_size(2048);

    if (int_asn1_encode_to(out, data, self) == KRYPT_ERR) {
	binyo_outstream_free(out);
	krypt_error_raise(eKryptASN1Error, "Error while encoding value");
    }

    len = binyo_outstream_bytes_get_bytes_free(out, &bytes);
    if (len > LONG_MAX)
	rb_raise(eKryptASN1Error, "Size of string too large: %ld", len);
    string = rb_str_new((const char *) bytes, (long) len);
    xfree(bytes);
    return string;
}

/*
 * call-seq:
 *    asn1.to_der -> DER-/BER-encoded String
 *
 * Encodes this ASN1Data into a DER-encoded String value. Newly created 
 * ASN1Data are DER-encoded except for the possibility of infinite length
 * encodings. If a value with BER encoding was parsed and is not modified,
 * the BER encoding will be preserved when encoding it again.
 */
static VALUE
krypt_asn1_data_to_der(VALUE self)
{
    krypt_asn1_data *data;
    krypt_asn1_object *object;

    int_asn1_data_get(self, data);
    object = data->object;

    if (object->bytes && object->header->tag_bytes && object->header->length_bytes)
	return int_asn1_data_to_der_cached(data->object);
    else
	return int_asn1_data_to_der_non_cached(data, self);
}

/*
 * call-seq:
 *    a <=> b -> -1 | 0 | +1 
 *
 * ASN1Data includes the Comparable module.
 *
 * +<=>+ compares two instances of ASN1Data by comparing the bytes of their
 * encoding. The order applied is SET order, i.e. a < b iff tag of a < tag
 * of b. If tags are equal, SET OF order is applied, a lexicographical byte
 * order. Element order is decided based on the first byte where two elements
 * differ, the lower byte indicates the lower element.
 *
 * If two elements differ in length, but are equal up to the last byte of the
 * smaller element, the smaller element is the lower one.
 *
 * == Example
 *
 * Given the following SET of values
 *
 *   [ 
 *     Krypt::ASN1::OctetString.new("a"),
 *     Krypt::ASN1::Null.new,
 *     Krypt::ASN1::Boolean.new(true),
 *     Krypt::ASN1::Integer.new(1)       
 *   ]
 *
 *   the implied SET order is
 *
 *   [ 
 *     Krypt::ASN1::Boolean.new(true),
 *     Krypt::ASN1::Integer.new(1)       
 *     Krypt::ASN1::OctetString.new("a"),
 *     Krypt::ASN1::Null.new,
 *   ]
 * 
 * Given the following byte representations of OCTET STRINGS,
 * 
 *   [ "\x04\x06\aaabaa", "\x04\x01b", "\x04\x06aaabba", "\x04\x04aaab" ] 
 *
 * the SET OF order implied is
 *
 *   [ "\x04\x01b", "\x04\x04aaab", "\x04\x06aaabaa", "\x04\x06aaabba" ] 
 */
static VALUE
krypt_asn1_data_cmp(VALUE a, VALUE b)
{
    VALUE vs1, vs2;
    int result;

    vs1 = krypt_asn1_data_to_der(a);
    if (!rb_respond_to(b, sKrypt_ID_TO_DER)) return Qnil;
    vs2 = krypt_to_der(b);

    if(krypt_asn1_cmp_set_of((uint8_t *) RSTRING_PTR(vs1), (size_t) RSTRING_LEN(vs1),
	                     (uint8_t *) RSTRING_PTR(vs2), (size_t) RSTRING_LEN(vs2), &result) == KRYPT_ERR) {
	krypt_error_raise(eKryptASN1Error, "Error while comparing values");
    }
    return INT2NUM(result);
}
/* End ASN1Data methods */

/* ASN1Constructive methods */

static VALUE
int_cons_each_i(VALUE cur, VALUE arg)
{
    rb_yield(cur);
    return Qnil;
}

/*
 * call-seq:
 *    asn1_ary.each { |asn1| block } -> asn1_ary
 *
 * Calls <i>block</i> once for each element in +self+, passing that element
 * as parameter +asn1+. If no block is given, an enumerator is returned
 * instead.
 *
 * == Example
 *   asn1_ary.each do |asn1|
 *     pp asn1
 *   end
 */
static VALUE
krypt_asn1_cons_each(VALUE self)
{
    VALUE enumerable = krypt_asn1_data_get_value(self);

    KRYPT_RETURN_ENUMERATOR(enumerable, sKrypt_ID_EACH);

    if (rb_obj_is_kind_of(enumerable, rb_cArray))
	return rb_ary_each(krypt_asn1_data_get_value(self));
    else
	return rb_iterate(rb_each, enumerable, int_cons_each_i, Qnil);
}

static int
int_asn1_cons_value_decode(VALUE self, krypt_asn1_data *data, VALUE *out)
{
    VALUE cur;
    binyo_instream *in;
    krypt_asn1_object *object;
    krypt_asn1_header *header;
    int ret;

    *out = rb_ary_new();
    object = data->object;
    if (!object->bytes)
	return 1;

    in = binyo_instream_new_bytes(object->bytes, object->bytes_len);
    
    while ((ret = krypt_asn1_next_header(in, &header)) == KRYPT_OK) {
	if (!(cur = krypt_asn1_data_new(in, header))) {
	    goto error;
	}
	rb_ary_push(*out, cur);
    }

    if (ret == KRYPT_ERR) goto error;

    /* discard EOC if available */
    if (object->header->is_infinite) {
	/* must be EOC because krypt_instream_chunked would otherwise indicate EOF */
	(void) rb_ary_pop(*out);
    }

    binyo_instream_free(in);
    return KRYPT_OK;

error: 
    binyo_instream_free(in);
    return KRYPT_ERR;
}

static VALUE
int_cons_encode_sub_elems_i(VALUE cur, VALUE args)
{
    binyo_outstream *out = NULL;
    int *eoc_p;
    krypt_asn1_data *data;
    krypt_asn1_header *header;
    
    Data_Get_Struct(rb_ary_entry(args, 0), binyo_outstream, out);
    Data_Get_Struct(rb_ary_entry(args, 1), int, eoc_p);
    int_asn1_data_get(cur, data);

    if (int_asn1_encode_to(out, data, cur) == KRYPT_ERR)
	rb_raise(eKryptASN1Error, "Error while encoding values");

    header = data->object->header;
    *eoc_p = header->tag == TAGS_END_OF_CONTENTS && header->tag_class == TAG_CLASS_UNIVERSAL;

    return Qnil;
}

static VALUE
int_cons_encode_sub_elems_wrapped(VALUE args)
{
    VALUE enumerable = rb_ary_pop(args);

    rb_iterate(rb_each, enumerable, int_cons_encode_sub_elems_i, args);
    
    return Qnil;
}

static int
int_cons_add_eoc(binyo_outstream *out)
{
    krypt_asn1_data *data;
    VALUE eoc = int_asn1_end_of_contents_new_instance();

    int_asn1_data_get(eoc, data);
    if (int_asn1_encode_to(out, data, eoc) == KRYPT_ERR) {
	krypt_error_add("Adding final END OF CONTENTS failed");
	return KRYPT_ERR;
    }
    return KRYPT_OK;
}

static int
int_cons_encode_sub_elems_enum(binyo_outstream *out, VALUE enumerable, int infinite)
{
    VALUE args, wrapped_out, wrapped_eoc_p;
    int state = 0;
    int eoc_p = 0;

    wrapped_out = Data_Wrap_Struct(rb_cObject, 0, 0, out); 
    wrapped_eoc_p = Data_Wrap_Struct(rb_cObject, 0, 0, &eoc_p);
    args = rb_ary_new();
    rb_ary_push(args, wrapped_out);
    rb_ary_push(args, wrapped_eoc_p);
    rb_ary_push(args, enumerable);
    (void) rb_protect(int_cons_encode_sub_elems_wrapped, args, &state);
    if (state) return KRYPT_ERR;
    if (infinite && !eoc_p) { /* add EOC if it was missing */
	return int_cons_add_eoc(out);
    }
    return KRYPT_OK;
}

static int
int_cons_add_eoc_ary(binyo_outstream *out, VALUE ary, long i)
{
    krypt_asn1_data *data;
    krypt_asn1_header *header;
    VALUE last = rb_ary_entry(ary, i - 1);

    int_asn1_data_get(last, data);
    header = data->object->header;
    if (header->tag != TAGS_END_OF_CONTENTS || header->tag_class != TAG_CLASS_UNIVERSAL) {
	return int_cons_add_eoc(out);
    }
    return KRYPT_OK;
}

static int
int_cons_encode_sub_elems_ary(binyo_outstream *out, VALUE ary, int infinite)
{
    long size, i;
    VALUE cur;
    size = RARRAY_LEN(ary);

    for (i=0; i < size; i++) {
	krypt_asn1_data *data;

	cur = rb_ary_entry(ary, i);
	int_asn1_data_get(cur, data);
	if (int_asn1_encode_to(out, data, cur) == KRYPT_ERR) return KRYPT_ERR;
    }

    if (infinite) { /* add closing EOC if it was missing */
	if (int_cons_add_eoc_ary(out, ary, i) == KRYPT_ERR) return KRYPT_ERR;
    }
    return KRYPT_OK;
}

static VALUE
int_cons_sort_to_ary(VALUE cur, VALUE ary)
{
    rb_ary_push(ary, cur);
    return Qnil;
}

static VALUE
int_cons_sort_set(VALUE enumerable)
{
    VALUE tmp_ary;

    if (rb_respond_to(enumerable, sKrypt_ID_SORT_BANG)) {
	(void) rb_funcall(enumerable, sKrypt_ID_SORT_BANG, 0);
	return enumerable;
    }
    if (rb_respond_to(enumerable, sKrypt_ID_SORT)) {
	VALUE copy = rb_funcall(enumerable, sKrypt_ID_SORT, 0);
	return copy;
    }

    tmp_ary = rb_ary_new();
    (void) rb_iterate(rb_each, enumerable, int_cons_sort_to_ary, tmp_ary);
    (void) rb_funcall(tmp_ary, sKrypt_ID_SORT_BANG, 0);
    return tmp_ary;
}

static int
int_cons_encode_sub_elems(binyo_outstream *out, VALUE enumerable, krypt_asn1_data *data) 
{
    krypt_asn1_header *header;

    if (NIL_P(enumerable))
	return KRYPT_OK;

    header = data->object->header;
    if (header->tag == TAGS_SET &&
	header->tag_class == TAG_CLASS_UNIVERSAL &&
       	int_asn1_data_is_modified(data)) 
    {
	/* We need to apply proper SET (OF) encoding when creating a new SET */
	enumerable = int_cons_sort_set(enumerable);
    }

    /* Optimize for Array */
    if (TYPE(enumerable) == T_ARRAY)
	return int_cons_encode_sub_elems_ary(out, enumerable, header->is_infinite);
    else
	return int_cons_encode_sub_elems_enum(out, enumerable, header->is_infinite);
}

static int
int_asn1_cons_update_length(VALUE ary, krypt_asn1_data *data, uint8_t **out, size_t *outlen)
{
    binyo_outstream *bos = binyo_outstream_new_bytes_size(1024);

    if (int_cons_encode_sub_elems(bos, ary, data) == KRYPT_ERR) {
	binyo_outstream_free(bos);
	return KRYPT_ERR;
    }
    *outlen = binyo_outstream_bytes_get_bytes_free(bos, out);
    return KRYPT_OK;
}

static int
int_asn1_cons_encode_update(binyo_outstream *out, VALUE ary, krypt_asn1_data *data)
{
    size_t len;
    uint8_t *bytes = NULL;
    krypt_asn1_header *header = data->object->header;

    if (int_asn1_cons_update_length(ary, data, &bytes, &len) == KRYPT_ERR) goto error;
    header->length = len;
    if (krypt_asn1_header_encode(out, header) == KRYPT_ERR) goto error;
    if (header->length > 0) {
	if (binyo_outstream_write(out, bytes, len) == BINYO_ERR) goto error;
    }

    xfree(bytes);
    return KRYPT_OK;
error:
    if (bytes) xfree(bytes);
    return KRYPT_ERR;
}


static int
int_asn1_cons_encode_to(VALUE self, binyo_outstream *out, VALUE ary, krypt_asn1_data *data)
{
    krypt_asn1_header *header;

    header = data->object->header;

    if (header->tag_class == TAG_CLASS_UNIVERSAL) {
	int tag = header->tag;
	if (tag != TAGS_SEQUENCE && tag != TAGS_SET && !header->is_infinite) {
	    krypt_error_add("Primitive constructed values must be infinite length");
	    return KRYPT_ERR;
	}
    }

    /* If the length encoding is still cached or we have an infinite length
     * value, we don't need to compute the length first, we can simply start
     * encoding */ 
    if (header->length_bytes == NULL && !header->is_infinite) {
	return int_asn1_cons_encode_update(out, ary, data);
    } else {
	if (krypt_asn1_header_encode(out, header) == KRYPT_ERR) return KRYPT_ERR;
	if (int_cons_encode_sub_elems(out, ary, data) == KRYPT_ERR) return KRYPT_ERR;
	return KRYPT_OK;
    }
}

/* End ASN1Constructive methods */

/* ASN1Primitive methods */

static int
int_asn1_prim_value_decode(VALUE self, krypt_asn1_data *data, VALUE *out)
{
    krypt_asn1_object *object;

    object = data->object;
    return data->codec->decoder(self, object->bytes, object->bytes_len, out);
}

static int
int_asn1_prim_encode_to(VALUE self, binyo_outstream *out, VALUE value, krypt_asn1_data *data)
{
    krypt_asn1_object *object;

    object = data->object;

    if (object->header->tag_class == TAG_CLASS_UNIVERSAL) {
	int tag = object->header->tag;
	if (tag == TAGS_SEQUENCE || tag == TAGS_SET) {
	    krypt_error_add("Set/Sequence value must be constructed");
	    return KRYPT_ERR;
	}
    }

    if (data->codec->validator(self, value) == KRYPT_ERR) return KRYPT_ERR;
    if (data->codec->encoder(self, value, &object->bytes, &object->bytes_len) == KRYPT_ERR) return KRYPT_ERR;
    object->header->length = object->bytes_len;
    if (krypt_asn1_object_encode(out, object) == KRYPT_ERR) return KRYPT_ERR;

    return KRYPT_OK;
}

static VALUE
krypt_asn1_bit_string_set_unused_bits(VALUE self, VALUE unused_bits)
{
    rb_ivar_set(self, sKrypt_IV_UNUSED_BITS, unused_bits);
    return unused_bits;
}

/**
 * If a bit string was parsed, we first need to parse
 * the internal value before we can give the precise
 * value of unused_bits.
 */
static VALUE
krypt_asn1_bit_string_get_unused_bits(VALUE self)
{
    if (int_asn1_decode_value(self) == KRYPT_ERR)
	krypt_error_raise(eKryptASN1Error, "Error while decoding value");
    return rb_ivar_get(self, sKrypt_IV_UNUSED_BITS);
}

/* End ASN1Primitive methods */

int 
krypt_asn1_decode_stream(binyo_instream *in, VALUE *out)
{
    krypt_asn1_header *header;
    VALUE ret;
    int result;

    result = krypt_asn1_next_header(in, &header);
    if (result == KRYPT_ASN1_EOF || result == KRYPT_ERR) return result;

    ret = krypt_asn1_data_new(in, header);
    if (NIL_P(ret)) {
	krypt_asn1_header_free(header);
	return KRYPT_ERR;
    }
    *out = ret;
    return KRYPT_OK;
}

static VALUE
int_asn1_fallback_decode(binyo_instream *in, binyo_instream *cache)
{
    VALUE ret;
    uint8_t *lookahead = NULL;
    size_t la_size;
    binyo_instream *bytes;
    binyo_instream *retry;
    int result;

    la_size = binyo_instream_cache_get_bytes(cache, &lookahead);
    binyo_instream_cache_free_wrapper(cache); /* do not use krypt_instream_free, would free in too */
    bytes = binyo_instream_new_bytes(lookahead, la_size);
    retry = binyo_instream_new_seq(bytes, in); /*chain cached bytes and original stream */
    result = krypt_asn1_decode_stream(retry, &ret);
    if (lookahead)
	xfree(lookahead);
    binyo_instream_free(retry);
    if (result != KRYPT_OK) 
	krypt_error_raise(eKryptASN1Error, "Error while DER-decoding value");
    return ret;
}

/**
 * call-seq:
 *    ASN1.decode(src) -> ASN1Data
 *
 * * +src+: May either be a +String+ containing a DER-/PEM-encoded value, an
 *         IO-like object supporting IO#read and IO#seek or any arbitrary
 *         object that supports either a +to_der+ or a +to_pem+ method
 *         transforming it into a DER-/BER-encoded or PEM-encoded +String+.
 *
 * Decodes arbitrary DER- or PEM-encoded ASN.1 objects and returns an instance
 * (or a subclass) of ASN1Data.
 *
 * == Examples
 *   io = File.open("my.der", "rb")
 *   asn1 = Krypt::ASN1.decode(io)
 *   io.close
 *
 *   str = #some PEM-encoded string
 *   asn1 = Krypt::ASN1.decode(str)
 *
 *   tagged = Krypt::ASN1::Integer.new(1, 0, :CONTEXT_SPECIFIC)
 *   tagged.tag = Krypt::ASN1::INTEGER
 *   tagged.tag_class = :UNIVERSAL
 *   int = Krypt::ASN1.decode(tagged)
 *   puts int.tag # => 2
 *   puts int.tag_class # => :UNIVERSAL
 *   puts int.value # => 1
 */
static VALUE
krypt_asn1_decode(VALUE self, VALUE obj)
{
    binyo_instream *in;
    binyo_instream *cache;
    binyo_instream *pem;
    VALUE ret;

    /* Try PEM first, if it fails, try as DER */
    in = krypt_instream_new_value_der(obj);
    cache = binyo_instream_new_cache(in);
    pem = krypt_instream_new_pem(cache);
    if (krypt_asn1_decode_stream(pem, &ret) != KRYPT_OK) {
	krypt_instream_pem_free_wrapper(pem);
	return int_asn1_fallback_decode(in, cache);
    }
    binyo_instream_free(pem); /* also frees in */
    return ret;
}

/**
 * call-seq:
 *    ASN1.decode_der(der) -> ASN1Data
 *
 * * +der+: May either be a +String+ containing a DER-encoded value, an
 *         IO-like object supporting IO#read and IO#seek or any arbitrary
 *         object that supports a +to_der+ method transforming it into a
 *         DER-/BER-encoded +String+.
 *
 * Decodes a DER-encoded ASN.1 object and returns an instance (or a subclass)
 * of ASN1Data. Can be used in the same way as +ASN1Data#decode+, except that
 * +decode_der+ explicitly assumes a DER-encoded source.
 */
static VALUE
krypt_asn1_decode_der(VALUE self, VALUE obj)
{
    VALUE ret;
    int result;

    binyo_instream *in = krypt_instream_new_value_der(obj);
    result = krypt_asn1_decode_stream(in, &ret);
    binyo_instream_free(in);
    if (result != KRYPT_OK)
	krypt_error_raise(eKryptASN1Error, "Error while DER-decoding value");
    return ret;
}

/**
 * call-seq:
 *    ASN1.decode_pem(pem) -> ASN1Data
 *
 * * +pem+: May either be a +String+ containing a PEM-encoded value, an
 *         IO-like object supporting IO#read and IO#seek or any arbitrary
 *         object that supports a +to_pem+ method transforming it into a
 *         PEM-encoded +String+.
 *
 * Decodes a PEM-encoded ASN.1 object and returns an instance (or a subclass)
 * of ASN1Data. Can be used in the same way as +ASN1Data#decode+, except that
 * +decode_pem+ explicitly assumes a PEM-encoded source.
 */
static VALUE
krypt_asn1_decode_pem(VALUE self, VALUE obj)
{
    VALUE ret;
    int result;
    
    binyo_instream *pem;
    pem = krypt_instream_new_pem(krypt_instream_new_value_pem(obj));
    result = krypt_asn1_decode_stream(pem, &ret);
    binyo_instream_free(pem);
    if (result != KRYPT_OK)
	krypt_error_raise(eKryptASN1Error, "Error while PEM-decoding value");
    return ret;
}

/**
 * Returns an ID representing the Symbol that stands for the corresponding
 * tag class.
 *
 * @param tag_class	The raw tag class value
 * @return		A Ruby Symbol representing the tag class, e.g. 
 * 			:UNIVERSAL, or 0 if the class is not recognized
 */
ID
krypt_asn1_tag_class_for_int(int tag_class)
{
    switch (tag_class) {
	case TAG_CLASS_UNIVERSAL:
	    return sKrypt_TC_UNIVERSAL;
	case TAG_CLASS_APPLICATION:
	    return sKrypt_TC_APPLICATION;
	case TAG_CLASS_CONTEXT_SPECIFIC:
	    return sKrypt_TC_CONTEXT_SPECIFIC;
	case TAG_CLASS_PRIVATE:
	    return sKrypt_TC_PRIVATE;
	default:
	    krypt_error_add("Unknown tag class: %d", tag_class);
	    return 0;
    }
}

/**
 * Returns an integer representing the tag class of the corresponding
 * symbol.
 *
 * @param tag_class	The tag class ID
 * @return		A positive integer representing the tag class
 *                      or 0 if the ID was not recognized
 */
int
krypt_asn1_tag_class_for_id(ID tag_class)
{
    VALUE str;
    if (tag_class == sKrypt_TC_UNIVERSAL)
	return TAG_CLASS_UNIVERSAL;
    else if (tag_class == sKrypt_TC_CONTEXT_SPECIFIC)
	return TAG_CLASS_CONTEXT_SPECIFIC;
    else if (tag_class == sKrypt_TC_EXPLICIT)
	return TAG_CLASS_CONTEXT_SPECIFIC;
    else if (tag_class == sKrypt_TC_IMPLICIT)
	return TAG_CLASS_CONTEXT_SPECIFIC;
    else if (tag_class == sKrypt_TC_APPLICATION)
	return TAG_CLASS_APPLICATION;
    else if (tag_class == sKrypt_TC_PRIVATE)
	return TAG_CLASS_PRIVATE;
    str = rb_funcall(ID2SYM(tag_class), rb_intern("to_s"), 0);
    StringValueCStr(str);
    krypt_error_add("Unknown tag class: %s", RSTRING_PTR(str));
    return KRYPT_ERR;
}

void
Init_krypt_asn1(void)
{ 
#if 0
    mKrypt = rb_define_module("Krypt"); /* Let RDoc know */
#endif

    VALUE ary;
    int i;

    sKrypt_TC_UNIVERSAL = rb_intern("UNIVERSAL");
    sKrypt_TC_APPLICATION = rb_intern("APPLICATION");
    sKrypt_TC_CONTEXT_SPECIFIC = rb_intern("CONTEXT_SPECIFIC");
    sKrypt_TC_PRIVATE = rb_intern("PRIVATE");
    sKrypt_TC_EXPLICIT = rb_intern("EXPLICIT");
    sKrypt_TC_IMPLICIT = rb_intern("IMPLICIT");

    sKrypt_IV_TAG = rb_intern("@tag");
    sKrypt_IV_TAG_CLASS = rb_intern("@tag_class");
    sKrypt_IV_INF_LEN = rb_intern("@infinite_length");
    sKrypt_IV_UNUSED_BITS = rb_intern("@unused_bits");

    sKrypt_IV_VALUE = rb_intern("@value");

    /*
     * Document-module: Krypt::ASN1
     *
     * Abstract Syntax Notation One (or ASN.1) is a notation syntax to
     * describe data structures and is defined in ITU-T X.680. ASN.1 itself
     * does not mandate any encoding or parsing rules, but usually ASN.1 data
     * structures are encoded using the Distinguished Encoding Rules (DER) or
     * less often the Basic Encoding Rules (BER) described in ITU-T X.690. DER
     * and BER encodings are binary Tag-Length-Value (TLV) encodings that are
     * quite concise compared to other popular data description formats such
     * as XML, JSON etc.
     * ASN.1 data structures are very common in cryptographic applications,
     * e.g. X.509 public key certificates or certificate revocation lists
     * (CRLs) are all defined in ASN.1 and DER-encoded. ASN.1, DER and BER are
     * the building blocks of applied cryptography.
     * The ASN1 module provides the necessary classes that allow generation
     * of ASN.1 data structures and the methods to encode them using a DER
     * encoding. The decode method allows parsing arbitrary BER-/DER-encoded
     * data to a Ruby object that can then be modified and re-encoded at will.
     * 
     * BER encodings of a parsed value are preserved when re-encoding them in
     * order to avoid breaking digital signatures that were computed over these
     * encodings. Once a parsed value is replaced by another manually,
     * the new value will be encoded in DER format, regardless of the previous
     * encoding of the old value.
     *
     * == ASN.1 class hierarchy
     *
     * The base class representing ASN.1 structures is ASN1Data. ASN1Data offers
     * attributes to read and set the +tag+, the +tag_class+ and finally the
     * +value+ of a particular ASN.1 item. Upon parsing, any tagged values
     * (implicit or explicit) will be represented by ASN1Data instances because
     * their "real type" can only be determined using out-of-band information
     * from the ASN.1 type declaration.
     *
     * === Constructive
     *
     * Constructive is, as its name implies, the base class for all
     * constructed encodings, i.e. those that consist of several values,
     * opposed to "primitive" encodings with just one single value.
     * Primitive values that are encoded with "infinite length" are typically
     * constructed (their values come in multiple chunks) and are therefore
     * represented by instances of Constructive. The value of a parsed 
     * Constructive is always an Array.
     *
     * ==== ASN1::Set and ASN1::Sequence
     *
     * The most common constructive encodings are SETs and SEQUENCEs, which is
     * why there are two sub-classes of Constructive representing each of
     * them.
     *
     * === Primitive
     *
     * This is the super class of all primitive values. Primitive
     * itself is not used when parsing ASN.1 data, all values are either
     * instances of a corresponding sub-class of Primitive or they are
     * instances of ASN1Data if the value was tagged implicitly or explicitly.
     * Please cf. Primitive documentation for details on sub-classes and
     * their respective mappings of ASN.1 data types to Ruby objects.
     *
     * == Possible values for +tag_class+
     *
     * It is possible to create arbitrary ASN1Data objects that also support
     * a PRIVATE or APPLICATION tag class. Possible values for the +tag_class+
     * attribute are:
     * * +:UNIVERSAL+ (the default for untagged values)
     * * +:CONTEXT_SPECIFIC+ (the default for tagged values)
     * * +:APPLICATION+
     * * +:PRIVATE+
     *
     * Additionally the following two may be used:
     * * +:IMPLICIT+
     * * +:EXPLICIT+
     *
     * where +:IMPLICIT+ is simply a synonym for +:CONTEXT_SPECIFIC+, and
     * exists mostly for convenience reasons to match real ASN.1 definitions
     * more closely. +:EXPLICIT+ on the other hand can be thought of as a
     * hint for encoding an ASN1Data from scratch. Neither +:IMPLICIT+ nor
     * +:EXPLICIT+ will ever be assigned during parsing. Both translate to
     * +:CONTEXT_SPECIFIC+ eventually when being encoded. The difference is
     * that +:EXPLICIT+ will force the corresponding value to be encoded
     * with explicit tagging, whereas +:IMPLICIT+, you guessed right, enforces
     * implicit tagging, in the same way that +:CONTEXT_SPECIFIC+ does.
     *
     * == Tag constants
     *
     * There is a constant defined for each universal tag:
     * * Krypt::ASN1::EOC (0)
     * * Krypt::ASN1::BOOLEAN (1)
     * * Krypt::ASN1::INTEGER (2)
     * * Krypt::ASN1::BIT_STRING (3)
     * * Krypt::ASN1::OCTET_STRING (4)
     * * Krypt::ASN1::NULL (5)
     * * Krypt::ASN1::OBJECT (6)
     * * Krypt::ASN1::ENUMERATED (10)
     * * Krypt::ASN1::UTF8STRING (12)
     * * Krypt::ASN1::SEQUENCE (16)
     * * Krypt::ASN1::SET (17)
     * * Krypt::ASN1::NUMERICSTRING (18)
     * * Krypt::ASN1::PRINTABLESTRING (19)
     * * Krypt::ASN1::T61STRING (20)
     * * Krypt::ASN1::VIDEOTEXSTRING (21)
     * * Krypt::ASN1::IA5STRING (22)
     * * Krypt::ASN1::UTCTIME (23)
     * * Krypt::ASN1::GENERALIZEDTIME (24)
     * * Krypt::ASN1::GRAPHICSTRING (25)
     * * Krypt::ASN1::ISO64STRING (26)
     * * Krypt::ASN1::GENERALSTRING (27)
     * * Krypt::ASN1::UNIVERSALSTRING (28)
     * * Krypt::ASN1::BMPSTRING (30)
     *
     * == UNIVERSAL_TAG_NAME constant
     *
     * An Array that stores the name of a given tag number. These names are
     * the same as the name of the tag constant that is additionally defined,
     * e.g. UNIVERSAL_TAG_NAME[2] = "INTEGER" and Krypt::ASN1::INTEGER = 2.
     *
     * == Example usage
     *
     * === Decoding and viewing a DER-encoded file
     *   require 'krypt'
     *   require 'pp'
     *   File.open('data.der', 'rb') do |f|
     *     pp Krypt::ASN1.decode(f)
     *   end
     *
     * === Creating an ASN.1 structure and DER-encoding it
     *   require 'krypt'
     *   version = Krypt::ASN1::Integer.new(1)
     *   # 0-tagged with context-specific tag class
     *   serial = Krypt::ASN1::Integer.new(12345, 0, :CONTEXT_SPECIFIC)
     *   name = Krypt::ASN1::PrintableString.new('Data 1')
     *   sequence = Krypt::ASN1::Sequence.new( [ version, serial, name ] )
     *   der = sequence.to_der
     */
    mKryptASN1 = rb_define_module_under(mKrypt, "ASN1");

    /* Document-class: Krypt::ASN1::ASN1Error
     *
     * Generic error class for all errors raised in ASN1 and any of the
     * classes defined under it.
     */
    eKryptASN1Error = rb_define_class_under(mKryptASN1, "ASN1Error", eKryptError);

    /* Document-class: Krypt::ASN1::ParseError
     *
     * Generic error class for all errors raised while parsing from a stream
     * with Krypt::ASN1::Parser or Krypt::ASN1::Header.
     */
    eKryptASN1ParseError = rb_define_class_under(mKryptASN1, "ParseError", eKryptASN1Error);

    /* Document-class: Krypt::ASN1::SerializeError
     *
     * Generic error class for all errors raised while writing to a stream
     * with Krypt::ASN1::Header#encode_to.
     */
    eKryptASN1SerializeError = rb_define_class_under(mKryptASN1, "SerializeError", eKryptASN1Error);

    ary = rb_ary_new();
    /*
     * Array storing tag names at the tag's index.
     */
    rb_define_const(mKryptASN1, "UNIVERSAL_TAG_NAME", ary);
    for(i = 0; i < krypt_asn1_infos_size; i++){
	if(krypt_asn1_infos[i].name[0] == '[') continue;
	rb_define_const(mKryptASN1, krypt_asn1_infos[i].name, INT2NUM(i));
	rb_ary_store(ary, i, rb_str_new2(krypt_asn1_infos[i].name));
    }

    rb_define_module_function(mKryptASN1, "decode", krypt_asn1_decode, 1);
    rb_define_module_function(mKryptASN1, "decode_der", krypt_asn1_decode_der, 1);
    rb_define_module_function(mKryptASN1, "decode_pem", krypt_asn1_decode_pem, 1);

    /* Document-class: Krypt::ASN1::ASN1Data
     *
     * The top-level class representing any ASN.1 object. When parsed by
     * ASN1.decode, tagged values are always represented by an instance
     * of ASN1Data.
     *
     * == The role of ASN1Data for parsing tagged values
     *
     * When encoding an ASN.1 type it is inherently clear what original
     * type (e.g. INTEGER, OCTET STRING etc.) this value has, regardless
     * of its tagging.
     * But opposed to the time an ASN.1 type is to be encoded, when parsing
     * them it is not possible to deduce the "real type" of tagged
     * values. This is why tagged values are generally parsed into ASN1Data
     * instances, but with a different outcome for implicit and explicit
     * tagging.
     *
     * === Example of a parsed implicitly tagged value
     *
     * An implicitly 1-tagged INTEGER value will be parsed as an
     * ASN1Data with
     * * +tag+ equal to 1
     * * +tag_class+ equal to +:CONTEXT_SPECIFIC+
     * * +value+ equal to a +String+ that carries the raw encoding
     *   of the INTEGER.
     * This implies that a subsequent decoding step is required to
     * completely decode implicitly tagged values.
     *
     * === Example of a parsed explicitly tagged value
     *
     * An explicitly 1-tagged INTEGER value will be parsed as an
     * ASN1Data with
     * * +tag+ equal to 1
     * * +tag_class+ equal to +:CONTEXT_SPECIFIC+
     * * +value+ equal to an +Array+ with one single element, an
     *   instance of Krypt::ASN1::Integer, i.e. the inner element
     *   is the non-tagged primitive value, and the tagging is represented
     *   in the outer ASN1Data
     *
     * == Example - Decoding an implicitly tagged INTEGER
     *   int = Krypt::ASN1::Integer.new(1, 0, :CONTEXT_SPECIFIC) # implicit 0-tagged
     *   seq = Krypt::ASN1::Sequence.new( [int] )
     *   der = seq.to_der
     *   asn1 = Krypt::ASN1.decode(der)
     *   # pp asn1 => #<Krypt::ASN1::Sequence:0x87326e0
     *   #              @infinite_length=false,
     *   #              @tag=16,
     *   #              @tag_class=:UNIVERSAL>
     *   # pp asn1.value => [#<Krypt::ASN1::ASN1Data:0x87326f4
     *   #                   @infinite_length=false,
     *   #                   @tag=0,
     *   #                   @tag_class=:CONTEXT_SPECIFIC>]
     *   # pp asn1.value[0].value => "\x01"
     *   raw_int = asn1.value[0]
     *   # manually rewrite tag and tag class to make it an UNIVERSAL value
     *   raw_int.tag = OpenSSL::ASN1::INTEGER
     *   raw_int.tag_class = :UNIVERSAL
     *   int2 = Krypt::ASN1.decode(raw_int)
     *   puts int2.value # => 1
     *
     * == Example - Decoding an explicitly tagged INTEGER
     *   int = Krypt::ASN1::Integer.new(1)
     *   data = Krypt::ASN1Data.new([int], 0, :CONTEXT_SPECIFIC) # explicit 0-tagged
     *   seq = Krypt::ASN1::Sequence.new( [data] )
     *   der = seq.to_der
     *   asn1 = Krypt::ASN1.decode(der)
     *   # pp asn1 => #<Krypt::ASN1::Sequence:0x87326e0
     *   #              @infinite_length=false,
     *   #              @tag=16,
     *   #              @tag_class=:UNIVERSAL>
     *   # pp asn1.value => [#<Krypt::ASN1::ASN1Data:0x87326f4
     *   #                   @infinite_length=false,
     *   #                   @tag=0,
     *   #                   @tag_class=:CONTEXT_SPECIFIC>]
     *   # pp asn1.value[0].value => [#<Krypt::ASN1::Integer:0x85bf308
     *   #                            @infinite_length=false,
     *   #                            @tag=2,
     *   #                            @tag_class=:UNIVERSAL>]
     *   int2 = asn1.value[0].value[0]
     *   puts int2.value # => 1
     */
    cKryptASN1Data = rb_define_class_under(mKryptASN1, "ASN1Data", rb_cObject);
    rb_include_module(cKryptASN1Data, rb_mComparable);
    rb_define_alloc_func(cKryptASN1Data, krypt_asn1_data_alloc);
    rb_define_method(cKryptASN1Data, "initialize", krypt_asn1_data_initialize, 3);
    rb_define_method(cKryptASN1Data, "tag", krypt_asn1_data_get_tag, 0);
    rb_define_method(cKryptASN1Data, "tag=", krypt_asn1_data_set_tag, 1);
    rb_define_method(cKryptASN1Data, "tag_class", krypt_asn1_data_get_tag_class, 0);
    rb_define_method(cKryptASN1Data, "tag_class=", krypt_asn1_data_set_tag_class, 1);
    rb_define_method(cKryptASN1Data, "infinite_length", krypt_asn1_data_get_inf_length, 0);
    rb_define_method(cKryptASN1Data, "infinite_length=", krypt_asn1_data_set_inf_length, 1);
    rb_define_method(cKryptASN1Data, "value", krypt_asn1_data_get_value, 0);
    rb_define_method(cKryptASN1Data, "value=", krypt_asn1_data_set_value, 1);
    rb_define_method(cKryptASN1Data, "to_der", krypt_asn1_data_to_der, 0);
    rb_define_method(cKryptASN1Data, "encode_to", krypt_asn1_data_encode_to, 1);
    rb_define_method(cKryptASN1Data, "<=>", krypt_asn1_data_cmp, 1);

    /* Document-class: Krypt::ASN1::Primitive
     *
     * The parent class for all primitive encodings. Attributes are the same as
     * for ASN1Data.
     * Primitive values can never be infinite length encodings, thus it is not
     * possible to set the +infinite_length+ attribute for Primitive and its
     * sub-classes.
     *
     * == Primitive sub-classes and their mapping to Ruby classes
     * * Krypt::ASN1::EndOfContents   <=> +value+ is always +nil+
     * * Krypt::ASN1::Boolean         <=> +value+ is a +Boolean+
     * * Krypt::ASN1::Integer         <=> +value+ is a +Number+
     * * Krypt::ASN1::BitString       <=> +value+ is a +String+
     * * Krypt::ASN1::OctetString     <=> +value+ is a +String+
     * * Krypt::ASN1::Null            <=> +value+ is always +nil+
     * * Krypt::ASN1::Object          <=> +value+ is a +String+
     * * Krypt::ASN1::Enumerated      <=> +value+ is a +Number+
     * * Krypt::ASN1::UTF8String      <=> +value+ is a +String+
     * * Krypt::ASN1::NumericString   <=> +value+ is a +String+
     * * Krypt::ASN1::PrintableString <=> +value+ is a +String+
     * * Krypt::ASN1::T61String       <=> +value+ is a +String+
     * * Krypt::ASN1::VideotexString  <=> +value+ is a +String+
     * * Krypt::ASN1::IA5String       <=> +value+ is a +String+
     * * Krypt::ASN1::UTCTime         <=> +value+ is a +Time+ (or a Number when creating them)
     * * Krypt::ASN1::GeneralizedTime <=> +value+ is a +Time+ (or a Number when creating them)
     * * Krypt::ASN1::GraphicString   <=> +value+ is a +String+
     * * Krypt::ASN1::ISO64String     <=> +value+ is a +String+
     * * Krypt::ASN1::GeneralString   <=> +value+ is a +String+
     * * Krypt::ASN1::UniversalString <=> +value+ is a +String+
     * * Krypt::ASN1::BMPString       <=> +value+ is a +String+
     *
     * == Krypt::ASN1::BitString
     *
     * === Additional attribute
     * +unused_bits+: if the underlying BIT STRING's
     * length is a multiple of 8 then +unused_bits+ is 0. Otherwise
     * +unused_bits+ indicates the number of bits that are to be ignored in
     * the final octet of the +BitString+'s +value+.
     *
     * == Examples
     * With the Exception of Krypt::ASN1::EndOfContents and Krypt::ASN1::Null,
     * each Primitive class constructor takes at least one parameter, the
     * +value+. Since the value of the former two is always +nil+, they also
     * support a no-arg constructor.
     *
     * === Creating EndOfContents and Null
     *   eoc = Krypt::ASN1::EndOfContents.new
     *   null = Krypt::ASN1::Null.new
     *
     * === Creating any other Primitive
     *   prim = <class>.new(value) # <class> being one of the sub-classes except EndOfContents of Null
     *   prim_zero_context = <class>.new(value, 0, :CONTEXT_SPECIFIC)
     *   prim_zero_private = <class>.new(value, 0, :PRIVATE)
     */
    cKryptASN1Primitive = rb_define_class_under(mKryptASN1, "Primitive", cKryptASN1Data);
    rb_define_method(cKryptASN1Primitive, "initialize", krypt_asn1_data_initialize, 3);

    /* Document-class: Krypt::ASN1::Constructive
     *
     * The parent class for all constructed encodings. The +value+ attribute
     * of a parsed Constructive is always an +Array+. Attributes are the same as
     * for ASN1Data.
     *
     * == SET and SEQUENCE
     *
     * Most constructed encodings come in the form of a SET or a SEQUENCE.
     * These encodings are represented by one of the two sub-classes of
     * Constructive:
     * * Krypt::ASN1::Set
     * * Krypt::ASN1::Sequence
     * Please note that tagged sequences and sets are still parsed as
     * instances of ASN1Data. Find further details on tagged values
     * there.
     *
     * === Example - constructing a SEQUENCE
     *   int = Krypt::ASN1::Integer.new(1)
     *   str = Krypt::ASN1::PrintableString.new('abc')
     *   sequence = Krypt::ASN1::Sequence.new( [ int, str ] )
     *
     * === Example - constructing a SET
     *   int = Krypt::ASN1::Integer.new(1)
     *   str = Krypt::ASN1::PrintableString.new('abc')
     *   set = Krypt::ASN1::Set.new( [ int, str ] )
     *
     * == Infinite length primitive values
     *
     * The only case where Constructive is used directly is for infinite
     * length encodings of primitive values. These encodings are always
     * constructed, with the contents of the +value+ +Array+ being either
     * UNIVERSAL non-infinite length partial encodings of the actual value
     * or again constructive encodings with infinite length (i.e. infinite
     * length primitive encodings may be constructed recursively with another
     * infinite length value within an already infinite length value). Each
     * partial encoding must be of the same UNIVERSAL type as the overall
     * encoding. The value of the overall encoding consists of the
     * concatenation of each partial encoding taken in sequence. The +value+
     * array of the outer infinite length value must end with a
     * Krypt::ASN1::EndOfContents instance.
     *
     * === Example - Infinite length OCTET STRING
     *   partial1 = Krypt::ASN1::OctetString.new("\x01")
     *   partial2 = Krypt::ASN1::OctetString.new("\x02")
     *   inf_octets = Krypt::ASN1::OctetString.new( [ partial1,
     *                                                partial2,
     *                                                Krypt::ASN1::EndOfContent.new ])
     *   # The real value of inf_octets is "\x01\x02", i.e. the concatenation
     *   # of partial1 and partial2
     *   inf_octets.infinite_length = true
     *   der = inf_octets.to_der
     *   asn1 = Krypt::ASN1.decode(der)
     *   puts asn1.infinite_length # => true
     */
    cKryptASN1Constructive = rb_define_class_under(mKryptASN1, "Constructive", cKryptASN1Data);
    rb_include_module(cKryptASN1Constructive, rb_mEnumerable);
    rb_define_method(cKryptASN1Constructive, "initialize", krypt_asn1_data_initialize, 3);
    rb_define_method(cKryptASN1Constructive, "each", krypt_asn1_cons_each, 0);

#define KRYPT_ASN1_DEFINE_CLASS(name, super, init)						\
    cKryptASN1##name = rb_define_class_under(mKryptASN1, #name, cKryptASN1##super);		\
    rb_define_method(cKryptASN1##name, "initialize", krypt_asn1_##init##_initialize, -1);

    KRYPT_ASN1_DEFINE_CLASS(EndOfContents,   Primitive, end_of_contents)
    KRYPT_ASN1_DEFINE_CLASS(Boolean,	     Primitive, boolean)
    KRYPT_ASN1_DEFINE_CLASS(Integer, 	     Primitive, integer)
    KRYPT_ASN1_DEFINE_CLASS(Enumerated,	     Primitive, enumerated)
    KRYPT_ASN1_DEFINE_CLASS(BitString, 	     Primitive, bit_string)
    KRYPT_ASN1_DEFINE_CLASS(OctetString,     Primitive, octet_string)
    KRYPT_ASN1_DEFINE_CLASS(UTF8String,      Primitive, utf8_string)
    KRYPT_ASN1_DEFINE_CLASS(NumericString,   Primitive, numeric_string)
    KRYPT_ASN1_DEFINE_CLASS(PrintableString, Primitive, printable_string)
    KRYPT_ASN1_DEFINE_CLASS(T61String, 	     Primitive, t61_string)
    KRYPT_ASN1_DEFINE_CLASS(VideotexString,  Primitive, videotex_string)
    KRYPT_ASN1_DEFINE_CLASS(IA5String,       Primitive, ia5_string)
    KRYPT_ASN1_DEFINE_CLASS(GraphicString,   Primitive, graphic_string)
    KRYPT_ASN1_DEFINE_CLASS(ISO64String,     Primitive, iso64_string)
    KRYPT_ASN1_DEFINE_CLASS(GeneralString,   Primitive, general_string)
    KRYPT_ASN1_DEFINE_CLASS(UniversalString, Primitive, universal_string)
    KRYPT_ASN1_DEFINE_CLASS(BMPString,       Primitive, bmp_string)
    KRYPT_ASN1_DEFINE_CLASS(Null, 	     Primitive, null)
    KRYPT_ASN1_DEFINE_CLASS(ObjectId, 	     Primitive, object_id)
    KRYPT_ASN1_DEFINE_CLASS(UTCTime, 	     Primitive, utc_time)
    KRYPT_ASN1_DEFINE_CLASS(GeneralizedTime, Primitive, generalized_time)
    KRYPT_ASN1_DEFINE_CLASS(Sequence, 	     Constructive, sequence)
    KRYPT_ASN1_DEFINE_CLASS(Set, 	     Constructive, set)

    rb_define_method(cKryptASN1BitString, "unused_bits", krypt_asn1_bit_string_get_unused_bits, 0);
    rb_define_method(cKryptASN1BitString, "unused_bits=", krypt_asn1_bit_string_set_unused_bits, 1);
   
    Init_krypt_asn1_parser();
    Init_krypt_asn1_template();
    Init_krypt_instream_adapter();
    Init_krypt_pem();
}

