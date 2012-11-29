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
#include "krypt_asn1_template-internal.h"

struct krypt_asn1_template_match_ctx {
    krypt_asn1_object *object;
    krypt_asn1_header *header;
    int free_header;
};

struct krypt_asn1_template_parse_ctx {
    int (*match)(VALUE recv, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def);
    int (*parse)(VALUE recv, krypt_asn1_object *obj, krypt_asn1_definition *def, int *dont_free);
    int (*decode)(VALUE recv, krypt_asn1_object *object, krypt_asn1_definition *def, VALUE *out);
};

static int int_match_prim(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def);
static int int_parse_assign(VALUE self, krypt_asn1_object *object, krypt_asn1_definition *def, int *dont_free);
static int int_decode_prim(VALUE self, krypt_asn1_object *object, krypt_asn1_definition *def, VALUE *out);

static int int_match_sequence(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def);
static int int_match_set(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def);
static int int_parse_cons(VALUE self, krypt_asn1_object *object, krypt_asn1_definition *def, int *dont_free);

static int int_match_template(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def);
static int int_parse_template(VALUE self, krypt_asn1_object *object, krypt_asn1_definition *def, int *dont_free);

static int int_match_seq_of(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def);
static int int_match_set_of(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def);
static int int_decode_cons_of(VALUE self, krypt_asn1_object *object, krypt_asn1_definition *def, VALUE *out);

static int int_match_any(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def);
static int int_decode_any(VALUE self, krypt_asn1_object *object, krypt_asn1_definition *def, VALUE *out);

static int int_match_choice(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def);
static int int_parse_choice(VALUE self, krypt_asn1_object *object, krypt_asn1_definition *def, int *dont_free);

static int krypt_asn1_template_parse_stream(binyo_instream *in, VALUE klass, VALUE *out);

static struct krypt_asn1_template_parse_ctx krypt_template_primitive_ctx= {
    int_match_prim,
    int_parse_assign,
    int_decode_prim
};

static struct krypt_asn1_template_parse_ctx krypt_template_sequence_ctx= {
    int_match_sequence,
    int_parse_cons,
    NULL
};

static struct krypt_asn1_template_parse_ctx krypt_template_set_ctx= {
    int_match_set,
    int_parse_cons,
    NULL
};

static struct krypt_asn1_template_parse_ctx krypt_template_template_ctx= {
    int_match_template,
    int_parse_template,
    NULL
};

static struct krypt_asn1_template_parse_ctx krypt_template_seq_of_ctx= {
    int_match_seq_of,
    int_parse_assign,
    int_decode_cons_of
};

static struct krypt_asn1_template_parse_ctx krypt_template_set_of_ctx= {
    int_match_set_of,
    int_parse_assign,
    int_decode_cons_of
};

static struct krypt_asn1_template_parse_ctx krypt_template_any_ctx= {
    int_match_any,
    int_parse_assign,
    int_decode_any
};

static struct krypt_asn1_template_parse_ctx krypt_template_choice_ctx= {
    int_match_choice,
    int_parse_choice,
    NULL
};

static struct krypt_asn1_template_parse_ctx *
int_get_parse_ctx_for_codec(ID codec) {
    if (codec == sKrypt_ID_PRIMITIVE)
	return &krypt_template_primitive_ctx;
    else if (codec == sKrypt_ID_SEQUENCE)
	return &krypt_template_sequence_ctx;
    else if (codec == sKrypt_ID_TEMPLATE)
	return &krypt_template_template_ctx;
    else if (codec == sKrypt_ID_SET)
	return &krypt_template_set_ctx;
    else if (codec == sKrypt_ID_SEQUENCE_OF)
	return &krypt_template_seq_of_ctx;
    else if (codec == sKrypt_ID_SET_OF)
	return &krypt_template_set_of_ctx;
    else if (codec == sKrypt_ID_ANY)
	return &krypt_template_any_ctx;
    else if (codec == sKrypt_ID_CHOICE)
	return &krypt_template_choice_ctx;
    else {
	krypt_error_add("Unknown codec: %s", rb_id2name(codec));
	return NULL;
    }
}

#define INT_KRYPT_MATCH 1
#define INT_KRYPT_NO_MATCH 0 
#define INT_KRYPT_MATCH_ERR -1
#define INT_KRYPT_MATCH_DEFAULT_APPLIED -2

static void
int_match_ctx_init(struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_object *object)
{
    ctx->object = object;
    ctx->header = object->header;
    ctx->free_header = 0;
}

static int
int_match_ctx_skip_header(struct krypt_asn1_template_match_ctx *ctx)
{
    krypt_asn1_header *next;
    binyo_instream *in = binyo_instream_new_bytes(ctx->object->bytes, ctx->object->bytes_len);
    if (krypt_asn1_next_header(in, &next) != KRYPT_OK) {
	binyo_instream_free(in);
	return KRYPT_ERR;
    }
    ctx->header = next;
    ctx->free_header = 1;
    binyo_instream_free(in);

    return KRYPT_OK;
}

static void
int_match_ctx_cleanup(struct krypt_asn1_template_match_ctx *ctx)
{
    if (ctx->free_header)
	xfree(ctx->header);
}

static int
int_expected_tag(VALUE tag, int default_tag)
{
    if (NIL_P(tag)) 
	return default_tag;
    else
        return NUM2INT(tag);
}

static int
int_expected_tag_class(VALUE tag_class)
{
    if (NIL_P(tag_class))
	return TAG_CLASS_UNIVERSAL;
    else
	return krypt_asn1_tag_class_for_id(SYM2ID(tag_class));
}

static int
int_match_tag(krypt_asn1_header *header, VALUE tag, int default_tag)
{
    if (header->tag == int_expected_tag(tag, default_tag))
	return INT_KRYPT_MATCH;
    else
	return INT_KRYPT_NO_MATCH;
}

static int
int_match_class(krypt_asn1_header *header, VALUE tag_class)
{
    int expected_tc;
    
    if ((expected_tc = int_expected_tag_class(tag_class)) == KRYPT_ERR) return INT_KRYPT_NO_MATCH;
    if (header->tag_class == expected_tc)
	return INT_KRYPT_MATCH;
    else
	return INT_KRYPT_NO_MATCH;
}

static int
int_tag_and_class_mismatch(krypt_asn1_header *header, VALUE tag, VALUE tagging, int default_tag, const char *name)
{
    int expected_tag = int_expected_tag(tag, default_tag);
    int expected_tag_class = int_expected_tag_class(tagging);
    
    if (name)
	krypt_error_add("Could not parse %s", name);
    if (header->tag != expected_tag)
	krypt_error_add("Tag mismatch. Expected: %d Got: %d", expected_tag, header->tag);
    if (header->tag_class != expected_tag_class) {
        ID expected = krypt_asn1_tag_class_for_int(expected_tag_class);
	ID got = krypt_asn1_tag_class_for_int(header->tag_class);
	krypt_error_add("Tag class mismatch. Expected: %s Got: %s", rb_id2name(expected), rb_id2name(got));
    }
    return INT_KRYPT_MATCH_ERR;
}

static int
int_match_tag_and_class(krypt_asn1_header *header, VALUE tag, VALUE tagging, int default_tag)
{
    if (int_match_tag(header, tag, default_tag) == INT_KRYPT_NO_MATCH) return INT_KRYPT_NO_MATCH;
    if (int_match_class(header, tagging) == INT_KRYPT_NO_MATCH) return INT_KRYPT_NO_MATCH;
    return INT_KRYPT_MATCH;
}

static krypt_asn1_header *
int_parse_explicit_header(krypt_asn1_object *object)
{
    krypt_asn1_header *header;
    binyo_instream *in = binyo_instream_new_bytes(object->bytes, object->bytes_len);

    if (krypt_asn1_next_header(in, &header) != KRYPT_OK) {
	krypt_error_add("Could not unpack explicitly tagged value");
	return NULL;
    }
    binyo_instream_free(in);
    return header;
}

static krypt_asn1_header *
int_unpack_explicit(VALUE tagging, krypt_asn1_object *object, uint8_t **pp, size_t *len, int *free_header)
{
    
    if (NIL_P(tagging) || SYM2ID(tagging) != sKrypt_TC_EXPLICIT) {
	*pp = object->bytes;
	*len = object->bytes_len;
	*free_header = 0;
	return object->header;
    } else {
	int header_len;
	krypt_asn1_header *header;

	if (!object->header->is_constructed) {
	    krypt_error_add("Constructive bit not set for explicitly tagged value");
	    return NULL;
	}
	if(!(header = int_parse_explicit_header(object))) return NULL;
	header_len = header->tag_len + header->length_len;
	*pp = object->bytes + header_len;
	*len = object->bytes_len - header_len;
	*free_header = 1;
	return header;
    }
}

static int
int_next_object(binyo_instream *in, krypt_asn1_object **out)
{
    krypt_asn1_header *next = NULL;
    krypt_asn1_object *next_object = NULL;
    int result;
    size_t value_len;
    uint8_t *value = NULL;

    result = krypt_asn1_next_header(in, &next);
    if (result == KRYPT_ASN1_EOF) return KRYPT_ASN1_EOF;
    if (result == KRYPT_ERR) goto error;

    if (krypt_asn1_get_value(in, next, &value, &value_len) == KRYPT_ERR) goto error;
    if (!(next_object = krypt_asn1_object_new_value(next, value, value_len))) goto error;

    *out = next_object;
    return KRYPT_OK;

error:
    if (next) krypt_asn1_header_free(next);
    krypt_error_add("Error while trying to read next value");
    return KRYPT_ERR;
}

static int
int_parse_eoc(binyo_instream *in)
{
    krypt_asn1_header *next;
    int result = krypt_asn1_next_header(in, &next);
    int ret;

    if (result == KRYPT_ASN1_EOF || result == KRYPT_ERR) return KRYPT_ERR;
    if (!(next->tag == TAGS_END_OF_CONTENTS && next->tag_class == TAG_CLASS_UNIVERSAL)) 
	ret = KRYPT_ERR;
    else
	ret = KRYPT_OK;
    krypt_asn1_header_free(next);
    return ret;
}
    
static int
int_ensure_stream_is_consumed(binyo_instream *in)
{
    uint8_t b;
    int result;

    result = binyo_instream_read(in, &b, 1);
    if (result == BINYO_OK) {
	krypt_error_add("Data left that could not be parsed");
	return KRYPT_ERR;
    } else if (result != BINYO_IO_EOF) {
       return KRYPT_ERR;
    }
    return KRYPT_OK;
}

static int
int_try_match_cons(struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def, int default_tag)
{
    krypt_asn1_header *header = ctx->header;
    VALUE tag = krypt_definition_get_tag(def);
    VALUE tagging = krypt_definition_get_tagging(def);

    if (header->is_constructed && 
	int_match_tag_and_class(header, tag, tagging, default_tag) == INT_KRYPT_MATCH) return INT_KRYPT_MATCH;

    if (!header->is_constructed && !krypt_definition_is_optional(def)) {
	krypt_error_add("Constructive bit not set");
	return INT_KRYPT_MATCH_ERR;
    }
    return INT_KRYPT_NO_MATCH;
}

static ID
int_determine_name(VALUE name)
{
    if (NIL_P(name))
        return sKrypt_IV_VALUE; /* CHOICE values have no name */
    else
        return SYM2ID(name);
}

static void
int_set_default_value(VALUE self, krypt_asn1_definition *def)
{
    ID name;
    VALUE obj, def_value; 
    krypt_asn1_template *template;

    name = int_determine_name(krypt_definition_get_name(def));
    /* set the default value, no more decoding needed */
    def_value = krypt_definition_get_default_value(def);
    template = krypt_asn1_template_new_value(def_value); 
    krypt_asn1_template_set(cKryptASN1TemplateValue, obj, template);
    rb_ivar_set(self, name, obj);
}

static int
int_check_optional_or_default(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def, int default_tag)
{
    krypt_asn1_header *header = ctx->header;
    VALUE tag = krypt_definition_get_tag(def);
    VALUE tagging = krypt_definition_get_tagging(def);

    if (!krypt_definition_is_optional(def)) { 
	const char *str;
	ID name = int_determine_name(krypt_definition_get_name(def));
        str = rb_id2name(name);
        krypt_error_add("Mandatory value %s is missing", str);
	return int_tag_and_class_mismatch(header, tag, tagging, default_tag, str);
    }

    if (krypt_definition_has_default(def)) {
	int_set_default_value(self, def);
	return INT_KRYPT_MATCH_DEFAULT_APPLIED;
    }

    return INT_KRYPT_NO_MATCH;
}

static int
int_match_prim(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def)
{
    VALUE tag, tagging, vdef_tag;
    krypt_asn1_header *header = ctx->header;
    int default_tag;

    get_or_raise(vdef_tag, krypt_definition_get_type(def), "'type is missing in ASN.1 definition");
    default_tag = NUM2INT(vdef_tag);
    tag = krypt_definition_get_tag(def);
    tagging = krypt_definition_get_tagging(def);

    if (int_match_tag_and_class(header, tag, tagging, default_tag) == INT_KRYPT_MATCH) return INT_KRYPT_MATCH;

    return int_check_optional_or_default(self, ctx, def, default_tag);
}

static int
int_parse_assign(VALUE self, krypt_asn1_object *object, krypt_asn1_definition *def, int *dont_free)
{
    ID name;
    VALUE instance;
    krypt_asn1_template *t;

    name = int_determine_name(krypt_definition_get_name(def));
    t = krypt_asn1_template_new(object, krypt_definition_get_definition(def), krypt_definition_get_options(def));
    krypt_asn1_template_set(cKryptASN1TemplateValue, instance, t);
    rb_ivar_set(self, name, instance);
    krypt_asn1_template_set_parsed(t, 1);
    *dont_free = 1;
    return KRYPT_OK;
}

/* TODO */
static int
int_decode_prim_inf(VALUE tvalue, krypt_asn1_object *obj, krypt_asn1_definition *def, VALUE *out)
{
    rb_raise(rb_eNotImpError, "Not implemented yet");
}

static int
int_decode_prim(VALUE tvalue, krypt_asn1_object *object, krypt_asn1_definition *def, VALUE *out)
{
    VALUE value, vtype, tagging;
    krypt_asn1_header *header = object->header;
    int free_header = 0, default_tag;
    uint8_t *p;
    size_t len;

    if (header->is_infinite)
	return int_decode_prim_inf(tvalue, object, def, out);

    get_or_raise(vtype, krypt_definition_get_type(def), "'type' missing in ASN.1 definition");
    tagging = krypt_definition_get_tagging(def);
    default_tag = NUM2INT(vtype);

    if (!(header = int_unpack_explicit(tagging, object, &p, &len, &free_header))) return KRYPT_ERR;
    if (header->is_constructed) {
	krypt_error_add("Constructed bit set");
	goto error;
    }

    if (!krypt_asn1_codecs[default_tag].decoder) {
	int default_tag = NUM2INT(vtype);
        krypt_error_add("No codec available for default tag %d", default_tag);
	goto error;
    }
    if (krypt_asn1_codecs[default_tag].decoder(tvalue, p, len, &value) == KRYPT_ERR) {
	goto error;
    }

    if (free_header) krypt_asn1_header_free(header);
    *out = value;
    return KRYPT_OK;

error: {
    ID name = int_determine_name(krypt_definition_get_name(def));
    krypt_error_add("Error while decoding value %s", rb_id2name(name));
    if (free_header) krypt_asn1_header_free(header);
    return KRYPT_ERR;
       }
}

static int
int_match_cons(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def, int default_tag)
{
    int match = int_try_match_cons(ctx, def, default_tag);

    if (match == INT_KRYPT_MATCH || match == INT_KRYPT_MATCH_ERR) return match;

    if (!krypt_definition_is_optional(def)) {
	VALUE tag = krypt_definition_get_tag(def);
	VALUE tagging = krypt_definition_get_tagging(def);
	krypt_error_add("Mandatory sequence value not found");
	return int_tag_and_class_mismatch(ctx->header, tag, tagging, default_tag, "Constructed");
    }
    return INT_KRYPT_NO_MATCH;
}

static int
int_match_sequence(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def)
{
    return int_match_cons(self, ctx, def, TAGS_SEQUENCE);
}

static int
int_match_set(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def)
{
    return int_match_cons(self, ctx, def, TAGS_SET);
}

static int
int_ensure_rest_is_optional(VALUE self, VALUE layout, long index)
{
    long i, size;

    size = RARRAY_LEN(layout);
    for (i=index; i < size; ++i) {
	krypt_asn1_definition def;
	VALUE cur_def = rb_ary_entry(layout, i);

	krypt_definition_init(&def, cur_def, krypt_hash_get_options(cur_def));
	if (!krypt_definition_is_optional(&def)) {
	    ID name = int_determine_name(krypt_definition_get_name(&def));
	    krypt_error_add("Mandatory value %s not found", rb_id2name(name));
	    return KRYPT_ERR;
	}
	if (krypt_definition_has_default(&def)) {
	    int_set_default_value(self, &def);
	}
    }
    return KRYPT_OK;
}

static int
int_parse_cons(VALUE self, krypt_asn1_object *object, krypt_asn1_definition *def, int *dont_free)
{
    binyo_instream *in;
    VALUE layout, vmin_size, tagging;
    long num_parsed = 0, layout_size, min_size, i;
    krypt_asn1_header *header = object->header;
    krypt_asn1_object *cur_object = NULL;
    int object_consumed = 0, free_header = 0;
    uint8_t *p;
    size_t len;

    get_or_raise(layout, krypt_definition_get_layout(def), "'layout' missing in ASN.1 definition");
    get_or_raise(vmin_size, krypt_definition_get_min_size(def), "'min_size' is missing in ASN.1 definition");
    min_size = NUM2LONG(vmin_size);
    tagging = krypt_definition_get_tagging(def);
    layout_size = RARRAY_LEN(layout);

    if(!(header = int_unpack_explicit(tagging, object, &p, &len, &free_header))) return KRYPT_ERR;
    if (!header->is_constructed) {
	krypt_error_add("Constructed bit not set");
	return KRYPT_ERR;
    }

    in = binyo_instream_new_bytes(p, len);
    if (int_next_object(in, &cur_object) != KRYPT_OK) goto error;

    for (i=0; i < layout_size; ++i) {
	ID codec;
	int result;
	krypt_asn1_definition inner_def;
	struct krypt_asn1_template_parse_ctx *parser;
	struct krypt_asn1_template_match_ctx ctx;
	VALUE cur_def = rb_ary_entry(layout, i);

	krypt_error_clear();
	krypt_definition_init(&inner_def, cur_def, krypt_hash_get_options(cur_def));
	codec = SYM2ID(krypt_hash_get_codec(cur_def));
	parser = int_get_parse_ctx_for_codec(codec);
	int_match_ctx_init(&ctx, cur_object);

	if ((result = parser->match(self, &ctx, &inner_def)) != INT_KRYPT_MATCH_ERR) {
	    if (result == INT_KRYPT_MATCH) {
		int inner_dont_free;
		if (parser->parse(self, cur_object, &inner_def, &inner_dont_free) == KRYPT_ERR) goto error;
		if (!inner_dont_free) krypt_asn1_object_free(cur_object);
		object_consumed = 1;
		num_parsed++;
		if (i < layout_size - 1) {
		    int has_more = int_next_object(in, &cur_object); 
		    if (has_more == KRYPT_ERR) goto error;
		    if (has_more == KRYPT_ASN1_EOF) {
		       	if (int_ensure_rest_is_optional(self, layout, i+1) == KRYPT_ERR) goto error;
			break; /* EOF reached */
		    }
		}
	    } /* else -> didn't match or default value was set */
	} else {
	    goto error;
	}
    }

    if (num_parsed < min_size) {
	krypt_error_add("Expected %d..%d values. Got: %d", min_size, layout_size, num_parsed);
	goto error;
    }
    if (header->is_infinite) {
	if(int_parse_eoc(in) == KRYPT_ERR) {
	    krypt_error_add("No closing END OF CONTENTS found for constructive value");
	    goto error;
	}
    }
    if (int_ensure_stream_is_consumed(in) == KRYPT_ERR) goto error;

    binyo_instream_free(in);
    if (free_header) krypt_asn1_header_free(header);
    *dont_free = 0;
    return KRYPT_OK;

error:
    binyo_instream_free(in);
    if (cur_object && !object_consumed) krypt_asn1_object_free(cur_object);
    if (free_header) krypt_asn1_header_free(header);
    return KRYPT_ERR;
} 

static int
int_match_template(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def)
{
    ID codec;
    VALUE type, type_def;
    krypt_asn1_definition new_def;
    struct krypt_asn1_template_parse_ctx *parser;
    int match;
    
    get_or_raise(type, krypt_definition_get_type(def), "'type' missing in ASN.1 definition");
    if (NIL_P((type_def = krypt_definition_get(type)))) {
	krypt_error_add("Type %s has no ASN.1 definition", rb_class2name(type));
	return INT_KRYPT_MATCH_ERR;
    }
    krypt_definition_init(&new_def, type_def, krypt_definition_get_options(def));
    codec = SYM2ID(krypt_hash_get_codec(type_def));
    parser = int_get_parse_ctx_for_codec(codec);
    match = parser->match(self, ctx, &new_def);
    if (match == INT_KRYPT_NO_MATCH) {
	if (krypt_definition_has_default(def)) {
	    int_set_default_value(self, def);
	    return INT_KRYPT_MATCH_DEFAULT_APPLIED;
	}   
    }
    return match;
}

static int
int_parse_template(VALUE self, krypt_asn1_object *object, krypt_asn1_definition *def, int *dont_free)
{
    ID name;
    VALUE container, instance;
    VALUE type, type_def, options;
    krypt_asn1_template *container_template, *value_template;

    get_or_raise(type, krypt_definition_get_type(def), "'type' missing in ASN.1 definition");
    name = int_determine_name(krypt_definition_get_name(def));
    if (NIL_P((type_def = krypt_definition_get(type)))) {
	krypt_error_add("Type %s has no ASN.1 definition", rb_class2name(type));
	return KRYPT_ERR;
    }

    options = krypt_definition_get_options(def);
    value_template = krypt_asn1_template_new(object, type_def, options);
    krypt_asn1_template_set(type, instance, value_template);

    container_template = krypt_asn1_template_new_value(instance);
    krypt_asn1_template_set_definition(container_template, krypt_definition_get_definition(def));
    krypt_asn1_template_set_options(container_template, options);
    krypt_asn1_template_set(cKryptASN1TemplateValue, container, container_template);

    rb_ivar_set(self, name, container);
    *dont_free = 1;
    return KRYPT_OK;
}

static int
int_match_cons_of(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def, int default_tag)
{
    int match = int_try_match_cons(ctx, def, default_tag);

    if (match == INT_KRYPT_MATCH || match == INT_KRYPT_MATCH_ERR) return match;
    return int_check_optional_or_default(self, ctx, def, default_tag);
}

static int
int_match_seq_of(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def)
{
    return int_match_cons_of(self, ctx, def, TAGS_SEQUENCE);
}

static int
int_match_set_of(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def)
{
    return int_match_cons_of(self, ctx, def, TAGS_SET);
}

static int
int_decode_cons_of_templates(binyo_instream *in, VALUE type, VALUE *out)
{
    VALUE cur;
    VALUE ary = rb_ary_new();
    int result;

    while ((result = krypt_asn1_template_parse_stream(in, type, &cur)) == KRYPT_OK) {
	rb_ary_push(ary, cur);
    }
    if (result == KRYPT_ERR) return KRYPT_ERR;
    *out = ary;
    return KRYPT_OK;
}

static int
int_decode_cons_of_prim(binyo_instream *in, VALUE type, VALUE *out)
{
    VALUE cur;
    VALUE ary = rb_ary_new();
    int result;

    while ((result = krypt_asn1_decode_stream(in, &cur)) == KRYPT_OK) {
	if (!rb_obj_is_kind_of(cur, type)) {
	    krypt_error_add("Expected %s but got %s instead", rb_class2name(type), rb_class2name(CLASS_OF(cur)));
	    return KRYPT_ERR;
	}
	rb_ary_push(ary, cur);
    }
    if (result == KRYPT_ERR) return KRYPT_ERR;
    *out = ary;
    return KRYPT_OK;
}

static int
int_decode_cons_of(VALUE self, krypt_asn1_object *object, krypt_asn1_definition *def, VALUE *out)
{
    ID name;
    binyo_instream *in;
    VALUE type, tagging, val_ary, mod_p;
    uint8_t *p;
    size_t len;
    int free_header = 0;
    krypt_asn1_header *header = object->header;

    get_or_raise(type, krypt_definition_get_type(def), "'type' missing in ASN.1 definition");
    name = int_determine_name(krypt_definition_get_name(def));
    tagging = krypt_definition_get_tagging(def);

    if (!(header = int_unpack_explicit(tagging, object, &p, &len, &free_header))) return KRYPT_ERR;
    if (!header->is_constructed) {
	krypt_error_add("Constructed bit not set");
	return KRYPT_ERR;
    }

    in = binyo_instream_new_bytes(p, len);

    mod_p = rb_funcall(type, rb_intern("include?"), 1, mKryptASN1Template);
    if (RTEST(mod_p)) {
	if (int_decode_cons_of_templates(in, type, &val_ary) == KRYPT_ERR) return KRYPT_ERR;
    }
    else {
	if (int_decode_cons_of_prim(in, type, &val_ary) == KRYPT_ERR) return KRYPT_ERR;
    }

    if (RARRAY_LEN(val_ary) == 0 && !krypt_definition_is_optional(def)) {
	krypt_error_add("Mandatory value %s could not be parsed. Sequence is empty", rb_id2name(name));
	goto error;
    }

    if (header->is_infinite) {
	if(int_parse_eoc(in) == KRYPT_ERR) {
	    krypt_error_add("No closing END OF CONTENTS found for %s", rb_id2name(name));
	    goto error;
	}
    }
    if (int_ensure_stream_is_consumed(in) == KRYPT_ERR) goto error;

    *out = val_ary;
    binyo_instream_free(in);
    if (free_header) krypt_asn1_header_free(header);
    return KRYPT_OK;

error:
    binyo_instream_free(in);
    if (free_header) krypt_asn1_header_free(header);
    return KRYPT_ERR;
}

static int
int_match_any(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def)
{
    if (krypt_definition_is_optional(def)) {
	VALUE tagging;
	krypt_asn1_header *header;
	int pseudo_default;
	VALUE tag = krypt_definition_get_tag(def);

	if (NIL_P(tag)) {
	    return INT_KRYPT_MATCH;
	}
	tagging = krypt_definition_get_tagging(def);
	header = ctx->header;
	pseudo_default = NUM2INT(tag);
	if (!int_match_tag_and_class(header, tag, tagging, pseudo_default)) {
	    if (krypt_definition_has_default(def)) {
		int_set_default_value(self, def);
		return INT_KRYPT_MATCH_DEFAULT_APPLIED;
	    }
	    return INT_KRYPT_NO_MATCH;
	}
    }
    return INT_KRYPT_MATCH;
}

static int
int_decode_any(VALUE self, krypt_asn1_object *object, krypt_asn1_definition *def, VALUE *out)
{
    VALUE value, tagging;
    binyo_instream *in, *seq_a, *seq_b, *seq_c;
    krypt_asn1_header *header = object->header;
    int free_header = 0;
    uint8_t *p;
    size_t len;

    tagging = krypt_definition_get_tagging(def);

    if(!(header = int_unpack_explicit(tagging, object, &p, &len, &free_header))) return KRYPT_ERR;

    seq_a = binyo_instream_new_bytes(header->tag_bytes, header->tag_len);
    seq_b = binyo_instream_new_bytes(header->length_bytes, header->length_len);
    seq_c = binyo_instream_new_bytes(p, len);
    in = binyo_instream_new_seq_n(3, seq_a, seq_b, seq_c);
    if (krypt_asn1_decode_stream(in, &value) != KRYPT_OK) goto error;

    binyo_instream_free(in);
    if (free_header) krypt_asn1_header_free(header);
    *out = value;
    return KRYPT_OK;

error: {
    ID name = int_determine_name(krypt_definition_get_name(def));
    binyo_instream_free(in);
    krypt_error_add("Error while decoding value %s", rb_id2name(name));
    if (free_header) krypt_asn1_header_free(header);
    return KRYPT_ERR;
       }
}

static int
int_enforce_explicit_tagging(krypt_asn1_definition *def, VALUE *tagging)
{
    VALUE tc = krypt_definition_get_tagging(def);
    if (!(NIL_P(tc) || SYM2ID(tc) == sKrypt_TC_EXPLICIT)) {
        krypt_error_add("Only explicit tagging is allowed for CHOICEs");
        return KRYPT_ERR;
    }
    *tagging = tc;
    return KRYPT_OK;
}

static int
int_match_choice(VALUE self, struct krypt_asn1_template_match_ctx *ctx, krypt_asn1_definition *def)
{
    VALUE layout, tagging;
    long i, layout_size, first_any = -1;
    struct krypt_asn1_template_match_ctx inner_ctx;
    
    get_or_raise(layout, krypt_definition_get_layout(def), "'layout' missing in ASN.1 definition");
    if (int_enforce_explicit_tagging(def, &tagging) == KRYPT_ERR) return INT_KRYPT_MATCH_ERR;
    int_match_ctx_init(&inner_ctx, ctx->object);
    /* No match if tagging was explicit but we can't skip the header */
    if (!(NIL_P(tagging) || int_match_ctx_skip_header(&inner_ctx) == KRYPT_OK)) 
	return INT_KRYPT_NO_MATCH; 
    
    layout_size = RARRAY_LEN(layout);
    for (i=0; i < layout_size; ++i) {
	ID codec;
	int result;
	krypt_asn1_definition inner_def;
	struct krypt_asn1_template_parse_ctx *parser;
	VALUE options;
	VALUE cur_def = rb_ary_entry(layout, i);

	krypt_error_clear();
        options = krypt_hash_get_options(cur_def);
	krypt_definition_init(&inner_def, cur_def, options);
	codec = SYM2ID(krypt_hash_get_codec(cur_def));
	parser = int_get_parse_ctx_for_codec(codec);
	if (codec == sKrypt_ID_ANY && first_any == -1) {
	    first_any = i;
	}
	
	if ((result = parser->match(self, &inner_ctx, &inner_def)) == INT_KRYPT_MATCH) {
            int_match_ctx_cleanup(&inner_ctx);
	    krypt_definition_set_matched_layout(def, i);
	    return INT_KRYPT_MATCH;
	}
	
        if (result == INT_KRYPT_MATCH_DEFAULT_APPLIED) {
            int_match_ctx_cleanup(&inner_ctx);
            return INT_KRYPT_MATCH_DEFAULT_APPLIED;
        }
	/* else -> didn't match */
    }

    int_match_ctx_cleanup(&inner_ctx);
    
    if (first_any != -1) {
        krypt_definition_set_matched_layout(def, first_any); /*the first ANY value matches if no other will */
        return INT_KRYPT_MATCH;
    }

    if (!krypt_definition_is_optional(def)) {
	krypt_error_add("Mandatory CHOICE value not found");
	return INT_KRYPT_MATCH_ERR;
    }
    return INT_KRYPT_NO_MATCH;
}

static krypt_asn1_object *
int_skip_explicit_choice_header(VALUE tagging, krypt_asn1_object *object, int *new_object)
{
    binyo_instream *in;
    krypt_asn1_object *next_object = NULL;

    if (NIL_P(tagging)) {
	*new_object = 0;
	return object;
    }

    in = binyo_instream_new_bytes(object->bytes, object->bytes_len);
    if (int_next_object(in, &next_object) != KRYPT_OK) {
	binyo_instream_free(in);
	krypt_error_add("Error while trying to read next value");
	return NULL;
    }

    binyo_instream_free(in);
    *new_object = 1;
    return next_object;
}

static int
int_parse_choice(VALUE self, krypt_asn1_object *object, krypt_asn1_definition *def, int *dont_free)
{
    ID codec;
    struct krypt_asn1_template_parse_ctx *parser;
    struct krypt_asn1_template_match_ctx ctx;
    VALUE layout, matched_def, matched_opts, tagging, type;
    krypt_asn1_object *unpacked;
    krypt_asn1_definition inner_def;
    long matched_index;
    int new_object, inner_dont_free;
    
    get_or_raise(layout, krypt_definition_get_layout(def), "'layout' missing in ASN.1 definition");
    if (int_enforce_explicit_tagging(def, &tagging) == KRYPT_ERR) return KRYPT_ERR;
    
    /* determine the matching index */
    int_match_ctx_init(&ctx, object);
    if (int_match_choice(self, &ctx, def) != INT_KRYPT_MATCH) {
        krypt_error_add("Matching value not found");
        return KRYPT_ERR;
    }
    matched_index = krypt_definition_get_matched_layout(def);
    matched_def = rb_ary_entry(layout, matched_index);
    matched_opts = krypt_hash_get_options(matched_def);
    
    /* Set up a temporary inner definition for actual parsing, using the matching definition */
    krypt_definition_init(&inner_def, matched_def, matched_opts);
    get_or_raise(type, krypt_definition_get_type(&inner_def), "'type' missing in inner choice definition");

    if (!(unpacked = int_skip_explicit_choice_header(tagging, object, &new_object))) return KRYPT_ERR;
    
    codec = SYM2ID(krypt_hash_get_codec(matched_def));
    parser = int_get_parse_ctx_for_codec(codec);
    if (parser->parse(self, unpacked, &inner_def, &inner_dont_free) == KRYPT_ERR) return KRYPT_ERR;

    rb_ivar_set(self, sKrypt_IV_TYPE, type);
    rb_ivar_set(self, sKrypt_IV_TAG, INT2NUM(unpacked->header->tag));
    
    /* complicated cleanup */
    if (!inner_dont_free) {
	if (new_object)
	    krypt_asn1_object_free(unpacked); /* free the unpacked object also, since bytes were copied in inner processing */
	*dont_free = 0; /* free the argument object in any case */
    } else {
	if (new_object)
	    *dont_free = 0; /* we unpacked the explicit tag, so free the argument object */
	else
	    *dont_free = 1; /* the original object was consumed as is within, so don't free it */
    }

    return KRYPT_OK;
}

static int
int_template_parse(VALUE self, krypt_asn1_template *t)
{
    ID codec;
    VALUE definition;
    krypt_asn1_definition def;
    struct krypt_asn1_template_parse_ctx *parser;
    int dont_free = 0;

    definition = krypt_asn1_template_get_definition(t);
    krypt_definition_init(&def, definition, krypt_asn1_template_get_options(t));
    codec = SYM2ID(krypt_hash_get_codec(definition));
    parser = int_get_parse_ctx_for_codec(codec);

    if (parser->parse(self, t->object, &def, &dont_free) == KRYPT_ERR) return KRYPT_ERR;
    krypt_asn1_template_set_parsed(t, 1);
    krypt_asn1_template_set_decoded(t, 1);

    /* Invalidate the cached template encoding */
    /* If dont_free is 0 this means that the encoding bytes were copied and
     * processed further inside -> we can free the template's object */
    if (!dont_free) {
        krypt_asn1_object_free(t->object);
    }
    t->object = NULL;
    return KRYPT_OK;
}

static int
int_value_decode(VALUE self, krypt_asn1_template *t)
{
    ID codec;
    VALUE definition, value;
    krypt_asn1_definition def;
    struct krypt_asn1_template_parse_ctx *parser;
    
    definition = krypt_asn1_template_get_definition(t);
    krypt_definition_init(&def, definition, krypt_asn1_template_get_options(t));
    codec = SYM2ID(krypt_hash_get_codec(definition));
    parser = int_get_parse_ctx_for_codec(codec);
    if (!parser->decode) return KRYPT_OK;
    if (parser->decode(self, t->object, &def, &value) == KRYPT_ERR) return KRYPT_ERR;
    krypt_asn1_template_set_decoded(t, 1);
    krypt_asn1_template_set_value(t, value);
    return KRYPT_OK;
}

static int
int_get_inner_value(VALUE self, ID ivname, VALUE *out)
{
    krypt_asn1_template *template;

    krypt_asn1_template_get(self, template);
    if (!(krypt_asn1_template_is_parsed(template))) {
	if (int_template_parse(self, template) == KRYPT_ERR) return KRYPT_ERR;
    }

    *out = rb_ivar_get(self, ivname);
    return KRYPT_OK;
}

int
krypt_asn1_template_get_cb_value(VALUE self, ID ivname, VALUE *out)
{
    krypt_asn1_template *value_template;
    VALUE value = Qnil;
    
    if (int_get_inner_value(self, ivname, &value) == KRYPT_ERR) return KRYPT_ERR;
    if (NIL_P(value)) {
	*out = Qnil;
	return KRYPT_OK;
    }
    
    krypt_asn1_template_get(value, value_template);

    if (!krypt_asn1_template_is_decoded(value_template)) {
	if (int_value_decode(value, value_template) == KRYPT_ERR) return KRYPT_ERR;
    }

    *out = krypt_asn1_template_get_value(value_template);
    return KRYPT_OK;
}

void
krypt_asn1_template_set_cb_value(VALUE self, ID ivname, VALUE value)
{
    VALUE container;
    krypt_asn1_template *template, *value_template;

    container = rb_ivar_get(self, ivname);
    krypt_asn1_template_get(self, template);

    if (NIL_P(container)) {
	VALUE obj;
	value_template = krypt_asn1_template_new_value(value);
	krypt_asn1_template_set(cKryptASN1TemplateValue, obj, value_template);
	rb_ivar_set(self, ivname, obj); 
    } else {
	krypt_asn1_template_get(container, value_template);
    }

    krypt_asn1_template_set_modified(template, 1);
    krypt_asn1_template_set_value(value_template, value);
}

static VALUE
int_rb_template_new_initial(VALUE klass, binyo_instream *in, krypt_asn1_header *header)
{
    ID codec;
    VALUE obj;
    VALUE definition;
    krypt_asn1_template *template;
    krypt_asn1_definition def;
    struct krypt_asn1_template_match_ctx ctx;
    struct krypt_asn1_template_parse_ctx *parser; 

    if (NIL_P((definition = krypt_definition_get(klass)))) {
        krypt_error_add("%s has no ASN.1 definition", rb_class2name(klass));
        return Qnil;
    }

    if (!(template = krypt_asn1_template_new_from_stream(in, header, definition, krypt_hash_get_options(definition)))) {
        krypt_error_add("Error while reading data");
        return Qnil;
    }

    /* ensure it matches */
    krypt_definition_init(&def, definition, Qnil); /* top-level definition has no options */
    codec = SYM2ID(krypt_hash_get_codec(definition));
    parser = int_get_parse_ctx_for_codec(codec);
    int_match_ctx_init(&ctx, template->object);
    obj = rb_obj_alloc(klass);
    if (parser->match(obj, &ctx, &def) != INT_KRYPT_MATCH) {
	krypt_error_add("Type mismatch");
	return Qnil;
    }

    krypt_asn1_template_set(klass, obj, template);
    return obj;
}

static int
krypt_asn1_template_parse_stream(binyo_instream *in, VALUE klass, VALUE *out)
{
    krypt_asn1_header *header;
    VALUE ret;
    int result;

    result = krypt_asn1_next_header(in, &header);
    if (result == KRYPT_ASN1_EOF || result == KRYPT_ERR) return result;

    ret = int_rb_template_new_initial(klass, in, header);
    if (NIL_P(ret)) {
	krypt_asn1_header_free(header);
	return KRYPT_ERR;
    }
    *out = ret;
    return KRYPT_OK;
}

VALUE
krypt_asn1_template_parse_der(VALUE klass, VALUE der)
{
    VALUE ret = Qnil;
    int result;
    binyo_instream *in = krypt_instream_new_value_der(der);

    result = krypt_asn1_template_parse_stream(in, klass, &ret);
    binyo_instream_free(in);
    if (result == KRYPT_ASN1_EOF || result == KRYPT_ERR)
	krypt_error_raise(eKryptASN1Error, "Parsing the value failed"); 
    return ret;
}

void
Init_krypt_asn1_template_parser(void)
{
    VALUE mParser = rb_define_module_under(mKryptASN1Template, "Parser");
    rb_define_method(mParser, "parse_der", krypt_asn1_template_parse_der, 1);
    rb_define_alias(mParser, "decode_der", "parse_der");
}

