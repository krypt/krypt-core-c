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

ID sKrypt_ID_OPTIONS, sKrypt_ID_NAME, sKrypt_ID_TYPE,
   sKrypt_ID_CODEC, sKrypt_ID_LAYOUT, sKrypt_ID_MIN_SIZE;

ID sKrypt_ID_DEFAULT,  sKrypt_ID_OPTIONAL, sKrypt_ID_TAG, sKrypt_ID_TAGGING;
   
ID sKrypt_ID_PRIMITIVE, sKrypt_ID_SEQUENCE, sKrypt_ID_SET, sKrypt_ID_TEMPLATE,
   sKrypt_ID_SEQUENCE_OF, sKrypt_ID_SET_OF, sKrypt_ID_CHOICE, sKrypt_ID_ANY;

ID sKrypt_IV_TYPE, sKrypt_IV_DEFINITION, sKrypt_IV_OPTIONS;

ID sKrypt_ID_MERGE;

VALUE mKryptASN1Template;
VALUE cKryptASN1TemplateValue;

void
krypt_definition_init(krypt_asn1_definition *def, VALUE definition, VALUE options)
{
    memset(def, 0, sizeof(krypt_asn1_definition));
    def->definition = definition;
    def->options = options;
}

#define DEFINITION_GETTER(getter, idx)					\
VALUE									\
krypt_definition_get_##getter(krypt_asn1_definition *def)		\
{									\
    if (!def->value_read[(idx)]) {					\
	def->values[(idx)] = krypt_hash_get_##getter(def->definition);	\
	def->value_read[(idx)] = 1;					\
    }									\
    return def->values[(idx)];						\
}

#define OPTIONS_GETTER(getter, idx)					\
VALUE									\
krypt_definition_get_##getter(krypt_asn1_definition *def)		\
{									\
    if (!def->value_read[(idx)]) {					\
	if (NIL_P(def->options))					\
	    def->values[(idx)] = Qnil;					\
	else								\
	   def->values[(idx)] = krypt_hash_get_##getter(def->options);	\
	def->value_read[(idx)] = 1;					\
    }									\
    return def->values[(idx)];						\
}

DEFINITION_GETTER(name, KRYPT_DEFINITION_NAME)
DEFINITION_GETTER(type, KRYPT_DEFINITION_TYPE)
DEFINITION_GETTER(layout, KRYPT_DEFINITION_LAYOUT)
DEFINITION_GETTER(min_size, KRYPT_DEFINITION_MIN_SIZE)

OPTIONS_GETTER(optional, KRYPT_DEFINITION_OPTIONAL)
OPTIONS_GETTER(tag, KRYPT_DEFINITION_TAG)
OPTIONS_GETTER(tagging, KRYPT_DEFINITION_TAGGING)
OPTIONS_GETTER(default_value, KRYPT_DEFINITION_DEFAULT)

int 
krypt_definition_is_optional(krypt_asn1_definition *def)
{
    VALUE x = krypt_definition_get_optional(def);
    int optional = RTEST(x);
    if (optional) return 1;
    x = krypt_definition_get_default_value(def);
    return !NIL_P(x);
}

int 
krypt_definition_has_default(krypt_asn1_definition *def)
{
    return !NIL_P(krypt_definition_get_default_value(def));
}

krypt_asn1_template *
krypt_asn1_template_new(krypt_asn1_object *object, VALUE definition, VALUE options)
{
    krypt_asn1_template *ret;

    ret = ALLOC(krypt_asn1_template);
    ret->object = object;
    ret->definition = definition;
    ret->options = options;
    ret->value = Qnil;
    ret->flags = 0;
    return ret;
}

krypt_asn1_template *
krypt_asn1_template_new_from_stream(binyo_instream *in, krypt_asn1_header *header, VALUE definition, VALUE options)
{
    krypt_asn1_object *encoding;
    uint8_t *value = NULL;
    size_t value_len;

    if (krypt_asn1_get_value(in, header, &value, &value_len) == KRYPT_ERR) return NULL;
    if (!(encoding = krypt_asn1_object_new_value(header, value, value_len))) return NULL;
    return krypt_asn1_template_new(encoding, definition, options);
}

krypt_asn1_template *
krypt_asn1_template_new_value(VALUE value)
{
    krypt_asn1_template *ret;

    ret = krypt_asn1_template_new(NULL, Qnil, Qnil);
    ret->value = value;
    ret->flags = KRYPT_TEMPLATE_PARSED | KRYPT_TEMPLATE_DECODED;
    return ret;
}

void
krypt_asn1_template_free(krypt_asn1_template *template)
{
    if (!template) return;
    if (template->object)
	krypt_asn1_object_free(template->object);
    xfree(template);
}

void
krypt_asn1_template_mark(krypt_asn1_template *template)
{
    if (!template) return;
    if (!NIL_P(template->value))
	rb_gc_mark(template->value);
}

static VALUE
krypt_asn1_template_initialize(VALUE self)
{
    krypt_asn1_template *template;
    VALUE definition, klass;

    if (DATA_PTR(self))
	rb_raise(eKryptASN1Error, "Template already initialized");
    klass = CLASS_OF(self);
    if (NIL_P((definition = krypt_definition_get(klass)))) {
        krypt_error_add("%s has no ASN.1 definition", rb_class2name(klass));
        return Qnil;
    }
    template = krypt_asn1_template_new(NULL, definition, krypt_hash_get_options(definition));
    krypt_asn1_template_set_parsed(template, 1);
    krypt_asn1_template_set_decoded(template, 1);
    DATA_PTR(self) = template;

    if (rb_block_given_p()) {
	VALUE blk = rb_block_proc();
	rb_funcall(blk, rb_intern("call"), 1, self);
    }
    return self;
}

static VALUE
krypt_asn1_template_alloc(VALUE klass)
{
    return Data_Wrap_Struct(klass, krypt_asn1_template_mark, krypt_asn1_template_free, 0);
}

static VALUE
int_traverse_template(VALUE vt, 
		      VALUE name, 
		      void (*traverse_cb) (VALUE, VALUE, void *), 
		      void *args)
{
    ID codec;
    VALUE vcodec, definition;
    krypt_asn1_template *t;

    traverse_cb(vt, name, args);

    if (NIL_P(vt)) {
	/* base case 1 */
	return Qnil;
    }

    krypt_asn1_template_get(vt, t);

    definition = krypt_asn1_template_get_definition(t);
    if (NIL_P(definition)) {
	/* base case 2 */
	return Qnil;
    }

    get_or_raise(vcodec, krypt_hash_get_codec(definition), "No codec found in definition");
    codec = SYM2ID(vcodec);
    if (codec == sKrypt_ID_PRIMITIVE) {
	/* base case 3 */
	return Qnil;
    }
    if (codec == sKrypt_ID_ANY ||
	codec == sKrypt_ID_CHOICE ||
	codec == sKrypt_ID_SET_OF ||
	codec == sKrypt_ID_SEQUENCE_OF) {
	VALUE name = krypt_hash_get_name(definition);
	VALUE value = rb_ivar_get(vt, sKrypt_IV_VALUE);
	return int_traverse_template(value, name, traverse_cb, args);
    }
    if (codec == sKrypt_ID_SET || codec == sKrypt_ID_SEQUENCE) {
	long i;
	VALUE dummy = Qnil;
	VALUE layout = krypt_hash_get_layout(definition);
	for (i=0; i < RARRAY_LEN(layout); ++i) {
	    VALUE name, value;
	    VALUE cur_def = rb_ary_entry(layout, i);

	    get_or_raise(name, krypt_hash_get_name(cur_def), "SEQ/SET value without name found");
	    value = rb_ivar_get(vt, SYM2ID(name));
	    dummy = int_traverse_template(value, name, traverse_cb, args);
	}
	return dummy;
    }
    if (codec == sKrypt_ID_TEMPLATE) {
	return int_traverse_template(t->value, name, traverse_cb, args);
    }

    rb_raise(eKryptASN1Error, "Unknown codec encountered: %s", rb_id2name(codec));
    return Qnil;
}

static VALUE
krypt_asn1_template_mod_included_callback(VALUE self, VALUE klass)
{
    rb_define_alloc_func(klass, krypt_asn1_template_alloc);
    return Qnil;
}

static VALUE
int_return_choice_attr(VALUE self, ID ivname)
{
    VALUE dummy;

    if (krypt_asn1_template_get_cb_value(self, sKrypt_IV_VALUE, &dummy) == KRYPT_ERR) {
	krypt_error_raise(eKryptASN1Error, "Could not access %s", rb_id2name(ivname));
    }
    return rb_ivar_get(self, ivname);
}

VALUE
krypt_asn1_template_get_callback(VALUE self, VALUE name)
{
    VALUE ret = Qnil;
    ID ivname = SYM2ID(name);

    if (krypt_asn1_template_get_cb_value(self, ivname, &ret) == KRYPT_ERR)
	krypt_error_raise(eKryptASN1Error, "Could not access %s", rb_id2name(ivname));
    return ret;
}

VALUE
krypt_asn1_template_get_callback_choice(VALUE self, VALUE name)
{
    ID ivname = SYM2ID(name);

    if (ivname == sKrypt_IV_TAG || ivname == sKrypt_IV_TYPE)
	return int_return_choice_attr(self, ivname);

    return krypt_asn1_template_get_callback(self, name);
}

VALUE
krypt_asn1_template_set_callback(VALUE self, VALUE name, VALUE value)
{
    ID ivname = SYM2ID(name);
    krypt_asn1_template_set_cb_value(self, ivname, value);
    return value;
}

VALUE
krypt_asn1_template_set_callback_choice(VALUE self, VALUE name, VALUE value)
{
    ID ivname = SYM2ID(name);

    if (ivname == sKrypt_IV_TAG || ivname == sKrypt_IV_TYPE)
	return rb_ivar_set(self, ivname, value);

    return krypt_asn1_template_set_callback(self, name, value);
}

VALUE
krypt_asn1_template_cmp(VALUE self, VALUE other)
{
    VALUE vs1, vs2;
    int result;

    vs1 = krypt_asn1_template_to_der(self);
    if (!rb_respond_to(other, sKrypt_ID_TO_DER)) return Qnil;
    vs2 = krypt_to_der(other);

    if (krypt_asn1_cmp_set_of((uint8_t *) RSTRING_PTR(vs1), (size_t) RSTRING_LEN(vs1),
	                      (uint8_t *) RSTRING_PTR(vs2), (size_t) RSTRING_LEN(vs2), &result) == KRYPT_ERR) {
	krypt_error_raise(eKryptASN1Error, "Error while comparing values");
    }
    return INT2NUM(result);
}

static void
int_inspect_i(VALUE template_value, VALUE name, void *args)
{
    krypt_asn1_template *t;
    krypt_asn1_object *object;
    VALUE definition, codec, str;
    ID puts = rb_intern("puts");
    ID to_s = rb_intern("to_s");
    VALUE yes = rb_str_new2("y"), no = rb_str_new2("n");

    str = rb_str_new2("Name: ");
    rb_str_append(str, rb_funcall(name, to_s, 0));
    if (NIL_P(template_value)) {
	rb_str_append(str, rb_str_new2(" @value"));
	rb_funcall(rb_mKernel, puts, 1, str);
	return;
    }

    krypt_asn1_template_get(template_value, t);

    definition = krypt_asn1_template_get_definition(t);
    codec = NIL_P(definition) ? rb_str_new2("") : krypt_hash_get_codec(definition);

    rb_str_append(str, rb_str_new2(" Codec: "));
    rb_str_append(str, rb_funcall(codec, to_s, 0));
    rb_str_append(str, rb_str_new2(" Parsed: "));
    rb_str_append(str, krypt_asn1_template_is_parsed(t) ? yes : no);
    rb_str_append(str, rb_str_new2(" Decoded: "));
    rb_str_append(str, krypt_asn1_template_is_decoded(t) ? yes : no);
    rb_str_append(str, rb_str_new2(" Modified: "));
    rb_str_append(str, krypt_asn1_template_is_modified(t) ? yes : no);
    rb_str_append(str, rb_str_new2(" Object: "));
    object = krypt_asn1_template_get_object(t);
    rb_str_append(str, object ? yes : no);
    rb_str_append(str, rb_str_new2(" Bytes: "));
    rb_str_append(str, (object && object->bytes) ? yes : no);
    rb_funcall(rb_mKernel, puts, 1, str);

    str = rb_str_new2("Value: ");
    rb_str_append(str, rb_funcall(krypt_asn1_template_get_value(t), to_s, 0));
    rb_funcall(rb_mKernel, puts, 1, str);

    str = rb_str_new2("Definition: ");
    rb_str_append(str, rb_funcall(krypt_asn1_template_get_definition(t), to_s, 0));
    rb_funcall(rb_mKernel, puts, 1, str);

    str = rb_str_new2("Options: ");
    rb_str_append(str, rb_funcall(krypt_asn1_template_get_options(t), to_s, 0));
    rb_funcall(rb_mKernel, puts, 1, str);
}

static VALUE
krypt_asn1_template_inspect(VALUE self)
{
    VALUE name = rb_str_new2("ROOT");
    return int_traverse_template(self, name, int_inspect_i, NULL);
}

/*
 * call-seq:
 *    asn1.to_der -> DER-/BER-encoded String
 *
 * Behaves the same way that Krypt::ASN1#to_der does.
 */
VALUE
krypt_asn1_template_to_der(VALUE template)
{
    VALUE ret;

    if (krypt_asn1_template_encode(template, &ret) == KRYPT_ERR)
	krypt_error_raise(eKryptASN1Error, "Error while encoding value");
    return ret;
}

static VALUE
krypt_asn1_template_value_to_s(VALUE self)
{
    krypt_asn1_template *template;

    krypt_asn1_template_get(self, template);
    if (NIL_P(template->value))
	return rb_str_new2("");
    return rb_funcall(template->value, rb_intern("to_s"), 0);
}

void
Init_krypt_asn1_template(void)
{
    sKrypt_ID_CODEC = rb_intern("codec");
    sKrypt_ID_OPTIONS = rb_intern("options");
    sKrypt_ID_DEFAULT = rb_intern("default");
    sKrypt_ID_NAME = rb_intern("name");
    sKrypt_ID_TYPE = rb_intern("type");
    sKrypt_ID_OPTIONAL = rb_intern("optional");
    sKrypt_ID_TAG = rb_intern("tag");
    sKrypt_ID_TAGGING = rb_intern("tagging");
    sKrypt_ID_LAYOUT = rb_intern("layout");
    sKrypt_ID_MIN_SIZE = rb_intern("min_size");

    sKrypt_ID_PRIMITIVE = rb_intern("PRIMITIVE");
    sKrypt_ID_SEQUENCE = rb_intern("SEQUENCE");
    sKrypt_ID_SET = rb_intern("SET");
    sKrypt_ID_TEMPLATE = rb_intern("TEMPLATE");
    sKrypt_ID_SEQUENCE_OF = rb_intern("SEQUENCE_OF");
    sKrypt_ID_SET_OF = rb_intern("SET_OF");
    sKrypt_ID_CHOICE = rb_intern("CHOICE");
    sKrypt_ID_ANY = rb_intern("ANY");
    
    sKrypt_IV_TYPE = rb_intern("@type");
    sKrypt_IV_DEFINITION = rb_intern("@definition");
    sKrypt_IV_OPTIONS = rb_intern("@options");

    sKrypt_ID_MERGE = rb_intern("merge");

    mKryptASN1Template = rb_define_module_under(mKryptASN1, "Template");
    rb_define_module_function(mKryptASN1Template, "_mod_included_callback", krypt_asn1_template_mod_included_callback, 1);
    rb_define_method(mKryptASN1Template, "initialize", krypt_asn1_template_initialize, 0);
    rb_define_method(mKryptASN1Template, "_get_callback", krypt_asn1_template_get_callback, 1);
    rb_define_method(mKryptASN1Template, "_set_callback", krypt_asn1_template_set_callback, 2);
    rb_define_method(mKryptASN1Template, "_get_callback_choice", krypt_asn1_template_get_callback_choice, 1);
    rb_define_method(mKryptASN1Template, "_set_callback_choice", krypt_asn1_template_set_callback_choice, 2);
    rb_define_method(mKryptASN1Template, "to_der", krypt_asn1_template_to_der, 0);
    rb_define_method(mKryptASN1Template, "<=>", krypt_asn1_template_cmp, 1);
    rb_define_method(mKryptASN1Template, "__inspect__", krypt_asn1_template_inspect, 0);

    cKryptASN1TemplateValue = rb_define_class_under(mKryptASN1Template, "Value", rb_cObject);
    rb_define_method(cKryptASN1TemplateValue, "to_s", krypt_asn1_template_value_to_s, 0);

    Init_krypt_asn1_template_parser();
}

