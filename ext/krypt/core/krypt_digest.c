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

VALUE mKryptDigest;
VALUE eKryptDigestError;

VALUE cKryptNativeDigest;

/** public internal digest API **/

#define int_check_provider_has(p, m) 		if (!(p) || !(p)->m) return NULL;
#define int_check_digest_has(d, m) 		if (!(d) || !(d)->methods || !(d)->methods->m) return 0;

krypt_md *
krypt_md_oid_new(krypt_provider *provider, const char *oid)
{
    int_check_provider_has(provider, md_new_oid);
    return provider->md_new_oid(provider, oid);
}

krypt_md *
krypt_md_name_new(krypt_provider *provider, const char *name)
{
    int_check_provider_has(provider, md_new_name);
    return provider->md_new_name(provider, name);
}

krypt_md *
krypt_md_new(krypt_provider *provider, const char *name_or_oid)
{
    krypt_md *ret = NULL;
    if ((ret = krypt_md_name_new(provider, name_or_oid)))
	return ret;
    return krypt_md_oid_new(provider, name_or_oid);
}

int
krypt_md_reset(krypt_md *md)
{
    int_check_digest_has(md, md_reset);
    return md->methods->md_reset(md);
}

int
krypt_md_update(krypt_md *md, unsigned char *data, size_t len)
{
    int_check_digest_has(md, md_update);
    return md->methods->md_update(md, data, len);
}

int
krypt_md_final(krypt_md *md, unsigned char **digest, size_t *len)
{
    int_check_digest_has(md, md_final);
    if (!md->methods->md_final(md, digest, len)) return 0;
    return krypt_md_reset(md);
}

int
krypt_md_digest(krypt_md *md, unsigned char *data, size_t len, unsigned char **digest, size_t *digest_len)
{
    int_check_digest_has(md, md_digest);
    if(!md->methods->md_digest(md, data, len, digest, digest_len)) return 0;
    return krypt_md_reset(md);
}

int
krypt_md_digest_length(krypt_md *md, int *len)
{
    int_check_digest_has(md, md_digest_length);
    return md->methods->md_digest_length(md, len);
}

int
krypt_md_block_length(krypt_md *md, int *len)
{
    int_check_digest_has(md, md_block_length);
    return md->methods->md_block_length(md, len);
}

int
krypt_md_name(krypt_md *md, const char **name)
{
    int_check_digest_has(md, md_name);
    return md->methods->md_name(md, name);
}

void
krypt_md_mark(krypt_md *md)
{
    if (!md) return; 
    if (md->methods->mark)
	md->methods->mark(md);
}

void
krypt_md_free(krypt_md *md)
{
    if (!md) return; 
    md->methods->free(md);
}

/** Digest class implementation **/

VALUE
krypt_digest_new(krypt_md *md)
{
    VALUE obj;

    obj = Data_Wrap_Struct(cKryptNativeDigest, krypt_md_mark, krypt_md_free, md);
    return obj;
}

#define int_md_get(obj, md)					\
do { 								\
    Data_Get_Struct((obj), krypt_md, (md));			\
    if (!(md)) { 						\
	rb_raise(eKryptError, "Uninitialized krypt_md");	\
    } 								\
} while (0)

/*
 *  call-seq:
 *     digest.reset -> self
 *
 * Resets the Digest in the sense that any Digest#update that has been
 * performed is abandoned and the Digest is set to its initial state again.
 *
 */
static VALUE
krypt_digest_reset(VALUE self)
{
    krypt_md *md;

    int_md_get(self, md);
    if (!krypt_md_reset(md)) {
	rb_raise(eKryptDigestError, "Error while resetting digest");
    }
    return self;
}

/*
 *  call-seq:
 *     digest.update(string) -> aString
 *
 * Not every message digest can be computed in one single pass. If a message
 * digest is to be computed from several subsequent sources, then each may
 * be passed individually to the Digest instance.
 *
 * === Example
 *   digest = Krypt::Digest::SHA256.new
 *   digest.update('First input')
 *   digest << 'Second input' # equivalent to digest.update('Second input')
 *   result = digest.digest
 *
 */
static VALUE
krypt_digest_update(VALUE self, VALUE data)
{
    krypt_md *md;
    unsigned char *bytes;
    size_t len;

    int_md_get(self, md);
    StringValue(data);
    bytes = (unsigned char *) RSTRING_PTR(data);
    len = (size_t) RSTRING_LEN(data);
    if (!krypt_md_update(md, bytes, len)) {
	rb_raise(eKryptDigestError, "Error while updating digest");
    }
    return self;
}

static VALUE
int_digest_data(krypt_md *md, VALUE data)
{
    unsigned char *bytes;
    size_t len;
    unsigned char *digest;
    size_t digest_len;
    VALUE ret;

    StringValue(data);
    bytes = (unsigned char *) RSTRING_PTR(data);
    len = (size_t) RSTRING_LEN(data);
    if (!krypt_md_digest(md, bytes, len, &digest, &digest_len)) {
	rb_raise(eKryptDigestError, "Error while computing digest");
    }
    ret = rb_str_new((const char *) digest, digest_len);
    xfree(digest);
    return ret;
}

static VALUE
int_digest_final(krypt_md *md)
{
    unsigned char *digest;
    size_t len;
    VALUE ret;
    if (!krypt_md_final(md, &digest, &len)) {
	rb_raise(eKryptDigestError, "Error while finalizing digest");
    }
    ret = rb_str_new((const char *) digest, len);
    xfree(digest);
    return ret;
}

/*
 *  call-seq:
 *     digest.digest([string]) -> String
 *
 * When called with no arguments, the result will be the hash of the data that
 * has been fed to this Digest instance so far. If called with a String
 * argument, the hash of that argument will be computed.
 *
 * === Example
 *   digest = Krypt::Digest::SHA256.new
 *   result = digest.digest('First input')
 *
 * is equivalent to
 *   
 *   digest = Krypt::Digest::SHA256.new
 *   digest << 'First input' # equivalent to digest.update('Second input')
 *   result = digest.digest
 *
 */
static VALUE
krypt_digest_digest(int argc, VALUE *args, VALUE self)
{
    krypt_md *md;
    VALUE data;

    rb_scan_args(argc, args, "01", &data);
    int_md_get(self, md);
    if (!(NIL_P(data)))
	return int_digest_data(md, data);
    else
	return int_digest_final(md);
}

/*
 *  call-seq:
 *     digest.hexdigest([string]) -> String
 *
 * Works the with the same semantics as Digest#digest with the difference that
 * instead of the raw bytes the hex-encoded form of the raw representation is
 * returned.
 */
static VALUE
krypt_digest_hexdigest(int argc, VALUE *args, VALUE self)
{
    VALUE digest, ret;
    unsigned char *bytes;
    ssize_t len;

    digest = krypt_digest_digest(argc, args, self);
    len = krypt_hex_encode((unsigned char *) RSTRING_PTR(digest), RSTRING_LEN(digest), &bytes);
    if (len == -1)
	rb_raise(eKryptDigestError, "Error while hex-encoding digest");
    ret = rb_str_new((const char *) bytes, len);
    xfree(bytes);
    return ret;
}

/*
 *  call-seq:
 *      digest.digest_length -> integer
 *
 * Returns the output size of the digest, i.e. the length in bytes of the
 * final message digest result.
 *
 * === Example
 *   digest = Krypt::Digest::SHA1.new
 *   puts digest.digest_length # => 20
 *
 */
static VALUE
krypt_digest_digest_length(VALUE self)
{
    krypt_md *md;
    int len;

    int_md_get(self, md);
    if (!krypt_md_digest_length(md, &len)) {
	rb_raise(eKryptDigestError, "Error while getting digest length");
    }
    return INT2NUM(len);
}

/*
 *  call-seq:
 *      digest.block_length -> integer
 *
 * Returns the block length of the digest algorithm, i.e. the length in bytes
 * of an individual block. Most modern algorithms partition a message to be
 * digested into a sequence of fix-sized blocks that are processed
 * consecutively.
 *
 * === Example
 *   digest = Krypt::Digest::SHA1.new
 *   puts digest.block_length # => 64
 */
static VALUE
krypt_digest_block_length(VALUE self)
{
    krypt_md *md;
    int len;

    int_md_get(self, md);
    if (!krypt_md_block_length(md, &len)) {
	rb_raise(eKryptDigestError, "Error while getting digest block length");
    }
    return INT2NUM(len);
}

/*
 *  call-seq:
 *      digest.name -> string
 *
 * Returns the sn of this Digest instance.
 *
 * === Example
 *   digest = Krypt::Digest::SHA512.new
 *   puts digest.name # => SHA512
 *
 */
static VALUE
krypt_digest_name(VALUE self)
{
    krypt_md *md;
    const char *name;

    int_md_get(self, md);
    if (!krypt_md_name(md, &name)) {
	rb_raise(eKryptDigestError, "Error while getting digest name");
    }
    return rb_str_new2(name);
}

void
Init_krypt_digest(void)
{
#if 0
    mKrypt = rb_define_module("Krypt"); /* Let RDoc know */
#endif

    mKryptDigest = rb_path2class("Krypt::Digest");
    eKryptDigestError = rb_path2class("Krypt::Digest::DigestError");

    /* Document-class: Krypt::Digest::NativeDigest
     * Native C implementation of the Krypt::Digest interface. 
     */
    cKryptNativeDigest = rb_define_class_under(mKryptDigest, "NativeDigest", rb_cObject);

    rb_define_method(cKryptNativeDigest, "reset", krypt_digest_reset, 0);
    rb_define_method(cKryptNativeDigest, "update", krypt_digest_update, 1);
    rb_define_alias(cKryptNativeDigest, "<<", "update");
    rb_define_method(cKryptNativeDigest, "digest", krypt_digest_digest, -1);
    rb_define_method(cKryptNativeDigest, "hexdigest", krypt_digest_hexdigest, -1);
    rb_define_method(cKryptNativeDigest, "digest_length", krypt_digest_digest_length, 0);
    rb_define_method(cKryptNativeDigest, "block_length", krypt_digest_block_length, 0);
    rb_define_method(cKryptNativeDigest, "name", krypt_digest_name, 0);
    rb_undef_method(CLASS_OF(cKryptNativeDigest), "new"); /* private constructor */	
}

