/*
 * krypt-core API - C implementation
 *
 * Copyright (c) 2011-2013
 * Hiroshi Nakamura <nahi@ruby-lang.org>
 * Martin Bosslet <martin.bosslet@gmail.com>
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "krypt-core.h"

VALUE mKryptPEM;
VALUE eKryptPEMError;

static int
int_consume_stream(binyo_instream *in, VALUE *vout)
{
    binyo_outstream *out;
    size_t len;
    uint8_t *str;
    uint8_t buf[BINYO_IO_BUF_SIZE];
    ssize_t read;
    
    out = binyo_outstream_new_bytes_size(BINYO_IO_BUF_SIZE);

    while ((read = binyo_instream_read(in, buf, BINYO_IO_BUF_SIZE)) >= 0) {
	binyo_outstream_write(out, buf, read);
    }
    if (read == BINYO_ERR) {
	binyo_outstream_free(out);
	return KRYPT_ERR;
    }

    len = binyo_outstream_bytes_get_bytes_free(out, &str);
    if (len == 0) {
	*vout = Qnil;
    } else {
    	*vout = rb_str_new((const char*)str, len);
	xfree(str);
    }
    return KRYPT_OK;
}

/*
 *  call-seq:
 *      Krypt::PEM.decode(data) { |der, name, i| block } -> Array
 *
 * +data+ can be either a PEM-encoded String, an IO-like object that features
 * a +read+ method or any arbitrary object that has a +to_pem+ method returning
 * either a String or an IO-like object.
 *
 * Returns an Array that contains the DER-encoded results in the order they
 * were decoded. PEM data can potentially consist of multiple elements, a
 * common example being 'trusted certificate bundles' that contain a set of
 * to-be-trusted certificates.
 *
 * If additionally a block is given, +block+ is called for each element that is
 * decoded, where +der+ contains the decoded element, +name+ the identifier of
 * the current element (e.g. 'CERTIFICATE') and +i+ the index of the current
 * element starting with 0. 
 *
 * === Example: Decoding a simple certificate file
 *
 *   File.open("certificate.pem", "rb") do |f|
 *     cert = Krypt::PEM.decode(f)[0]
 *     # process the certificate
 *   end
 *
 * === Example: Decoding multiple elements contained in one file
 *
 *   File.open("trusted-certs.pem", "rb") do |f|
 *     Krypt::PEM.decode(f) do |der, name, i|
 *       puts "Element #{i}: #{name}"
 *       File.open("cert-#{i}.der", "wb") do |g|
 *         g.print der
 *       end
 *     end
 *   end
 */
static VALUE
krypt_pem_decode(VALUE self, VALUE pem)
{
    VALUE ary, der;
    size_t i = 0;
    int result;
    binyo_instream *in = krypt_instream_new_pem(krypt_instream_new_value_pem(pem));
    
    ary = rb_ary_new();

    while ((result = int_consume_stream(in, &der)) == KRYPT_OK) {
	if (NIL_P(der))
	    break;

	rb_ary_push(ary, der);
	if(rb_block_given_p()) {
	    uint8_t *name;
	    size_t len;
	    VALUE vname;
	    if (krypt_pem_get_last_name(in, &name, &len) == BINYO_ERR) goto error;
	    vname = rb_str_new((const char *) name, len);
	    xfree(name);
	    rb_yield_values(3, der, vname, LONG2NUM(i++));
	}
	krypt_pem_continue_stream(in);
    }
    if (result == KRYPT_ERR) goto error;

    binyo_instream_free(in);
    return ary;

error:
    binyo_instream_free(in);
    krypt_error_raise(eKryptPEMError, "Error while decoding PEM data");
    return Qnil;
}

void
Init_krypt_pem(void)
{
#if 0
    mKrypt = rb_define_module("Krypt"); /* Let RDoc know */
#endif

    /* Document-module: Krypt::PEM
     *
     * The popular PEM format is essentially the Base64 encoding of some
     * DER-encoded data, with additional "header" and "footer" lines
     * indicating the type of data being encoded. The PEM module offers
     * ways to conveniently encode and decode arbitrary PEM-formatted
     * data.
     *
     * === Converting from PEM to DER
     *
     * PEM-encoded data can be easily converted to equivalent DER-encoded
     * data:
     *
     *   pem = File.read("data.pem")
     *   File.open("data.der", "wb") do |f|
     *     f.print(Krypt::PEM.decode(pem))
     *   end
     */
    mKryptPEM = rb_define_module_under(mKrypt, "PEM");
    rb_define_module_function(mKryptPEM, "decode", krypt_pem_decode, 1);

    /* Document-class: Krypt::PEM::PEMError
     *
     * Generic error class for all errors raised while writing to or reading
     * from a stream with PEM data.
     */
    eKryptPEMError = rb_define_class_under(mKryptPEM, "PEMError", eKryptError);
}

