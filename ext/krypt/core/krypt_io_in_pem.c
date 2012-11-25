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

enum krypt_pem_state {
    HEADER = 0,
    CONTENT,
    FOOTER,
    DONE
};

#define KRYPT_LINE_BUF_SIZE 256

typedef struct krypt_pem_parse_ctx_st {
    char *line;
    size_t len;
    size_t off;
    char *name;
} krypt_pem_parse_ctx;

typedef struct krypt_b64_buffer_st {
    krypt_instream *inner;
    uint8_t *buffer;
    size_t len;
    size_t off;
    enum krypt_pem_state state;
    char *name;
    int eof;
} krypt_b64_buffer;

typedef struct krypt_instream_pem_st {
    krypt_instream_interface *methods;
    krypt_b64_buffer *buffer;
} krypt_instream_pem;

#define int_safe_cast(out, in)		krypt_safe_cast_instream((out), (in), KRYPT_INSTREAM_TYPE_PEM, krypt_instream_pem)

static krypt_instream_pem* int_pem_alloc(void);
static ssize_t int_pem_read(krypt_instream *in, uint8_t *buf, size_t len);
static int int_pem_seek(krypt_instream *in, off_t offset, int whence);
static void int_pem_mark(krypt_instream *in);
static void int_pem_free(krypt_instream *in);

static krypt_instream_interface interface_pem = {
    KRYPT_INSTREAM_TYPE_PEM,
    int_pem_read,
    NULL,
    NULL,
    int_pem_seek,
    int_pem_mark,
    int_pem_free
};

static krypt_b64_buffer*
int_krypt_b64_buffer_new(krypt_instream *original)
{
    krypt_b64_buffer *ret;
    ret = ALLOC(krypt_b64_buffer);
    memset(ret, 0, sizeof(krypt_b64_buffer));
    ret->inner = original;
    ret->state = HEADER;
    return ret;
}

krypt_instream *
krypt_instream_new_pem(krypt_instream *original)
{
    krypt_instream_pem *in;

    in = int_pem_alloc();
    in->buffer = int_krypt_b64_buffer_new(original);
    return (krypt_instream *) in;
}

static krypt_instream_pem*
int_pem_alloc(void)
{
    krypt_instream_pem *ret;
    ret = ALLOC(krypt_instream_pem);
    memset(ret, 0, sizeof(krypt_instream_pem));
    ret->methods = &interface_pem;
    return ret;
}

static int
int_pem_seek(krypt_instream *instream, off_t offset, int whence)
{
    /* TODO */
    return 0;
}

static void
int_pem_mark(krypt_instream *instream)
{
    krypt_instream_pem *in;

    if (!instream) return;
    int_safe_cast(in, instream);
    krypt_instream_mark(in->buffer->inner);
}

static void
int_pem_free_inner(krypt_instream_pem *in)
{
    krypt_b64_buffer *b64;

    b64 = in->buffer;
    if (b64->buffer)
	xfree(b64->buffer);
    if (b64->name)
	xfree(b64->name);
    xfree(b64);
}

static void
int_pem_free(krypt_instream *instream)
{
    krypt_instream_pem *in;
    krypt_b64_buffer *b64;

    if (!instream) return;
    int_safe_cast(in, instream);
    b64 = in->buffer;

    krypt_instream_free(b64->inner);
    int_pem_free_inner(in);
}

void
krypt_instream_pem_free_wrapper(krypt_instream *instream)
{
    krypt_instream_pem *in;

    if (!instream) return;
    int_safe_cast(in, instream);

    int_pem_free_inner(in);
    xfree(in);
}

size_t
krypt_pem_get_last_name(krypt_instream *instream, uint8_t **out)
{
    krypt_instream_pem *in;
    krypt_b64_buffer *b64;
    size_t retlen;

    if (!instream) {
	*out = NULL;
	return 0;
    }

    int_safe_cast(in, instream);
    b64 = in->buffer;

    if (!b64->name) {
	*out = NULL;
	return 0;
    }

    retlen = strlen(b64->name);
    *out = ALLOC_N(uint8_t, retlen);
    memcpy(*out, b64->name, retlen);
    return retlen;
}


void
krypt_pem_continue_stream(krypt_instream *instream)
{
    krypt_instream_pem *in;
    krypt_b64_buffer *b64;

    if (!instream) return;
    int_safe_cast(in, instream);
    b64 = in->buffer;
    b64->state = HEADER;
    b64->eof = 0;
    b64->off = 0;
    b64->len = 0;
    if (b64->name)
	xfree(b64->name);
    b64->name = NULL;
    if (b64->buffer)
	xfree(b64->buffer);
    b64->buffer = NULL;
}


static int
int_match_header(krypt_pem_parse_ctx *ctx)
{
    if (ctx->len == KRYPT_LINE_BUF_SIZE)
	return 0;
    if (strncmp(ctx->line, "-----BEGIN ", 11) == 0) {
	size_t len;
	len = ctx->len;
	if (strncmp(ctx->line + len - 5, "-----", 5) != 0)
	    return 0;
	ctx->name = ALLOC_N(char, len - 11 - 4);
	memcpy(ctx->name, ctx->line + 11, len - 11 - 5);
	ctx->name[len - 11 - 5] = '\0';
	return 1;
    }
    return 0;
}

static int
int_match_footer(krypt_pem_parse_ctx *ctx)
{
    char *name = ctx->name;

    if (ctx->len == KRYPT_LINE_BUF_SIZE)
	return 0;
    if (strncmp(ctx->line, "-----END ", 9) == 0) {
	size_t len;
	len = ctx->len;
	if (strncmp(ctx->line + len - 5, "-----", 5) != 0)
	    return 0;
	if (strncmp(ctx->line + 9, name, len - 9 - 5) == 0)
	    return 1;
    }
    return 0;
}

static int
int_b64_fill(krypt_b64_buffer *in)
{
    krypt_outstream *out;
    size_t total = 0;
    ssize_t linelen;
    char linebuf[KRYPT_LINE_BUF_SIZE]; 

    if (in->buffer) {
	xfree(in->buffer);
        in->buffer = NULL;
    }

    out = krypt_outstream_new_bytes_size(KRYPT_IO_BUF_SIZE + KRYPT_LINE_BUF_SIZE);
    linelen = krypt_instream_gets(in->inner, linebuf, KRYPT_LINE_BUF_SIZE);
    if (linelen < -1) return 0;

    while (in->state != DONE && total < KRYPT_IO_BUF_SIZE && linelen != -1) {
	if (linelen == 0) {
	    linelen = krypt_instream_gets(in->inner, linebuf, KRYPT_LINE_BUF_SIZE);
	    continue;
	}
	switch (in->state) {
	    case HEADER:
		if (linebuf[0] == '-') {
		    krypt_pem_parse_ctx linectx;
		    linectx.line = linebuf;
		    linectx.len = linelen;
		    linectx.off = 0;
		    if (int_match_header(&linectx)) {
			in->name = linectx.name;
			in->state = CONTENT;
		    }
		}
		linelen = krypt_instream_gets(in->inner, linebuf, KRYPT_LINE_BUF_SIZE);
		break;
	    case CONTENT:
		if (linebuf[0] == '-') {
		    in->state = FOOTER;
		}
		else {
		    if (!krypt_base64_buffer_decode_to(out, (uint8_t *) linebuf, 0, linelen)) {
			krypt_error_add("Could not decode Base64 data");
			return 0;
		    }
		    total += linelen;
		    if (total < KRYPT_IO_BUF_SIZE)
			linelen = krypt_instream_gets(in->inner, linebuf, KRYPT_LINE_BUF_SIZE);
		}
		break;
	    case FOOTER:
		if (linebuf[0] == '-') {
		    krypt_pem_parse_ctx linectx;
		    linectx.line = linebuf;
		    linectx.len = linelen;
		    linectx.off = 0;
		    linectx.name = in->name;
		    if (int_match_footer(&linectx))
			in->state = DONE;
		    else
			linelen = krypt_instream_gets(in->inner, linebuf, KRYPT_LINE_BUF_SIZE);
		}
		else {
		    linelen = krypt_instream_gets(in->inner, linebuf, KRYPT_LINE_BUF_SIZE);
		}
		break;
	    default:
		break;
	}
    }

    if (in->state == DONE || linelen == -1)
	in->eof = 1;

    if (linelen == -1 && in->state != DONE) {
	krypt_outstream_free(out);
	switch (in->state) {
	    case HEADER:
		in->len = in->off = 0;
		in->eof = 1;
		return 1;
	    case CONTENT:
		krypt_error_add("PEM data ended prematurely");
		return 0;
	    default:
		krypt_error_add("Could not find matching PEM footer");
		return 0;
	}
    }

    in->off = 0;
    in->len = krypt_outstream_bytes_get_bytes_free(out, &in->buffer);
    return 1;
}

static size_t
int_consume_bytes(krypt_b64_buffer *in, uint8_t *buf, size_t len)
{
    size_t available, toread;

    if (in->off == in->len)
	return 0;

    available = in->len - in->off;
    toread = len < available ? len : available;
    memcpy(buf, in->buffer + in->off, toread);
    in->off += toread;
    return toread;
}

static ssize_t
int_b64_read(krypt_b64_buffer *in, uint8_t *buf, size_t len)
{
    size_t total = 0;

    while (total != len && !(in->off == in->len && in->eof)) {
	if (in->off == in->len) {
	    if (!int_b64_fill(in))
		return -2;
	}
	total += int_consume_bytes(in, buf + total, len - total);
    }

    if (total == 0 && in->eof)
	return -1;

    if (total > SSIZE_MAX) {
	krypt_error_add("Return size too large: %ld", total);
	return -2;
    }
    return (ssize_t) total;
}

static ssize_t
int_pem_read(krypt_instream *instream, uint8_t *buf, size_t len)
{
    krypt_instream_pem *in;
    if (!buf) return -2;
    int_safe_cast(in, instream);
    return int_b64_read(in->buffer, buf, len);
}

