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
#include <stdarg.h>

typedef struct krypt_instream_seq_st {
    krypt_instream_interface *methods;
    krypt_instream *active;
    int i;
    krypt_instream **streams;
    int num;
} krypt_instream_seq;

#define int_safe_cast(out, in)		krypt_safe_cast_instream((out), (in), KRYPT_INSTREAM_TYPE_SEQ, krypt_instream_seq)

static krypt_instream_seq* int_seq_alloc(void);
static ssize_t int_seq_read(krypt_instream *in, uint8_t *buf, size_t len);
static int int_seq_seek(krypt_instream *in, off_t offset, int whence);
static void int_seq_mark(krypt_instream *in);
static void int_seq_free(krypt_instream *in);

static krypt_instream_interface krypt_interface_seq = {
    KRYPT_INSTREAM_TYPE_SEQ,
    int_seq_read,
    NULL,
    NULL,
    int_seq_seek,
    int_seq_mark,
    int_seq_free
};

krypt_instream *
krypt_instream_new_seq(krypt_instream *in1, krypt_instream *in2)
{
    return krypt_instream_new_seq_n(2, in1, in2);
}

krypt_instream *
krypt_instream_new_seq_n(int num, krypt_instream *in1, krypt_instream *in2, ...)
{
    krypt_instream_seq *in;
    va_list args;
    int i = 0;

    if (num < 2) {
	krypt_error_add("At least two streams must be passed");
	return NULL;
    }

    in = int_seq_alloc();
    in->streams = ALLOC_N(krypt_instream *, num);
    in->streams[i++] = in1;
    in->streams[i++] = in2;
    va_start(args, in2);

    while (i < num) {
	in->streams[i++] = va_arg(args, krypt_instream *);
    }

    va_end(args);
    in->num = num;
    in->i = 0;
    in->active = in1;
    return (krypt_instream *) in;
}

static krypt_instream_seq*
int_seq_alloc(void)
{
    krypt_instream_seq *ret;
    ret = ALLOC(krypt_instream_seq);
    memset(ret, 0, sizeof(krypt_instream_seq));
    ret->methods = &krypt_interface_seq;
    return ret;
}

static ssize_t
int_do_read(krypt_instream_seq *in, uint8_t *buf, size_t len)
{
    ssize_t read = 0;
    size_t total = 0;

    while (total < len && ((read = krypt_instream_read(in->active, buf, len - total)) >= 0)) {
	total += read;
	buf += read;
    }

    if (read < -1) return -2;
    if (total == 0) return -1;
    return total;
}

static ssize_t
int_seq_read(krypt_instream *instream, uint8_t *buf, size_t len)
{
    ssize_t read;
    krypt_instream_seq *in;
    size_t total = 0;

    int_safe_cast(in, instream);

    if (!buf) return -2;

    while (total < len) {
    	read = int_do_read(in, buf, len - total);
	if (read < -1) return -2;
	if (read == -1) {
	    in->i++;
	    if (in->i == in->num) {
		return -1;
	    }
	    else {
		in->active = in->streams[in->i];
	    }
	}
	else {
	    total += read;
	    buf += read;
	}
    }

    return total;
}

static int
int_seq_seek(krypt_instream *instream, off_t offset, int whence)
{
    krypt_instream_seq *in;

    int_safe_cast(in, instream);
    return krypt_instream_seek(in->active, offset, whence);
}

static void
int_seq_mark(krypt_instream *instream)
{
    krypt_instream_seq *in;
    int i;

    if (!instream) return;
    int_safe_cast(in, instream);

    for(i=0; i < in->num; i++) {
	krypt_instream_mark(in->streams[i]);
    }
}

static void
int_seq_free(krypt_instream *instream)
{
    krypt_instream_seq *in;
    int i;

    if (!instream) return;
    int_safe_cast(in, instream);

    for(i=0; i < in->num; i++) {
	krypt_instream_free(in->streams[i]);
    }
    xfree(in->streams);
}

