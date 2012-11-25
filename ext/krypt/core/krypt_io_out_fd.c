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

#include <unistd.h>
#include <errno.h>
#include "krypt-core.h"

typedef struct krypt_outstream_fd_st {
    krypt_outstream_interface *methods;
    int fd;
} krypt_outstream_fd;

#define int_safe_cast(out, in)		krypt_safe_cast_outstream((out), (in), KRYPT_OUTSTREAM_TYPE_FD, krypt_outstream_fd)

static krypt_outstream_fd* int_fd_alloc(void);
static ssize_t int_fd_write(krypt_outstream *out, uint8_t *buf, size_t len);
static void int_fd_free(krypt_outstream *out);

static krypt_outstream_interface krypt_interface_fd = {
    KRYPT_OUTSTREAM_TYPE_FD,
    int_fd_write,
    NULL,
    NULL,
    int_fd_free
};

krypt_outstream *
krypt_outstream_new_fd_io(VALUE value)
{
    rb_io_t *fptr;
    GetOpenFile(value, fptr);
    rb_io_check_writable(fptr);
    return krypt_outstream_new_fd(fptr->fd);
}

krypt_outstream *
krypt_outstream_new_fd(int fd)
{
    krypt_outstream_fd *out;

    out = int_fd_alloc();
    out->fd = fd;
    return (krypt_outstream *) out;
}

static krypt_outstream_fd*
int_fd_alloc(void)
{
    krypt_outstream_fd *ret;
    ret = ALLOC(krypt_outstream_fd);
    memset(ret, 0, sizeof(krypt_outstream_fd));
    ret->methods = &krypt_interface_fd;
    return ret;
}

static ssize_t
int_fd_write(krypt_outstream *outstream, uint8_t *buf, size_t len)
{
    int fd;
    ssize_t w;
    krypt_outstream_fd *out;
   
    int_safe_cast(out, outstream); 

    if (!buf) return -1;

    fd = out->fd;
    krypt_clear_sys_error();
    /* no need to increase out->num_written */
    w = write(fd, buf, len);
    
    if (w < 0) {
	krypt_add_io_error();
	return -1;
    }
    else {
    	return w;
    }
}

static void
int_fd_free(krypt_outstream *out)
{
    /* do not close the fd, should be done explicitly */
}

