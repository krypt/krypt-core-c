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

typedef struct krypt_instream_fd_st {
    krypt_instream_interface *methods;
    int fd;
} krypt_instream_fd;

#define int_safe_cast(out, in)	krypt_safe_cast_instream((out), (in), KRYPT_INSTREAM_TYPE_FD, krypt_instream_fd)
    
static krypt_instream_fd *int_fd_alloc(void);
static ssize_t int_fd_read(krypt_instream *in, uint8_t *buf, size_t len);
static ssize_t int_fd_gets(krypt_instream *in, char *line, size_t len);
static int int_fd_seek(krypt_instream *in, off_t offset, int whence);
static void int_fd_free(krypt_instream *in);

static krypt_instream_interface krypt_interface_fd = {
    KRYPT_INSTREAM_TYPE_FD,
    int_fd_read,
    NULL,
    int_fd_gets,
    int_fd_seek,
    NULL,
    int_fd_free
};

krypt_instream *
krypt_instream_new_fd_io(VALUE value)
{
    rb_io_t *fptr;
    GetOpenFile(value, fptr);
    rb_io_check_byte_readable(fptr);
    return krypt_instream_new_fd(fptr->fd);
}

krypt_instream *
krypt_instream_new_fd(int fd)
{
    krypt_instream_fd *in;

    in = int_fd_alloc();
    in->fd = fd;
    return (krypt_instream *) in;
}

static krypt_instream_fd*
int_fd_alloc(void)
{
    krypt_instream_fd *ret;
    ret = ALLOC(krypt_instream_fd);
    memset(ret, 0, sizeof(krypt_instream_fd));
    ret->methods = &krypt_interface_fd;
    return ret;
}

static ssize_t
int_fd_read(krypt_instream *instream, uint8_t *buf, size_t len)
{
    int fd;
    ssize_t r;
    krypt_instream_fd *in;

    int_safe_cast(in, instream);
    if (!buf) return -2;

    fd = in->fd;
    krypt_clear_sys_error();
    r = read(fd, buf, len);
    
    if (r == -1) {
	krypt_add_io_error();
	return -2;
    }
    else if (r == 0) {
	return -1;
    }
    else {
    	return r;
    }
}

static ssize_t
int_fd_gets(krypt_instream *instream, char *line, size_t len)
{
    int fd;
    krypt_instream_fd *in;
    ssize_t ret = 0, r = 0;
    char *p = line;
    char *end = line + len;

    int_safe_cast(in, instream);
    if (!line) return -2;

    fd = in->fd;
    krypt_clear_sys_error();

    while ( (p < end) &&
	    ((r = read(fd, p, 1)) == 1) &&
	    (*p != '\n') ) {
	    p++;
	    ret++;
    }

    if (r == -1) {
	return -2;
    }
    
    if (ret == 0 && r == 0)
	return -1;

    if (*p == '\n' && *(p - 1) == '\r')
	ret--;

    return ret;
}

static int
int_fd_seek(krypt_instream *instream, off_t offset, int whence)
{
    int fd;
    long off;
    krypt_instream_fd *in;

    int_safe_cast(in, instream);
    fd = in->fd;
    off = lseek(fd, offset, whence);

    if (off == -1) 
	return 0;
    return 1;
}

static void
int_fd_free(krypt_instream *instream)
{
    /* do not close the fd, should be done explicitly */
}

