/*
* binyo - Fast binary IO for Ruby
*
* Copyright (C) 2012
* Martin Bosslet <martin.bosslet@googlemail.com>
* All rights reserved.
*
* See the file 'LICENSE' for further details about licensing.
*/

#if !defined(_BINYO_IO_H_)
#define _BINYO_IO_H_

#include "binyo-io-buffer.h"

extern ID sBinyo_ID_READ, sBinyo_ID_SEEK, sBinyo_ID_WRITE, sBinyo_ID_CLOSE;

extern VALUE sBinyo_ID_SEEK_CUR, sBinyo_ID_SEEK_SET, sBinyo_ID_SEEK_END;

#define BINYO_IO_BUF_SIZE 8192

#define BINYO_INSTREAM_TYPE_FD         	0
#define BINYO_INSTREAM_TYPE_BYTES      	1
#define BINYO_INSTREAM_TYPE_IO_GENERIC 	2
#define BINYO_INSTREAM_TYPE_SEQ		3
#define BINYO_INSTREAM_TYPE_CACHE	4

#define BINYO_OUTSTREAM_TYPE_FD         10
#define BINYO_OUTSTREAM_TYPE_BYTES      11
#define BINYO_OUTSTREAM_TYPE_IO_GENERIC 12

typedef struct binyo_instream_interface_st binyo_instream_interface;
typedef struct binyo_outstream_interface_st binyo_outstream_interface;

typedef struct binyo_instream_st {
   binyo_instream_interface *methods;
} binyo_instream;

typedef struct binyo_out_stream_st {
   binyo_outstream_interface *methods;
} binyo_outstream;

struct binyo_instream_interface_st {
    int type;

    ssize_t (*read)(binyo_instream*, uint8_t*, size_t);
    int (*rb_read)(binyo_instream*, VALUE, VALUE, VALUE*);
    ssize_t (*gets)(binyo_instream*, char *, size_t);
    int (*seek)(binyo_instream*, off_t, int); 
    void (*mark)(binyo_instream*);
    void (*free)(binyo_instream*);
};

struct binyo_outstream_interface_st {
    int type;

    ssize_t (*write)(binyo_outstream*, uint8_t *buf, size_t);
    int (*rb_write)(binyo_outstream*, VALUE, VALUE*);
    void (*mark)(binyo_outstream*);
    void (*free)(binyo_outstream*);
};

#ifdef _WIN32
#define binyo_last_sys_error()	GetLastError()
#define binyo_clear_sys_error()	SetLastError(0)
#else
#define binyo_last_sys_error()	errno
#define binyo_clear_sys_error()	errno=0
#endif

#define binyo_safe_cast_stream(out, in, t, ptype, stype)	        \
    do {	                					\
        if (!(in))		                       			\
            rb_raise(rb_eRuntimeError, "Uninitialized stream.");     	\
        if (((stype *) (in))->methods->type == (t)) {  	       	    	\
            out = (ptype *) in;		   	                       	\
        }                                                       	\
        else {                                                  	\
	    int errt = ((stype *) (in))->methods->type;			\
            rb_raise(rb_eArgError, "Unknown type: %d", errt);		\
        }                                                       	\
    } while (0)					                	\

#define binyo_safe_cast_outstream(out, in, type, ptrtype)	binyo_safe_cast_stream((out), (in), (type), ptrtype, binyo_outstream)
#define binyo_safe_cast_instream(out, in, type, ptrtype)	binyo_safe_cast_stream((out), (in), (type), ptrtype, binyo_instream)

void binyo_add_io_error(void);

ssize_t binyo_instream_read(binyo_instream *in, uint8_t *buf, size_t len);
int binyo_instream_rb_read(binyo_instream *in, VALUE vlen, VALUE vbuf, VALUE *out);
ssize_t binyo_instream_gets(binyo_instream *in, char *line, size_t len);
int binyo_instream_seek(binyo_instream *in, off_t offset, int whence);
#define binyo_instream_skip(in, n)	binyo_instream_seek((in), (n), SEEK_CUR)
void binyo_instream_mark(binyo_instream *in);
void binyo_instream_free(binyo_instream *in);

binyo_instream *binyo_instream_new_fd(int fd);
binyo_instream *binyo_instream_new_fd_io(VALUE io);
binyo_instream *binyo_instream_new_bytes(uint8_t *bytes, size_t len);
binyo_instream *binyo_instream_new_io_generic(VALUE io);
binyo_instream *binyo_instream_new_value(VALUE value);
binyo_instream *binyo_instream_new_seq(binyo_instream *in1, binyo_instream *in2);
binyo_instream *binyo_instream_new_seq_n(int num, binyo_instream *in1, binyo_instream *in2, ...);
binyo_instream *binyo_instream_new_cache(binyo_instream *original);
void binyo_instream_cache_free_wrapper(binyo_instream *instream);
size_t binyo_instream_cache_get_bytes(binyo_instream *in, uint8_t **out);

ssize_t binyo_outstream_write(binyo_outstream *out, uint8_t *buf, size_t len);
int binyo_outstream_rb_write(binyo_outstream *out, VALUE vbuf, VALUE *ret);
void binyo_outstream_mark(binyo_outstream *in);
void binyo_outstream_free(binyo_outstream *out);

size_t binyo_outstream_bytes_get_bytes_free(binyo_outstream *outstream, uint8_t **bytes);
VALUE binyo_outstream_string_build(binyo_outstream *outstream);

binyo_outstream *binyo_outstream_new_fd(int fd);
binyo_outstream *binyo_outstream_new_fd_io(VALUE io);
binyo_outstream *binyo_outstream_new_bytes(void);
binyo_outstream *binyo_outstream_new_bytes_size(size_t size);
binyo_outstream *binyo_outstream_new_bytes_prealloc(uint8_t *b, size_t len);
binyo_outstream *binyo_outstream_new_io_generic(VALUE io);
binyo_outstream *binyo_outstream_new_value(VALUE value);
binyo_outstream *binyo_outstream_new_string(void);
binyo_outstream *binyo_outstream_new_string_size(size_t size);

#endif /* _BINYO_IO_H_ */

