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
#include <stdarg.h>

typedef struct krypt_err_stack_elem_st krypt_err_stack_elem;

typedef struct krypt_err_stack_st {
    int count;
    krypt_err_stack_elem *head;
} krypt_err_stack;

struct krypt_err_stack_elem_st {
    char *message;
    size_t len;
    krypt_err_stack_elem *prev;
};

static krypt_err_stack err_stack = { 0 };

#define int_err_stack_empty()	(err_stack.count == 0)

static void
int_err_stack_push(char *message, size_t len)
{
    krypt_err_stack_elem *elem;

    elem = ALLOC(krypt_err_stack_elem);
    elem->message = message;
    elem->len = len;
    elem->prev = err_stack.head;
    err_stack.head = elem;
    err_stack.count++;
}

static char *
int_err_stack_pop()
{
    char *message;
    krypt_err_stack_elem *head = err_stack.head;

    if (!head) return NULL;

    err_stack.head = head->prev;
    message = head->message;
    xfree(head);
    err_stack.count--;
    return message;
}

int
krypt_has_errors(void)
{
    return !int_err_stack_empty();
}

int
krypt_error_message(char *buf, int buf_len)
{
    krypt_err_stack_elem *head = err_stack.head;
    int len = 0;

    while (head) {
	int cur_len;
	char *message = head->message;
	cur_len = snprintf(buf + len, buf_len, "%s%s", (len ? ": " : ""), message);
	if (cur_len > 0)
	    len += cur_len;
	head = head->prev;
    }

    return len;
}

void
krypt_error_add(const char *format, ...)
{
    char *buf;
    int len = 0;
    va_list args;

    va_start(args, format);
    buf = ALLOC_N(char, BUFSIZ);
    if ((len = vsnprintf(buf, BUFSIZ, format, args)) < 0) return;
    int_err_stack_push(buf, len);
    va_end(args);
}

static int
int_add_binyo_errors(char *buf, int len)
{
    int l = 0;

    if (binyo_has_errors()) {
	int cur_len;
	if ((cur_len = snprintf(buf + l, len, "%s", ": ")) > 0)
	    l += cur_len;
       	if ((cur_len = binyo_error_message(buf + l, len)) > 0)
	    l += cur_len;
    }

    return l;
}

static int
int_error_msg_create(char *buf, int len, const char *format, va_list args)
{
    int l;

    if ((l = vsnprintf(buf, len, format, args)) < 0) {
	return -1;
    }

    while (!int_err_stack_empty()) {
	int cur_len;
	char *message = int_err_stack_pop();
	cur_len = snprintf(buf + l, len, "%s%s", (l ? ": " : ""), message);
	xfree(message);
	if (cur_len > 0)
	    l += cur_len;
    }

    l += int_add_binyo_errors(buf + l, len);
    binyo_error_clear();

    return l;
}

static VALUE
int_error_create(VALUE exception_class, const char *format, va_list args)
{
    char buf[BUFSIZ];
    int len = 0;

    if ((len = int_error_msg_create(buf, BUFSIZ, format, args)) < 0) {
	return rb_funcall(exception_class, rb_intern("new"), 0);
    }

    return rb_exc_new(exception_class, buf, len);
}

static VALUE
int_error_enhance(VALUE exception_class, VALUE active_exc, const char *format, va_list args)
{
    char buf[BUFSIZ];
    int len;
    VALUE orig_msg;
    long orig_len;
    const char *active_name = rb_class2name(CLASS_OF(active_exc));
    size_t active_name_len = strlen(active_name);

    if ((len = int_error_msg_create(buf, BUFSIZ, format, args)) < 0) {
	return active_exc;
    }

    orig_msg = rb_funcall(active_exc, rb_intern("message"), 0);
    StringValueCStr(orig_msg);
    orig_len = RSTRING_LEN(orig_msg);
    if (len <= BUFSIZ - ( (int) active_name_len ) - orig_len - 4) {
	strcat(buf, ": ");
	strcat(buf, active_name);
	strcat(buf, ": ");
	strcat(buf, RSTRING_PTR(orig_msg));
	len += active_name_len + orig_len + 4;
    }

    return rb_exc_new(exception_class, buf, len);
}

void
krypt_error_raise(VALUE exception_class, const char *format, ...)
{
    VALUE exc;
    VALUE active_exc;
    va_list args;

    va_start(args, format);
    active_exc = rb_errinfo();
    if (NIL_P(active_exc)) {
	exc = int_error_create(exception_class, format, args);
    } else {
	exc = int_error_enhance(exception_class, active_exc, format, args);
    }
    va_end(args);
    rb_exc_raise(exc);
}

void
krypt_error_clear(void)
{
    while (!int_err_stack_empty()) {
	xfree(int_err_stack_pop());
    }
}

