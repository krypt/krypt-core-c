/*
* binyo - Fast binary IO for Ruby
*
* Copyright (C) 2012
* Martin Bosslet <martin.bosslet@googlemail.com>
* All rights reserved.
*
* See the file 'LICENSE' for further details about licensing.
*/

#ifndef _BINYO_ERROR_H_
#define _BINYO_ERROR_H_

#define BINYO_OK 1
#define BINYO_ERR -1

#define BINYO_IO_EOF -2

int binyo_has_errors(void);
int binyo_error_message(char *buf, int buf_len);
void binyo_error_clear(void);

#endif /* BINYO_ERROR_H */

