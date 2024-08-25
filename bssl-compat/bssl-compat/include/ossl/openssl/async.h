/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>

#ifndef ossl_OPENSSL_ASYNC_H
# define ossl_OPENSSL_ASYNC_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_ASYNC_H
# endif

#if defined(_WIN32)
# if defined(BASETYPES) || defined(_WINDEF_H)
/* application has to include <windows.h> to use this */
#define ossl_OSSL_ASYNC_FD       HANDLE
#define ossl_OSSL_BAD_ASYNC_FD   INVALID_HANDLE_VALUE
# endif
#else
#define ossl_OSSL_ASYNC_FD       int
#define ossl_OSSL_BAD_ASYNC_FD   -1
#endif
# include "ossl/openssl/asyncerr.h"


# ifdef  __cplusplus
extern "C" {
# endif

typedef struct ossl_async_job_st ossl_ASYNC_JOB;
typedef struct ossl_async_wait_ctx_st ossl_ASYNC_WAIT_CTX;
typedef int (*ossl_ASYNC_callback_fn)(void *arg);

#define ossl_ASYNC_ERR      0
#define ossl_ASYNC_NO_JOBS  1
#define ossl_ASYNC_PAUSE    2
#define ossl_ASYNC_FINISH   3

#define ossl_ASYNC_STATUS_UNSUPPORTED    0
#define ossl_ASYNC_STATUS_ERR            1
#define ossl_ASYNC_STATUS_OK             2
#define ossl_ASYNC_STATUS_EAGAIN         3

int ossl_ASYNC_init_thread(size_t max_size, size_t init_size);
void ossl_ASYNC_cleanup_thread(void);

#ifdef ossl_OSSL_ASYNC_FD
ossl_ASYNC_WAIT_CTX *ossl_ASYNC_WAIT_CTX_new(void);
void ossl_ASYNC_WAIT_CTX_free(ossl_ASYNC_WAIT_CTX *ctx);
int ossl_ASYNC_WAIT_CTX_set_wait_fd(ossl_ASYNC_WAIT_CTX *ctx, const void *key,
                               ossl_OSSL_ASYNC_FD fd,
                               void *custom_data,
                               void (*cleanup)(ossl_ASYNC_WAIT_CTX *, const void *,
                                               ossl_OSSL_ASYNC_FD, void *));
int ossl_ASYNC_WAIT_CTX_get_fd(ossl_ASYNC_WAIT_CTX *ctx, const void *key,
                        ossl_OSSL_ASYNC_FD *fd, void **custom_data);
int ossl_ASYNC_WAIT_CTX_get_all_fds(ossl_ASYNC_WAIT_CTX *ctx, ossl_OSSL_ASYNC_FD *fd,
                               size_t *numfds);
int ossl_ASYNC_WAIT_CTX_get_callback(ossl_ASYNC_WAIT_CTX *ctx,
                                ossl_ASYNC_callback_fn *callback,
                                void **callback_arg);
int ossl_ASYNC_WAIT_CTX_set_callback(ossl_ASYNC_WAIT_CTX *ctx,
                                ossl_ASYNC_callback_fn callback,
                                void *callback_arg);
int ossl_ASYNC_WAIT_CTX_set_status(ossl_ASYNC_WAIT_CTX *ctx, int status);
int ossl_ASYNC_WAIT_CTX_get_status(ossl_ASYNC_WAIT_CTX *ctx);
int ossl_ASYNC_WAIT_CTX_get_changed_fds(ossl_ASYNC_WAIT_CTX *ctx, ossl_OSSL_ASYNC_FD *addfd,
                                   size_t *numaddfds, ossl_OSSL_ASYNC_FD *delfd,
                                   size_t *numdelfds);
int ossl_ASYNC_WAIT_CTX_clear_fd(ossl_ASYNC_WAIT_CTX *ctx, const void *key);
#endif

int ossl_ASYNC_is_capable(void);

int ossl_ASYNC_start_job(ossl_ASYNC_JOB **job, ossl_ASYNC_WAIT_CTX *ctx, int *ret,
                    int (*func)(void *), void *args, size_t size);
int ossl_ASYNC_pause_job(void);

ossl_ASYNC_JOB *ossl_ASYNC_get_current_job(void);
ossl_ASYNC_WAIT_CTX *ossl_ASYNC_get_wait_ctx(ossl_ASYNC_JOB *job);
void ossl_ASYNC_block_pause(void);
void ossl_ASYNC_unblock_pause(void);


# ifdef  __cplusplus
}
# endif
#endif
