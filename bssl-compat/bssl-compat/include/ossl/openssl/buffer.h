/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_BUFFER_H
# define ossl_OPENSSL_BUFFER_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_BUFFER_H
# endif

# include "ossl/openssl/types.h"
# ifndef ossl_OPENSSL_CRYPTO_H
#  include "ossl/openssl/crypto.h"
# endif
# include "ossl/openssl/buffererr.h"


#ifdef  __cplusplus
extern "C" {
#endif

# include <stddef.h>
# include <sys/types.h>

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_BUF_strdup(s) ossl_OPENSSL_strdup(s)
#  define ossl_BUF_strndup(s, size) ossl_OPENSSL_strndup(s, size)
#  define ossl_BUF_memdup(data, size) ossl_OPENSSL_memdup(data, size)
#  define ossl_BUF_strlcpy(dst, src, size)  ossl_OPENSSL_strlcpy(dst, src, size)
#  define ossl_BUF_strlcat(dst, src, size) ossl_OPENSSL_strlcat(dst, src, size)
#  define ossl_BUF_strnlen(str, maxlen) ossl_OPENSSL_strnlen(str, maxlen)
# endif

struct ossl_buf_mem_st {
    size_t length;              /* current number of bytes */
    char *data;
    size_t max;                 /* size of buffer */
    unsigned long flags;
};

# define ossl_BUF_MEM_FLAG_SECURE  0x01

ossl_BUF_MEM *ossl_BUF_MEM_new(void);
ossl_BUF_MEM *ossl_BUF_MEM_new_ex(unsigned long flags);
void ossl_BUF_MEM_free(ossl_BUF_MEM *a);
size_t ossl_BUF_MEM_grow(ossl_BUF_MEM *str, size_t len);
size_t ossl_BUF_MEM_grow_clean(ossl_BUF_MEM *str, size_t len);
void ossl_BUF_reverse(unsigned char *out, const unsigned char *in, size_t siz);


# ifdef  __cplusplus
}
# endif
#endif
