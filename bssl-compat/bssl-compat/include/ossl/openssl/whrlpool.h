/*
 * Copyright 2005-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_WHRLPOOL_H
# define ossl_OPENSSL_WHRLPOOL_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_WHRLPOOL_H
# endif

# include "ossl/openssl/opensslconf.h"

# ifndef ossl_OPENSSL_NO_WHIRLPOOL
#  include "ossl/openssl/e_os2.h"
#  include <stddef.h>
#  ifdef __cplusplus
extern "C" {
#  endif

#  define ossl_WHIRLPOOL_DIGEST_LENGTH (512/8)

#  if !defined(ossl_OPENSSL_NO_DEPRECATED_3_0)

#   define ossl_WHIRLPOOL_BBLOCK        512
#   define ossl_WHIRLPOOL_COUNTER       (256/8)

typedef struct {
    union {
        unsigned char c[ossl_WHIRLPOOL_DIGEST_LENGTH];
        /* double q is here to ensure 64-bit alignment */
        double q[ossl_WHIRLPOOL_DIGEST_LENGTH / sizeof(double)];
    } H;
    unsigned char data[ossl_WHIRLPOOL_BBLOCK / 8];
    unsigned int bitoff;
    size_t bitlen[ossl_WHIRLPOOL_COUNTER / sizeof(size_t)];
} ossl_WHIRLPOOL_CTX;
#  endif
#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_WHIRLPOOL_Init(ossl_WHIRLPOOL_CTX *c);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_WHIRLPOOL_Update(ossl_WHIRLPOOL_CTX *c,
                                           const void *inp, size_t bytes);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_WHIRLPOOL_BitUpdate(ossl_WHIRLPOOL_CTX *c,
                                               const void *inp, size_t bits);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_WHIRLPOOL_Final(unsigned char *md, ossl_WHIRLPOOL_CTX *c);
ossl_OSSL_DEPRECATEDIN_3_0 unsigned char *ossl_WHIRLPOOL(const void *inp, size_t bytes,
                                               unsigned char *md);
#  endif

#  ifdef __cplusplus
}
#  endif
# endif

#endif
