/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_RIPEMD_H
# define ossl_OPENSSL_RIPEMD_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_RIPEMD_H
# endif

# include "ossl/openssl/opensslconf.h"

# ifndef ossl_OPENSSL_NO_RMD160
#  include "ossl/openssl/e_os2.h"
#  include <stddef.h>

#  define ossl_RIPEMD160_DIGEST_LENGTH 20

#  ifdef  __cplusplus
extern "C" {
#  endif
#  if !defined(ossl_OPENSSL_NO_DEPRECATED_3_0)

#   define ossl_RIPEMD160_LONG unsigned int

#   define ossl_RIPEMD160_CBLOCK        64
#   define ossl_RIPEMD160_LBLOCK        (ossl_RIPEMD160_CBLOCK/4)

typedef struct ossl_RIPEMD160state_st {
    ossl_RIPEMD160_LONG A, B, C, D, E;
    ossl_RIPEMD160_LONG Nl, Nh;
    ossl_RIPEMD160_LONG data[ossl_RIPEMD160_LBLOCK];
    unsigned int num;
} ossl_RIPEMD160_CTX;
#  endif
#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RIPEMD160_Init(ossl_RIPEMD160_CTX *c);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RIPEMD160_Update(ossl_RIPEMD160_CTX *c, const void *data,
                                           size_t len);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RIPEMD160_Final(unsigned char *md, ossl_RIPEMD160_CTX *c);
ossl_OSSL_DEPRECATEDIN_3_0 unsigned char *ossl_RIPEMD160(const unsigned char *d, size_t n,
                                               unsigned char *md);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_RIPEMD160_Transform(ossl_RIPEMD160_CTX *c,
                                               const unsigned char *b);
#  endif

#  ifdef  __cplusplus
}
#  endif
# endif
#endif
