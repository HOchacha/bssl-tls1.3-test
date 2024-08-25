/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_MD4_H
# define ossl_OPENSSL_MD4_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_MD4_H
# endif

# include "ossl/openssl/opensslconf.h"

# ifndef ossl_OPENSSL_NO_MD4
#  include "ossl/openssl/e_os2.h"
#  include <stddef.h>
#  ifdef  __cplusplus
extern "C" {
#   endif

#  define ossl_MD4_DIGEST_LENGTH 16

#  if !defined(ossl_OPENSSL_NO_DEPRECATED_3_0)

/*-
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! ossl_MD4_LONG has to be at least 32 bits wide.                     !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */
#   define ossl_MD4_LONG unsigned int

#   define ossl_MD4_CBLOCK      64
#   define ossl_MD4_LBLOCK      (ossl_MD4_CBLOCK/4)

typedef struct ossl_MD4state_st {
    ossl_MD4_LONG A, B, C, D;
    ossl_MD4_LONG Nl, Nh;
    ossl_MD4_LONG data[ossl_MD4_LBLOCK];
    unsigned int num;
} ossl_MD4_CTX;
#  endif
#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_MD4_Init(ossl_MD4_CTX *c);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_MD4_Update(ossl_MD4_CTX *c, const void *data, size_t len);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_MD4_Final(unsigned char *md, ossl_MD4_CTX *c);
ossl_OSSL_DEPRECATEDIN_3_0 unsigned char *ossl_MD4(const unsigned char *d, size_t n,
                                         unsigned char *md);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_MD4_Transform(ossl_MD4_CTX *c, const unsigned char *b);
#  endif

#  ifdef  __cplusplus
}
#  endif
# endif

#endif
