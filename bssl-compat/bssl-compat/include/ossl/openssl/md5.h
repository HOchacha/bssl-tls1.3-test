/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_MD5_H
# define ossl_OPENSSL_MD5_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_MD5_H
# endif

# include "ossl/openssl/opensslconf.h"

# ifndef ossl_OPENSSL_NO_MD5
#  include "ossl/openssl/e_os2.h"
#  include <stddef.h>
#  ifdef  __cplusplus
extern "C" {
#  endif

#  define ossl_MD5_DIGEST_LENGTH 16

#  if !defined(ossl_OPENSSL_NO_DEPRECATED_3_0)
/*
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! ossl_MD5_LONG has to be at least 32 bits wide.                     !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */
#   define ossl_MD5_LONG unsigned int

#   define ossl_MD5_CBLOCK      64
#   define ossl_MD5_LBLOCK      (ossl_MD5_CBLOCK/4)

typedef struct ossl_MD5state_st {
    ossl_MD5_LONG A, B, C, D;
    ossl_MD5_LONG Nl, Nh;
    ossl_MD5_LONG data[ossl_MD5_LBLOCK];
    unsigned int num;
} ossl_MD5_CTX;
#  endif
#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_MD5_Init(ossl_MD5_CTX *c);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_MD5_Update(ossl_MD5_CTX *c, const void *data, size_t len);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_MD5_Final(unsigned char *md, ossl_MD5_CTX *c);
ossl_OSSL_DEPRECATEDIN_3_0 unsigned char *ossl_MD5(const unsigned char *d, size_t n,
                                         unsigned char *md);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_MD5_Transform(ossl_MD5_CTX *c, const unsigned char *b);
#  endif

#  ifdef  __cplusplus
}
#  endif
# endif

#endif
