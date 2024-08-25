/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_MDC2_H
# define ossl_OPENSSL_MDC2_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_MDC2_H
# endif

# include "ossl/openssl/opensslconf.h"

# ifndef ossl_OPENSSL_NO_MDC2
#  include <stdlib.h>
#  include "ossl/openssl/des.h"
#  ifdef  __cplusplus
extern "C" {
#  endif

#  define ossl_MDC2_DIGEST_LENGTH      16

#  if !defined(ossl_OPENSSL_NO_DEPRECATED_3_0)

#   define ossl_MDC2_BLOCK              8

typedef struct ossl_mdc2_ctx_st {
    unsigned int num;
    unsigned char data[ossl_MDC2_BLOCK];
    ossl_DES_cblock h, hh;
    unsigned int pad_type;   /* either 1 or 2, default 1 */
} ossl_MDC2_CTX;
#  endif
#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_MDC2_Init(ossl_MDC2_CTX *c);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_MDC2_Update(ossl_MDC2_CTX *c, const unsigned char *data,
                                      size_t len);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_MDC2_Final(unsigned char *md, ossl_MDC2_CTX *c);
ossl_OSSL_DEPRECATEDIN_3_0 unsigned char *ossl_MDC2(const unsigned char *d, size_t n,
                                          unsigned char *md);
#  endif

#  ifdef  __cplusplus
}
#  endif
# endif

#endif
