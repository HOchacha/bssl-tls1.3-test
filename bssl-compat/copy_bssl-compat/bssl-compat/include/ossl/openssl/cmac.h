/*
 * Copyright 2010-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_CMAC_H
# define ossl_OPENSSL_CMAC_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_CMAC_H
# endif

# ifndef ossl_OPENSSL_NO_CMAC

#  ifdef __cplusplus
extern "C" {
#  endif

#  include "ossl/openssl/evp.h"

#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
/* Opaque */
typedef struct ossl_CMAC_CTX_st ossl_CMAC_CTX;
#  endif
#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 ossl_CMAC_CTX *ossl_CMAC_CTX_new(void);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_CMAC_CTX_cleanup(ossl_CMAC_CTX *ctx);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_CMAC_CTX_free(ossl_CMAC_CTX *ctx);
ossl_OSSL_DEPRECATEDIN_3_0 ossl_EVP_CIPHER_CTX *ossl_CMAC_CTX_get0_cipher_ctx(ossl_CMAC_CTX *ctx);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_CMAC_CTX_copy(ossl_CMAC_CTX *out, const ossl_CMAC_CTX *in);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_CMAC_Init(ossl_CMAC_CTX *ctx,
                                    const void *key, size_t keylen,
                                    const ossl_EVP_CIPHER *cipher, ossl_ENGINE *impl);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_CMAC_Update(ossl_CMAC_CTX *ctx,
                                      const void *data, size_t dlen);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_CMAC_Final(ossl_CMAC_CTX *ctx,
                                     unsigned char *out, size_t *poutlen);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_CMAC_resume(ossl_CMAC_CTX *ctx);
#  endif

#  ifdef  __cplusplus
}
#  endif

# endif
#endif
