/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_HMAC_H
# define ossl_OPENSSL_HMAC_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_HMAC_H
# endif

# include "ossl/openssl/opensslconf.h"

# include "ossl/openssl/evp.h"

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HMAC_MAX_MD_CBLOCK      200    /* Deprecated */
# endif

# ifdef  __cplusplus
extern "C" {
# endif

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 size_t ossl_HMAC_size(const ossl_HMAC_CTX *e);
ossl_OSSL_DEPRECATEDIN_3_0 ossl_HMAC_CTX *ossl_HMAC_CTX_new(void);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_HMAC_CTX_reset(ossl_HMAC_CTX *ctx);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_HMAC_CTX_free(ossl_HMAC_CTX *ctx);
# endif
# ifndef ossl_OPENSSL_NO_DEPRECATED_1_1_0
ossl_OSSL_DEPRECATEDIN_1_1_0 ossl___owur int ossl_HMAC_Init(ossl_HMAC_CTX *ctx,
                                             const void *key, int len,
                                             const ossl_EVP_MD *md);
# endif
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_HMAC_Init_ex(ossl_HMAC_CTX *ctx, const void *key, int len,
                                       const ossl_EVP_MD *md, ossl_ENGINE *impl);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_HMAC_Update(ossl_HMAC_CTX *ctx, const unsigned char *data,
                                      size_t len);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_HMAC_Final(ossl_HMAC_CTX *ctx, unsigned char *md,
                                     unsigned int *len);
ossl_OSSL_DEPRECATEDIN_3_0 ossl___owur int ossl_HMAC_CTX_copy(ossl_HMAC_CTX *dctx, ossl_HMAC_CTX *sctx);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_HMAC_CTX_set_flags(ossl_HMAC_CTX *ctx, unsigned long flags);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_EVP_MD *ossl_HMAC_CTX_get_md(const ossl_HMAC_CTX *ctx);
# endif

unsigned char *ossl_HMAC(const ossl_EVP_MD *evp_md, const void *key, int key_len,
                    const unsigned char *data, size_t data_len,
                    unsigned char *md, unsigned int *md_len);

# ifdef  __cplusplus
}
# endif

#endif
