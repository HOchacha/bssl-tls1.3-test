/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_BLOWFISH_H
# define ossl_OPENSSL_BLOWFISH_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_BLOWFISH_H
# endif

# include "ossl/openssl/opensslconf.h"

# ifndef ossl_OPENSSL_NO_BF
# include "ossl/openssl/e_os2.h"
# ifdef  __cplusplus
extern "C" {
# endif

# define ossl_BF_BLOCK        8

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0

#  define ossl_BF_ENCRYPT      1
#  define ossl_BF_DECRYPT      0

/*-
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! ossl_BF_LONG has to be at least 32 bits wide.                     !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */
#  define ossl_BF_LONG unsigned int

#  define ossl_BF_ROUNDS       16

typedef struct ossl_bf_key_st {
    ossl_BF_LONG P[ossl_BF_ROUNDS + 2];
    ossl_BF_LONG S[4 * 256];
} ossl_BF_KEY;

# endif /* ossl_OPENSSL_NO_DEPRECATED_3_0 */
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_BF_set_key(ossl_BF_KEY *key, int len,
                                      const unsigned char *data);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_BF_encrypt(ossl_BF_LONG *data, const ossl_BF_KEY *key);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_BF_decrypt(ossl_BF_LONG *data, const ossl_BF_KEY *key);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_BF_ecb_encrypt(const unsigned char *in,
                                          unsigned char *out, const ossl_BF_KEY *key,
                                          int enc);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_BF_cbc_encrypt(const unsigned char *in,
                                          unsigned char *out, long length,
                                          const ossl_BF_KEY *schedule,
                                          unsigned char *ivec, int enc);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_BF_cfb64_encrypt(const unsigned char *in,
                                            unsigned char *out,
                                            long length, const ossl_BF_KEY *schedule,
                                            unsigned char *ivec, int *num,
                                            int enc);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_BF_ofb64_encrypt(const unsigned char *in,
                                            unsigned char *out,
                                            long length, const ossl_BF_KEY *schedule,
                                            unsigned char *ivec, int *num);
ossl_OSSL_DEPRECATEDIN_3_0 const char *ossl_BF_options(void);
# endif

# ifdef  __cplusplus
}
# endif
# endif

#endif
