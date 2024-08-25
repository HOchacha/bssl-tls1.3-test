/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_CAST_H
# define ossl_OPENSSL_CAST_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_CAST_H
# endif

# include "ossl/openssl/opensslconf.h"

# ifndef ossl_OPENSSL_NO_CAST
# ifdef  __cplusplus
extern "C" {
# endif

# define ossl_CAST_BLOCK      8
# define ossl_CAST_KEY_LENGTH 16

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0

#  define ossl_CAST_ENCRYPT    1
#  define ossl_CAST_DECRYPT    0

#  define ossl_CAST_LONG unsigned int

typedef struct ossl_cast_key_st {
    ossl_CAST_LONG data[32];
    int short_key;              /* Use reduced rounds for short key */
} ossl_CAST_KEY;

# endif /* ossl_OPENSSL_NO_DEPRECATED_3_0 */
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_CAST_set_key(ossl_CAST_KEY *key, int len, const unsigned char *data);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_CAST_ecb_encrypt(const unsigned char *in, unsigned char *out,
                      const ossl_CAST_KEY *key, int enc);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_CAST_encrypt(ossl_CAST_LONG *data, const ossl_CAST_KEY *key);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_CAST_decrypt(ossl_CAST_LONG *data, const ossl_CAST_KEY *key);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_CAST_cbc_encrypt(const unsigned char *in, unsigned char *out,
                      long length, const ossl_CAST_KEY *ks, unsigned char *iv,
                      int enc);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_CAST_cfb64_encrypt(const unsigned char *in, unsigned char *out,
                        long length, const ossl_CAST_KEY *schedule,
                        unsigned char *ivec, int *num, int enc);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_CAST_ofb64_encrypt(const unsigned char *in, unsigned char *out,
                        long length, const ossl_CAST_KEY *schedule,
                        unsigned char *ivec, int *num);
# endif

# ifdef  __cplusplus
}
# endif
# endif

#endif
