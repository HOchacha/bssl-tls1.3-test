/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_RC2_H
# define ossl_OPENSSL_RC2_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_RC2_H
# endif

# include "ossl/openssl/opensslconf.h"

# ifndef ossl_OPENSSL_NO_RC2
#  ifdef  __cplusplus
extern "C" {
#  endif

#  define ossl_RC2_BLOCK       8
#  define ossl_RC2_KEY_LENGTH  16

#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
typedef unsigned int ossl_RC2_INT;

#   define ossl_RC2_ENCRYPT     1
#   define ossl_RC2_DECRYPT     0

typedef struct ossl_rc2_key_st {
    ossl_RC2_INT data[64];
} ossl_RC2_KEY;
#  endif
#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_RC2_set_key(ossl_RC2_KEY *key, int len,
                                       const unsigned char *data, int bits);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_RC2_ecb_encrypt(const unsigned char *in,
                                           unsigned char *out, ossl_RC2_KEY *key,
                                           int enc);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_RC2_encrypt(unsigned long *data, ossl_RC2_KEY *key);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_RC2_decrypt(unsigned long *data, ossl_RC2_KEY *key);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_RC2_cbc_encrypt(const unsigned char *in,
                                           unsigned char *out, long length,
                                           ossl_RC2_KEY *ks, unsigned char *iv,
                                           int enc);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_RC2_cfb64_encrypt(const unsigned char *in,
                                             unsigned char *out, long length,
                                             ossl_RC2_KEY *schedule,
                                             unsigned char *ivec,
                                             int *num, int enc);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_RC2_ofb64_encrypt(const unsigned char *in,
                                             unsigned char *out, long length,
                                             ossl_RC2_KEY *schedule,
                                             unsigned char *ivec,
                                             int *num);
#  endif

#  ifdef  __cplusplus
}
#  endif
# endif

#endif
