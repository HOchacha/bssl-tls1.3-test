/*
 * Copyright 2006-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_CAMELLIA_H
# define ossl_OPENSSL_CAMELLIA_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_CAMELLIA_H
# endif

# include "ossl/openssl/opensslconf.h"

# ifndef ossl_OPENSSL_NO_CAMELLIA
# include <stddef.h>
#ifdef  __cplusplus
extern "C" {
#endif

# define ossl_CAMELLIA_BLOCK_SIZE 16

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0

#  define ossl_CAMELLIA_ENCRYPT        1
#  define ossl_CAMELLIA_DECRYPT        0

/*
 * Because array size can't be a const in C, the following two are macros.
 * Both sizes are in bytes.
 */

/* This should be a hidden type, but EVP requires that the size be known */

#  define ossl_CAMELLIA_TABLE_BYTE_LEN 272
#  define ossl_CAMELLIA_TABLE_WORD_LEN (ossl_CAMELLIA_TABLE_BYTE_LEN / 4)

typedef unsigned int ossl_KEY_TABLE_TYPE[ossl_CAMELLIA_TABLE_WORD_LEN]; /* to match
                                                               * with WORD */

struct ossl_camellia_key_st {
    union {
        double d;               /* ensures 64-bit align */
        ossl_KEY_TABLE_TYPE rd_key;
    } u;
    int grand_rounds;
};
typedef struct ossl_camellia_key_st ossl_CAMELLIA_KEY;

# endif /* ossl_OPENSSL_NO_DEPRECATED_3_0 */
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_Camellia_set_key(const unsigned char *userKey,
                                           const int bits,
                                           ossl_CAMELLIA_KEY *key);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_Camellia_encrypt(const unsigned char *in,
                                            unsigned char *out,
                                            const ossl_CAMELLIA_KEY *key);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_Camellia_decrypt(const unsigned char *in,
                                            unsigned char *out,
                                            const ossl_CAMELLIA_KEY *key);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_Camellia_ecb_encrypt(const unsigned char *in,
                                                unsigned char *out,
                                                const ossl_CAMELLIA_KEY *key,
                                                const int enc);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_Camellia_cbc_encrypt(const unsigned char *in,
                                                unsigned char *out,
                                                size_t length,
                                                const ossl_CAMELLIA_KEY *key,
                                                unsigned char *ivec,
                                                const int enc);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_Camellia_cfb128_encrypt(const unsigned char *in,
                                                   unsigned char *out,
                                                   size_t length,
                                                   const ossl_CAMELLIA_KEY *key,
                                                   unsigned char *ivec,
                                                   int *num,
                                                   const int enc);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_Camellia_cfb1_encrypt(const unsigned char *in,
                                                 unsigned char *out,
                                                 size_t length,
                                                 const ossl_CAMELLIA_KEY *key,
                                                 unsigned char *ivec,
                                                 int *num,
                                                 const int enc);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_Camellia_cfb8_encrypt(const unsigned char *in,
                                                 unsigned char *out,
                                                 size_t length,
                                                 const ossl_CAMELLIA_KEY *key,
                                                 unsigned char *ivec,
                                                 int *num,
                                                 const int enc);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_Camellia_ofb128_encrypt(const unsigned char *in,
                                                   unsigned char *out,
                                                   size_t length,
                                                   const ossl_CAMELLIA_KEY *key,
                                                   unsigned char *ivec,
                                                   int *num);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_Camellia_ctr128_encrypt(const unsigned char *in, unsigned char *out,
                             size_t length, const ossl_CAMELLIA_KEY *key,
                             unsigned char ivec[ossl_CAMELLIA_BLOCK_SIZE],
                             unsigned char ecount_buf[ossl_CAMELLIA_BLOCK_SIZE],
                             unsigned int *num);
# endif

# ifdef  __cplusplus
}
# endif
# endif

#endif
