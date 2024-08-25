/*
 * Copyright 2002-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_AES_H
# define ossl_OPENSSL_AES_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_AES_H
# endif

# include "ossl/openssl/opensslconf.h"

# include <stddef.h>
# ifdef  __cplusplus
extern "C" {
# endif

# define ossl_AES_BLOCK_SIZE 16

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0

#  define ossl_AES_ENCRYPT     1
#  define ossl_AES_DECRYPT     0

#  define ossl_AES_MAXNR 14


/* This should be a hidden type, but EVP requires that the size be known */
struct ossl_aes_key_st {
#  ifdef ossl_AES_LONG
    unsigned long rd_key[4 * (ossl_AES_MAXNR + 1)];
#  else
    unsigned int rd_key[4 * (ossl_AES_MAXNR + 1)];
#  endif
    int rounds;
};
typedef struct ossl_aes_key_st ossl_AES_KEY;

# endif
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 const char *ossl_AES_options(void);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_AES_set_encrypt_key(const unsigned char *userKey, const int bits,
                        ossl_AES_KEY *key);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_AES_set_decrypt_key(const unsigned char *userKey, const int bits,
                        ossl_AES_KEY *key);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_AES_encrypt(const unsigned char *in, unsigned char *out,
                 const ossl_AES_KEY *key);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_AES_decrypt(const unsigned char *in, unsigned char *out,
                 const ossl_AES_KEY *key);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_AES_ecb_encrypt(const unsigned char *in, unsigned char *out,
                     const ossl_AES_KEY *key, const int enc);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
                     size_t length, const ossl_AES_KEY *key,
                     unsigned char *ivec, const int enc);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_AES_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                        size_t length, const ossl_AES_KEY *key,
                        unsigned char *ivec, int *num, const int enc);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_AES_cfb1_encrypt(const unsigned char *in, unsigned char *out,
                      size_t length, const ossl_AES_KEY *key,
                      unsigned char *ivec, int *num, const int enc);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_AES_cfb8_encrypt(const unsigned char *in, unsigned char *out,
                      size_t length, const ossl_AES_KEY *key,
                      unsigned char *ivec, int *num, const int enc);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_AES_ofb128_encrypt(const unsigned char *in, unsigned char *out,
                        size_t length, const ossl_AES_KEY *key,
                        unsigned char *ivec, int *num);

/* NB: the IV is _two_ blocks long */
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_AES_ige_encrypt(const unsigned char *in, unsigned char *out,
                     size_t length, const ossl_AES_KEY *key,
                     unsigned char *ivec, const int enc);
/* NB: the IV is _four_ blocks long */
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_AES_bi_ige_encrypt(const unsigned char *in, unsigned char *out,
                        size_t length, const ossl_AES_KEY *key, const ossl_AES_KEY *key2,
                        const unsigned char *ivec, const int enc);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_AES_wrap_key(ossl_AES_KEY *key, const unsigned char *iv,
                 unsigned char *out, const unsigned char *in,
                 unsigned int inlen);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_AES_unwrap_key(ossl_AES_KEY *key, const unsigned char *iv,
                   unsigned char *out, const unsigned char *in,
                   unsigned int inlen);
# endif


# ifdef  __cplusplus
}
# endif

#endif
