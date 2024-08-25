/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_SHA_H
# define ossl_OPENSSL_SHA_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_SHA_H
# endif

# include "ossl/openssl/e_os2.h"
# include <stddef.h>

# ifdef  __cplusplus
extern "C" {
# endif

# define ossl_SHA_DIGEST_LENGTH 20

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
/*-
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! ossl_SHA_LONG has to be at least 32 bits wide.                    !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */
#  define ossl_SHA_LONG unsigned int

#  define ossl_SHA_LBLOCK      16
#  define ossl_SHA_CBLOCK      (ossl_SHA_LBLOCK*4)/* SHA treats input data as a
                                         * contiguous array of 32 bit wide
                                         * big-endian values. */
#  define ossl_SHA_LAST_BLOCK  (ossl_SHA_CBLOCK-8)

typedef struct ossl_SHAstate_st {
    ossl_SHA_LONG h0, h1, h2, h3, h4;
    ossl_SHA_LONG Nl, Nh;
    ossl_SHA_LONG data[ossl_SHA_LBLOCK];
    unsigned int num;
} ossl_SHA_CTX;

ossl_OSSL_DEPRECATEDIN_3_0 int ossl_SHA1_Init(ossl_SHA_CTX *c);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_SHA1_Update(ossl_SHA_CTX *c, const void *data, size_t len);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_SHA1_Final(unsigned char *md, ossl_SHA_CTX *c);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_SHA1_Transform(ossl_SHA_CTX *c, const unsigned char *data);
# endif

unsigned char *ossl_SHA1(const unsigned char *d, size_t n, unsigned char *md);

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_SHA256_CBLOCK   (ossl_SHA_LBLOCK*4)/* SHA-256 treats input data as a
                                        * contiguous array of 32 bit wide
                                        * big-endian values. */

typedef struct ossl_SHA256state_st {
    ossl_SHA_LONG h[8];
    ossl_SHA_LONG Nl, Nh;
    ossl_SHA_LONG data[ossl_SHA_LBLOCK];
    unsigned int num, md_len;
} ossl_SHA256_CTX;

ossl_OSSL_DEPRECATEDIN_3_0 int ossl_SHA224_Init(ossl_SHA256_CTX *c);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_SHA224_Update(ossl_SHA256_CTX *c,
                                        const void *data, size_t len);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_SHA224_Final(unsigned char *md, ossl_SHA256_CTX *c);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_SHA256_Init(ossl_SHA256_CTX *c);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_SHA256_Update(ossl_SHA256_CTX *c,
                                        const void *data, size_t len);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_SHA256_Final(unsigned char *md, ossl_SHA256_CTX *c);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_SHA256_Transform(ossl_SHA256_CTX *c,
                                            const unsigned char *data);
# endif

unsigned char *ossl_SHA224(const unsigned char *d, size_t n, unsigned char *md);
unsigned char *ossl_SHA256(const unsigned char *d, size_t n, unsigned char *md);

# define ossl_SHA224_DIGEST_LENGTH    28
# define ossl_SHA256_DIGEST_LENGTH    32
# define ossl_SHA384_DIGEST_LENGTH    48
# define ossl_SHA512_DIGEST_LENGTH    64

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
/*
 * Unlike 32-bit digest algorithms, SHA-512 *relies* on ossl_SHA_LONG64
 * being exactly 64-bit wide. See Implementation Notes in sha512.c
 * for further details.
 */
/*
 * SHA-512 treats input data as a
 * contiguous array of 64 bit
 * wide big-endian values.
 */
#  define ossl_SHA512_CBLOCK   (ossl_SHA_LBLOCK*8)
#  if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
#   define ossl_SHA_LONG64 unsigned __int64
#  elif defined(__arch64__)
#   define ossl_SHA_LONG64 unsigned long
#  else
#   define ossl_SHA_LONG64 unsigned long long
#  endif

typedef struct ossl_SHA512state_st {
    ossl_SHA_LONG64 h[8];
    ossl_SHA_LONG64 Nl, Nh;
    union {
        ossl_SHA_LONG64 d[ossl_SHA_LBLOCK];
        unsigned char p[ossl_SHA512_CBLOCK];
    } u;
    unsigned int num, md_len;
} ossl_SHA512_CTX;

ossl_OSSL_DEPRECATEDIN_3_0 int ossl_SHA384_Init(ossl_SHA512_CTX *c);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_SHA384_Update(ossl_SHA512_CTX *c,
                                        const void *data, size_t len);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_SHA384_Final(unsigned char *md, ossl_SHA512_CTX *c);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_SHA512_Init(ossl_SHA512_CTX *c);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_SHA512_Update(ossl_SHA512_CTX *c,
                                        const void *data, size_t len);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_SHA512_Final(unsigned char *md, ossl_SHA512_CTX *c);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_SHA512_Transform(ossl_SHA512_CTX *c,
                                            const unsigned char *data);
# endif

unsigned char *ossl_SHA384(const unsigned char *d, size_t n, unsigned char *md);
unsigned char *ossl_SHA512(const unsigned char *d, size_t n, unsigned char *md);

# ifdef  __cplusplus
}
# endif

#endif
