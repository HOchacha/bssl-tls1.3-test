/*
 * Copyright 2008-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_MODES_H
# define ossl_OPENSSL_MODES_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_MODES_H
# endif

# include <stddef.h>
# include "ossl/openssl/types.h"

# ifdef  __cplusplus
extern "C" {
# endif
typedef void (*ossl_block128_f) (const unsigned char in[16],
                            unsigned char out[16], const void *key);

typedef void (*ossl_cbc128_f) (const unsigned char *in, unsigned char *out,
                          size_t len, const void *key,
                          unsigned char ivec[16], int enc);

typedef void (*ossl_ecb128_f) (const unsigned char *in, unsigned char *out,
                          size_t len, const void *key,
                          int enc);

typedef void (*ossl_ctr128_f) (const unsigned char *in, unsigned char *out,
                          size_t blocks, const void *key,
                          const unsigned char ivec[16]);

typedef void (*ossl_ccm128_f) (const unsigned char *in, unsigned char *out,
                          size_t blocks, const void *key,
                          const unsigned char ivec[16],
                          unsigned char cmac[16]);

void ossl_CRYPTO_cbc128_encrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key,
                           unsigned char ivec[16], ossl_block128_f block);
void ossl_CRYPTO_cbc128_decrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key,
                           unsigned char ivec[16], ossl_block128_f block);

void ossl_CRYPTO_ctr128_encrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key,
                           unsigned char ivec[16],
                           unsigned char ecount_buf[16], unsigned int *num,
                           ossl_block128_f block);

void ossl_CRYPTO_ctr128_encrypt_ctr32(const unsigned char *in, unsigned char *out,
                                 size_t len, const void *key,
                                 unsigned char ivec[16],
                                 unsigned char ecount_buf[16],
                                 unsigned int *num, ossl_ctr128_f ctr);

void ossl_CRYPTO_ofb128_encrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key,
                           unsigned char ivec[16], int *num,
                           ossl_block128_f block);

void ossl_CRYPTO_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key,
                           unsigned char ivec[16], int *num,
                           int enc, ossl_block128_f block);
void ossl_CRYPTO_cfb128_8_encrypt(const unsigned char *in, unsigned char *out,
                             size_t length, const void *key,
                             unsigned char ivec[16], int *num,
                             int enc, ossl_block128_f block);
void ossl_CRYPTO_cfb128_1_encrypt(const unsigned char *in, unsigned char *out,
                             size_t bits, const void *key,
                             unsigned char ivec[16], int *num,
                             int enc, ossl_block128_f block);

size_t ossl_CRYPTO_cts128_encrypt_block(const unsigned char *in,
                                   unsigned char *out, size_t len,
                                   const void *key, unsigned char ivec[16],
                                   ossl_block128_f block);
size_t ossl_CRYPTO_cts128_encrypt(const unsigned char *in, unsigned char *out,
                             size_t len, const void *key,
                             unsigned char ivec[16], ossl_cbc128_f cbc);
size_t ossl_CRYPTO_cts128_decrypt_block(const unsigned char *in,
                                   unsigned char *out, size_t len,
                                   const void *key, unsigned char ivec[16],
                                   ossl_block128_f block);
size_t ossl_CRYPTO_cts128_decrypt(const unsigned char *in, unsigned char *out,
                             size_t len, const void *key,
                             unsigned char ivec[16], ossl_cbc128_f cbc);

size_t ossl_CRYPTO_nistcts128_encrypt_block(const unsigned char *in,
                                       unsigned char *out, size_t len,
                                       const void *key,
                                       unsigned char ivec[16],
                                       ossl_block128_f block);
size_t ossl_CRYPTO_nistcts128_encrypt(const unsigned char *in, unsigned char *out,
                                 size_t len, const void *key,
                                 unsigned char ivec[16], ossl_cbc128_f cbc);
size_t ossl_CRYPTO_nistcts128_decrypt_block(const unsigned char *in,
                                       unsigned char *out, size_t len,
                                       const void *key,
                                       unsigned char ivec[16],
                                       ossl_block128_f block);
size_t ossl_CRYPTO_nistcts128_decrypt(const unsigned char *in, unsigned char *out,
                                 size_t len, const void *key,
                                 unsigned char ivec[16], ossl_cbc128_f cbc);

typedef struct ossl_gcm128_context ossl_GCM128_CONTEXT;

ossl_GCM128_CONTEXT *ossl_CRYPTO_gcm128_new(void *key, ossl_block128_f block);
void ossl_CRYPTO_gcm128_init(ossl_GCM128_CONTEXT *ctx, void *key, ossl_block128_f block);
void ossl_CRYPTO_gcm128_setiv(ossl_GCM128_CONTEXT *ctx, const unsigned char *iv,
                         size_t len);
int ossl_CRYPTO_gcm128_aad(ossl_GCM128_CONTEXT *ctx, const unsigned char *aad,
                      size_t len);
int ossl_CRYPTO_gcm128_encrypt(ossl_GCM128_CONTEXT *ctx,
                          const unsigned char *in, unsigned char *out,
                          size_t len);
int ossl_CRYPTO_gcm128_decrypt(ossl_GCM128_CONTEXT *ctx,
                          const unsigned char *in, unsigned char *out,
                          size_t len);
int ossl_CRYPTO_gcm128_encrypt_ctr32(ossl_GCM128_CONTEXT *ctx,
                                const unsigned char *in, unsigned char *out,
                                size_t len, ossl_ctr128_f stream);
int ossl_CRYPTO_gcm128_decrypt_ctr32(ossl_GCM128_CONTEXT *ctx,
                                const unsigned char *in, unsigned char *out,
                                size_t len, ossl_ctr128_f stream);
int ossl_CRYPTO_gcm128_finish(ossl_GCM128_CONTEXT *ctx, const unsigned char *tag,
                         size_t len);
void ossl_CRYPTO_gcm128_tag(ossl_GCM128_CONTEXT *ctx, unsigned char *tag, size_t len);
void ossl_CRYPTO_gcm128_release(ossl_GCM128_CONTEXT *ctx);

typedef struct ossl_ccm128_context ossl_CCM128_CONTEXT;

void ossl_CRYPTO_ccm128_init(ossl_CCM128_CONTEXT *ctx,
                        unsigned int M, unsigned int L, void *key,
                        ossl_block128_f block);
int ossl_CRYPTO_ccm128_setiv(ossl_CCM128_CONTEXT *ctx, const unsigned char *nonce,
                        size_t nlen, size_t mlen);
void ossl_CRYPTO_ccm128_aad(ossl_CCM128_CONTEXT *ctx, const unsigned char *aad,
                       size_t alen);
int ossl_CRYPTO_ccm128_encrypt(ossl_CCM128_CONTEXT *ctx, const unsigned char *inp,
                          unsigned char *out, size_t len);
int ossl_CRYPTO_ccm128_decrypt(ossl_CCM128_CONTEXT *ctx, const unsigned char *inp,
                          unsigned char *out, size_t len);
int ossl_CRYPTO_ccm128_encrypt_ccm64(ossl_CCM128_CONTEXT *ctx, const unsigned char *inp,
                                unsigned char *out, size_t len,
                                ossl_ccm128_f stream);
int ossl_CRYPTO_ccm128_decrypt_ccm64(ossl_CCM128_CONTEXT *ctx, const unsigned char *inp,
                                unsigned char *out, size_t len,
                                ossl_ccm128_f stream);
size_t ossl_CRYPTO_ccm128_tag(ossl_CCM128_CONTEXT *ctx, unsigned char *tag, size_t len);

typedef struct ossl_xts128_context ossl_XTS128_CONTEXT;

int ossl_CRYPTO_xts128_encrypt(const ossl_XTS128_CONTEXT *ctx,
                          const unsigned char iv[16],
                          const unsigned char *inp, unsigned char *out,
                          size_t len, int enc);

size_t ossl_CRYPTO_128_wrap(void *key, const unsigned char *iv,
                       unsigned char *out,
                       const unsigned char *in, size_t inlen,
                       ossl_block128_f block);

size_t ossl_CRYPTO_128_unwrap(void *key, const unsigned char *iv,
                         unsigned char *out,
                         const unsigned char *in, size_t inlen,
                         ossl_block128_f block);
size_t ossl_CRYPTO_128_wrap_pad(void *key, const unsigned char *icv,
                           unsigned char *out, const unsigned char *in,
                           size_t inlen, ossl_block128_f block);
size_t ossl_CRYPTO_128_unwrap_pad(void *key, const unsigned char *icv,
                             unsigned char *out, const unsigned char *in,
                             size_t inlen, ossl_block128_f block);

# ifndef ossl_OPENSSL_NO_OCB
typedef struct ossl_ocb128_context ossl_OCB128_CONTEXT;

typedef void (*ossl_ocb128_f) (const unsigned char *in, unsigned char *out,
                          size_t blocks, const void *key,
                          size_t start_block_num,
                          unsigned char offset_i[16],
                          const unsigned char L_[][16],
                          unsigned char checksum[16]);

ossl_OCB128_CONTEXT *ossl_CRYPTO_ocb128_new(void *keyenc, void *keydec,
                                  ossl_block128_f encrypt, ossl_block128_f decrypt,
                                  ossl_ocb128_f stream);
int ossl_CRYPTO_ocb128_init(ossl_OCB128_CONTEXT *ctx, void *keyenc, void *keydec,
                       ossl_block128_f encrypt, ossl_block128_f decrypt,
                       ossl_ocb128_f stream);
int ossl_CRYPTO_ocb128_copy_ctx(ossl_OCB128_CONTEXT *dest, ossl_OCB128_CONTEXT *src,
                           void *keyenc, void *keydec);
int ossl_CRYPTO_ocb128_setiv(ossl_OCB128_CONTEXT *ctx, const unsigned char *iv,
                        size_t len, size_t taglen);
int ossl_CRYPTO_ocb128_aad(ossl_OCB128_CONTEXT *ctx, const unsigned char *aad,
                      size_t len);
int ossl_CRYPTO_ocb128_encrypt(ossl_OCB128_CONTEXT *ctx, const unsigned char *in,
                          unsigned char *out, size_t len);
int ossl_CRYPTO_ocb128_decrypt(ossl_OCB128_CONTEXT *ctx, const unsigned char *in,
                          unsigned char *out, size_t len);
int ossl_CRYPTO_ocb128_finish(ossl_OCB128_CONTEXT *ctx, const unsigned char *tag,
                         size_t len);
int ossl_CRYPTO_ocb128_tag(ossl_OCB128_CONTEXT *ctx, unsigned char *tag, size_t len);
void ossl_CRYPTO_ocb128_cleanup(ossl_OCB128_CONTEXT *ctx);
# endif                          /* ossl_OPENSSL_NO_OCB */

# ifdef  __cplusplus
}
# endif

#endif
