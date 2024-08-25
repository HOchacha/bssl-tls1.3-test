/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_RAND_H
# define ossl_OPENSSL_RAND_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_RAND_H
# endif

# include <stdlib.h>
# include "ossl/openssl/types.h"
# include "ossl/openssl/e_os2.h"
# include "ossl/openssl/randerr.h"
# include "ossl/openssl/evp.h"

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * Default security strength (in the sense of [NIST SP 800-90Ar1])
 *
 * NIST SP 800-90Ar1 supports the strength of the DRBG being smaller than that
 * of the cipher by collecting less entropy. The current DRBG implementation
 * does not take ossl_RAND_DRBG_STRENGTH into account and sets the strength of the
 * DRBG to that of the cipher.
 */
# define ossl_RAND_DRBG_STRENGTH             256

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
struct ossl_rand_meth_st {
    int (*seed) (const void *buf, int num);
    int (*bytes) (unsigned char *buf, int num);
    void (*cleanup) (void);
    int (*add) (const void *buf, int num, double randomness);
    int (*pseudorand) (unsigned char *buf, int num);
    int (*status) (void);
};

ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RAND_set_rand_method(const ossl_RAND_METHOD *meth);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_RAND_METHOD *ossl_RAND_get_rand_method(void);
#  ifndef ossl_OPENSSL_NO_ENGINE
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RAND_set_rand_engine(ossl_ENGINE *engine);
#  endif

ossl_OSSL_DEPRECATEDIN_3_0 ossl_RAND_METHOD *ossl_RAND_OpenSSL(void);
# endif /* ossl_OPENSSL_NO_DEPRECATED_3_0 */

# ifndef ossl_OPENSSL_NO_DEPRECATED_1_1_0
#   define ossl_RAND_cleanup() while(0) continue
# endif
int ossl_RAND_bytes(unsigned char *buf, int num);
int ossl_RAND_priv_bytes(unsigned char *buf, int num);

/*
 * Equivalent of ossl_RAND_priv_bytes() but additionally taking an ossl_OSSL_LIB_CTX and
 * a strength.
 */
int ossl_RAND_priv_bytes_ex(ossl_OSSL_LIB_CTX *ctx, unsigned char *buf, size_t num,
                       unsigned int strength);

/*
 * Equivalent of ossl_RAND_bytes() but additionally taking an ossl_OSSL_LIB_CTX and
 * a strength.
 */
int ossl_RAND_bytes_ex(ossl_OSSL_LIB_CTX *ctx, unsigned char *buf, size_t num,
                  unsigned int strength);

# ifndef ossl_OPENSSL_NO_DEPRECATED_1_1_0
ossl_OSSL_DEPRECATEDIN_1_1_0 int ossl_RAND_pseudo_bytes(unsigned char *buf, int num);
# endif

ossl_EVP_RAND_CTX *ossl_RAND_get0_primary(ossl_OSSL_LIB_CTX *ctx);
ossl_EVP_RAND_CTX *ossl_RAND_get0_public(ossl_OSSL_LIB_CTX *ctx);
ossl_EVP_RAND_CTX *ossl_RAND_get0_private(ossl_OSSL_LIB_CTX *ctx);

int ossl_RAND_set_DRBG_type(ossl_OSSL_LIB_CTX *ctx, const char *drbg, const char *propq,
                       const char *cipher, const char *digest);
int ossl_RAND_set_seed_source_type(ossl_OSSL_LIB_CTX *ctx, const char *seed,
                              const char *propq);

void ossl_RAND_seed(const void *buf, int num);
void ossl_RAND_keep_random_devices_open(int keep);

# if defined(__ANDROID__) && defined(__NDK_FPABI__)
__NDK_FPABI__   /* __attribute__((pcs("aapcs"))) on ARM */
# endif
void ossl_RAND_add(const void *buf, int num, double randomness);
int ossl_RAND_load_file(const char *file, long max_bytes);
int ossl_RAND_write_file(const char *file);
const char *ossl_RAND_file_name(char *file, size_t num);
int ossl_RAND_status(void);

# ifndef ossl_OPENSSL_NO_EGD
int RAND_query_egd_bytes(const char *path, unsigned char *buf, int bytes);
int RAND_egd(const char *path);
int RAND_egd_bytes(const char *path, int bytes);
# endif

int ossl_RAND_poll(void);

# if defined(_WIN32) && (defined(BASETYPES) || defined(_WINDEF_H))
/* application has to include <windows.h> in order to use these */
#  ifndef ossl_OPENSSL_NO_DEPRECATED_1_1_0
ossl_OSSL_DEPRECATEDIN_1_1_0 void RAND_screen(void);
ossl_OSSL_DEPRECATEDIN_1_1_0 int RAND_event(UINT, WPARAM, LPARAM);
#  endif
# endif

#ifdef  __cplusplus
}
#endif

#endif
