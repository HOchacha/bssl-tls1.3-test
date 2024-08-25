/*
 * Copyright 2016-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_KDF_H
# define ossl_OPENSSL_KDF_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_KDF_H
# endif

# include <stdarg.h>
# include <stddef.h>
# include "ossl/openssl/types.h"
# include "ossl/openssl/core.h"

# ifdef __cplusplus
extern "C" {
# endif

int ossl_EVP_KDF_up_ref(ossl_EVP_KDF *kdf);
void ossl_EVP_KDF_free(ossl_EVP_KDF *kdf);
ossl_EVP_KDF *ossl_EVP_KDF_fetch(ossl_OSSL_LIB_CTX *libctx, const char *algorithm,
                       const char *properties);

ossl_EVP_KDF_CTX *ossl_EVP_KDF_CTX_new(ossl_EVP_KDF *kdf);
void ossl_EVP_KDF_CTX_free(ossl_EVP_KDF_CTX *ctx);
ossl_EVP_KDF_CTX *ossl_EVP_KDF_CTX_dup(const ossl_EVP_KDF_CTX *src);
const char *ossl_EVP_KDF_get0_description(const ossl_EVP_KDF *kdf);
int ossl_EVP_KDF_is_a(const ossl_EVP_KDF *kdf, const char *name);
const char *ossl_EVP_KDF_get0_name(const ossl_EVP_KDF *kdf);
const ossl_OSSL_PROVIDER *ossl_EVP_KDF_get0_provider(const ossl_EVP_KDF *kdf);
const ossl_EVP_KDF *ossl_EVP_KDF_CTX_kdf(ossl_EVP_KDF_CTX *ctx);

void ossl_EVP_KDF_CTX_reset(ossl_EVP_KDF_CTX *ctx);
size_t ossl_EVP_KDF_CTX_get_kdf_size(ossl_EVP_KDF_CTX *ctx);
int ossl_EVP_KDF_derive(ossl_EVP_KDF_CTX *ctx, unsigned char *key, size_t keylen,
                   const ossl_OSSL_PARAM params[]);
int ossl_EVP_KDF_get_params(ossl_EVP_KDF *kdf, ossl_OSSL_PARAM params[]);
int ossl_EVP_KDF_CTX_get_params(ossl_EVP_KDF_CTX *ctx, ossl_OSSL_PARAM params[]);
int ossl_EVP_KDF_CTX_set_params(ossl_EVP_KDF_CTX *ctx, const ossl_OSSL_PARAM params[]);
const ossl_OSSL_PARAM *ossl_EVP_KDF_gettable_params(const ossl_EVP_KDF *kdf);
const ossl_OSSL_PARAM *ossl_EVP_KDF_gettable_ctx_params(const ossl_EVP_KDF *kdf);
const ossl_OSSL_PARAM *ossl_EVP_KDF_settable_ctx_params(const ossl_EVP_KDF *kdf);
const ossl_OSSL_PARAM *ossl_EVP_KDF_CTX_gettable_params(ossl_EVP_KDF_CTX *ctx);
const ossl_OSSL_PARAM *ossl_EVP_KDF_CTX_settable_params(ossl_EVP_KDF_CTX *ctx);

void ossl_EVP_KDF_do_all_provided(ossl_OSSL_LIB_CTX *libctx,
                             void (*fn)(ossl_EVP_KDF *kdf, void *arg),
                             void *arg);
int ossl_EVP_KDF_names_do_all(const ossl_EVP_KDF *kdf,
                         void (*fn)(const char *name, void *data),
                         void *data);

# define ossl_EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND  0
# define ossl_EVP_KDF_HKDF_MODE_EXTRACT_ONLY        1
# define ossl_EVP_KDF_HKDF_MODE_EXPAND_ONLY         2

#define ossl_EVP_KDF_SSHKDF_TYPE_INITIAL_IV_CLI_TO_SRV     65
#define ossl_EVP_KDF_SSHKDF_TYPE_INITIAL_IV_SRV_TO_CLI     66
#define ossl_EVP_KDF_SSHKDF_TYPE_ENCRYPTION_KEY_CLI_TO_SRV 67
#define ossl_EVP_KDF_SSHKDF_TYPE_ENCRYPTION_KEY_SRV_TO_CLI 68
#define ossl_EVP_KDF_SSHKDF_TYPE_INTEGRITY_KEY_CLI_TO_SRV  69
#define ossl_EVP_KDF_SSHKDF_TYPE_INTEGRITY_KEY_SRV_TO_CLI  70

/**** The legacy PKEY-based KDF API follows. ****/

# define ossl_EVP_PKEY_CTRL_TLS_MD                   (ossl_EVP_PKEY_ALG_CTRL)
# define ossl_EVP_PKEY_CTRL_TLS_SECRET               (ossl_EVP_PKEY_ALG_CTRL + 1)
# define ossl_EVP_PKEY_CTRL_TLS_SEED                 (ossl_EVP_PKEY_ALG_CTRL + 2)
# define ossl_EVP_PKEY_CTRL_HKDF_MD                  (ossl_EVP_PKEY_ALG_CTRL + 3)
# define ossl_EVP_PKEY_CTRL_HKDF_SALT                (ossl_EVP_PKEY_ALG_CTRL + 4)
# define ossl_EVP_PKEY_CTRL_HKDF_KEY                 (ossl_EVP_PKEY_ALG_CTRL + 5)
# define ossl_EVP_PKEY_CTRL_HKDF_INFO                (ossl_EVP_PKEY_ALG_CTRL + 6)
# define ossl_EVP_PKEY_CTRL_HKDF_MODE                (ossl_EVP_PKEY_ALG_CTRL + 7)
# define ossl_EVP_PKEY_CTRL_PASS                     (ossl_EVP_PKEY_ALG_CTRL + 8)
# define ossl_EVP_PKEY_CTRL_SCRYPT_SALT              (ossl_EVP_PKEY_ALG_CTRL + 9)
# define ossl_EVP_PKEY_CTRL_SCRYPT_N                 (ossl_EVP_PKEY_ALG_CTRL + 10)
# define ossl_EVP_PKEY_CTRL_SCRYPT_R                 (ossl_EVP_PKEY_ALG_CTRL + 11)
# define ossl_EVP_PKEY_CTRL_SCRYPT_P                 (ossl_EVP_PKEY_ALG_CTRL + 12)
# define ossl_EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES      (ossl_EVP_PKEY_ALG_CTRL + 13)

# define ossl_EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND \
            ossl_EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND
# define ossl_EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY       \
            ossl_EVP_KDF_HKDF_MODE_EXTRACT_ONLY
# define ossl_EVP_PKEY_HKDEF_MODE_EXPAND_ONLY        \
            ossl_EVP_KDF_HKDF_MODE_EXPAND_ONLY

int ossl_EVP_PKEY_CTX_set_tls1_prf_md(ossl_EVP_PKEY_CTX *ctx, const ossl_EVP_MD *md);

int ossl_EVP_PKEY_CTX_set1_tls1_prf_secret(ossl_EVP_PKEY_CTX *pctx,
                                      const unsigned char *sec, int seclen);

int ossl_EVP_PKEY_CTX_add1_tls1_prf_seed(ossl_EVP_PKEY_CTX *pctx,
                                    const unsigned char *seed, int seedlen);

int ossl_EVP_PKEY_CTX_set_hkdf_md(ossl_EVP_PKEY_CTX *ctx, const ossl_EVP_MD *md);

int ossl_EVP_PKEY_CTX_set1_hkdf_salt(ossl_EVP_PKEY_CTX *ctx,
                                const unsigned char *salt, int saltlen);

int ossl_EVP_PKEY_CTX_set1_hkdf_key(ossl_EVP_PKEY_CTX *ctx,
                               const unsigned char *key, int keylen);

int ossl_EVP_PKEY_CTX_add1_hkdf_info(ossl_EVP_PKEY_CTX *ctx,
                                const unsigned char *info, int infolen);

int ossl_EVP_PKEY_CTX_set_hkdf_mode(ossl_EVP_PKEY_CTX *ctx, int mode);
# define ossl_EVP_PKEY_CTX_hkdf_mode ossl_EVP_PKEY_CTX_set_hkdf_mode

int ossl_EVP_PKEY_CTX_set1_pbe_pass(ossl_EVP_PKEY_CTX *ctx, const char *pass,
                               int passlen);

int ossl_EVP_PKEY_CTX_set1_scrypt_salt(ossl_EVP_PKEY_CTX *ctx,
                                  const unsigned char *salt, int saltlen);

int ossl_EVP_PKEY_CTX_set_scrypt_N(ossl_EVP_PKEY_CTX *ctx, uint64_t n);

int ossl_EVP_PKEY_CTX_set_scrypt_r(ossl_EVP_PKEY_CTX *ctx, uint64_t r);

int ossl_EVP_PKEY_CTX_set_scrypt_p(ossl_EVP_PKEY_CTX *ctx, uint64_t p);

int ossl_EVP_PKEY_CTX_set_scrypt_maxmem_bytes(ossl_EVP_PKEY_CTX *ctx,
                                         uint64_t maxmem_bytes);


# ifdef __cplusplus
}
# endif
#endif
