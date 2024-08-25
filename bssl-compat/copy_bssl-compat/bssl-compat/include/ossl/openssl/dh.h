/*
 * Copyright 1995-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_DH_H
# define ossl_OPENSSL_DH_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_DH_H
# endif

# include "ossl/openssl/opensslconf.h"
# include "ossl/openssl/types.h"

# ifdef  __cplusplus
extern "C" {
# endif

#include <stdlib.h>

/* ossl_DH parameter generation types used by ossl_EVP_PKEY_CTX_set_dh_paramgen_type() */
# define ossl_DH_PARAMGEN_TYPE_GENERATOR     0   /* Use a safe prime generator */
# define ossl_DH_PARAMGEN_TYPE_FIPS_186_2    1   /* Use FIPS186-2 standard */
# define ossl_DH_PARAMGEN_TYPE_FIPS_186_4    2   /* Use FIPS186-4 standard */
# define ossl_DH_PARAMGEN_TYPE_GROUP         3   /* Use a named safe prime group */

int ossl_EVP_PKEY_CTX_set_dh_paramgen_type(ossl_EVP_PKEY_CTX *ctx, int typ);
int ossl_EVP_PKEY_CTX_set_dh_paramgen_gindex(ossl_EVP_PKEY_CTX *ctx, int gindex);
int ossl_EVP_PKEY_CTX_set_dh_paramgen_seed(ossl_EVP_PKEY_CTX *ctx,
                                      const unsigned char *seed,
                                      size_t seedlen);
int ossl_EVP_PKEY_CTX_set_dh_paramgen_prime_len(ossl_EVP_PKEY_CTX *ctx, int pbits);
int ossl_EVP_PKEY_CTX_set_dh_paramgen_subprime_len(ossl_EVP_PKEY_CTX *ctx, int qlen);
int ossl_EVP_PKEY_CTX_set_dh_paramgen_generator(ossl_EVP_PKEY_CTX *ctx, int gen);
int ossl_EVP_PKEY_CTX_set_dh_nid(ossl_EVP_PKEY_CTX *ctx, int nid);
int ossl_EVP_PKEY_CTX_set_dh_rfc5114(ossl_EVP_PKEY_CTX *ctx, int gen);
int ossl_EVP_PKEY_CTX_set_dhx_rfc5114(ossl_EVP_PKEY_CTX *ctx, int gen);
int ossl_EVP_PKEY_CTX_set_dh_pad(ossl_EVP_PKEY_CTX *ctx, int pad);

int ossl_EVP_PKEY_CTX_set_dh_kdf_type(ossl_EVP_PKEY_CTX *ctx, int kdf);
int ossl_EVP_PKEY_CTX_get_dh_kdf_type(ossl_EVP_PKEY_CTX *ctx);
int ossl_EVP_PKEY_CTX_set0_dh_kdf_oid(ossl_EVP_PKEY_CTX *ctx, ossl_ASN1_OBJECT *oid);
int ossl_EVP_PKEY_CTX_get0_dh_kdf_oid(ossl_EVP_PKEY_CTX *ctx, ossl_ASN1_OBJECT **oid);
int ossl_EVP_PKEY_CTX_set_dh_kdf_md(ossl_EVP_PKEY_CTX *ctx, const ossl_EVP_MD *md);
int ossl_EVP_PKEY_CTX_get_dh_kdf_md(ossl_EVP_PKEY_CTX *ctx, const ossl_EVP_MD **md);
int ossl_EVP_PKEY_CTX_set_dh_kdf_outlen(ossl_EVP_PKEY_CTX *ctx, int len);
int ossl_EVP_PKEY_CTX_get_dh_kdf_outlen(ossl_EVP_PKEY_CTX *ctx, int *len);
int ossl_EVP_PKEY_CTX_set0_dh_kdf_ukm(ossl_EVP_PKEY_CTX *ctx, unsigned char *ukm, int len);
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_PKEY_CTX_get0_dh_kdf_ukm(ossl_EVP_PKEY_CTX *ctx, unsigned char **ukm);
#endif

# define ossl_EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN     (ossl_EVP_PKEY_ALG_CTRL + 1)
# define ossl_EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR     (ossl_EVP_PKEY_ALG_CTRL + 2)
# define ossl_EVP_PKEY_CTRL_DH_RFC5114                (ossl_EVP_PKEY_ALG_CTRL + 3)
# define ossl_EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN  (ossl_EVP_PKEY_ALG_CTRL + 4)
# define ossl_EVP_PKEY_CTRL_DH_PARAMGEN_TYPE          (ossl_EVP_PKEY_ALG_CTRL + 5)
# define ossl_EVP_PKEY_CTRL_DH_KDF_TYPE               (ossl_EVP_PKEY_ALG_CTRL + 6)
# define ossl_EVP_PKEY_CTRL_DH_KDF_MD                 (ossl_EVP_PKEY_ALG_CTRL + 7)
# define ossl_EVP_PKEY_CTRL_GET_DH_KDF_MD             (ossl_EVP_PKEY_ALG_CTRL + 8)
# define ossl_EVP_PKEY_CTRL_DH_KDF_OUTLEN             (ossl_EVP_PKEY_ALG_CTRL + 9)
# define ossl_EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN         (ossl_EVP_PKEY_ALG_CTRL + 10)
# define ossl_EVP_PKEY_CTRL_DH_KDF_UKM                (ossl_EVP_PKEY_ALG_CTRL + 11)
# define ossl_EVP_PKEY_CTRL_GET_DH_KDF_UKM            (ossl_EVP_PKEY_ALG_CTRL + 12)
# define ossl_EVP_PKEY_CTRL_DH_KDF_OID                (ossl_EVP_PKEY_ALG_CTRL + 13)
# define ossl_EVP_PKEY_CTRL_GET_DH_KDF_OID            (ossl_EVP_PKEY_ALG_CTRL + 14)
# define ossl_EVP_PKEY_CTRL_DH_NID                    (ossl_EVP_PKEY_ALG_CTRL + 15)
# define ossl_EVP_PKEY_CTRL_DH_PAD                    (ossl_EVP_PKEY_ALG_CTRL + 16)

/* KDF types */
# define ossl_EVP_PKEY_DH_KDF_NONE                            1
# define ossl_EVP_PKEY_DH_KDF_X9_42                           2

# ifndef ossl_OPENSSL_NO_DH
#  include "ossl/openssl/e_os2.h"
#  include "ossl/openssl/bio.h"
#  include "ossl/openssl/asn1.h"
#  ifndef ossl_OPENSSL_NO_DEPRECATED_1_1_0
#   include "ossl/openssl/bn.h"
#  endif
#  include "ossl/openssl/dherr.h"

#  ifndef ossl_OPENSSL_DH_MAX_MODULUS_BITS
#   define ossl_OPENSSL_DH_MAX_MODULUS_BITS        10000
#  endif

#  ifndef ossl_OPENSSL_DH_CHECK_MAX_MODULUS_BITS
#   define ossl_OPENSSL_DH_CHECK_MAX_MODULUS_BITS  32768
#  endif

#  define ossl_OPENSSL_DH_FIPS_MIN_MODULUS_BITS 1024

#  define ossl_DH_FLAG_CACHE_MONT_P     0x01

#  define ossl_DH_FLAG_TYPE_MASK             0xF000
#  define ossl_DH_FLAG_TYPE_DH               0x0000
#  define ossl_DH_FLAG_TYPE_DHX              0x1000

#  ifndef ossl_OPENSSL_NO_DEPRECATED_1_1_0
/*
 * Does nothing. Previously this switched off constant time behaviour.
 */
#   define ossl_DH_FLAG_NO_EXP_CONSTTIME 0x00
#  endif

#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
/*
 * If this flag is set the ossl_DH method is FIPS compliant and can be used in
 * FIPS mode. This is set in the validated module method. If an application
 * sets this flag in its own methods it is its responsibility to ensure the
 * result is compliant.
 */

#   define ossl_DH_FLAG_FIPS_METHOD                     0x0400

/*
 * If this flag is set the operations normally disabled in FIPS mode are
 * permitted it is then the applications responsibility to ensure that the
 * usage is compliant.
 */

#   define ossl_DH_FLAG_NON_FIPS_ALLOW                  0x0400
#  endif

/* Already defined in ossl_typ.h */
/* typedef struct ossl_dh_st ossl_DH; */
/* typedef struct ossl_dh_method ossl_DH_METHOD; */

ossl_DECLARE_ASN1_ITEM(ossl_DHparams)

#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#   define ossl_DH_GENERATOR_2          2
#   define ossl_DH_GENERATOR_3          3
#   define ossl_DH_GENERATOR_5          5

/* ossl_DH_check error codes, some of them shared with ossl_DH_check_pub_key */
/*
 * NB: These values must align with the equivalently named macros in
 * internal/ffc.h.
 */
#   define ossl_DH_CHECK_P_NOT_PRIME            0x01
#   define ossl_DH_CHECK_P_NOT_SAFE_PRIME       0x02
#   define ossl_DH_UNABLE_TO_CHECK_GENERATOR    0x04
#   define ossl_DH_NOT_SUITABLE_GENERATOR       0x08
#   define ossl_DH_CHECK_Q_NOT_PRIME            0x10
#   define ossl_DH_CHECK_INVALID_Q_VALUE        0x20 /* +ossl_DH_check_pub_key */
#   define ossl_DH_CHECK_INVALID_J_VALUE        0x40
#   define ossl_DH_MODULUS_TOO_SMALL            0x80
#   define ossl_DH_MODULUS_TOO_LARGE            0x100 /* +ossl_DH_check_pub_key */

/* ossl_DH_check_pub_key error codes */
#   define ossl_DH_CHECK_PUBKEY_TOO_SMALL       0x01
#   define ossl_DH_CHECK_PUBKEY_TOO_LARGE       0x02
#   define ossl_DH_CHECK_PUBKEY_INVALID         0x04

/*
 * primes p where (p-1)/2 is prime too are called "safe"; we define this for
 * backward compatibility:
 */
#   define ossl_DH_CHECK_P_NOT_STRONG_PRIME     ossl_DH_CHECK_P_NOT_SAFE_PRIME

#   define ossl_d2i_DHparams_fp(fp, x) \
        (ossl_DH *)ossl_ASN1_d2i_fp((char *(*)())ossl_DH_new, \
                          (char *(*)())ossl_d2i_DHparams, \
                          (fp), \
                          (unsigned char **)(x))
#   define ossl_i2d_DHparams_fp(fp, x) \
        ossl_ASN1_i2d_fp(ossl_i2d_DHparams,(fp), (unsigned char *)(x))
#   define ossl_d2i_DHparams_bio(bp, x) \
        ossl_ASN1_d2i_bio_of(ossl_DH, ossl_DH_new, ossl_d2i_DHparams, bp, x)
#   define ossl_i2d_DHparams_bio(bp, x) \
        ossl_ASN1_i2d_bio_of(ossl_DH, ossl_i2d_DHparams, bp, x)

#   define ossl_d2i_DHxparams_fp(fp,x) \
        (ossl_DH *)ossl_ASN1_d2i_fp((char *(*)())ossl_DH_new, \
                          (char *(*)())ossl_d2i_DHxparams, \
                          (fp), \
                          (unsigned char **)(x))
#   define ossl_i2d_DHxparams_fp(fp, x) \
        ossl_ASN1_i2d_fp(ossl_i2d_DHxparams,(fp), (unsigned char *)(x))
#   define ossl_d2i_DHxparams_bio(bp, x) \
        ossl_ASN1_d2i_bio_of(ossl_DH, ossl_DH_new, ossl_d2i_DHxparams, bp, x)
#   define ossl_i2d_DHxparams_bio(bp, x) \
        ossl_ASN1_i2d_bio_of(ossl_DH, ossl_i2d_DHxparams, bp, x)

ossl_DECLARE_ASN1_DUP_FUNCTION_name_attr(ossl_OSSL_DEPRECATEDIN_3_0, ossl_DH, ossl_DHparams)

ossl_OSSL_DEPRECATEDIN_3_0 const ossl_DH_METHOD *ossl_DH_OpenSSL(void);

ossl_OSSL_DEPRECATEDIN_3_0 void ossl_DH_set_default_method(const ossl_DH_METHOD *meth);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_DH_METHOD *ossl_DH_get_default_method(void);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_set_method(ossl_DH *dh, const ossl_DH_METHOD *meth);
ossl_OSSL_DEPRECATEDIN_3_0 ossl_DH *ossl_DH_new_method(ossl_ENGINE *engine);

ossl_OSSL_DEPRECATEDIN_3_0 ossl_DH *ossl_DH_new(void);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_DH_free(ossl_DH *dh);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_up_ref(ossl_DH *dh);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_bits(const ossl_DH *dh);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_size(const ossl_DH *dh);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_security_bits(const ossl_DH *dh);

#   define ossl_DH_get_ex_new_index(l, p, newf, dupf, freef) \
        ossl_CRYPTO_get_ex_new_index(ossl_CRYPTO_EX_INDEX_DH, l, p, newf, dupf, freef)

ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_set_ex_data(ossl_DH *d, int idx, void *arg);
ossl_OSSL_DEPRECATEDIN_3_0 void *ossl_DH_get_ex_data(const ossl_DH *d, int idx);

ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_generate_parameters_ex(ossl_DH *dh, int prime_len,
                                                    int generator,
                                                    ossl_BN_GENCB *cb);

ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_check_params_ex(const ossl_DH *dh);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_check_ex(const ossl_DH *dh);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_check_pub_key_ex(const ossl_DH *dh, const ossl_BIGNUM *pub_key);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_check_params(const ossl_DH *dh, int *ret);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_check(const ossl_DH *dh, int *codes);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_check_pub_key(const ossl_DH *dh, const ossl_BIGNUM *pub_key,
                                           int *codes);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_generate_key(ossl_DH *dh);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_compute_key(unsigned char *key,
                                         const ossl_BIGNUM *pub_key, ossl_DH *dh);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_compute_key_padded(unsigned char *key,
                                                const ossl_BIGNUM *pub_key, ossl_DH *dh);

ossl_DECLARE_ASN1_ENCODE_FUNCTIONS_only_attr(ossl_OSSL_DEPRECATEDIN_3_0, ossl_DH, ossl_DHparams)
ossl_DECLARE_ASN1_ENCODE_FUNCTIONS_only_attr(ossl_OSSL_DEPRECATEDIN_3_0, ossl_DH, DHxparams)

#   ifndef ossl_OPENSSL_NO_STDIO
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DHparams_print_fp(FILE *fp, const ossl_DH *x);
#   endif
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DHparams_print(ossl_BIO *bp, const ossl_DH *x);

/* RFC 5114 parameters */
ossl_OSSL_DEPRECATEDIN_3_0 ossl_DH *ossl_DH_get_1024_160(void);
ossl_OSSL_DEPRECATEDIN_3_0 ossl_DH *ossl_DH_get_2048_224(void);
ossl_OSSL_DEPRECATEDIN_3_0 ossl_DH *ossl_DH_get_2048_256(void);

/* Named parameters, currently RFC7919 and RFC3526 */
ossl_OSSL_DEPRECATEDIN_3_0 ossl_DH *ossl_DH_new_by_nid(int nid);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_get_nid(const ossl_DH *dh);

/* RFC2631 KDF */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_KDF_X9_42(unsigned char *out, size_t outlen,
                                       const unsigned char *Z, size_t Zlen,
                                       ossl_ASN1_OBJECT *key_oid,
                                       const unsigned char *ukm,
                                       size_t ukmlen, const ossl_EVP_MD *md);

ossl_OSSL_DEPRECATEDIN_3_0 void ossl_DH_get0_pqg(const ossl_DH *dh, const ossl_BIGNUM **p,
                                       const ossl_BIGNUM **q, const ossl_BIGNUM **g);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_set0_pqg(ossl_DH *dh, ossl_BIGNUM *p, ossl_BIGNUM *q, ossl_BIGNUM *g);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_DH_get0_key(const ossl_DH *dh, const ossl_BIGNUM **pub_key,
                                       const ossl_BIGNUM **priv_key);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_set0_key(ossl_DH *dh, ossl_BIGNUM *pub_key, ossl_BIGNUM *priv_key);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_BIGNUM *ossl_DH_get0_p(const ossl_DH *dh);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_BIGNUM *ossl_DH_get0_q(const ossl_DH *dh);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_BIGNUM *ossl_DH_get0_g(const ossl_DH *dh);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_BIGNUM *ossl_DH_get0_priv_key(const ossl_DH *dh);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_BIGNUM *ossl_DH_get0_pub_key(const ossl_DH *dh);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_DH_clear_flags(ossl_DH *dh, int flags);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_test_flags(const ossl_DH *dh, int flags);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_DH_set_flags(ossl_DH *dh, int flags);
ossl_OSSL_DEPRECATEDIN_3_0 ossl_ENGINE *ossl_DH_get0_engine(ossl_DH *d);
ossl_OSSL_DEPRECATEDIN_3_0 long ossl_DH_get_length(const ossl_DH *dh);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_set_length(ossl_DH *dh, long length);

ossl_OSSL_DEPRECATEDIN_3_0 ossl_DH_METHOD *ossl_DH_meth_new(const char *name, int flags);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_DH_meth_free(ossl_DH_METHOD *dhm);
ossl_OSSL_DEPRECATEDIN_3_0 ossl_DH_METHOD *ossl_DH_meth_dup(const ossl_DH_METHOD *dhm);
ossl_OSSL_DEPRECATEDIN_3_0 const char *ossl_DH_meth_get0_name(const ossl_DH_METHOD *dhm);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_meth_set1_name(ossl_DH_METHOD *dhm, const char *name);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_meth_get_flags(const ossl_DH_METHOD *dhm);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_meth_set_flags(ossl_DH_METHOD *dhm, int flags);
ossl_OSSL_DEPRECATEDIN_3_0 void *ossl_DH_meth_get0_app_data(const ossl_DH_METHOD *dhm);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_meth_set0_app_data(ossl_DH_METHOD *dhm, void *app_data);
ossl_OSSL_DEPRECATEDIN_3_0 int (*ossl_DH_meth_get_generate_key(const ossl_DH_METHOD *dhm)) (ossl_DH *);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_meth_set_generate_key(ossl_DH_METHOD *dhm,
                                                   int (*generate_key) (ossl_DH *));
ossl_OSSL_DEPRECATEDIN_3_0 int (*ossl_DH_meth_get_compute_key(const ossl_DH_METHOD *dhm))
                                                   (unsigned char *key,
                                                    const ossl_BIGNUM *pub_key,
                                                    ossl_DH *dh);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_meth_set_compute_key(ossl_DH_METHOD *dhm,
                                                  int (*compute_key)
                                                  (unsigned char *key,
                                                   const ossl_BIGNUM *pub_key,
                                                   ossl_DH *dh));
ossl_OSSL_DEPRECATEDIN_3_0 int (*ossl_DH_meth_get_bn_mod_exp(const ossl_DH_METHOD *dhm))
                                                   (const ossl_DH *, ossl_BIGNUM *,
                                                    const ossl_BIGNUM *,
                                                    const ossl_BIGNUM *,
                                                    const ossl_BIGNUM *, ossl_BN_CTX *,
                                                    ossl_BN_MONT_CTX *);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_meth_set_bn_mod_exp(ossl_DH_METHOD *dhm,
                                                 int (*bn_mod_exp)
                                                 (const ossl_DH *, ossl_BIGNUM *,
                                                  const ossl_BIGNUM *, const ossl_BIGNUM *,
                                                  const ossl_BIGNUM *, ossl_BN_CTX *,
                                                  ossl_BN_MONT_CTX *));
ossl_OSSL_DEPRECATEDIN_3_0 int (*ossl_DH_meth_get_init(const ossl_DH_METHOD *dhm))(ossl_DH *);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_meth_set_init(ossl_DH_METHOD *dhm, int (*init)(ossl_DH *));
ossl_OSSL_DEPRECATEDIN_3_0 int (*ossl_DH_meth_get_finish(const ossl_DH_METHOD *dhm)) (ossl_DH *);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_meth_set_finish(ossl_DH_METHOD *dhm, int (*finish) (ossl_DH *));
ossl_OSSL_DEPRECATEDIN_3_0 int (*ossl_DH_meth_get_generate_params(const ossl_DH_METHOD *dhm))
                                                        (ossl_DH *, int, int,
                                                         ossl_BN_GENCB *);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DH_meth_set_generate_params(ossl_DH_METHOD *dhm,
                                                      int (*generate_params)
                                                      (ossl_DH *, int, int,
                                                       ossl_BN_GENCB *));
#  endif /* ossl_OPENSSL_NO_DEPRECATED_3_0 */

#  ifndef ossl_OPENSSL_NO_DEPRECATED_0_9_8
ossl_OSSL_DEPRECATEDIN_0_9_8 ossl_DH *ossl_DH_generate_parameters(int prime_len, int generator,
                                                   void (*callback) (int, int,
                                                                void *),
                                                   void *cb_arg);
#  endif

# endif
# ifdef  __cplusplus
}
# endif
#endif
