/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_DSA_H
# define ossl_OPENSSL_DSA_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_DSA_H
# endif

# include "ossl/openssl/opensslconf.h"
# include "ossl/openssl/types.h"

# ifdef  __cplusplus
extern "C" {
# endif

# include <stdlib.h>

int ossl_EVP_PKEY_CTX_set_dsa_paramgen_bits(ossl_EVP_PKEY_CTX *ctx, int nbits);
int ossl_EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ossl_EVP_PKEY_CTX *ctx, int qbits);
int ossl_EVP_PKEY_CTX_set_dsa_paramgen_md_props(ossl_EVP_PKEY_CTX *ctx,
                                           const char *md_name,
                                           const char *md_properties);
int ossl_EVP_PKEY_CTX_set_dsa_paramgen_gindex(ossl_EVP_PKEY_CTX *ctx, int gindex);
int ossl_EVP_PKEY_CTX_set_dsa_paramgen_type(ossl_EVP_PKEY_CTX *ctx, const char *name);
int ossl_EVP_PKEY_CTX_set_dsa_paramgen_seed(ossl_EVP_PKEY_CTX *ctx,
                                       const unsigned char *seed,
                                       size_t seedlen);
int ossl_EVP_PKEY_CTX_set_dsa_paramgen_md(ossl_EVP_PKEY_CTX *ctx, const ossl_EVP_MD *md);

# define ossl_EVP_PKEY_CTRL_DSA_PARAMGEN_BITS         (ossl_EVP_PKEY_ALG_CTRL + 1)
# define ossl_EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS       (ossl_EVP_PKEY_ALG_CTRL + 2)
# define ossl_EVP_PKEY_CTRL_DSA_PARAMGEN_MD           (ossl_EVP_PKEY_ALG_CTRL + 3)

# ifndef ossl_OPENSSL_NO_DSA
#  include "ossl/openssl/e_os2.h"
#  include "ossl/openssl/asn1.h"
#  include "ossl/openssl/bio.h"
#  include "ossl/openssl/crypto.h"
#  include "ossl/openssl/bn.h"
#  ifndef ossl_OPENSSL_NO_DEPRECATED_1_1_0
#   include "ossl/openssl/dh.h"
#  endif
#  include "ossl/openssl/dsaerr.h"

#  ifndef ossl_OPENSSL_DSA_MAX_MODULUS_BITS
#   define ossl_OPENSSL_DSA_MAX_MODULUS_BITS   10000
#  endif

#  define ossl_OPENSSL_DSA_FIPS_MIN_MODULUS_BITS 1024

typedef struct ossl_DSA_SIG_st ossl_DSA_SIG;
ossl_DSA_SIG *ossl_DSA_SIG_new(void);
void ossl_DSA_SIG_free(ossl_DSA_SIG *a);
ossl_DECLARE_ASN1_ENCODE_FUNCTIONS_only(ossl_DSA_SIG, ossl_DSA_SIG)
void ossl_DSA_SIG_get0(const ossl_DSA_SIG *sig, const ossl_BIGNUM **pr, const ossl_BIGNUM **ps);
int ossl_DSA_SIG_set0(ossl_DSA_SIG *sig, ossl_BIGNUM *r, ossl_BIGNUM *s);


#  ifndef ossl_OPENSSL_NO_DEPRECATED_1_1_0
/*
 * Does nothing. Previously this switched off constant time behaviour.
 */
#   define ossl_DSA_FLAG_NO_EXP_CONSTTIME       0x00
#  endif

#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#   define ossl_DSA_FLAG_CACHE_MONT_P   0x01

/*
 * If this flag is set the ossl_DSA method is FIPS compliant and can be used in
 * FIPS mode. This is set in the validated module method. If an application
 * sets this flag in its own methods it is its responsibility to ensure the
 * result is compliant.
 */

#   define ossl_DSA_FLAG_FIPS_METHOD                    0x0400

/*
 * If this flag is set the operations normally disabled in FIPS mode are
 * permitted it is then the applications responsibility to ensure that the
 * usage is compliant.
 */

#   define ossl_DSA_FLAG_NON_FIPS_ALLOW                 0x0400
#   define ossl_DSA_FLAG_FIPS_CHECKED                   0x0800

/* Already defined in ossl_typ.h */
/* typedef struct ossl_dsa_st ossl_DSA; */
/* typedef struct ossl_dsa_method ossl_DSA_METHOD; */

#   define ossl_d2i_DSAparams_fp(fp, x) \
        (ossl_DSA *)ossl_ASN1_d2i_fp((char *(*)())ossl_DSA_new, \
                           (char *(*)())ossl_d2i_DSAparams, (fp), \
                           (unsigned char **)(x))
#   define ossl_i2d_DSAparams_fp(fp, x) \
        ossl_ASN1_i2d_fp(ossl_i2d_DSAparams, (fp), (unsigned char *)(x))
#   define ossl_d2i_DSAparams_bio(bp, x) \
        ossl_ASN1_d2i_bio_of(ossl_DSA, ossl_DSA_new, ossl_d2i_DSAparams, bp, x)
#   define ossl_i2d_DSAparams_bio(bp, x) \
        ossl_ASN1_i2d_bio_of(ossl_DSA, ossl_i2d_DSAparams, bp, x)

ossl_DECLARE_ASN1_DUP_FUNCTION_name_attr(ossl_OSSL_DEPRECATEDIN_3_0, ossl_DSA, DSAparams)
ossl_OSSL_DEPRECATEDIN_3_0 ossl_DSA_SIG *ossl_DSA_do_sign(const unsigned char *dgst, int dlen,
                                           ossl_DSA *dsa);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_do_verify(const unsigned char *dgst, int dgst_len,
                                        ossl_DSA_SIG *sig, ossl_DSA *dsa);

ossl_OSSL_DEPRECATEDIN_3_0 const ossl_DSA_METHOD *ossl_DSA_OpenSSL(void);

ossl_OSSL_DEPRECATEDIN_3_0 void ossl_DSA_set_default_method(const ossl_DSA_METHOD *);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_DSA_METHOD *ossl_DSA_get_default_method(void);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_set_method(ossl_DSA *dsa, const ossl_DSA_METHOD *);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_DSA_METHOD *ossl_DSA_get_method(ossl_DSA *d);

ossl_OSSL_DEPRECATEDIN_3_0 ossl_DSA *ossl_DSA_new(void);
ossl_OSSL_DEPRECATEDIN_3_0 ossl_DSA *ossl_DSA_new_method(ossl_ENGINE *engine);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_DSA_free(ossl_DSA *r);
/* "up" the ossl_DSA object's reference count */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_up_ref(ossl_DSA *r);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_size(const ossl_DSA *);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_bits(const ossl_DSA *d);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_security_bits(const ossl_DSA *d);
        /* next 4 return -1 on error */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_sign_setup(ossl_DSA *dsa, ossl_BN_CTX *ctx_in,
                                         ossl_BIGNUM **kinvp, ossl_BIGNUM **rp);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_sign(int type, const unsigned char *dgst,
                                   int dlen, unsigned char *sig,
                                   unsigned int *siglen, ossl_DSA *dsa);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_verify(int type, const unsigned char *dgst,
                                     int dgst_len, const unsigned char *sigbuf,
                                     int siglen, ossl_DSA *dsa);

#   define ossl_DSA_get_ex_new_index(l, p, newf, dupf, freef) \
        ossl_CRYPTO_get_ex_new_index(ossl_CRYPTO_EX_INDEX_DSA, l, p, newf, dupf, freef)
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_set_ex_data(ossl_DSA *d, int idx, void *arg);
ossl_OSSL_DEPRECATEDIN_3_0 void *ossl_DSA_get_ex_data(const ossl_DSA *d, int idx);

ossl_DECLARE_ASN1_ENCODE_FUNCTIONS_only_attr(ossl_OSSL_DEPRECATEDIN_3_0,
                                        ossl_DSA, DSAPublicKey)
ossl_DECLARE_ASN1_ENCODE_FUNCTIONS_only_attr(ossl_OSSL_DEPRECATEDIN_3_0,
                                        ossl_DSA, DSAPrivateKey)
ossl_DECLARE_ASN1_ENCODE_FUNCTIONS_only_attr(ossl_OSSL_DEPRECATEDIN_3_0,
                                        ossl_DSA, DSAparams)
#  endif

#  ifndef ossl_OPENSSL_NO_DEPRECATED_0_9_8
/* Deprecated version */
ossl_OSSL_DEPRECATEDIN_0_9_8
ossl_DSA *ossl_DSA_generate_parameters(int bits, unsigned char *seed, int seed_len,
                             int *counter_ret, unsigned long *h_ret,
                             void (*callback) (int, int, void *),
                             void *cb_arg);
#  endif

#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
/* New version */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_generate_parameters_ex(ossl_DSA *dsa, int bits,
                                                     const unsigned char *seed,
                                                     int seed_len,
                                                     int *counter_ret,
                                                     unsigned long *h_ret,
                                                     ossl_BN_GENCB *cb);

ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_generate_key(ossl_DSA *a);

ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSAparams_print(ossl_BIO *bp, const ossl_DSA *x);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_print(ossl_BIO *bp, const ossl_DSA *x, int off);
#   ifndef ossl_OPENSSL_NO_STDIO
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSAparams_print_fp(FILE *fp, const ossl_DSA *x);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_print_fp(FILE *bp, const ossl_DSA *x, int off);
#   endif

#   define ossl_DSS_prime_checks 64
/*
 * Primality test according to FIPS PUB 186-4, Appendix C.3. Since we only
 * have one value here we set the number of checks to 64 which is the 128 bit
 * security level that is the highest level and valid for creating a 3072 bit
 * ossl_DSA key.
 */
#   define ossl_DSA_is_prime(n, callback, cb_arg) \
            ossl_BN_is_prime(n, ossl_DSS_prime_checks, callback, NULL, cb_arg)

#   ifndef ossl_OPENSSL_NO_DH
/*
 * Convert ossl_DSA structure (key or just parameters) into ossl_DH structure (be
 * careful to avoid small subgroup attacks when using this!)
 */
ossl_OSSL_DEPRECATEDIN_3_0 ossl_DH *ossl_DSA_dup_DH(const ossl_DSA *r);
#   endif

ossl_OSSL_DEPRECATEDIN_3_0 void ossl_DSA_get0_pqg(const ossl_DSA *d, const ossl_BIGNUM **p,
                                        const ossl_BIGNUM **q, const ossl_BIGNUM **g);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_set0_pqg(ossl_DSA *d, ossl_BIGNUM *p, ossl_BIGNUM *q, ossl_BIGNUM *g);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_DSA_get0_key(const ossl_DSA *d, const ossl_BIGNUM **pub_key,
                                        const ossl_BIGNUM **priv_key);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_set0_key(ossl_DSA *d, ossl_BIGNUM *pub_key,
                                       ossl_BIGNUM *priv_key);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_BIGNUM *ossl_DSA_get0_p(const ossl_DSA *d);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_BIGNUM *ossl_DSA_get0_q(const ossl_DSA *d);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_BIGNUM *ossl_DSA_get0_g(const ossl_DSA *d);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_BIGNUM *ossl_DSA_get0_pub_key(const ossl_DSA *d);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_BIGNUM *ossl_DSA_get0_priv_key(const ossl_DSA *d);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_DSA_clear_flags(ossl_DSA *d, int flags);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_test_flags(const ossl_DSA *d, int flags);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_DSA_set_flags(ossl_DSA *d, int flags);
ossl_OSSL_DEPRECATEDIN_3_0 ossl_ENGINE *ossl_DSA_get0_engine(ossl_DSA *d);

ossl_OSSL_DEPRECATEDIN_3_0 ossl_DSA_METHOD *ossl_DSA_meth_new(const char *name, int flags);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_DSA_meth_free(ossl_DSA_METHOD *dsam);
ossl_OSSL_DEPRECATEDIN_3_0 ossl_DSA_METHOD *ossl_DSA_meth_dup(const ossl_DSA_METHOD *dsam);
ossl_OSSL_DEPRECATEDIN_3_0 const char *ossl_DSA_meth_get0_name(const ossl_DSA_METHOD *dsam);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_meth_set1_name(ossl_DSA_METHOD *dsam,
                                             const char *name);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_meth_get_flags(const ossl_DSA_METHOD *dsam);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_meth_set_flags(ossl_DSA_METHOD *dsam, int flags);
ossl_OSSL_DEPRECATEDIN_3_0 void *ossl_DSA_meth_get0_app_data(const ossl_DSA_METHOD *dsam);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_meth_set0_app_data(ossl_DSA_METHOD *dsam,
                                                 void *app_data);
ossl_OSSL_DEPRECATEDIN_3_0 ossl_DSA_SIG *(*ossl_DSA_meth_get_sign(const ossl_DSA_METHOD *dsam))
        (const unsigned char *, int, ossl_DSA *);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_meth_set_sign(ossl_DSA_METHOD *dsam,
                       ossl_DSA_SIG *(*sign) (const unsigned char *, int, ossl_DSA *));
ossl_OSSL_DEPRECATEDIN_3_0 int (*ossl_DSA_meth_get_sign_setup(const ossl_DSA_METHOD *dsam))
        (ossl_DSA *, ossl_BN_CTX *, ossl_BIGNUM **, ossl_BIGNUM **);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_meth_set_sign_setup(ossl_DSA_METHOD *dsam,
        int (*sign_setup) (ossl_DSA *, ossl_BN_CTX *, ossl_BIGNUM **, ossl_BIGNUM **));
ossl_OSSL_DEPRECATEDIN_3_0 int (*ossl_DSA_meth_get_verify(const ossl_DSA_METHOD *dsam))
        (const unsigned char *, int, ossl_DSA_SIG *, ossl_DSA *);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_meth_set_verify(ossl_DSA_METHOD *dsam,
    int (*verify) (const unsigned char *, int, ossl_DSA_SIG *, ossl_DSA *));
ossl_OSSL_DEPRECATEDIN_3_0 int (*ossl_DSA_meth_get_mod_exp(const ossl_DSA_METHOD *dsam))
        (ossl_DSA *, ossl_BIGNUM *, const ossl_BIGNUM *, const ossl_BIGNUM *, const ossl_BIGNUM *,
         const ossl_BIGNUM *, const ossl_BIGNUM *, ossl_BN_CTX *, ossl_BN_MONT_CTX *);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_meth_set_mod_exp(ossl_DSA_METHOD *dsam,
    int (*mod_exp) (ossl_DSA *, ossl_BIGNUM *, const ossl_BIGNUM *, const ossl_BIGNUM *,
                    const ossl_BIGNUM *, const ossl_BIGNUM *, const ossl_BIGNUM *, ossl_BN_CTX *,
                    ossl_BN_MONT_CTX *));
ossl_OSSL_DEPRECATEDIN_3_0 int (*ossl_DSA_meth_get_bn_mod_exp(const ossl_DSA_METHOD *dsam))
    (ossl_DSA *, ossl_BIGNUM *, const ossl_BIGNUM *, const ossl_BIGNUM *, const ossl_BIGNUM *,
     ossl_BN_CTX *, ossl_BN_MONT_CTX *);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_meth_set_bn_mod_exp(ossl_DSA_METHOD *dsam,
    int (*bn_mod_exp) (ossl_DSA *, ossl_BIGNUM *, const ossl_BIGNUM *, const ossl_BIGNUM *,
                       const ossl_BIGNUM *, ossl_BN_CTX *, ossl_BN_MONT_CTX *));
ossl_OSSL_DEPRECATEDIN_3_0 int (*ossl_DSA_meth_get_init(const ossl_DSA_METHOD *dsam))(ossl_DSA *);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_meth_set_init(ossl_DSA_METHOD *dsam,
                                            int (*init)(ossl_DSA *));
ossl_OSSL_DEPRECATEDIN_3_0 int (*ossl_DSA_meth_get_finish(const ossl_DSA_METHOD *dsam))(ossl_DSA *);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_meth_set_finish(ossl_DSA_METHOD *dsam,
                                              int (*finish)(ossl_DSA *));
ossl_OSSL_DEPRECATEDIN_3_0 int (*ossl_DSA_meth_get_paramgen(const ossl_DSA_METHOD *dsam))
        (ossl_DSA *, int, const unsigned char *, int, int *, unsigned long *,
         ossl_BN_GENCB *);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_meth_set_paramgen(ossl_DSA_METHOD *dsam,
        int (*paramgen) (ossl_DSA *, int, const unsigned char *, int, int *,
                         unsigned long *, ossl_BN_GENCB *));
ossl_OSSL_DEPRECATEDIN_3_0 int (*ossl_DSA_meth_get_keygen(const ossl_DSA_METHOD *dsam))(ossl_DSA *);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DSA_meth_set_keygen(ossl_DSA_METHOD *dsam,
                                              int (*keygen) (ossl_DSA *));

#  endif
# endif
# ifdef  __cplusplus
}
# endif
#endif
