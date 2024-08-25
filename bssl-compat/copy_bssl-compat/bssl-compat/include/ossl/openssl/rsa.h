/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_RSA_H
# define ossl_OPENSSL_RSA_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_RSA_H
# endif

# include "ossl/openssl/opensslconf.h"

# include "ossl/openssl/asn1.h"
# include "ossl/openssl/bio.h"
# include "ossl/openssl/crypto.h"
# include "ossl/openssl/types.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_1_1_0
#  include "ossl/openssl/bn.h"
# endif
# include "ossl/openssl/rsaerr.h"
# include "ossl/openssl/safestack.h"

# ifdef  __cplusplus
extern "C" {
# endif

# ifndef ossl_OPENSSL_RSA_MAX_MODULUS_BITS
#  define ossl_OPENSSL_RSA_MAX_MODULUS_BITS   16384
# endif

# define ossl_RSA_3   0x3L
# define ossl_RSA_F4  0x10001L

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
/* The types ossl_RSA and ossl_RSA_METHOD are defined in ossl_typ.h */

#  define ossl_OPENSSL_RSA_FIPS_MIN_MODULUS_BITS 2048

#  ifndef ossl_OPENSSL_RSA_SMALL_MODULUS_BITS
#   define ossl_OPENSSL_RSA_SMALL_MODULUS_BITS 3072
#  endif

/* exponent limit enforced for "large" modulus only */
#  ifndef ossl_OPENSSL_RSA_MAX_PUBEXP_BITS
#   define ossl_OPENSSL_RSA_MAX_PUBEXP_BITS    64
#  endif
/* based on RFC 8017 appendix A.1.2 */
#  define ossl_RSA_ASN1_VERSION_DEFAULT        0
#  define ossl_RSA_ASN1_VERSION_MULTI          1

#  define ossl_RSA_DEFAULT_PRIME_NUM           2

#  define ossl_RSA_METHOD_FLAG_NO_CHECK        0x0001
#  define ossl_RSA_FLAG_CACHE_PUBLIC           0x0002
#  define ossl_RSA_FLAG_CACHE_PRIVATE          0x0004
#  define ossl_RSA_FLAG_BLINDING               0x0008
#  define ossl_RSA_FLAG_THREAD_SAFE            0x0010
/*
 * This flag means the private key operations will be handled by rsa_mod_exp
 * and that they do not depend on the private key components being present:
 * for example a key stored in external hardware. Without this flag
 * bn_mod_exp gets called when private key components are absent.
 */
#  define ossl_RSA_FLAG_EXT_PKEY               0x0020

/*
 * new with 0.9.6j and 0.9.7b; the built-in
 * ossl_RSA implementation now uses blinding by
 * default (ignoring ossl_RSA_FLAG_BLINDING),
 * but other engines might not need it
 */
#  define ossl_RSA_FLAG_NO_BLINDING            0x0080
# endif /* ossl_OPENSSL_NO_DEPRECATED_3_0 */
/*
 * Does nothing. Previously this switched off constant time behaviour.
 */
# ifndef ossl_OPENSSL_NO_DEPRECATED_1_1_0
#  define ossl_RSA_FLAG_NO_CONSTTIME           0x0000
# endif
/* deprecated name for the flag*/
/*
 * new with 0.9.7h; the built-in ossl_RSA
 * implementation now uses constant time
 * modular exponentiation for secret exponents
 * by default. This flag causes the
 * faster variable sliding window method to
 * be used for all exponents.
 */
# ifndef ossl_OPENSSL_NO_DEPRECATED_0_9_8
#  define ossl_RSA_FLAG_NO_EXP_CONSTTIME ossl_RSA_FLAG_NO_CONSTTIME
# endif

/*-
 * New with 3.0: use part of the flags to denote exact type of ossl_RSA key,
 * some of which are limited to specific signature and encryption schemes.
 * These different types share the same ossl_RSA structure, but indicate the
 * use of certain fields in that structure.
 * Currently known are:
 * ossl_RSA          - this is the "normal" unlimited ossl_RSA structure (typenum 0)
 * RSASSA-PSS   - indicates that the PSS parameters are used.
 * RSAES-OAEP   - no specific field used for the moment, but OAEP padding
 *                is expected.  (currently unused)
 *
 * 4 bits allow for 16 types
 */
# define ossl_RSA_FLAG_TYPE_MASK            0xF000
# define ossl_RSA_FLAG_TYPE_RSA             0x0000
# define ossl_RSA_FLAG_TYPE_RSASSAPSS       0x1000
# define ossl_RSA_FLAG_TYPE_RSAESOAEP       0x2000

int ossl_EVP_PKEY_CTX_set_rsa_padding(ossl_EVP_PKEY_CTX *ctx, int pad_mode);
int ossl_EVP_PKEY_CTX_get_rsa_padding(ossl_EVP_PKEY_CTX *ctx, int *pad_mode);

int ossl_EVP_PKEY_CTX_set_rsa_pss_saltlen(ossl_EVP_PKEY_CTX *ctx, int saltlen);
int ossl_EVP_PKEY_CTX_get_rsa_pss_saltlen(ossl_EVP_PKEY_CTX *ctx, int *saltlen);

int ossl_EVP_PKEY_CTX_set_rsa_keygen_bits(ossl_EVP_PKEY_CTX *ctx, int bits);
int ossl_EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ossl_EVP_PKEY_CTX *ctx, ossl_BIGNUM *pubexp);
int ossl_EVP_PKEY_CTX_set_rsa_keygen_primes(ossl_EVP_PKEY_CTX *ctx, int primes);
int ossl_EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ossl_EVP_PKEY_CTX *ctx, int saltlen);
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_PKEY_CTX_set_rsa_keygen_pubexp(ossl_EVP_PKEY_CTX *ctx, ossl_BIGNUM *pubexp);
# endif

/* Salt length matches digest */
# define ossl_RSA_PSS_SALTLEN_DIGEST -1
/* Verify only: auto detect salt length */
# define ossl_RSA_PSS_SALTLEN_AUTO   -2
/* Set salt length to maximum possible */
# define ossl_RSA_PSS_SALTLEN_MAX    -3
/* Old compatible max salt length for sign only */
# define ossl_RSA_PSS_SALTLEN_MAX_SIGN    -2

int ossl_EVP_PKEY_CTX_set_rsa_mgf1_md(ossl_EVP_PKEY_CTX *ctx, const ossl_EVP_MD *md);
int ossl_EVP_PKEY_CTX_set_rsa_mgf1_md_name(ossl_EVP_PKEY_CTX *ctx, const char *mdname,
                                      const char *mdprops);
int ossl_EVP_PKEY_CTX_get_rsa_mgf1_md(ossl_EVP_PKEY_CTX *ctx, const ossl_EVP_MD **md);
int ossl_EVP_PKEY_CTX_get_rsa_mgf1_md_name(ossl_EVP_PKEY_CTX *ctx, char *name,
                                      size_t namelen);
int ossl_EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ossl_EVP_PKEY_CTX *ctx, const ossl_EVP_MD *md);
int ossl_EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(ossl_EVP_PKEY_CTX *ctx,
                                                 const char *mdname);

int ossl_EVP_PKEY_CTX_set_rsa_pss_keygen_md(ossl_EVP_PKEY_CTX *ctx, const ossl_EVP_MD *md);
int ossl_EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(ossl_EVP_PKEY_CTX *ctx,
                                            const char *mdname,
                                            const char *mdprops);

int ossl_EVP_PKEY_CTX_set_rsa_oaep_md(ossl_EVP_PKEY_CTX *ctx, const ossl_EVP_MD *md);
int ossl_EVP_PKEY_CTX_set_rsa_oaep_md_name(ossl_EVP_PKEY_CTX *ctx, const char *mdname,
                                      const char *mdprops);
int ossl_EVP_PKEY_CTX_get_rsa_oaep_md(ossl_EVP_PKEY_CTX *ctx, const ossl_EVP_MD **md);
int ossl_EVP_PKEY_CTX_get_rsa_oaep_md_name(ossl_EVP_PKEY_CTX *ctx, char *name,
                                      size_t namelen);
int ossl_EVP_PKEY_CTX_set0_rsa_oaep_label(ossl_EVP_PKEY_CTX *ctx, void *label, int llen);
int ossl_EVP_PKEY_CTX_get0_rsa_oaep_label(ossl_EVP_PKEY_CTX *ctx, unsigned char **label);

# define ossl_EVP_PKEY_CTRL_RSA_PADDING       (ossl_EVP_PKEY_ALG_CTRL + 1)
# define ossl_EVP_PKEY_CTRL_RSA_PSS_SALTLEN   (ossl_EVP_PKEY_ALG_CTRL + 2)

# define ossl_EVP_PKEY_CTRL_RSA_KEYGEN_BITS   (ossl_EVP_PKEY_ALG_CTRL + 3)
# define ossl_EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP (ossl_EVP_PKEY_ALG_CTRL + 4)
# define ossl_EVP_PKEY_CTRL_RSA_MGF1_MD       (ossl_EVP_PKEY_ALG_CTRL + 5)

# define ossl_EVP_PKEY_CTRL_GET_RSA_PADDING           (ossl_EVP_PKEY_ALG_CTRL + 6)
# define ossl_EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN       (ossl_EVP_PKEY_ALG_CTRL + 7)
# define ossl_EVP_PKEY_CTRL_GET_RSA_MGF1_MD           (ossl_EVP_PKEY_ALG_CTRL + 8)

# define ossl_EVP_PKEY_CTRL_RSA_OAEP_MD       (ossl_EVP_PKEY_ALG_CTRL + 9)
# define ossl_EVP_PKEY_CTRL_RSA_OAEP_LABEL    (ossl_EVP_PKEY_ALG_CTRL + 10)

# define ossl_EVP_PKEY_CTRL_GET_RSA_OAEP_MD   (ossl_EVP_PKEY_ALG_CTRL + 11)
# define ossl_EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL (ossl_EVP_PKEY_ALG_CTRL + 12)

# define ossl_EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES  (ossl_EVP_PKEY_ALG_CTRL + 13)

# define ossl_RSA_PKCS1_PADDING          1
# define ossl_RSA_NO_PADDING             3
# define ossl_RSA_PKCS1_OAEP_PADDING     4
# define ossl_RSA_X931_PADDING           5

/* EVP_PKEY_ only */
# define ossl_RSA_PKCS1_PSS_PADDING      6
# define ossl_RSA_PKCS1_WITH_TLS_PADDING 7

# define ossl_RSA_PKCS1_PADDING_SIZE    11

# define ossl_RSA_set_app_data(s,arg)         ossl_RSA_set_ex_data(s,0,arg)
# define ossl_RSA_get_app_data(s)             ossl_RSA_get_ex_data(s,0)

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 ossl_RSA *ossl_RSA_new(void);
ossl_OSSL_DEPRECATEDIN_3_0 ossl_RSA *ossl_RSA_new_method(ossl_ENGINE *engine);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_bits(const ossl_RSA *rsa);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_size(const ossl_RSA *rsa);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_security_bits(const ossl_RSA *rsa);

ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_set0_key(ossl_RSA *r, ossl_BIGNUM *n, ossl_BIGNUM *e, ossl_BIGNUM *d);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_set0_factors(ossl_RSA *r, ossl_BIGNUM *p, ossl_BIGNUM *q);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_set0_crt_params(ossl_RSA *r,
                                              ossl_BIGNUM *dmp1, ossl_BIGNUM *dmq1,
                                              ossl_BIGNUM *iqmp);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_set0_multi_prime_params(ossl_RSA *r,
                                                      ossl_BIGNUM *primes[],
                                                      ossl_BIGNUM *exps[],
                                                      ossl_BIGNUM *coeffs[],
                                                      int pnum);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_RSA_get0_key(const ossl_RSA *r,
                                        const ossl_BIGNUM **n, const ossl_BIGNUM **e,
                                        const ossl_BIGNUM **d);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_RSA_get0_factors(const ossl_RSA *r,
                                            const ossl_BIGNUM **p, const ossl_BIGNUM **q);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_get_multi_prime_extra_count(const ossl_RSA *r);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_get0_multi_prime_factors(const ossl_RSA *r,
                                                       const ossl_BIGNUM *primes[]);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_RSA_get0_crt_params(const ossl_RSA *r,
                                               const ossl_BIGNUM **dmp1,
                                               const ossl_BIGNUM **dmq1,
                                               const ossl_BIGNUM **iqmp);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_get0_multi_prime_crt_params(const ossl_RSA *r, const ossl_BIGNUM *exps[],
                                    const ossl_BIGNUM *coeffs[]);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_BIGNUM *ossl_RSA_get0_n(const ossl_RSA *d);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_BIGNUM *ossl_RSA_get0_e(const ossl_RSA *d);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_BIGNUM *ossl_RSA_get0_d(const ossl_RSA *d);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_BIGNUM *ossl_RSA_get0_p(const ossl_RSA *d);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_BIGNUM *ossl_RSA_get0_q(const ossl_RSA *d);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_BIGNUM *ossl_RSA_get0_dmp1(const ossl_RSA *r);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_BIGNUM *ossl_RSA_get0_dmq1(const ossl_RSA *r);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_BIGNUM *ossl_RSA_get0_iqmp(const ossl_RSA *r);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_RSA_PSS_PARAMS *ossl_RSA_get0_pss_params(const ossl_RSA *r);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_RSA_clear_flags(ossl_RSA *r, int flags);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_test_flags(const ossl_RSA *r, int flags);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_RSA_set_flags(ossl_RSA *r, int flags);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_get_version(ossl_RSA *r);
ossl_OSSL_DEPRECATEDIN_3_0 ossl_ENGINE *ossl_RSA_get0_engine(const ossl_RSA *r);
# endif  /* !ossl_OPENSSL_NO_DEPRECATED_3_0 */

# define ossl_EVP_RSA_gen(bits) \
    ossl_EVP_PKEY_Q_keygen(NULL, NULL, "ossl_RSA", (size_t)(0 + (bits)))

/* Deprecated version */
# ifndef ossl_OPENSSL_NO_DEPRECATED_0_9_8
ossl_OSSL_DEPRECATEDIN_0_9_8 ossl_RSA *ossl_RSA_generate_key(int bits, unsigned long e, void
                                              (*callback) (int, int, void *),
                                              void *cb_arg);
# endif

/* New version */
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_generate_key_ex(ossl_RSA *rsa, int bits, ossl_BIGNUM *e,
                                              ossl_BN_GENCB *cb);
/* Multi-prime version */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_generate_multi_prime_key(ossl_RSA *rsa, int bits,
                                                       int primes, ossl_BIGNUM *e,
                                                       ossl_BN_GENCB *cb);

ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_X931_derive_ex(ossl_RSA *rsa, ossl_BIGNUM *p1, ossl_BIGNUM *p2,
                       ossl_BIGNUM *q1, ossl_BIGNUM *q2,
                       const ossl_BIGNUM *Xp1, const ossl_BIGNUM *Xp2,
                       const ossl_BIGNUM *Xp, const ossl_BIGNUM *Xq1,
                       const ossl_BIGNUM *Xq2, const ossl_BIGNUM *Xq,
                       const ossl_BIGNUM *e, ossl_BN_GENCB *cb);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_X931_generate_key_ex(ossl_RSA *rsa, int bits,
                                                   const ossl_BIGNUM *e,
                                                   ossl_BN_GENCB *cb);

ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_check_key(const ossl_RSA *);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_check_key_ex(const ossl_RSA *, ossl_BN_GENCB *cb);
        /* next 4 return -1 on error */
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_public_encrypt(int flen, const unsigned char *from, unsigned char *to,
                       ossl_RSA *rsa, int padding);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_private_encrypt(int flen, const unsigned char *from, unsigned char *to,
                        ossl_RSA *rsa, int padding);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_public_decrypt(int flen, const unsigned char *from, unsigned char *to,
                       ossl_RSA *rsa, int padding);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_private_decrypt(int flen, const unsigned char *from, unsigned char *to,
                        ossl_RSA *rsa, int padding);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_RSA_free(ossl_RSA *r);
/* "up" the ossl_RSA object's reference count */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_up_ref(ossl_RSA *r);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_flags(const ossl_RSA *r);

ossl_OSSL_DEPRECATEDIN_3_0 void ossl_RSA_set_default_method(const ossl_RSA_METHOD *meth);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_RSA_METHOD *ossl_RSA_get_default_method(void);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_RSA_METHOD *ossl_RSA_null_method(void);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_RSA_METHOD *ossl_RSA_get_method(const ossl_RSA *rsa);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_set_method(ossl_RSA *rsa, const ossl_RSA_METHOD *meth);

/* these are the actual ossl_RSA functions */
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_RSA_METHOD *ossl_RSA_PKCS1_OpenSSL(void);

ossl_DECLARE_ASN1_ENCODE_FUNCTIONS_name_attr(ossl_OSSL_DEPRECATEDIN_3_0,
                                        ossl_RSA, ossl_RSAPublicKey)
ossl_DECLARE_ASN1_ENCODE_FUNCTIONS_name_attr(ossl_OSSL_DEPRECATEDIN_3_0,
                                        ossl_RSA, ossl_RSAPrivateKey)
# endif  /* !ossl_OPENSSL_NO_DEPRECATED_3_0 */

int ossl_RSA_pkey_ctx_ctrl(ossl_EVP_PKEY_CTX *ctx, int optype, int cmd, int p1, void *p2);

struct ossl_rsa_pss_params_st {
    ossl_X509_ALGOR *hashAlgorithm;
    ossl_X509_ALGOR *maskGenAlgorithm;
    ossl_ASN1_INTEGER *saltLength;
    ossl_ASN1_INTEGER *trailerField;
    /* Decoded hash algorithm from maskGenAlgorithm */
    ossl_X509_ALGOR *maskHash;
};

ossl_DECLARE_ASN1_FUNCTIONS(ossl_RSA_PSS_PARAMS)
ossl_DECLARE_ASN1_DUP_FUNCTION(ossl_RSA_PSS_PARAMS)

typedef struct ossl_rsa_oaep_params_st {
    ossl_X509_ALGOR *hashFunc;
    ossl_X509_ALGOR *maskGenFunc;
    ossl_X509_ALGOR *pSourceFunc;
    /* Decoded hash algorithm from maskGenFunc */
    ossl_X509_ALGOR *maskHash;
} ossl_RSA_OAEP_PARAMS;

ossl_DECLARE_ASN1_FUNCTIONS(ossl_RSA_OAEP_PARAMS)

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  ifndef ossl_OPENSSL_NO_STDIO
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_print_fp(FILE *fp, const ossl_RSA *r, int offset);
#  endif

ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_print(ossl_BIO *bp, const ossl_RSA *r, int offset);

/*
 * The following 2 functions sign and verify a ossl_X509_SIG ASN1 object inside
 * PKCS#1 padded ossl_RSA encryption
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_sign(int type, const unsigned char *m,
                                   unsigned int m_length, unsigned char *sigret,
                                   unsigned int *siglen, ossl_RSA *rsa);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_verify(int type, const unsigned char *m,
                                     unsigned int m_length,
                                     const unsigned char *sigbuf,
                                     unsigned int siglen, ossl_RSA *rsa);

/*
 * The following 2 function sign and verify a ossl_ASN1_OCTET_STRING object inside
 * PKCS#1 padded ossl_RSA encryption
 */
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_sign_ASN1_OCTET_STRING(int type,
                               const unsigned char *m, unsigned int m_length,
                               unsigned char *sigret, unsigned int *siglen,
                               ossl_RSA *rsa);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_verify_ASN1_OCTET_STRING(int type,
                                 const unsigned char *m, unsigned int m_length,
                                 unsigned char *sigbuf, unsigned int siglen,
                                 ossl_RSA *rsa);

ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_blinding_on(ossl_RSA *rsa, ossl_BN_CTX *ctx);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_RSA_blinding_off(ossl_RSA *rsa);
ossl_OSSL_DEPRECATEDIN_3_0 ossl_BN_BLINDING *ossl_RSA_setup_blinding(ossl_RSA *rsa, ossl_BN_CTX *ctx);

ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_padding_add_PKCS1_type_1(unsigned char *to, int tlen,
                                 const unsigned char *f, int fl);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_padding_check_PKCS1_type_1(unsigned char *to, int tlen,
                                   const unsigned char *f, int fl,
                                   int rsa_len);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_padding_add_PKCS1_type_2(unsigned char *to, int tlen,
                                 const unsigned char *f, int fl);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_padding_check_PKCS1_type_2(unsigned char *to, int tlen,
                                   const unsigned char *f, int fl,
                                   int rsa_len);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_PKCS1_MGF1(unsigned char *mask, long len,
                                     const unsigned char *seed, long seedlen,
                                     const ossl_EVP_MD *dgst);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_padding_add_PKCS1_OAEP(unsigned char *to, int tlen,
                               const unsigned char *f, int fl,
                               const unsigned char *p, int pl);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_padding_check_PKCS1_OAEP(unsigned char *to, int tlen,
                                 const unsigned char *f, int fl, int rsa_len,
                                 const unsigned char *p, int pl);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_padding_add_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
                                    const unsigned char *from, int flen,
                                    const unsigned char *param, int plen,
                                    const ossl_EVP_MD *md, const ossl_EVP_MD *mgf1md);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_padding_check_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
                                      const unsigned char *from, int flen,
                                      int num,
                                      const unsigned char *param, int plen,
                                      const ossl_EVP_MD *md, const ossl_EVP_MD *mgf1md);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_padding_add_none(unsigned char *to, int tlen,
                                               const unsigned char *f, int fl);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_padding_check_none(unsigned char *to, int tlen,
                                                 const unsigned char *f, int fl,
                                                 int rsa_len);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_padding_add_X931(unsigned char *to, int tlen,
                                               const unsigned char *f, int fl);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_padding_check_X931(unsigned char *to, int tlen,
                                                 const unsigned char *f, int fl,
                                                 int rsa_len);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_X931_hash_id(int nid);

ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_verify_PKCS1_PSS(ossl_RSA *rsa, const unsigned char *mHash,
                         const ossl_EVP_MD *Hash, const unsigned char *EM,
                         int sLen);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_padding_add_PKCS1_PSS(ossl_RSA *rsa, unsigned char *EM,
                              const unsigned char *mHash, const ossl_EVP_MD *Hash,
                              int sLen);

ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_verify_PKCS1_PSS_mgf1(ossl_RSA *rsa, const unsigned char *mHash,
                              const ossl_EVP_MD *Hash, const ossl_EVP_MD *mgf1Hash,
                              const unsigned char *EM, int sLen);

ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_padding_add_PKCS1_PSS_mgf1(ossl_RSA *rsa, unsigned char *EM,
                                   const unsigned char *mHash,
                                   const ossl_EVP_MD *Hash, const ossl_EVP_MD *mgf1Hash,
                                   int sLen);

# define ossl_RSA_get_ex_new_index(l, p, newf, dupf, freef) \
    ossl_CRYPTO_get_ex_new_index(ossl_CRYPTO_EX_INDEX_RSA, l, p, newf, dupf, freef)
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_set_ex_data(ossl_RSA *r, int idx, void *arg);
ossl_OSSL_DEPRECATEDIN_3_0 void *ossl_RSA_get_ex_data(const ossl_RSA *r, int idx);

ossl_DECLARE_ASN1_DUP_FUNCTION_name_attr(ossl_OSSL_DEPRECATEDIN_3_0, ossl_RSA, ossl_RSAPublicKey)
ossl_DECLARE_ASN1_DUP_FUNCTION_name_attr(ossl_OSSL_DEPRECATEDIN_3_0, ossl_RSA, ossl_RSAPrivateKey)

/*
 * If this flag is set the ossl_RSA method is FIPS compliant and can be used in
 * FIPS mode. This is set in the validated module method. If an application
 * sets this flag in its own methods it is its responsibility to ensure the
 * result is compliant.
 */

#  define ossl_RSA_FLAG_FIPS_METHOD                    0x0400

/*
 * If this flag is set the operations normally disabled in FIPS mode are
 * permitted it is then the applications responsibility to ensure that the
 * usage is compliant.
 */

#  define ossl_RSA_FLAG_NON_FIPS_ALLOW                 0x0400
/*
 * Application has decided PRNG is good enough to generate a key: don't
 * check.
 */
#  define ossl_RSA_FLAG_CHECKED                        0x0800

ossl_OSSL_DEPRECATEDIN_3_0 ossl_RSA_METHOD *ossl_RSA_meth_new(const char *name, int flags);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_RSA_meth_free(ossl_RSA_METHOD *meth);
ossl_OSSL_DEPRECATEDIN_3_0 ossl_RSA_METHOD *ossl_RSA_meth_dup(const ossl_RSA_METHOD *meth);
ossl_OSSL_DEPRECATEDIN_3_0 const char *ossl_RSA_meth_get0_name(const ossl_RSA_METHOD *meth);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_meth_set1_name(ossl_RSA_METHOD *meth,
                                             const char *name);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_meth_get_flags(const ossl_RSA_METHOD *meth);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_meth_set_flags(ossl_RSA_METHOD *meth, int flags);
ossl_OSSL_DEPRECATEDIN_3_0 void *ossl_RSA_meth_get0_app_data(const ossl_RSA_METHOD *meth);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_RSA_meth_set0_app_data(ossl_RSA_METHOD *meth,
                                                 void *app_data);
ossl_OSSL_DEPRECATEDIN_3_0
int (*ossl_RSA_meth_get_pub_enc(const ossl_RSA_METHOD *meth)) (int flen,
                                                     const unsigned char *from,
                                                     unsigned char *to,
                                                     ossl_RSA *rsa, int padding);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_meth_set_pub_enc(ossl_RSA_METHOD *rsa,
                         int (*pub_enc) (int flen, const unsigned char *from,
                                         unsigned char *to, ossl_RSA *rsa,
                                         int padding));
ossl_OSSL_DEPRECATEDIN_3_0
int (*ossl_RSA_meth_get_pub_dec(const ossl_RSA_METHOD *meth)) (int flen,
                                                     const unsigned char *from,
                                                     unsigned char *to,
                                                     ossl_RSA *rsa, int padding);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_meth_set_pub_dec(ossl_RSA_METHOD *rsa,
                         int (*pub_dec) (int flen, const unsigned char *from,
                                         unsigned char *to, ossl_RSA *rsa,
                                         int padding));
ossl_OSSL_DEPRECATEDIN_3_0
int (*ossl_RSA_meth_get_priv_enc(const ossl_RSA_METHOD *meth)) (int flen,
                                                      const unsigned char *from,
                                                      unsigned char *to,
                                                      ossl_RSA *rsa, int padding);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_meth_set_priv_enc(ossl_RSA_METHOD *rsa,
                          int (*priv_enc) (int flen, const unsigned char *from,
                                           unsigned char *to, ossl_RSA *rsa,
                                           int padding));
ossl_OSSL_DEPRECATEDIN_3_0
int (*ossl_RSA_meth_get_priv_dec(const ossl_RSA_METHOD *meth)) (int flen,
                                                      const unsigned char *from,
                                                      unsigned char *to,
                                                      ossl_RSA *rsa, int padding);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_meth_set_priv_dec(ossl_RSA_METHOD *rsa,
                          int (*priv_dec) (int flen, const unsigned char *from,
                                           unsigned char *to, ossl_RSA *rsa,
                                           int padding));
ossl_OSSL_DEPRECATEDIN_3_0
int (*ossl_RSA_meth_get_mod_exp(const ossl_RSA_METHOD *meth)) (ossl_BIGNUM *r0,
                                                     const ossl_BIGNUM *i,
                                                     ossl_RSA *rsa, ossl_BN_CTX *ctx);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_meth_set_mod_exp(ossl_RSA_METHOD *rsa,
                         int (*mod_exp) (ossl_BIGNUM *r0, const ossl_BIGNUM *i, ossl_RSA *rsa,
                                         ossl_BN_CTX *ctx));
ossl_OSSL_DEPRECATEDIN_3_0
int (*ossl_RSA_meth_get_bn_mod_exp(const ossl_RSA_METHOD *meth)) (ossl_BIGNUM *r,
                                                        const ossl_BIGNUM *a,
                                                        const ossl_BIGNUM *p,
                                                        const ossl_BIGNUM *m,
                                                        ossl_BN_CTX *ctx,
                                                        ossl_BN_MONT_CTX *m_ctx);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_meth_set_bn_mod_exp(ossl_RSA_METHOD *rsa,
                            int (*bn_mod_exp) (ossl_BIGNUM *r,
                                               const ossl_BIGNUM *a,
                                               const ossl_BIGNUM *p,
                                               const ossl_BIGNUM *m,
                                               ossl_BN_CTX *ctx,
                                               ossl_BN_MONT_CTX *m_ctx));
ossl_OSSL_DEPRECATEDIN_3_0
int (*ossl_RSA_meth_get_init(const ossl_RSA_METHOD *meth)) (ossl_RSA *rsa);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_meth_set_init(ossl_RSA_METHOD *rsa, int (*init) (ossl_RSA *rsa));
ossl_OSSL_DEPRECATEDIN_3_0
int (*ossl_RSA_meth_get_finish(const ossl_RSA_METHOD *meth)) (ossl_RSA *rsa);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_meth_set_finish(ossl_RSA_METHOD *rsa, int (*finish) (ossl_RSA *rsa));
ossl_OSSL_DEPRECATEDIN_3_0
int (*ossl_RSA_meth_get_sign(const ossl_RSA_METHOD *meth)) (int type,
                                                  const unsigned char *m,
                                                  unsigned int m_length,
                                                  unsigned char *sigret,
                                                  unsigned int *siglen,
                                                  const ossl_RSA *rsa);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_meth_set_sign(ossl_RSA_METHOD *rsa,
                      int (*sign) (int type, const unsigned char *m,
                                   unsigned int m_length,
                                   unsigned char *sigret, unsigned int *siglen,
                                   const ossl_RSA *rsa));
ossl_OSSL_DEPRECATEDIN_3_0
int (*ossl_RSA_meth_get_verify(const ossl_RSA_METHOD *meth)) (int dtype,
                                                    const unsigned char *m,
                                                    unsigned int m_length,
                                                    const unsigned char *sigbuf,
                                                    unsigned int siglen,
                                                    const ossl_RSA *rsa);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_meth_set_verify(ossl_RSA_METHOD *rsa,
                        int (*verify) (int dtype, const unsigned char *m,
                                       unsigned int m_length,
                                       const unsigned char *sigbuf,
                                       unsigned int siglen, const ossl_RSA *rsa));
ossl_OSSL_DEPRECATEDIN_3_0
int (*ossl_RSA_meth_get_keygen(const ossl_RSA_METHOD *meth)) (ossl_RSA *rsa, int bits,
                                                    ossl_BIGNUM *e, ossl_BN_GENCB *cb);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_meth_set_keygen(ossl_RSA_METHOD *rsa,
                        int (*keygen) (ossl_RSA *rsa, int bits, ossl_BIGNUM *e,
                                       ossl_BN_GENCB *cb));
ossl_OSSL_DEPRECATEDIN_3_0
int (*ossl_RSA_meth_get_multi_prime_keygen(const ossl_RSA_METHOD *meth)) (ossl_RSA *rsa,
                                                                int bits,
                                                                int primes,
                                                                ossl_BIGNUM *e,
                                                                ossl_BN_GENCB *cb);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_RSA_meth_set_multi_prime_keygen(ossl_RSA_METHOD *meth,
                                    int (*keygen) (ossl_RSA *rsa, int bits,
                                                   int primes, ossl_BIGNUM *e,
                                                   ossl_BN_GENCB *cb));
#endif  /* !ossl_OPENSSL_NO_DEPRECATED_3_0 */

# ifdef  __cplusplus
}
# endif
#endif
