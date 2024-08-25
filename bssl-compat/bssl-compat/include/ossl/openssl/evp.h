/*
 * Copyright 1995-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_EVP_H
# define ossl_OPENSSL_EVP_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_ENVELOPE_H
# endif

# include <stdarg.h>

# ifndef ossl_OPENSSL_NO_STDIO
#  include <stdio.h>
# endif

# include "ossl/openssl/opensslconf.h"
# include "ossl/openssl/types.h"
# include "ossl/openssl/core.h"
# include "ossl/openssl/core_dispatch.h"
# include "ossl/openssl/symhacks.h"
# include "ossl/openssl/bio.h"
# include "ossl/openssl/evperr.h"
# include "ossl/openssl/params.h"

# define ossl_EVP_MAX_MD_SIZE                 64/* longest known is ossl_SHA512 */
# define ossl_EVP_MAX_KEY_LENGTH              64
# define ossl_EVP_MAX_IV_LENGTH               16
# define ossl_EVP_MAX_BLOCK_LENGTH            32

# define ossl_PKCS5_SALT_LEN                  8
/* Default PKCS#5 iteration count */
# define ossl_PKCS5_DEFAULT_ITER              2048

# include "ossl/openssl/objects.h"

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_EVP_PK_RSA      0x0001
#  define ossl_EVP_PK_DSA      0x0002
#  define ossl_EVP_PK_DH       0x0004
#  define ossl_EVP_PK_EC       0x0008
#  define ossl_EVP_PKT_SIGN    0x0010
#  define ossl_EVP_PKT_ENC     0x0020
#  define ossl_EVP_PKT_EXCH    0x0040
#  define ossl_EVP_PKS_RSA     0x0100
#  define ossl_EVP_PKS_DSA     0x0200
#  define ossl_EVP_PKS_EC      0x0400
# endif

# define ossl_EVP_PKEY_NONE   ossl_NID_undef
# define ossl_EVP_PKEY_RSA    ossl_NID_rsaEncryption
# define ossl_EVP_PKEY_RSA2   ossl_NID_rsa
# define ossl_EVP_PKEY_RSA_PSS ossl_NID_rsassaPss
# define ossl_EVP_PKEY_DSA    ossl_NID_dsa
# define ossl_EVP_PKEY_DSA1   ossl_NID_dsa_2
# define ossl_EVP_PKEY_DSA2   ossl_NID_dsaWithSHA
# define ossl_EVP_PKEY_DSA3   ossl_NID_dsaWithSHA1
# define ossl_EVP_PKEY_DSA4   ossl_NID_dsaWithSHA1_2
# define ossl_EVP_PKEY_DH     ossl_NID_dhKeyAgreement
# define ossl_EVP_PKEY_DHX    ossl_NID_dhpublicnumber
# define ossl_EVP_PKEY_EC     ossl_NID_X9_62_id_ecPublicKey
# define ossl_EVP_PKEY_SM2    ossl_NID_sm2
# define ossl_EVP_PKEY_HMAC   ossl_NID_hmac
# define ossl_EVP_PKEY_CMAC   ossl_NID_cmac
# define ossl_EVP_PKEY_SCRYPT ossl_NID_id_scrypt
# define ossl_EVP_PKEY_TLS1_PRF ossl_NID_tls1_prf
# define ossl_EVP_PKEY_HKDF   ossl_NID_hkdf
# define ossl_EVP_PKEY_POLY1305 ossl_NID_poly1305
# define ossl_EVP_PKEY_SIPHASH ossl_NID_siphash
# define ossl_EVP_PKEY_X25519 ossl_NID_X25519
# define ossl_EVP_PKEY_ED25519 ossl_NID_ED25519
# define ossl_EVP_PKEY_X448 ossl_NID_X448
# define ossl_EVP_PKEY_ED448 ossl_NID_ED448
/* Special indicator that the object is uniquely provider side */
# define ossl_EVP_PKEY_KEYMGMT -1

/* Easy to use macros for ossl_EVP_PKEY related selections */
# define ossl_EVP_PKEY_KEY_PARAMETERS                                            \
    ( ossl_OSSL_KEYMGMT_SELECT_ALL_PARAMETERS )
# define ossl_EVP_PKEY_PRIVATE_KEY                                               \
    ( ossl_EVP_PKEY_KEY_PARAMETERS | ossl_OSSL_KEYMGMT_SELECT_PRIVATE_KEY )
# define ossl_EVP_PKEY_PUBLIC_KEY                                                \
    ( ossl_EVP_PKEY_KEY_PARAMETERS | ossl_OSSL_KEYMGMT_SELECT_PUBLIC_KEY )
# define ossl_EVP_PKEY_KEYPAIR                                                   \
    ( ossl_EVP_PKEY_PUBLIC_KEY | ossl_OSSL_KEYMGMT_SELECT_PRIVATE_KEY )

#ifdef  __cplusplus
extern "C" {
#endif

int ossl_EVP_set_default_properties(ossl_OSSL_LIB_CTX *libctx, const char *propq);
int ossl_EVP_default_properties_is_fips_enabled(ossl_OSSL_LIB_CTX *libctx);
int ossl_EVP_default_properties_enable_fips(ossl_OSSL_LIB_CTX *libctx, int enable);

# define ossl_EVP_PKEY_MO_SIGN        0x0001
# define ossl_EVP_PKEY_MO_VERIFY      0x0002
# define ossl_EVP_PKEY_MO_ENCRYPT     0x0004
# define ossl_EVP_PKEY_MO_DECRYPT     0x0008

# ifndef ossl_EVP_MD
#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 ossl_EVP_MD *ossl_EVP_MD_meth_new(int md_type, int pkey_type);
ossl_OSSL_DEPRECATEDIN_3_0 ossl_EVP_MD *ossl_EVP_MD_meth_dup(const ossl_EVP_MD *md);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_MD_meth_free(ossl_EVP_MD *md);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_MD_meth_set_input_blocksize(ossl_EVP_MD *md, int blocksize);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_MD_meth_set_result_size(ossl_EVP_MD *md, int resultsize);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_MD_meth_set_app_datasize(ossl_EVP_MD *md, int datasize);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_MD_meth_set_flags(ossl_EVP_MD *md, unsigned long flags);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_MD_meth_set_init(ossl_EVP_MD *md, int (*init)(ossl_EVP_MD_CTX *ctx));
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_MD_meth_set_update(ossl_EVP_MD *md, int (*update)(ossl_EVP_MD_CTX *ctx,
                                                     const void *data,
                                                     size_t count));
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_MD_meth_set_final(ossl_EVP_MD *md, int (*final)(ossl_EVP_MD_CTX *ctx,
                                                   unsigned char *md));
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_MD_meth_set_copy(ossl_EVP_MD *md, int (*copy)(ossl_EVP_MD_CTX *to,
                                                 const ossl_EVP_MD_CTX *from));
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_MD_meth_set_cleanup(ossl_EVP_MD *md, int (*cleanup)(ossl_EVP_MD_CTX *ctx));
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_MD_meth_set_ctrl(ossl_EVP_MD *md, int (*ctrl)(ossl_EVP_MD_CTX *ctx, int cmd,
                                                 int p1, void *p2));
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EVP_MD_meth_get_input_blocksize(const ossl_EVP_MD *md);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EVP_MD_meth_get_result_size(const ossl_EVP_MD *md);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EVP_MD_meth_get_app_datasize(const ossl_EVP_MD *md);
ossl_OSSL_DEPRECATEDIN_3_0 unsigned long ossl_EVP_MD_meth_get_flags(const ossl_EVP_MD *md);
ossl_OSSL_DEPRECATEDIN_3_0
int (*ossl_EVP_MD_meth_get_init(const ossl_EVP_MD *md))(ossl_EVP_MD_CTX *ctx);
ossl_OSSL_DEPRECATEDIN_3_0
int (*ossl_EVP_MD_meth_get_update(const ossl_EVP_MD *md))(ossl_EVP_MD_CTX *ctx,
                                                const void *data, size_t count);
ossl_OSSL_DEPRECATEDIN_3_0
int (*ossl_EVP_MD_meth_get_final(const ossl_EVP_MD *md))(ossl_EVP_MD_CTX *ctx,
                                               unsigned char *md);
ossl_OSSL_DEPRECATEDIN_3_0
int (*ossl_EVP_MD_meth_get_copy(const ossl_EVP_MD *md))(ossl_EVP_MD_CTX *to,
                                              const ossl_EVP_MD_CTX *from);
ossl_OSSL_DEPRECATEDIN_3_0
int (*ossl_EVP_MD_meth_get_cleanup(const ossl_EVP_MD *md))(ossl_EVP_MD_CTX *ctx);
ossl_OSSL_DEPRECATEDIN_3_0
int (*ossl_EVP_MD_meth_get_ctrl(const ossl_EVP_MD *md))(ossl_EVP_MD_CTX *ctx, int cmd,
                                              int p1, void *p2);
#  endif
/* digest can only handle a single block */
#  define ossl_EVP_MD_FLAG_ONESHOT     0x0001

/* digest is extensible-output function, XOF */
#  define ossl_EVP_MD_FLAG_XOF         0x0002

/* DigestAlgorithmIdentifier flags... */

#  define ossl_EVP_MD_FLAG_DIGALGID_MASK               0x0018

/* NULL or absent parameter accepted. Use NULL */

#  define ossl_EVP_MD_FLAG_DIGALGID_NULL               0x0000

/* NULL or absent parameter accepted. Use NULL for PKCS#1 otherwise absent */

#  define ossl_EVP_MD_FLAG_DIGALGID_ABSENT             0x0008

/* Custom handling via ctrl */

#  define ossl_EVP_MD_FLAG_DIGALGID_CUSTOM             0x0018

/* Note if suitable for use in FIPS mode */
#  define ossl_EVP_MD_FLAG_FIPS        0x0400

/* Digest ctrls */

#  define ossl_EVP_MD_CTRL_DIGALGID                    0x1
#  define ossl_EVP_MD_CTRL_MICALG                      0x2
#  define ossl_EVP_MD_CTRL_XOF_LEN                     0x3
#  define ossl_EVP_MD_CTRL_TLSTREE                     0x4

/* Minimum Algorithm specific ctrl value */

#  define ossl_EVP_MD_CTRL_ALG_CTRL                    0x1000

# endif                         /* !ossl_EVP_MD */

/* values for ossl_EVP_MD_CTX flags */

# define ossl_EVP_MD_CTX_FLAG_ONESHOT         0x0001/* digest update will be
                                                * called once only */
# define ossl_EVP_MD_CTX_FLAG_CLEANED         0x0002/* context has already been
                                                * cleaned */
# define ossl_EVP_MD_CTX_FLAG_REUSE           0x0004/* Don't free up ctx->md_data
                                                * in ossl_EVP_MD_CTX_reset */
/*
 * FIPS and pad options are ignored in 1.0.0, definitions are here so we
 * don't accidentally reuse the values for other purposes.
 */

/* This flag has no effect from openssl-3.0 onwards */
# define ossl_EVP_MD_CTX_FLAG_NON_FIPS_ALLOW  0x0008

/*
 * The following PAD options are also currently ignored in 1.0.0, digest
 * parameters are handled through ossl_EVP_DigestSign*() and ossl_EVP_DigestVerify*()
 * instead.
 */
# define ossl_EVP_MD_CTX_FLAG_PAD_MASK        0xF0/* ossl_RSA mode to use */
# define ossl_EVP_MD_CTX_FLAG_PAD_PKCS1       0x00/* PKCS#1 v1.5 mode */
# define ossl_EVP_MD_CTX_FLAG_PAD_X931        0x10/* X9.31 mode */
# define ossl_EVP_MD_CTX_FLAG_PAD_PSS         0x20/* PSS mode */

# define ossl_EVP_MD_CTX_FLAG_NO_INIT         0x0100/* Don't initialize md_data */
/*
 * Some functions such as ossl_EVP_DigestSign only finalise copies of internal
 * contexts so additional data can be included after the finalisation call.
 * This is inefficient if this functionality is not required: it is disabled
 * if the following flag is set.
 */
# define ossl_EVP_MD_CTX_FLAG_FINALISE        0x0200
/* NOTE: 0x0400 is reserved for internal usage */
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0
ossl_EVP_CIPHER *ossl_EVP_CIPHER_meth_new(int cipher_type, int block_size, int key_len);
ossl_OSSL_DEPRECATEDIN_3_0
ossl_EVP_CIPHER *ossl_EVP_CIPHER_meth_dup(const ossl_EVP_CIPHER *cipher);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_EVP_CIPHER_meth_free(ossl_EVP_CIPHER *cipher);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_CIPHER_meth_set_iv_length(ossl_EVP_CIPHER *cipher, int iv_len);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_CIPHER_meth_set_flags(ossl_EVP_CIPHER *cipher, unsigned long flags);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_CIPHER_meth_set_impl_ctx_size(ossl_EVP_CIPHER *cipher, int ctx_size);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_CIPHER_meth_set_init(ossl_EVP_CIPHER *cipher,
                             int (*init) (ossl_EVP_CIPHER_CTX *ctx,
                                          const unsigned char *key,
                                          const unsigned char *iv,
                                          int enc));
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_CIPHER_meth_set_do_cipher(ossl_EVP_CIPHER *cipher,
                                  int (*do_cipher) (ossl_EVP_CIPHER_CTX *ctx,
                                                    unsigned char *out,
                                                    const unsigned char *in,
                                                    size_t inl));
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_CIPHER_meth_set_cleanup(ossl_EVP_CIPHER *cipher,
                                int (*cleanup) (ossl_EVP_CIPHER_CTX *));
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_CIPHER_meth_set_set_asn1_params(ossl_EVP_CIPHER *cipher,
                                        int (*set_asn1_parameters) (ossl_EVP_CIPHER_CTX *,
                                                                    ossl_ASN1_TYPE *));
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_CIPHER_meth_set_get_asn1_params(ossl_EVP_CIPHER *cipher,
                                        int (*get_asn1_parameters) (ossl_EVP_CIPHER_CTX *,
                                                                    ossl_ASN1_TYPE *));
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_CIPHER_meth_set_ctrl(ossl_EVP_CIPHER *cipher,
                             int (*ctrl) (ossl_EVP_CIPHER_CTX *, int type,
                                          int arg, void *ptr));
ossl_OSSL_DEPRECATEDIN_3_0 int
(*ossl_EVP_CIPHER_meth_get_init(const ossl_EVP_CIPHER *cipher))(ossl_EVP_CIPHER_CTX *ctx,
                                                      const unsigned char *key,
                                                      const unsigned char *iv,
                                                      int enc);
ossl_OSSL_DEPRECATEDIN_3_0 int
(*ossl_EVP_CIPHER_meth_get_do_cipher(const ossl_EVP_CIPHER *cipher))(ossl_EVP_CIPHER_CTX *ctx,
                                                           unsigned char *out,
                                                           const unsigned char *in,
                                                           size_t inl);
ossl_OSSL_DEPRECATEDIN_3_0 int
(*ossl_EVP_CIPHER_meth_get_cleanup(const ossl_EVP_CIPHER *cipher))(ossl_EVP_CIPHER_CTX *);
ossl_OSSL_DEPRECATEDIN_3_0 int
(*ossl_EVP_CIPHER_meth_get_set_asn1_params(const ossl_EVP_CIPHER *cipher))(ossl_EVP_CIPHER_CTX *,
                                                                 ossl_ASN1_TYPE *);
ossl_OSSL_DEPRECATEDIN_3_0 int
(*ossl_EVP_CIPHER_meth_get_get_asn1_params(const ossl_EVP_CIPHER *cipher))(ossl_EVP_CIPHER_CTX *,
                                                                 ossl_ASN1_TYPE *);
ossl_OSSL_DEPRECATEDIN_3_0 int
(*ossl_EVP_CIPHER_meth_get_ctrl(const ossl_EVP_CIPHER *cipher))(ossl_EVP_CIPHER_CTX *, int type,
                                                      int arg, void *ptr);
# endif

/* Values for cipher flags */

/* Modes for ciphers */

# define         ossl_EVP_CIPH_STREAM_CIPHER          0x0
# define         ossl_EVP_CIPH_ECB_MODE               0x1
# define         ossl_EVP_CIPH_CBC_MODE               0x2
# define         ossl_EVP_CIPH_CFB_MODE               0x3
# define         ossl_EVP_CIPH_OFB_MODE               0x4
# define         ossl_EVP_CIPH_CTR_MODE               0x5
# define         ossl_EVP_CIPH_GCM_MODE               0x6
# define         ossl_EVP_CIPH_CCM_MODE               0x7
# define         ossl_EVP_CIPH_XTS_MODE               0x10001
# define         ossl_EVP_CIPH_WRAP_MODE              0x10002
# define         ossl_EVP_CIPH_OCB_MODE               0x10003
# define         ossl_EVP_CIPH_SIV_MODE               0x10004
# define         ossl_EVP_CIPH_MODE                   0xF0007
/* Set if variable length cipher */
# define         ossl_EVP_CIPH_VARIABLE_LENGTH        0x8
/* Set if the iv handling should be done by the cipher itself */
# define         ossl_EVP_CIPH_CUSTOM_IV              0x10
/* Set if the cipher's init() function should be called if key is NULL */
# define         ossl_EVP_CIPH_ALWAYS_CALL_INIT       0x20
/* Call ctrl() to init cipher parameters */
# define         ossl_EVP_CIPH_CTRL_INIT              0x40
/* Don't use standard key length function */
# define         ossl_EVP_CIPH_CUSTOM_KEY_LENGTH      0x80
/* Don't use standard block padding */
# define         ossl_EVP_CIPH_NO_PADDING             0x100
/* cipher handles random key generation */
# define         ossl_EVP_CIPH_RAND_KEY               0x200
/* cipher has its own additional copying logic */
# define         ossl_EVP_CIPH_CUSTOM_COPY            0x400
/* Don't use standard iv length function */
# define         ossl_EVP_CIPH_CUSTOM_IV_LENGTH       0x800
/* Legacy and no longer relevant: Allow use default ASN1 get/set iv */
# define         ossl_EVP_CIPH_FLAG_DEFAULT_ASN1      0
/* Free:                                         0x1000 */
/* Buffer length in bits not bytes: CFB1 mode only */
# define         ossl_EVP_CIPH_FLAG_LENGTH_BITS       0x2000
/* Deprecated FIPS flag: was 0x4000 */
# define         ossl_EVP_CIPH_FLAG_FIPS              0
/* Deprecated FIPS flag: was 0x8000 */
# define         ossl_EVP_CIPH_FLAG_NON_FIPS_ALLOW    0

/*
 * Cipher handles any and all padding logic as well as finalisation.
 */
# define         ossl_EVP_CIPH_FLAG_CTS               0x4000
# define         ossl_EVP_CIPH_FLAG_CUSTOM_CIPHER     0x100000
# define         ossl_EVP_CIPH_FLAG_AEAD_CIPHER       0x200000
# define         ossl_EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK 0x400000
/* Cipher can handle pipeline operations */
# define         ossl_EVP_CIPH_FLAG_PIPELINE          0X800000
/* For provider implementations that handle  ASN1 get/set param themselves */
# define         ossl_EVP_CIPH_FLAG_CUSTOM_ASN1       0x1000000
/* For ciphers generating unprotected CMS attributes */
# define         ossl_EVP_CIPH_FLAG_CIPHER_WITH_MAC   0x2000000
/* For supplementary wrap cipher support */
# define         ossl_EVP_CIPH_FLAG_GET_WRAP_CIPHER   0x4000000
# define         ossl_EVP_CIPH_FLAG_INVERSE_CIPHER    0x8000000

/*
 * Cipher context flag to indicate we can handle wrap mode: if allowed in
 * older applications it could overflow buffers.
 */

# define         ossl_EVP_CIPHER_CTX_FLAG_WRAP_ALLOW  0x1

/* ctrl() values */

# define         ossl_EVP_CTRL_INIT                   0x0
# define         ossl_EVP_CTRL_SET_KEY_LENGTH         0x1
# define         ossl_EVP_CTRL_GET_RC2_KEY_BITS       0x2
# define         ossl_EVP_CTRL_SET_RC2_KEY_BITS       0x3
# define         ossl_EVP_CTRL_GET_RC5_ROUNDS         0x4
# define         ossl_EVP_CTRL_SET_RC5_ROUNDS         0x5
# define         ossl_EVP_CTRL_RAND_KEY               0x6
# define         ossl_EVP_CTRL_PBE_PRF_NID            0x7
# define         ossl_EVP_CTRL_COPY                   0x8
# define         ossl_EVP_CTRL_AEAD_SET_IVLEN         0x9
# define         ossl_EVP_CTRL_AEAD_GET_TAG           0x10
# define         ossl_EVP_CTRL_AEAD_SET_TAG           0x11
# define         ossl_EVP_CTRL_AEAD_SET_IV_FIXED      0x12
# define         ossl_EVP_CTRL_GCM_SET_IVLEN          ossl_EVP_CTRL_AEAD_SET_IVLEN
# define         ossl_EVP_CTRL_GCM_GET_TAG            ossl_EVP_CTRL_AEAD_GET_TAG
# define         ossl_EVP_CTRL_GCM_SET_TAG            ossl_EVP_CTRL_AEAD_SET_TAG
# define         ossl_EVP_CTRL_GCM_SET_IV_FIXED       ossl_EVP_CTRL_AEAD_SET_IV_FIXED
# define         ossl_EVP_CTRL_GCM_IV_GEN             0x13
# define         ossl_EVP_CTRL_CCM_SET_IVLEN          ossl_EVP_CTRL_AEAD_SET_IVLEN
# define         ossl_EVP_CTRL_CCM_GET_TAG            ossl_EVP_CTRL_AEAD_GET_TAG
# define         ossl_EVP_CTRL_CCM_SET_TAG            ossl_EVP_CTRL_AEAD_SET_TAG
# define         ossl_EVP_CTRL_CCM_SET_IV_FIXED       ossl_EVP_CTRL_AEAD_SET_IV_FIXED
# define         ossl_EVP_CTRL_CCM_SET_L              0x14
# define         ossl_EVP_CTRL_CCM_SET_MSGLEN         0x15
/*
 * AEAD cipher deduces payload length and returns number of bytes required to
 * store MAC and eventual padding. Subsequent call to ossl_EVP_Cipher even
 * appends/verifies MAC.
 */
# define         ossl_EVP_CTRL_AEAD_TLS1_AAD          0x16
/* Used by composite AEAD ciphers, no-op in GCM, CCM... */
# define         ossl_EVP_CTRL_AEAD_SET_MAC_KEY       0x17
/* Set the GCM invocation field, decrypt only */
# define         ossl_EVP_CTRL_GCM_SET_IV_INV         0x18

# define         ossl_EVP_CTRL_TLS1_1_MULTIBLOCK_AAD  0x19
# define         ossl_EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT      0x1a
# define         ossl_EVP_CTRL_TLS1_1_MULTIBLOCK_DECRYPT      0x1b
# define         ossl_EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE  0x1c

# define         ossl_EVP_CTRL_SSL3_MASTER_SECRET             0x1d

/* ossl_EVP_CTRL_SET_SBOX takes the char * specifying S-boxes */
# define         ossl_EVP_CTRL_SET_SBOX                       0x1e
/*
 * ossl_EVP_CTRL_SBOX_USED takes a 'size_t' and 'char *', pointing at a
 * pre-allocated buffer with specified size
 */
# define         ossl_EVP_CTRL_SBOX_USED                      0x1f
/* ossl_EVP_CTRL_KEY_MESH takes 'size_t' number of bytes to mesh the key after,
 * 0 switches meshing off
 */
# define         ossl_EVP_CTRL_KEY_MESH                       0x20
/* ossl_EVP_CTRL_BLOCK_PADDING_MODE takes the padding mode */
# define         ossl_EVP_CTRL_BLOCK_PADDING_MODE             0x21

/* Set the output buffers to use for a pipelined operation */
# define         ossl_EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS       0x22
/* Set the input buffers to use for a pipelined operation */
# define         ossl_EVP_CTRL_SET_PIPELINE_INPUT_BUFS        0x23
/* Set the input buffer lengths to use for a pipelined operation */
# define         ossl_EVP_CTRL_SET_PIPELINE_INPUT_LENS        0x24
/* Get the IV length used by the cipher */
# define         ossl_EVP_CTRL_GET_IVLEN                      0x25
/* 0x26 is unused */
/* Tell the cipher it's doing a speed test (SIV disallows multiple ops) */
# define         ossl_EVP_CTRL_SET_SPEED                      0x27
/* Get the unprotectedAttrs from cipher ctx */
# define         ossl_EVP_CTRL_PROCESS_UNPROTECTED            0x28
/* Get the supplementary wrap cipher */
#define          ossl_EVP_CTRL_GET_WRAP_CIPHER                0x29
/* TLSTREE key diversification */
#define          ossl_EVP_CTRL_TLSTREE                        0x2A

/* Padding modes */
#define ossl_EVP_PADDING_PKCS7       1
#define ossl_EVP_PADDING_ISO7816_4   2
#define ossl_EVP_PADDING_ANSI923     3
#define ossl_EVP_PADDING_ISO10126    4
#define ossl_EVP_PADDING_ZERO        5

/* RFC 5246 defines additional data to be 13 bytes in length */
# define         ossl_EVP_AEAD_TLS1_AAD_LEN           13

typedef struct {
    unsigned char *out;
    const unsigned char *inp;
    size_t len;
    unsigned int interleave;
} ossl_EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM;

/* GCM TLS constants */
/* Length of fixed part of IV derived from PRF */
# define ossl_EVP_GCM_TLS_FIXED_IV_LEN                        4
/* Length of explicit part of IV part of TLS records */
# define ossl_EVP_GCM_TLS_EXPLICIT_IV_LEN                     8
/* Length of tag for TLS */
# define ossl_EVP_GCM_TLS_TAG_LEN                             16

/* CCM TLS constants */
/* Length of fixed part of IV derived from PRF */
# define ossl_EVP_CCM_TLS_FIXED_IV_LEN                        4
/* Length of explicit part of IV part of TLS records */
# define ossl_EVP_CCM_TLS_EXPLICIT_IV_LEN                     8
/* Total length of CCM IV length for TLS */
# define ossl_EVP_CCM_TLS_IV_LEN                              12
/* Length of tag for TLS */
# define ossl_EVP_CCM_TLS_TAG_LEN                             16
/* Length of CCM8 tag for TLS */
# define ossl_EVP_CCM8_TLS_TAG_LEN                            8

/* Length of tag for TLS */
# define ossl_EVP_CHACHAPOLY_TLS_TAG_LEN                      16

typedef struct ossl_evp_cipher_info_st {
    const ossl_EVP_CIPHER *cipher;
    unsigned char iv[ossl_EVP_MAX_IV_LENGTH];
} ossl_EVP_CIPHER_INFO;


/* Password based encryption function */
typedef int (ossl_EVP_PBE_KEYGEN) (ossl_EVP_CIPHER_CTX *ctx, const char *pass,
                              int passlen, ossl_ASN1_TYPE *param,
                              const ossl_EVP_CIPHER *cipher, const ossl_EVP_MD *md,
                              int en_de);

typedef int (ossl_EVP_PBE_KEYGEN_EX) (ossl_EVP_CIPHER_CTX *ctx, const char *pass,
                                 int passlen, ossl_ASN1_TYPE *param,
                                 const ossl_EVP_CIPHER *cipher, const ossl_EVP_MD *md,
                                 int en_de, ossl_OSSL_LIB_CTX *libctx, const char *propq);

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_EVP_PKEY_assign_RSA(pkey,rsa) ossl_EVP_PKEY_assign((pkey),ossl_EVP_PKEY_RSA,\
                                                         (rsa))
# endif

# ifndef ossl_OPENSSL_NO_DSA
#  define ossl_EVP_PKEY_assign_DSA(pkey,dsa) ossl_EVP_PKEY_assign((pkey),ossl_EVP_PKEY_DSA,\
                                        (dsa))
# endif

# if !defined(ossl_OPENSSL_NO_DH) && !defined(ossl_OPENSSL_NO_DEPRECATED_3_0)
#  define ossl_EVP_PKEY_assign_DH(pkey,dh) ossl_EVP_PKEY_assign((pkey),ossl_EVP_PKEY_DH,(dh))
# endif

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  ifndef ossl_OPENSSL_NO_EC
#   define ossl_EVP_PKEY_assign_EC_KEY(pkey,eckey) \
        ossl_EVP_PKEY_assign((pkey), ossl_EVP_PKEY_EC, (eckey))
#  endif
# endif
# ifndef ossl_OPENSSL_NO_SIPHASH
#  define ossl_EVP_PKEY_assign_SIPHASH(pkey,shkey) ossl_EVP_PKEY_assign((pkey),\
                                        ossl_EVP_PKEY_SIPHASH,(shkey))
# endif

# ifndef ossl_OPENSSL_NO_POLY1305
#  define ossl_EVP_PKEY_assign_POLY1305(pkey,polykey) ossl_EVP_PKEY_assign((pkey),\
                                        ossl_EVP_PKEY_POLY1305,(polykey))
# endif

/* Add some extra combinations */
# define ossl_EVP_get_digestbynid(a) ossl_EVP_get_digestbyname(ossl_OBJ_nid2sn(a))
# define ossl_EVP_get_digestbyobj(a) ossl_EVP_get_digestbynid(ossl_OBJ_obj2nid(a))
# define ossl_EVP_get_cipherbynid(a) ossl_EVP_get_cipherbyname(ossl_OBJ_nid2sn(a))
# define ossl_EVP_get_cipherbyobj(a) ossl_EVP_get_cipherbynid(ossl_OBJ_obj2nid(a))

int ossl_EVP_MD_get_type(const ossl_EVP_MD *md);
# define ossl_EVP_MD_type ossl_EVP_MD_get_type
# define ossl_EVP_MD_nid ossl_EVP_MD_get_type
const char *ossl_EVP_MD_get0_name(const ossl_EVP_MD *md);
# define ossl_EVP_MD_name ossl_EVP_MD_get0_name
const char *ossl_EVP_MD_get0_description(const ossl_EVP_MD *md);
int ossl_EVP_MD_is_a(const ossl_EVP_MD *md, const char *name);
int ossl_EVP_MD_names_do_all(const ossl_EVP_MD *md,
                        void (*fn)(const char *name, void *data),
                        void *data);
const ossl_OSSL_PROVIDER *ossl_EVP_MD_get0_provider(const ossl_EVP_MD *md);
int ossl_EVP_MD_get_pkey_type(const ossl_EVP_MD *md);
# define ossl_EVP_MD_pkey_type ossl_EVP_MD_get_pkey_type
int ossl_EVP_MD_get_size(const ossl_EVP_MD *md);
# define ossl_EVP_MD_size ossl_EVP_MD_get_size
int ossl_EVP_MD_get_block_size(const ossl_EVP_MD *md);
# define ossl_EVP_MD_block_size ossl_EVP_MD_get_block_size
unsigned long ossl_EVP_MD_get_flags(const ossl_EVP_MD *md);
# define ossl_EVP_MD_flags ossl_EVP_MD_get_flags

const ossl_EVP_MD *ossl_EVP_MD_CTX_get0_md(const ossl_EVP_MD_CTX *ctx);
ossl_EVP_MD *ossl_EVP_MD_CTX_get1_md(ossl_EVP_MD_CTX *ctx);
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0
const ossl_EVP_MD *ossl_EVP_MD_CTX_md(const ossl_EVP_MD_CTX *ctx);
ossl_OSSL_DEPRECATEDIN_3_0
int (*ossl_EVP_MD_CTX_update_fn(ossl_EVP_MD_CTX *ctx))(ossl_EVP_MD_CTX *ctx,
                                             const void *data, size_t count);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_EVP_MD_CTX_set_update_fn(ossl_EVP_MD_CTX *ctx,
                              int (*update) (ossl_EVP_MD_CTX *ctx,
                                             const void *data, size_t count));
# endif
# define ossl_EVP_MD_CTX_get0_name(e)       ossl_EVP_MD_get0_name(ossl_EVP_MD_CTX_get0_md(e))
# define ossl_EVP_MD_CTX_get_size(e)        ossl_EVP_MD_get_size(ossl_EVP_MD_CTX_get0_md(e))
# define ossl_EVP_MD_CTX_size               ossl_EVP_MD_CTX_get_size
# define ossl_EVP_MD_CTX_get_block_size(e)  ossl_EVP_MD_get_block_size(ossl_EVP_MD_CTX_get0_md(e))
# define ossl_EVP_MD_CTX_block_size ossl_EVP_MD_CTX_get_block_size
# define ossl_EVP_MD_CTX_get_type(e)            ossl_EVP_MD_get_type(ossl_EVP_MD_CTX_get0_md(e))
# define ossl_EVP_MD_CTX_type ossl_EVP_MD_CTX_get_type
ossl_EVP_PKEY_CTX *ossl_EVP_MD_CTX_get_pkey_ctx(const ossl_EVP_MD_CTX *ctx);
# define ossl_EVP_MD_CTX_pkey_ctx ossl_EVP_MD_CTX_get_pkey_ctx
void ossl_EVP_MD_CTX_set_pkey_ctx(ossl_EVP_MD_CTX *ctx, ossl_EVP_PKEY_CTX *pctx);
void *ossl_EVP_MD_CTX_get0_md_data(const ossl_EVP_MD_CTX *ctx);
# define ossl_EVP_MD_CTX_md_data ossl_EVP_MD_CTX_get0_md_data

int ossl_EVP_CIPHER_get_nid(const ossl_EVP_CIPHER *cipher);
# define ossl_EVP_CIPHER_nid ossl_EVP_CIPHER_get_nid
const char *ossl_EVP_CIPHER_get0_name(const ossl_EVP_CIPHER *cipher);
# define ossl_EVP_CIPHER_name ossl_EVP_CIPHER_get0_name
const char *ossl_EVP_CIPHER_get0_description(const ossl_EVP_CIPHER *cipher);
int ossl_EVP_CIPHER_is_a(const ossl_EVP_CIPHER *cipher, const char *name);
int ossl_EVP_CIPHER_names_do_all(const ossl_EVP_CIPHER *cipher,
                            void (*fn)(const char *name, void *data),
                            void *data);
const ossl_OSSL_PROVIDER *ossl_EVP_CIPHER_get0_provider(const ossl_EVP_CIPHER *cipher);
int ossl_EVP_CIPHER_get_block_size(const ossl_EVP_CIPHER *cipher);
# define ossl_EVP_CIPHER_block_size ossl_EVP_CIPHER_get_block_size
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_CIPHER_impl_ctx_size(const ossl_EVP_CIPHER *cipher);
# endif
int ossl_EVP_CIPHER_get_key_length(const ossl_EVP_CIPHER *cipher);
# define ossl_EVP_CIPHER_key_length ossl_EVP_CIPHER_get_key_length
int ossl_EVP_CIPHER_get_iv_length(const ossl_EVP_CIPHER *cipher);
# define ossl_EVP_CIPHER_iv_length ossl_EVP_CIPHER_get_iv_length
unsigned long ossl_EVP_CIPHER_get_flags(const ossl_EVP_CIPHER *cipher);
# define ossl_EVP_CIPHER_flags ossl_EVP_CIPHER_get_flags
int ossl_EVP_CIPHER_get_mode(const ossl_EVP_CIPHER *cipher);
# define ossl_EVP_CIPHER_mode ossl_EVP_CIPHER_get_mode
int ossl_EVP_CIPHER_get_type(const ossl_EVP_CIPHER *cipher);
# define ossl_EVP_CIPHER_type ossl_EVP_CIPHER_get_type
ossl_EVP_CIPHER *ossl_EVP_CIPHER_fetch(ossl_OSSL_LIB_CTX *ctx, const char *algorithm,
                             const char *properties);
int ossl_EVP_CIPHER_up_ref(ossl_EVP_CIPHER *cipher);
void ossl_EVP_CIPHER_free(ossl_EVP_CIPHER *cipher);

const ossl_EVP_CIPHER *ossl_EVP_CIPHER_CTX_get0_cipher(const ossl_EVP_CIPHER_CTX *ctx);
ossl_EVP_CIPHER *ossl_EVP_CIPHER_CTX_get1_cipher(ossl_EVP_CIPHER_CTX *ctx);
int ossl_EVP_CIPHER_CTX_is_encrypting(const ossl_EVP_CIPHER_CTX *ctx);
# define ossl_EVP_CIPHER_CTX_encrypting ossl_EVP_CIPHER_CTX_is_encrypting
int ossl_EVP_CIPHER_CTX_get_nid(const ossl_EVP_CIPHER_CTX *ctx);
# define ossl_EVP_CIPHER_CTX_nid ossl_EVP_CIPHER_CTX_get_nid
int ossl_EVP_CIPHER_CTX_get_block_size(const ossl_EVP_CIPHER_CTX *ctx);
# define ossl_EVP_CIPHER_CTX_block_size ossl_EVP_CIPHER_CTX_get_block_size
int ossl_EVP_CIPHER_CTX_get_key_length(const ossl_EVP_CIPHER_CTX *ctx);
# define ossl_EVP_CIPHER_CTX_key_length ossl_EVP_CIPHER_CTX_get_key_length
int ossl_EVP_CIPHER_CTX_get_iv_length(const ossl_EVP_CIPHER_CTX *ctx);
# define ossl_EVP_CIPHER_CTX_iv_length ossl_EVP_CIPHER_CTX_get_iv_length
int ossl_EVP_CIPHER_CTX_get_tag_length(const ossl_EVP_CIPHER_CTX *ctx);
# define ossl_EVP_CIPHER_CTX_tag_length ossl_EVP_CIPHER_CTX_get_tag_length
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
const ossl_EVP_CIPHER *ossl_EVP_CIPHER_CTX_cipher(const ossl_EVP_CIPHER_CTX *ctx);
ossl_OSSL_DEPRECATEDIN_3_0 const unsigned char *ossl_EVP_CIPHER_CTX_iv(const ossl_EVP_CIPHER_CTX *ctx);
ossl_OSSL_DEPRECATEDIN_3_0 const unsigned char *ossl_EVP_CIPHER_CTX_original_iv(const ossl_EVP_CIPHER_CTX *ctx);
ossl_OSSL_DEPRECATEDIN_3_0 unsigned char *ossl_EVP_CIPHER_CTX_iv_noconst(ossl_EVP_CIPHER_CTX *ctx);
# endif
int ossl_EVP_CIPHER_CTX_get_updated_iv(ossl_EVP_CIPHER_CTX *ctx, void *buf, size_t len);
int ossl_EVP_CIPHER_CTX_get_original_iv(ossl_EVP_CIPHER_CTX *ctx, void *buf, size_t len);
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0
unsigned char *ossl_EVP_CIPHER_CTX_buf_noconst(ossl_EVP_CIPHER_CTX *ctx);
# endif
int ossl_EVP_CIPHER_CTX_get_num(const ossl_EVP_CIPHER_CTX *ctx);
# define ossl_EVP_CIPHER_CTX_num ossl_EVP_CIPHER_CTX_get_num
int ossl_EVP_CIPHER_CTX_set_num(ossl_EVP_CIPHER_CTX *ctx, int num);
int ossl_EVP_CIPHER_CTX_copy(ossl_EVP_CIPHER_CTX *out, const ossl_EVP_CIPHER_CTX *in);
void *ossl_EVP_CIPHER_CTX_get_app_data(const ossl_EVP_CIPHER_CTX *ctx);
void ossl_EVP_CIPHER_CTX_set_app_data(ossl_EVP_CIPHER_CTX *ctx, void *data);
void *ossl_EVP_CIPHER_CTX_get_cipher_data(const ossl_EVP_CIPHER_CTX *ctx);
void *ossl_EVP_CIPHER_CTX_set_cipher_data(ossl_EVP_CIPHER_CTX *ctx, void *cipher_data);
# define ossl_EVP_CIPHER_CTX_get0_name(c) ossl_EVP_CIPHER_get0_name(ossl_EVP_CIPHER_CTX_get0_cipher(c))
# define ossl_EVP_CIPHER_CTX_get_type(c)  ossl_EVP_CIPHER_get_type(ossl_EVP_CIPHER_CTX_get0_cipher(c))
# define ossl_EVP_CIPHER_CTX_type         ossl_EVP_CIPHER_CTX_get_type
# ifndef ossl_OPENSSL_NO_DEPRECATED_1_1_0
#  define ossl_EVP_CIPHER_CTX_flags(c)    ossl_EVP_CIPHER_get_flags(ossl_EVP_CIPHER_CTX_get0_cipher(c))
# endif
# define ossl_EVP_CIPHER_CTX_get_mode(c)  ossl_EVP_CIPHER_get_mode(ossl_EVP_CIPHER_CTX_get0_cipher(c))
# define ossl_EVP_CIPHER_CTX_mode         ossl_EVP_CIPHER_CTX_get_mode

# define ossl_EVP_ENCODE_LENGTH(l)    ((((l)+2)/3*4)+((l)/48+1)*2+80)
# define ossl_EVP_DECODE_LENGTH(l)    (((l)+3)/4*3+80)

# define ossl_EVP_SignInit_ex(a,b,c)          ossl_EVP_DigestInit_ex(a,b,c)
# define ossl_EVP_SignInit(a,b)               ossl_EVP_DigestInit(a,b)
# define ossl_EVP_SignUpdate(a,b,c)           ossl_EVP_DigestUpdate(a,b,c)
# define ossl_EVP_VerifyInit_ex(a,b,c)        ossl_EVP_DigestInit_ex(a,b,c)
# define ossl_EVP_VerifyInit(a,b)             ossl_EVP_DigestInit(a,b)
# define ossl_EVP_VerifyUpdate(a,b,c)         ossl_EVP_DigestUpdate(a,b,c)
# define ossl_EVP_OpenUpdate(a,b,c,d,e)       ossl_EVP_DecryptUpdate(a,b,c,d,e)
# define ossl_EVP_SealUpdate(a,b,c,d,e)       ossl_EVP_EncryptUpdate(a,b,c,d,e)

# ifdef CONST_STRICT
void ossl_BIO_set_md(ossl_BIO *, const ossl_EVP_MD *md);
# else
#  define ossl_BIO_set_md(b,md)          ossl_BIO_ctrl(b,ossl_BIO_C_SET_MD,0,(void *)(md))
# endif
# define ossl_BIO_get_md(b,mdp)          ossl_BIO_ctrl(b,ossl_BIO_C_GET_MD,0,(mdp))
# define ossl_BIO_get_md_ctx(b,mdcp)     ossl_BIO_ctrl(b,ossl_BIO_C_GET_MD_CTX,0,(mdcp))
# define ossl_BIO_set_md_ctx(b,mdcp)     ossl_BIO_ctrl(b,ossl_BIO_C_SET_MD_CTX,0,(mdcp))
# define ossl_BIO_get_cipher_status(b)   ossl_BIO_ctrl(b,ossl_BIO_C_GET_CIPHER_STATUS,0,NULL)
# define ossl_BIO_get_cipher_ctx(b,c_pp) ossl_BIO_ctrl(b,ossl_BIO_C_GET_CIPHER_CTX,0,(c_pp))

/*ossl___owur*/ int ossl_EVP_Cipher(ossl_EVP_CIPHER_CTX *c,
                          unsigned char *out,
                          const unsigned char *in, unsigned int inl);

# define ossl_EVP_add_cipher_alias(n,alias) \
        ossl_OBJ_NAME_add((alias),ossl_OBJ_NAME_TYPE_CIPHER_METH|ossl_OBJ_NAME_ALIAS,(n))
# define ossl_EVP_add_digest_alias(n,alias) \
        ossl_OBJ_NAME_add((alias),ossl_OBJ_NAME_TYPE_MD_METH|ossl_OBJ_NAME_ALIAS,(n))
# define ossl_EVP_delete_cipher_alias(alias) \
        ossl_OBJ_NAME_remove(alias,ossl_OBJ_NAME_TYPE_CIPHER_METH|ossl_OBJ_NAME_ALIAS);
# define ossl_EVP_delete_digest_alias(alias) \
        ossl_OBJ_NAME_remove(alias,ossl_OBJ_NAME_TYPE_MD_METH|ossl_OBJ_NAME_ALIAS);

int ossl_EVP_MD_get_params(const ossl_EVP_MD *digest, ossl_OSSL_PARAM params[]);
int ossl_EVP_MD_CTX_set_params(ossl_EVP_MD_CTX *ctx, const ossl_OSSL_PARAM params[]);
int ossl_EVP_MD_CTX_get_params(ossl_EVP_MD_CTX *ctx, ossl_OSSL_PARAM params[]);
const ossl_OSSL_PARAM *ossl_EVP_MD_gettable_params(const ossl_EVP_MD *digest);
const ossl_OSSL_PARAM *ossl_EVP_MD_settable_ctx_params(const ossl_EVP_MD *md);
const ossl_OSSL_PARAM *ossl_EVP_MD_gettable_ctx_params(const ossl_EVP_MD *md);
const ossl_OSSL_PARAM *ossl_EVP_MD_CTX_settable_params(ossl_EVP_MD_CTX *ctx);
const ossl_OSSL_PARAM *ossl_EVP_MD_CTX_gettable_params(ossl_EVP_MD_CTX *ctx);
int ossl_EVP_MD_CTX_ctrl(ossl_EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
ossl_EVP_MD_CTX *ossl_EVP_MD_CTX_new(void);
int ossl_EVP_MD_CTX_reset(ossl_EVP_MD_CTX *ctx);
void ossl_EVP_MD_CTX_free(ossl_EVP_MD_CTX *ctx);
# define ossl_EVP_MD_CTX_create()     ossl_EVP_MD_CTX_new()
# define ossl_EVP_MD_CTX_init(ctx)    ossl_EVP_MD_CTX_reset((ctx))
# define ossl_EVP_MD_CTX_destroy(ctx) ossl_EVP_MD_CTX_free((ctx))
ossl___owur int ossl_EVP_MD_CTX_copy_ex(ossl_EVP_MD_CTX *out, const ossl_EVP_MD_CTX *in);
void ossl_EVP_MD_CTX_set_flags(ossl_EVP_MD_CTX *ctx, int flags);
void ossl_EVP_MD_CTX_clear_flags(ossl_EVP_MD_CTX *ctx, int flags);
int ossl_EVP_MD_CTX_test_flags(const ossl_EVP_MD_CTX *ctx, int flags);
ossl___owur int ossl_EVP_DigestInit_ex2(ossl_EVP_MD_CTX *ctx, const ossl_EVP_MD *type,
                              const ossl_OSSL_PARAM params[]);
ossl___owur int ossl_EVP_DigestInit_ex(ossl_EVP_MD_CTX *ctx, const ossl_EVP_MD *type,
                                 ossl_ENGINE *impl);
ossl___owur int ossl_EVP_DigestUpdate(ossl_EVP_MD_CTX *ctx, const void *d,
                                size_t cnt);
ossl___owur int ossl_EVP_DigestFinal_ex(ossl_EVP_MD_CTX *ctx, unsigned char *md,
                                  unsigned int *s);
ossl___owur int ossl_EVP_Digest(const void *data, size_t count,
                          unsigned char *md, unsigned int *size,
                          const ossl_EVP_MD *type, ossl_ENGINE *impl);
ossl___owur int ossl_EVP_Q_digest(ossl_OSSL_LIB_CTX *libctx, const char *name,
                        const char *propq, const void *data, size_t datalen,
                        unsigned char *md, size_t *mdlen);

ossl___owur int ossl_EVP_MD_CTX_copy(ossl_EVP_MD_CTX *out, const ossl_EVP_MD_CTX *in);
ossl___owur int ossl_EVP_DigestInit(ossl_EVP_MD_CTX *ctx, const ossl_EVP_MD *type);
ossl___owur int ossl_EVP_DigestFinal(ossl_EVP_MD_CTX *ctx, unsigned char *md,
                           unsigned int *s);
ossl___owur int ossl_EVP_DigestFinalXOF(ossl_EVP_MD_CTX *ctx, unsigned char *md,
                              size_t len);

ossl___owur ossl_EVP_MD *ossl_EVP_MD_fetch(ossl_OSSL_LIB_CTX *ctx, const char *algorithm,
                            const char *properties);

int ossl_EVP_MD_up_ref(ossl_EVP_MD *md);
void ossl_EVP_MD_free(ossl_EVP_MD *md);

int ossl_EVP_read_pw_string(char *buf, int length, const char *prompt, int verify);
int ossl_EVP_read_pw_string_min(char *buf, int minlen, int maxlen,
                           const char *prompt, int verify);
void ossl_EVP_set_pw_prompt(const char *prompt);
char *ossl_EVP_get_pw_prompt(void);

ossl___owur int ossl_EVP_BytesToKey(const ossl_EVP_CIPHER *type, const ossl_EVP_MD *md,
                          const unsigned char *salt,
                          const unsigned char *data, int datal, int count,
                          unsigned char *key, unsigned char *iv);

void ossl_EVP_CIPHER_CTX_set_flags(ossl_EVP_CIPHER_CTX *ctx, int flags);
void ossl_EVP_CIPHER_CTX_clear_flags(ossl_EVP_CIPHER_CTX *ctx, int flags);
int ossl_EVP_CIPHER_CTX_test_flags(const ossl_EVP_CIPHER_CTX *ctx, int flags);

ossl___owur int ossl_EVP_EncryptInit(ossl_EVP_CIPHER_CTX *ctx, const ossl_EVP_CIPHER *cipher,
                           const unsigned char *key, const unsigned char *iv);
/*ossl___owur*/ int ossl_EVP_EncryptInit_ex(ossl_EVP_CIPHER_CTX *ctx,
                                  const ossl_EVP_CIPHER *cipher, ossl_ENGINE *impl,
                                  const unsigned char *key,
                                  const unsigned char *iv);
ossl___owur int ossl_EVP_EncryptInit_ex2(ossl_EVP_CIPHER_CTX *ctx, const ossl_EVP_CIPHER *cipher,
                               const unsigned char *key,
                               const unsigned char *iv,
                               const ossl_OSSL_PARAM params[]);
/*ossl___owur*/ int ossl_EVP_EncryptUpdate(ossl_EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 int *outl, const unsigned char *in, int inl);
/*ossl___owur*/ int ossl_EVP_EncryptFinal_ex(ossl_EVP_CIPHER_CTX *ctx, unsigned char *out,
                                   int *outl);
/*ossl___owur*/ int ossl_EVP_EncryptFinal(ossl_EVP_CIPHER_CTX *ctx, unsigned char *out,
                                int *outl);

ossl___owur int ossl_EVP_DecryptInit(ossl_EVP_CIPHER_CTX *ctx, const ossl_EVP_CIPHER *cipher,
                           const unsigned char *key, const unsigned char *iv);
/*ossl___owur*/ int ossl_EVP_DecryptInit_ex(ossl_EVP_CIPHER_CTX *ctx,
                                  const ossl_EVP_CIPHER *cipher, ossl_ENGINE *impl,
                                  const unsigned char *key,
                                  const unsigned char *iv);
ossl___owur int ossl_EVP_DecryptInit_ex2(ossl_EVP_CIPHER_CTX *ctx, const ossl_EVP_CIPHER *cipher,
                               const unsigned char *key,
                               const unsigned char *iv,
                               const ossl_OSSL_PARAM params[]);
/*ossl___owur*/ int ossl_EVP_DecryptUpdate(ossl_EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 int *outl, const unsigned char *in, int inl);
ossl___owur int ossl_EVP_DecryptFinal(ossl_EVP_CIPHER_CTX *ctx, unsigned char *outm,
                            int *outl);
/*ossl___owur*/ int ossl_EVP_DecryptFinal_ex(ossl_EVP_CIPHER_CTX *ctx, unsigned char *outm,
                                   int *outl);

ossl___owur int ossl_EVP_CipherInit(ossl_EVP_CIPHER_CTX *ctx, const ossl_EVP_CIPHER *cipher,
                          const unsigned char *key, const unsigned char *iv,
                          int enc);
/*ossl___owur*/ int ossl_EVP_CipherInit_ex(ossl_EVP_CIPHER_CTX *ctx,
                                 const ossl_EVP_CIPHER *cipher, ossl_ENGINE *impl,
                                 const unsigned char *key,
                                 const unsigned char *iv, int enc);
ossl___owur int ossl_EVP_CipherInit_ex2(ossl_EVP_CIPHER_CTX *ctx, const ossl_EVP_CIPHER *cipher,
                              const unsigned char *key, const unsigned char *iv,
                              int enc, const ossl_OSSL_PARAM params[]);
ossl___owur int ossl_EVP_CipherUpdate(ossl_EVP_CIPHER_CTX *ctx, unsigned char *out,
                            int *outl, const unsigned char *in, int inl);
ossl___owur int ossl_EVP_CipherFinal(ossl_EVP_CIPHER_CTX *ctx, unsigned char *outm,
                           int *outl);
ossl___owur int ossl_EVP_CipherFinal_ex(ossl_EVP_CIPHER_CTX *ctx, unsigned char *outm,
                              int *outl);

ossl___owur int ossl_EVP_SignFinal(ossl_EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s,
                         ossl_EVP_PKEY *pkey);
ossl___owur int ossl_EVP_SignFinal_ex(ossl_EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s,
                            ossl_EVP_PKEY *pkey, ossl_OSSL_LIB_CTX *libctx,
                            const char *propq);

ossl___owur int ossl_EVP_DigestSign(ossl_EVP_MD_CTX *ctx, unsigned char *sigret,
                          size_t *siglen, const unsigned char *tbs,
                          size_t tbslen);

ossl___owur int ossl_EVP_VerifyFinal(ossl_EVP_MD_CTX *ctx, const unsigned char *sigbuf,
                           unsigned int siglen, ossl_EVP_PKEY *pkey);
ossl___owur int ossl_EVP_VerifyFinal_ex(ossl_EVP_MD_CTX *ctx, const unsigned char *sigbuf,
                              unsigned int siglen, ossl_EVP_PKEY *pkey,
                              ossl_OSSL_LIB_CTX *libctx, const char *propq);

ossl___owur int ossl_EVP_DigestVerify(ossl_EVP_MD_CTX *ctx, const unsigned char *sigret,
                            size_t siglen, const unsigned char *tbs,
                            size_t tbslen);

int ossl_EVP_DigestSignInit_ex(ossl_EVP_MD_CTX *ctx, ossl_EVP_PKEY_CTX **pctx,
                          const char *mdname, ossl_OSSL_LIB_CTX *libctx,
                          const char *props, ossl_EVP_PKEY *pkey,
                          const ossl_OSSL_PARAM params[]);
/*ossl___owur*/ int ossl_EVP_DigestSignInit(ossl_EVP_MD_CTX *ctx, ossl_EVP_PKEY_CTX **pctx,
                                  const ossl_EVP_MD *type, ossl_ENGINE *e,
                                  ossl_EVP_PKEY *pkey);
int ossl_EVP_DigestSignUpdate(ossl_EVP_MD_CTX *ctx, const void *data, size_t dsize);
ossl___owur int ossl_EVP_DigestSignFinal(ossl_EVP_MD_CTX *ctx, unsigned char *sigret,
                               size_t *siglen);

int ossl_EVP_DigestVerifyInit_ex(ossl_EVP_MD_CTX *ctx, ossl_EVP_PKEY_CTX **pctx,
                            const char *mdname, ossl_OSSL_LIB_CTX *libctx,
                            const char *props, ossl_EVP_PKEY *pkey,
                            const ossl_OSSL_PARAM params[]);
ossl___owur int ossl_EVP_DigestVerifyInit(ossl_EVP_MD_CTX *ctx, ossl_EVP_PKEY_CTX **pctx,
                                const ossl_EVP_MD *type, ossl_ENGINE *e,
                                ossl_EVP_PKEY *pkey);
int ossl_EVP_DigestVerifyUpdate(ossl_EVP_MD_CTX *ctx, const void *data, size_t dsize);
ossl___owur int ossl_EVP_DigestVerifyFinal(ossl_EVP_MD_CTX *ctx, const unsigned char *sig,
                                 size_t siglen);

ossl___owur int ossl_EVP_OpenInit(ossl_EVP_CIPHER_CTX *ctx, const ossl_EVP_CIPHER *type,
                        const unsigned char *ek, int ekl,
                        const unsigned char *iv, ossl_EVP_PKEY *priv);
ossl___owur int ossl_EVP_OpenFinal(ossl_EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

ossl___owur int ossl_EVP_SealInit(ossl_EVP_CIPHER_CTX *ctx, const ossl_EVP_CIPHER *type,
                        unsigned char **ek, int *ekl, unsigned char *iv,
                        ossl_EVP_PKEY **pubk, int npubk);
ossl___owur int ossl_EVP_SealFinal(ossl_EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

ossl_EVP_ENCODE_CTX *ossl_EVP_ENCODE_CTX_new(void);
void ossl_EVP_ENCODE_CTX_free(ossl_EVP_ENCODE_CTX *ctx);
int ossl_EVP_ENCODE_CTX_copy(ossl_EVP_ENCODE_CTX *dctx, const ossl_EVP_ENCODE_CTX *sctx);
int ossl_EVP_ENCODE_CTX_num(ossl_EVP_ENCODE_CTX *ctx);
void ossl_EVP_EncodeInit(ossl_EVP_ENCODE_CTX *ctx);
int ossl_EVP_EncodeUpdate(ossl_EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl,
                     const unsigned char *in, int inl);
void ossl_EVP_EncodeFinal(ossl_EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl);
int ossl_EVP_EncodeBlock(unsigned char *t, const unsigned char *f, int n);

void ossl_EVP_DecodeInit(ossl_EVP_ENCODE_CTX *ctx);
int ossl_EVP_DecodeUpdate(ossl_EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl,
                     const unsigned char *in, int inl);
int ossl_EVP_DecodeFinal(ossl_EVP_ENCODE_CTX *ctx, unsigned
                    char *out, int *outl);
int ossl_EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n);

# ifndef ossl_OPENSSL_NO_DEPRECATED_1_1_0
#  define ossl_EVP_CIPHER_CTX_init(c)      ossl_EVP_CIPHER_CTX_reset(c)
#  define ossl_EVP_CIPHER_CTX_cleanup(c)   ossl_EVP_CIPHER_CTX_reset(c)
# endif
ossl_EVP_CIPHER_CTX *ossl_EVP_CIPHER_CTX_new(void);
int ossl_EVP_CIPHER_CTX_reset(ossl_EVP_CIPHER_CTX *c);
void ossl_EVP_CIPHER_CTX_free(ossl_EVP_CIPHER_CTX *c);
int ossl_EVP_CIPHER_CTX_set_key_length(ossl_EVP_CIPHER_CTX *x, int keylen);
int ossl_EVP_CIPHER_CTX_set_padding(ossl_EVP_CIPHER_CTX *c, int pad);
int ossl_EVP_CIPHER_CTX_ctrl(ossl_EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
int ossl_EVP_CIPHER_CTX_rand_key(ossl_EVP_CIPHER_CTX *ctx, unsigned char *key);
int ossl_EVP_CIPHER_get_params(ossl_EVP_CIPHER *cipher, ossl_OSSL_PARAM params[]);
int ossl_EVP_CIPHER_CTX_set_params(ossl_EVP_CIPHER_CTX *ctx, const ossl_OSSL_PARAM params[]);
int ossl_EVP_CIPHER_CTX_get_params(ossl_EVP_CIPHER_CTX *ctx, ossl_OSSL_PARAM params[]);
const ossl_OSSL_PARAM *ossl_EVP_CIPHER_gettable_params(const ossl_EVP_CIPHER *cipher);
const ossl_OSSL_PARAM *ossl_EVP_CIPHER_settable_ctx_params(const ossl_EVP_CIPHER *cipher);
const ossl_OSSL_PARAM *ossl_EVP_CIPHER_gettable_ctx_params(const ossl_EVP_CIPHER *cipher);
const ossl_OSSL_PARAM *ossl_EVP_CIPHER_CTX_settable_params(ossl_EVP_CIPHER_CTX *ctx);
const ossl_OSSL_PARAM *ossl_EVP_CIPHER_CTX_gettable_params(ossl_EVP_CIPHER_CTX *ctx);

const ossl_BIO_METHOD *ossl_BIO_f_md(void);
const ossl_BIO_METHOD *ossl_BIO_f_base64(void);
const ossl_BIO_METHOD *ossl_BIO_f_cipher(void);
const ossl_BIO_METHOD *ossl_BIO_f_reliable(void);
ossl___owur int ossl_BIO_set_cipher(ossl_BIO *b, const ossl_EVP_CIPHER *c, const unsigned char *k,
                          const unsigned char *i, int enc);

const ossl_EVP_MD *ossl_EVP_md_null(void);
# ifndef ossl_OPENSSL_NO_MD2
const ossl_EVP_MD *EVP_md2(void);
# endif
# ifndef ossl_OPENSSL_NO_MD4
const ossl_EVP_MD *ossl_EVP_md4(void);
# endif
# ifndef ossl_OPENSSL_NO_MD5
const ossl_EVP_MD *ossl_EVP_md5(void);
const ossl_EVP_MD *ossl_EVP_md5_sha1(void);
# endif
# ifndef ossl_OPENSSL_NO_BLAKE2
const ossl_EVP_MD *ossl_EVP_blake2b512(void);
const ossl_EVP_MD *ossl_EVP_blake2s256(void);
# endif
const ossl_EVP_MD *ossl_EVP_sha1(void);
const ossl_EVP_MD *ossl_EVP_sha224(void);
const ossl_EVP_MD *ossl_EVP_sha256(void);
const ossl_EVP_MD *ossl_EVP_sha384(void);
const ossl_EVP_MD *ossl_EVP_sha512(void);
const ossl_EVP_MD *ossl_EVP_sha512_224(void);
const ossl_EVP_MD *ossl_EVP_sha512_256(void);
const ossl_EVP_MD *ossl_EVP_sha3_224(void);
const ossl_EVP_MD *ossl_EVP_sha3_256(void);
const ossl_EVP_MD *ossl_EVP_sha3_384(void);
const ossl_EVP_MD *ossl_EVP_sha3_512(void);
const ossl_EVP_MD *ossl_EVP_shake128(void);
const ossl_EVP_MD *ossl_EVP_shake256(void);

# ifndef ossl_OPENSSL_NO_MDC2
const ossl_EVP_MD *ossl_EVP_mdc2(void);
# endif
# ifndef ossl_OPENSSL_NO_RMD160
const ossl_EVP_MD *ossl_EVP_ripemd160(void);
# endif
# ifndef ossl_OPENSSL_NO_WHIRLPOOL
const ossl_EVP_MD *ossl_EVP_whirlpool(void);
# endif
# ifndef ossl_OPENSSL_NO_SM3
const ossl_EVP_MD *ossl_EVP_sm3(void);
# endif
const ossl_EVP_CIPHER *ossl_EVP_enc_null(void); /* does nothing :-) */
# ifndef ossl_OPENSSL_NO_DES
const ossl_EVP_CIPHER *ossl_EVP_des_ecb(void);
const ossl_EVP_CIPHER *ossl_EVP_des_ede(void);
const ossl_EVP_CIPHER *ossl_EVP_des_ede3(void);
const ossl_EVP_CIPHER *ossl_EVP_des_ede_ecb(void);
const ossl_EVP_CIPHER *ossl_EVP_des_ede3_ecb(void);
const ossl_EVP_CIPHER *ossl_EVP_des_cfb64(void);
#  define ossl_EVP_des_cfb ossl_EVP_des_cfb64
const ossl_EVP_CIPHER *ossl_EVP_des_cfb1(void);
const ossl_EVP_CIPHER *ossl_EVP_des_cfb8(void);
const ossl_EVP_CIPHER *ossl_EVP_des_ede_cfb64(void);
#  define ossl_EVP_des_ede_cfb ossl_EVP_des_ede_cfb64
const ossl_EVP_CIPHER *ossl_EVP_des_ede3_cfb64(void);
#  define ossl_EVP_des_ede3_cfb ossl_EVP_des_ede3_cfb64
const ossl_EVP_CIPHER *ossl_EVP_des_ede3_cfb1(void);
const ossl_EVP_CIPHER *ossl_EVP_des_ede3_cfb8(void);
const ossl_EVP_CIPHER *ossl_EVP_des_ofb(void);
const ossl_EVP_CIPHER *ossl_EVP_des_ede_ofb(void);
const ossl_EVP_CIPHER *ossl_EVP_des_ede3_ofb(void);
const ossl_EVP_CIPHER *ossl_EVP_des_cbc(void);
const ossl_EVP_CIPHER *ossl_EVP_des_ede_cbc(void);
const ossl_EVP_CIPHER *ossl_EVP_des_ede3_cbc(void);
const ossl_EVP_CIPHER *ossl_EVP_desx_cbc(void);
const ossl_EVP_CIPHER *ossl_EVP_des_ede3_wrap(void);
/*
 * This should now be supported through the dev_crypto ossl_ENGINE. But also, why
 * are rc4 and md5 declarations made here inside a "NO_DES" precompiler
 * branch?
 */
# endif
# ifndef ossl_OPENSSL_NO_RC4
const ossl_EVP_CIPHER *ossl_EVP_rc4(void);
const ossl_EVP_CIPHER *ossl_EVP_rc4_40(void);
#  ifndef ossl_OPENSSL_NO_MD5
const ossl_EVP_CIPHER *ossl_EVP_rc4_hmac_md5(void);
#  endif
# endif
# ifndef ossl_OPENSSL_NO_IDEA
const ossl_EVP_CIPHER *ossl_EVP_idea_ecb(void);
const ossl_EVP_CIPHER *ossl_EVP_idea_cfb64(void);
#  define ossl_EVP_idea_cfb ossl_EVP_idea_cfb64
const ossl_EVP_CIPHER *ossl_EVP_idea_ofb(void);
const ossl_EVP_CIPHER *ossl_EVP_idea_cbc(void);
# endif
# ifndef ossl_OPENSSL_NO_RC2
const ossl_EVP_CIPHER *ossl_EVP_rc2_ecb(void);
const ossl_EVP_CIPHER *ossl_EVP_rc2_cbc(void);
const ossl_EVP_CIPHER *ossl_EVP_rc2_40_cbc(void);
const ossl_EVP_CIPHER *ossl_EVP_rc2_64_cbc(void);
const ossl_EVP_CIPHER *ossl_EVP_rc2_cfb64(void);
#  define ossl_EVP_rc2_cfb ossl_EVP_rc2_cfb64
const ossl_EVP_CIPHER *ossl_EVP_rc2_ofb(void);
# endif
# ifndef ossl_OPENSSL_NO_BF
const ossl_EVP_CIPHER *ossl_EVP_bf_ecb(void);
const ossl_EVP_CIPHER *ossl_EVP_bf_cbc(void);
const ossl_EVP_CIPHER *ossl_EVP_bf_cfb64(void);
#  define ossl_EVP_bf_cfb ossl_EVP_bf_cfb64
const ossl_EVP_CIPHER *ossl_EVP_bf_ofb(void);
# endif
# ifndef ossl_OPENSSL_NO_CAST
const ossl_EVP_CIPHER *ossl_EVP_cast5_ecb(void);
const ossl_EVP_CIPHER *ossl_EVP_cast5_cbc(void);
const ossl_EVP_CIPHER *ossl_EVP_cast5_cfb64(void);
#  define ossl_EVP_cast5_cfb ossl_EVP_cast5_cfb64
const ossl_EVP_CIPHER *ossl_EVP_cast5_ofb(void);
# endif
# ifndef ossl_OPENSSL_NO_RC5
const ossl_EVP_CIPHER *EVP_rc5_32_12_16_cbc(void);
const ossl_EVP_CIPHER *EVP_rc5_32_12_16_ecb(void);
const ossl_EVP_CIPHER *EVP_rc5_32_12_16_cfb64(void);
#  define EVP_rc5_32_12_16_cfb EVP_rc5_32_12_16_cfb64
const ossl_EVP_CIPHER *EVP_rc5_32_12_16_ofb(void);
# endif
const ossl_EVP_CIPHER *ossl_EVP_aes_128_ecb(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_128_cbc(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_128_cfb1(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_128_cfb8(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_128_cfb128(void);
# define ossl_EVP_aes_128_cfb ossl_EVP_aes_128_cfb128
const ossl_EVP_CIPHER *ossl_EVP_aes_128_ofb(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_128_ctr(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_128_ccm(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_128_gcm(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_128_xts(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_128_wrap(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_128_wrap_pad(void);
# ifndef ossl_OPENSSL_NO_OCB
const ossl_EVP_CIPHER *ossl_EVP_aes_128_ocb(void);
# endif
const ossl_EVP_CIPHER *ossl_EVP_aes_192_ecb(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_192_cbc(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_192_cfb1(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_192_cfb8(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_192_cfb128(void);
# define ossl_EVP_aes_192_cfb ossl_EVP_aes_192_cfb128
const ossl_EVP_CIPHER *ossl_EVP_aes_192_ofb(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_192_ctr(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_192_ccm(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_192_gcm(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_192_wrap(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_192_wrap_pad(void);
# ifndef ossl_OPENSSL_NO_OCB
const ossl_EVP_CIPHER *ossl_EVP_aes_192_ocb(void);
# endif
const ossl_EVP_CIPHER *ossl_EVP_aes_256_ecb(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_256_cbc(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_256_cfb1(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_256_cfb8(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_256_cfb128(void);
# define ossl_EVP_aes_256_cfb ossl_EVP_aes_256_cfb128
const ossl_EVP_CIPHER *ossl_EVP_aes_256_ofb(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_256_ctr(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_256_ccm(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_256_gcm(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_256_xts(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_256_wrap(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_256_wrap_pad(void);
# ifndef ossl_OPENSSL_NO_OCB
const ossl_EVP_CIPHER *ossl_EVP_aes_256_ocb(void);
# endif
const ossl_EVP_CIPHER *ossl_EVP_aes_128_cbc_hmac_sha1(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_256_cbc_hmac_sha1(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_128_cbc_hmac_sha256(void);
const ossl_EVP_CIPHER *ossl_EVP_aes_256_cbc_hmac_sha256(void);
# ifndef ossl_OPENSSL_NO_ARIA
const ossl_EVP_CIPHER *ossl_EVP_aria_128_ecb(void);
const ossl_EVP_CIPHER *ossl_EVP_aria_128_cbc(void);
const ossl_EVP_CIPHER *ossl_EVP_aria_128_cfb1(void);
const ossl_EVP_CIPHER *ossl_EVP_aria_128_cfb8(void);
const ossl_EVP_CIPHER *ossl_EVP_aria_128_cfb128(void);
#  define ossl_EVP_aria_128_cfb ossl_EVP_aria_128_cfb128
const ossl_EVP_CIPHER *ossl_EVP_aria_128_ctr(void);
const ossl_EVP_CIPHER *ossl_EVP_aria_128_ofb(void);
const ossl_EVP_CIPHER *ossl_EVP_aria_128_gcm(void);
const ossl_EVP_CIPHER *ossl_EVP_aria_128_ccm(void);
const ossl_EVP_CIPHER *ossl_EVP_aria_192_ecb(void);
const ossl_EVP_CIPHER *ossl_EVP_aria_192_cbc(void);
const ossl_EVP_CIPHER *ossl_EVP_aria_192_cfb1(void);
const ossl_EVP_CIPHER *ossl_EVP_aria_192_cfb8(void);
const ossl_EVP_CIPHER *ossl_EVP_aria_192_cfb128(void);
#  define ossl_EVP_aria_192_cfb ossl_EVP_aria_192_cfb128
const ossl_EVP_CIPHER *ossl_EVP_aria_192_ctr(void);
const ossl_EVP_CIPHER *ossl_EVP_aria_192_ofb(void);
const ossl_EVP_CIPHER *ossl_EVP_aria_192_gcm(void);
const ossl_EVP_CIPHER *ossl_EVP_aria_192_ccm(void);
const ossl_EVP_CIPHER *ossl_EVP_aria_256_ecb(void);
const ossl_EVP_CIPHER *ossl_EVP_aria_256_cbc(void);
const ossl_EVP_CIPHER *ossl_EVP_aria_256_cfb1(void);
const ossl_EVP_CIPHER *ossl_EVP_aria_256_cfb8(void);
const ossl_EVP_CIPHER *ossl_EVP_aria_256_cfb128(void);
#  define ossl_EVP_aria_256_cfb ossl_EVP_aria_256_cfb128
const ossl_EVP_CIPHER *ossl_EVP_aria_256_ctr(void);
const ossl_EVP_CIPHER *ossl_EVP_aria_256_ofb(void);
const ossl_EVP_CIPHER *ossl_EVP_aria_256_gcm(void);
const ossl_EVP_CIPHER *ossl_EVP_aria_256_ccm(void);
# endif
# ifndef ossl_OPENSSL_NO_CAMELLIA
const ossl_EVP_CIPHER *ossl_EVP_camellia_128_ecb(void);
const ossl_EVP_CIPHER *ossl_EVP_camellia_128_cbc(void);
const ossl_EVP_CIPHER *ossl_EVP_camellia_128_cfb1(void);
const ossl_EVP_CIPHER *ossl_EVP_camellia_128_cfb8(void);
const ossl_EVP_CIPHER *ossl_EVP_camellia_128_cfb128(void);
#  define ossl_EVP_camellia_128_cfb ossl_EVP_camellia_128_cfb128
const ossl_EVP_CIPHER *ossl_EVP_camellia_128_ofb(void);
const ossl_EVP_CIPHER *ossl_EVP_camellia_128_ctr(void);
const ossl_EVP_CIPHER *ossl_EVP_camellia_192_ecb(void);
const ossl_EVP_CIPHER *ossl_EVP_camellia_192_cbc(void);
const ossl_EVP_CIPHER *ossl_EVP_camellia_192_cfb1(void);
const ossl_EVP_CIPHER *ossl_EVP_camellia_192_cfb8(void);
const ossl_EVP_CIPHER *ossl_EVP_camellia_192_cfb128(void);
#  define ossl_EVP_camellia_192_cfb ossl_EVP_camellia_192_cfb128
const ossl_EVP_CIPHER *ossl_EVP_camellia_192_ofb(void);
const ossl_EVP_CIPHER *ossl_EVP_camellia_192_ctr(void);
const ossl_EVP_CIPHER *ossl_EVP_camellia_256_ecb(void);
const ossl_EVP_CIPHER *ossl_EVP_camellia_256_cbc(void);
const ossl_EVP_CIPHER *ossl_EVP_camellia_256_cfb1(void);
const ossl_EVP_CIPHER *ossl_EVP_camellia_256_cfb8(void);
const ossl_EVP_CIPHER *ossl_EVP_camellia_256_cfb128(void);
#  define ossl_EVP_camellia_256_cfb ossl_EVP_camellia_256_cfb128
const ossl_EVP_CIPHER *ossl_EVP_camellia_256_ofb(void);
const ossl_EVP_CIPHER *ossl_EVP_camellia_256_ctr(void);
# endif
# ifndef ossl_OPENSSL_NO_CHACHA
const ossl_EVP_CIPHER *ossl_EVP_chacha20(void);
#  ifndef ossl_OPENSSL_NO_POLY1305
const ossl_EVP_CIPHER *ossl_EVP_chacha20_poly1305(void);
#  endif
# endif

# ifndef ossl_OPENSSL_NO_SEED
const ossl_EVP_CIPHER *ossl_EVP_seed_ecb(void);
const ossl_EVP_CIPHER *ossl_EVP_seed_cbc(void);
const ossl_EVP_CIPHER *ossl_EVP_seed_cfb128(void);
#  define ossl_EVP_seed_cfb ossl_EVP_seed_cfb128
const ossl_EVP_CIPHER *ossl_EVP_seed_ofb(void);
# endif

# ifndef ossl_OPENSSL_NO_SM4
const ossl_EVP_CIPHER *ossl_EVP_sm4_ecb(void);
const ossl_EVP_CIPHER *ossl_EVP_sm4_cbc(void);
const ossl_EVP_CIPHER *ossl_EVP_sm4_cfb128(void);
#  define ossl_EVP_sm4_cfb ossl_EVP_sm4_cfb128
const ossl_EVP_CIPHER *ossl_EVP_sm4_ofb(void);
const ossl_EVP_CIPHER *ossl_EVP_sm4_ctr(void);
# endif

# ifndef ossl_OPENSSL_NO_DEPRECATED_1_1_0
#  define ossl_OPENSSL_add_all_algorithms_conf() \
    ossl_OPENSSL_init_crypto(ossl_OPENSSL_INIT_ADD_ALL_CIPHERS \
                        | ossl_OPENSSL_INIT_ADD_ALL_DIGESTS \
                        | ossl_OPENSSL_INIT_LOAD_CONFIG, NULL)
#  define ossl_OPENSSL_add_all_algorithms_noconf() \
    ossl_OPENSSL_init_crypto(ossl_OPENSSL_INIT_ADD_ALL_CIPHERS \
                        | ossl_OPENSSL_INIT_ADD_ALL_DIGESTS, NULL)

#  ifdef ossl_OPENSSL_LOAD_CONF
#   define ossl_OpenSSL_add_all_algorithms() ossl_OPENSSL_add_all_algorithms_conf()
#  else
#   define ossl_OpenSSL_add_all_algorithms() ossl_OPENSSL_add_all_algorithms_noconf()
#  endif

#  define ossl_OpenSSL_add_all_ciphers() \
    ossl_OPENSSL_init_crypto(ossl_OPENSSL_INIT_ADD_ALL_CIPHERS, NULL)
#  define ossl_OpenSSL_add_all_digests() \
    ossl_OPENSSL_init_crypto(ossl_OPENSSL_INIT_ADD_ALL_DIGESTS, NULL)

#  define ossl_EVP_cleanup() while(0) continue
# endif

int ossl_EVP_add_cipher(const ossl_EVP_CIPHER *cipher);
int ossl_EVP_add_digest(const ossl_EVP_MD *digest);

const ossl_EVP_CIPHER *ossl_EVP_get_cipherbyname(const char *name);
const ossl_EVP_MD *ossl_EVP_get_digestbyname(const char *name);

void ossl_EVP_CIPHER_do_all(void (*fn) (const ossl_EVP_CIPHER *ciph,
                                   const char *from, const char *to, void *x),
                       void *arg);
void ossl_EVP_CIPHER_do_all_sorted(void (*fn)
                               (const ossl_EVP_CIPHER *ciph, const char *from,
                                const char *to, void *x), void *arg);
void ossl_EVP_CIPHER_do_all_provided(ossl_OSSL_LIB_CTX *libctx,
                                void (*fn)(ossl_EVP_CIPHER *cipher, void *arg),
                                void *arg);

void ossl_EVP_MD_do_all(void (*fn) (const ossl_EVP_MD *ciph,
                               const char *from, const char *to, void *x),
                   void *arg);
void ossl_EVP_MD_do_all_sorted(void (*fn)
                           (const ossl_EVP_MD *ciph, const char *from,
                            const char *to, void *x), void *arg);
void ossl_EVP_MD_do_all_provided(ossl_OSSL_LIB_CTX *libctx,
                            void (*fn)(ossl_EVP_MD *md, void *arg),
                            void *arg);

/* MAC stuff */

ossl_EVP_MAC *ossl_EVP_MAC_fetch(ossl_OSSL_LIB_CTX *libctx, const char *algorithm,
                       const char *properties);
int ossl_EVP_MAC_up_ref(ossl_EVP_MAC *mac);
void ossl_EVP_MAC_free(ossl_EVP_MAC *mac);
const char *ossl_EVP_MAC_get0_name(const ossl_EVP_MAC *mac);
const char *ossl_EVP_MAC_get0_description(const ossl_EVP_MAC *mac);
int ossl_EVP_MAC_is_a(const ossl_EVP_MAC *mac, const char *name);
const ossl_OSSL_PROVIDER *ossl_EVP_MAC_get0_provider(const ossl_EVP_MAC *mac);
int ossl_EVP_MAC_get_params(ossl_EVP_MAC *mac, ossl_OSSL_PARAM params[]);

ossl_EVP_MAC_CTX *ossl_EVP_MAC_CTX_new(ossl_EVP_MAC *mac);
void ossl_EVP_MAC_CTX_free(ossl_EVP_MAC_CTX *ctx);
ossl_EVP_MAC_CTX *ossl_EVP_MAC_CTX_dup(const ossl_EVP_MAC_CTX *src);
ossl_EVP_MAC *ossl_EVP_MAC_CTX_get0_mac(ossl_EVP_MAC_CTX *ctx);
int ossl_EVP_MAC_CTX_get_params(ossl_EVP_MAC_CTX *ctx, ossl_OSSL_PARAM params[]);
int ossl_EVP_MAC_CTX_set_params(ossl_EVP_MAC_CTX *ctx, const ossl_OSSL_PARAM params[]);

size_t ossl_EVP_MAC_CTX_get_mac_size(ossl_EVP_MAC_CTX *ctx);
size_t ossl_EVP_MAC_CTX_get_block_size(ossl_EVP_MAC_CTX *ctx);
unsigned char *ossl_EVP_Q_mac(ossl_OSSL_LIB_CTX *libctx, const char *name, const char *propq,
                         const char *subalg, const ossl_OSSL_PARAM *params,
                         const void *key, size_t keylen,
                         const unsigned char *data, size_t datalen,
                         unsigned char *out, size_t outsize, size_t *outlen);
int ossl_EVP_MAC_init(ossl_EVP_MAC_CTX *ctx, const unsigned char *key, size_t keylen,
                 const ossl_OSSL_PARAM params[]);
int ossl_EVP_MAC_update(ossl_EVP_MAC_CTX *ctx, const unsigned char *data, size_t datalen);
int ossl_EVP_MAC_final(ossl_EVP_MAC_CTX *ctx,
                  unsigned char *out, size_t *outl, size_t outsize);
int ossl_EVP_MAC_finalXOF(ossl_EVP_MAC_CTX *ctx, unsigned char *out, size_t outsize);
const ossl_OSSL_PARAM *ossl_EVP_MAC_gettable_params(const ossl_EVP_MAC *mac);
const ossl_OSSL_PARAM *ossl_EVP_MAC_gettable_ctx_params(const ossl_EVP_MAC *mac);
const ossl_OSSL_PARAM *ossl_EVP_MAC_settable_ctx_params(const ossl_EVP_MAC *mac);
const ossl_OSSL_PARAM *ossl_EVP_MAC_CTX_gettable_params(ossl_EVP_MAC_CTX *ctx);
const ossl_OSSL_PARAM *ossl_EVP_MAC_CTX_settable_params(ossl_EVP_MAC_CTX *ctx);

void ossl_EVP_MAC_do_all_provided(ossl_OSSL_LIB_CTX *libctx,
                             void (*fn)(ossl_EVP_MAC *mac, void *arg),
                             void *arg);
int ossl_EVP_MAC_names_do_all(const ossl_EVP_MAC *mac,
                         void (*fn)(const char *name, void *data),
                         void *data);

/* RAND stuff */
ossl_EVP_RAND *ossl_EVP_RAND_fetch(ossl_OSSL_LIB_CTX *libctx, const char *algorithm,
                         const char *properties);
int ossl_EVP_RAND_up_ref(ossl_EVP_RAND *rand);
void ossl_EVP_RAND_free(ossl_EVP_RAND *rand);
const char *ossl_EVP_RAND_get0_name(const ossl_EVP_RAND *rand);
const char *ossl_EVP_RAND_get0_description(const ossl_EVP_RAND *md);
int ossl_EVP_RAND_is_a(const ossl_EVP_RAND *rand, const char *name);
const ossl_OSSL_PROVIDER *ossl_EVP_RAND_get0_provider(const ossl_EVP_RAND *rand);
int ossl_EVP_RAND_get_params(ossl_EVP_RAND *rand, ossl_OSSL_PARAM params[]);

ossl_EVP_RAND_CTX *ossl_EVP_RAND_CTX_new(ossl_EVP_RAND *rand, ossl_EVP_RAND_CTX *parent);
void ossl_EVP_RAND_CTX_free(ossl_EVP_RAND_CTX *ctx);
ossl_EVP_RAND *ossl_EVP_RAND_CTX_get0_rand(ossl_EVP_RAND_CTX *ctx);
int ossl_EVP_RAND_CTX_get_params(ossl_EVP_RAND_CTX *ctx, ossl_OSSL_PARAM params[]);
int ossl_EVP_RAND_CTX_set_params(ossl_EVP_RAND_CTX *ctx, const ossl_OSSL_PARAM params[]);
const ossl_OSSL_PARAM *ossl_EVP_RAND_gettable_params(const ossl_EVP_RAND *rand);
const ossl_OSSL_PARAM *ossl_EVP_RAND_gettable_ctx_params(const ossl_EVP_RAND *rand);
const ossl_OSSL_PARAM *ossl_EVP_RAND_settable_ctx_params(const ossl_EVP_RAND *rand);
const ossl_OSSL_PARAM *ossl_EVP_RAND_CTX_gettable_params(ossl_EVP_RAND_CTX *ctx);
const ossl_OSSL_PARAM *ossl_EVP_RAND_CTX_settable_params(ossl_EVP_RAND_CTX *ctx);

void ossl_EVP_RAND_do_all_provided(ossl_OSSL_LIB_CTX *libctx,
                              void (*fn)(ossl_EVP_RAND *rand, void *arg),
                              void *arg);
int ossl_EVP_RAND_names_do_all(const ossl_EVP_RAND *rand,
                          void (*fn)(const char *name, void *data),
                          void *data);

ossl___owur int ossl_EVP_RAND_instantiate(ossl_EVP_RAND_CTX *ctx, unsigned int strength,
                                int prediction_resistance,
                                const unsigned char *pstr, size_t pstr_len,
                                const ossl_OSSL_PARAM params[]);
int ossl_EVP_RAND_uninstantiate(ossl_EVP_RAND_CTX *ctx);
ossl___owur int ossl_EVP_RAND_generate(ossl_EVP_RAND_CTX *ctx, unsigned char *out,
                             size_t outlen, unsigned int strength,
                             int prediction_resistance,
                             const unsigned char *addin, size_t addin_len);
int ossl_EVP_RAND_reseed(ossl_EVP_RAND_CTX *ctx, int prediction_resistance,
                    const unsigned char *ent, size_t ent_len,
                    const unsigned char *addin, size_t addin_len);
ossl___owur int ossl_EVP_RAND_nonce(ossl_EVP_RAND_CTX *ctx, unsigned char *out, size_t outlen);
ossl___owur int ossl_EVP_RAND_enable_locking(ossl_EVP_RAND_CTX *ctx);

int ossl_EVP_RAND_verify_zeroization(ossl_EVP_RAND_CTX *ctx);
unsigned int ossl_EVP_RAND_get_strength(ossl_EVP_RAND_CTX *ctx);
int ossl_EVP_RAND_get_state(ossl_EVP_RAND_CTX *ctx);

# define ossl_EVP_RAND_STATE_UNINITIALISED    0
# define ossl_EVP_RAND_STATE_READY            1
# define ossl_EVP_RAND_STATE_ERROR            2

/* PKEY stuff */
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EVP_PKEY_decrypt_old(unsigned char *dec_key,
                                          const unsigned char *enc_key,
                                          int enc_key_len,
                                          ossl_EVP_PKEY *private_key);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EVP_PKEY_encrypt_old(unsigned char *enc_key,
                                          const unsigned char *key,
                                          int key_len, ossl_EVP_PKEY *pub_key);
# endif
int ossl_EVP_PKEY_is_a(const ossl_EVP_PKEY *pkey, const char *name);
int ossl_EVP_PKEY_type_names_do_all(const ossl_EVP_PKEY *pkey,
                               void (*fn)(const char *name, void *data),
                               void *data);
int ossl_EVP_PKEY_type(int type);
int ossl_EVP_PKEY_get_id(const ossl_EVP_PKEY *pkey);
# define ossl_EVP_PKEY_id ossl_EVP_PKEY_get_id
int ossl_EVP_PKEY_get_base_id(const ossl_EVP_PKEY *pkey);
# define ossl_EVP_PKEY_base_id ossl_EVP_PKEY_get_base_id
int ossl_EVP_PKEY_get_bits(const ossl_EVP_PKEY *pkey);
# define ossl_EVP_PKEY_bits ossl_EVP_PKEY_get_bits
int ossl_EVP_PKEY_get_security_bits(const ossl_EVP_PKEY *pkey);
# define ossl_EVP_PKEY_security_bits ossl_EVP_PKEY_get_security_bits
int ossl_EVP_PKEY_get_size(const ossl_EVP_PKEY *pkey);
# define ossl_EVP_PKEY_size ossl_EVP_PKEY_get_size
int ossl_EVP_PKEY_can_sign(const ossl_EVP_PKEY *pkey);
int ossl_EVP_PKEY_set_type(ossl_EVP_PKEY *pkey, int type);
int ossl_EVP_PKEY_set_type_str(ossl_EVP_PKEY *pkey, const char *str, int len);
int ossl_EVP_PKEY_set_type_by_keymgmt(ossl_EVP_PKEY *pkey, ossl_EVP_KEYMGMT *keymgmt);
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  ifndef ossl_OPENSSL_NO_ENGINE
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_PKEY_set1_engine(ossl_EVP_PKEY *pkey, ossl_ENGINE *e);
ossl_OSSL_DEPRECATEDIN_3_0
ossl_ENGINE *ossl_EVP_PKEY_get0_engine(const ossl_EVP_PKEY *pkey);
#  endif
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_PKEY_assign(ossl_EVP_PKEY *pkey, int type, void *key);
ossl_OSSL_DEPRECATEDIN_3_0
void *ossl_EVP_PKEY_get0(const ossl_EVP_PKEY *pkey);
ossl_OSSL_DEPRECATEDIN_3_0
const unsigned char *ossl_EVP_PKEY_get0_hmac(const ossl_EVP_PKEY *pkey, size_t *len);
#  ifndef ossl_OPENSSL_NO_POLY1305
ossl_OSSL_DEPRECATEDIN_3_0
const unsigned char *ossl_EVP_PKEY_get0_poly1305(const ossl_EVP_PKEY *pkey, size_t *len);
#  endif
#  ifndef ossl_OPENSSL_NO_SIPHASH
ossl_OSSL_DEPRECATEDIN_3_0
const unsigned char *ossl_EVP_PKEY_get0_siphash(const ossl_EVP_PKEY *pkey, size_t *len);
#  endif

struct ossl_rsa_st;
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_PKEY_set1_RSA(ossl_EVP_PKEY *pkey, struct ossl_rsa_st *key);
ossl_OSSL_DEPRECATEDIN_3_0
const struct ossl_rsa_st *ossl_EVP_PKEY_get0_RSA(const ossl_EVP_PKEY *pkey);
ossl_OSSL_DEPRECATEDIN_3_0
struct ossl_rsa_st *ossl_EVP_PKEY_get1_RSA(ossl_EVP_PKEY *pkey);

#  ifndef ossl_OPENSSL_NO_DSA
struct ossl_dsa_st;
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_PKEY_set1_DSA(ossl_EVP_PKEY *pkey, struct ossl_dsa_st *key);
ossl_OSSL_DEPRECATEDIN_3_0
const struct ossl_dsa_st *ossl_EVP_PKEY_get0_DSA(const ossl_EVP_PKEY *pkey);
ossl_OSSL_DEPRECATEDIN_3_0
struct ossl_dsa_st *ossl_EVP_PKEY_get1_DSA(ossl_EVP_PKEY *pkey);
#  endif

#  ifndef ossl_OPENSSL_NO_DH
struct ossl_dh_st;
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EVP_PKEY_set1_DH(ossl_EVP_PKEY *pkey, struct ossl_dh_st *key);
ossl_OSSL_DEPRECATEDIN_3_0 const struct ossl_dh_st *ossl_EVP_PKEY_get0_DH(const ossl_EVP_PKEY *pkey);
ossl_OSSL_DEPRECATEDIN_3_0 struct ossl_dh_st *ossl_EVP_PKEY_get1_DH(ossl_EVP_PKEY *pkey);
#  endif

#  ifndef ossl_OPENSSL_NO_EC
struct ossl_ec_key_st;
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_PKEY_set1_EC_KEY(ossl_EVP_PKEY *pkey, struct ossl_ec_key_st *key);
ossl_OSSL_DEPRECATEDIN_3_0
const struct ossl_ec_key_st *ossl_EVP_PKEY_get0_EC_KEY(const ossl_EVP_PKEY *pkey);
ossl_OSSL_DEPRECATEDIN_3_0
struct ossl_ec_key_st *ossl_EVP_PKEY_get1_EC_KEY(ossl_EVP_PKEY *pkey);
#  endif
# endif /* ossl_OPENSSL_NO_DEPRECATED_3_0 */

ossl_EVP_PKEY *ossl_EVP_PKEY_new(void);
int ossl_EVP_PKEY_up_ref(ossl_EVP_PKEY *pkey);
ossl_EVP_PKEY *ossl_EVP_PKEY_dup(ossl_EVP_PKEY *pkey);
void ossl_EVP_PKEY_free(ossl_EVP_PKEY *pkey);
const char *ossl_EVP_PKEY_get0_description(const ossl_EVP_PKEY *pkey);
const ossl_OSSL_PROVIDER *ossl_EVP_PKEY_get0_provider(const ossl_EVP_PKEY *key);

ossl_EVP_PKEY *ossl_d2i_PublicKey(int type, ossl_EVP_PKEY **a, const unsigned char **pp,
                        long length);
int ossl_i2d_PublicKey(const ossl_EVP_PKEY *a, unsigned char **pp);


ossl_EVP_PKEY *ossl_d2i_PrivateKey_ex(int type, ossl_EVP_PKEY **a, const unsigned char **pp,
                            long length, ossl_OSSL_LIB_CTX *libctx,
                            const char *propq);
ossl_EVP_PKEY *ossl_d2i_PrivateKey(int type, ossl_EVP_PKEY **a, const unsigned char **pp,
                         long length);
ossl_EVP_PKEY *ossl_d2i_AutoPrivateKey_ex(ossl_EVP_PKEY **a, const unsigned char **pp,
                                long length, ossl_OSSL_LIB_CTX *libctx,
                                const char *propq);
ossl_EVP_PKEY *ossl_d2i_AutoPrivateKey(ossl_EVP_PKEY **a, const unsigned char **pp,
                             long length);
int ossl_i2d_PrivateKey(const ossl_EVP_PKEY *a, unsigned char **pp);

int ossl_i2d_KeyParams(const ossl_EVP_PKEY *a, unsigned char **pp);
ossl_EVP_PKEY *ossl_d2i_KeyParams(int type, ossl_EVP_PKEY **a, const unsigned char **pp,
                        long length);
int ossl_i2d_KeyParams_bio(ossl_BIO *bp, const ossl_EVP_PKEY *pkey);
ossl_EVP_PKEY *ossl_d2i_KeyParams_bio(int type, ossl_EVP_PKEY **a, ossl_BIO *in);

int ossl_EVP_PKEY_copy_parameters(ossl_EVP_PKEY *to, const ossl_EVP_PKEY *from);
int ossl_EVP_PKEY_missing_parameters(const ossl_EVP_PKEY *pkey);
int ossl_EVP_PKEY_save_parameters(ossl_EVP_PKEY *pkey, int mode);
int ossl_EVP_PKEY_parameters_eq(const ossl_EVP_PKEY *a, const ossl_EVP_PKEY *b);
int ossl_EVP_PKEY_eq(const ossl_EVP_PKEY *a, const ossl_EVP_PKEY *b);

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_PKEY_cmp_parameters(const ossl_EVP_PKEY *a, const ossl_EVP_PKEY *b);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_PKEY_cmp(const ossl_EVP_PKEY *a, const ossl_EVP_PKEY *b);
# endif

int ossl_EVP_PKEY_print_public(ossl_BIO *out, const ossl_EVP_PKEY *pkey,
                          int indent, ossl_ASN1_PCTX *pctx);
int ossl_EVP_PKEY_print_private(ossl_BIO *out, const ossl_EVP_PKEY *pkey,
                           int indent, ossl_ASN1_PCTX *pctx);
int ossl_EVP_PKEY_print_params(ossl_BIO *out, const ossl_EVP_PKEY *pkey,
                          int indent, ossl_ASN1_PCTX *pctx);
# ifndef ossl_OPENSSL_NO_STDIO
int ossl_EVP_PKEY_print_public_fp(FILE *fp, const ossl_EVP_PKEY *pkey,
                             int indent, ossl_ASN1_PCTX *pctx);
int ossl_EVP_PKEY_print_private_fp(FILE *fp, const ossl_EVP_PKEY *pkey,
                              int indent, ossl_ASN1_PCTX *pctx);
int ossl_EVP_PKEY_print_params_fp(FILE *fp, const ossl_EVP_PKEY *pkey,
                             int indent, ossl_ASN1_PCTX *pctx);
# endif

int ossl_EVP_PKEY_get_default_digest_nid(ossl_EVP_PKEY *pkey, int *pnid);
int ossl_EVP_PKEY_get_default_digest_name(ossl_EVP_PKEY *pkey,
                                     char *mdname, size_t mdname_sz);
int ossl_EVP_PKEY_digestsign_supports_digest(ossl_EVP_PKEY *pkey, ossl_OSSL_LIB_CTX *libctx,
                                        const char *name, const char *propq);

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
/*
 * For backwards compatibility. Use ossl_EVP_PKEY_set1_encoded_public_key in
 * preference
 */
#  define ossl_EVP_PKEY_set1_tls_encodedpoint(pkey, pt, ptlen) \
          ossl_EVP_PKEY_set1_encoded_public_key((pkey), (pt), (ptlen))
# endif

int ossl_EVP_PKEY_set1_encoded_public_key(ossl_EVP_PKEY *pkey,
                                     const unsigned char *pub, size_t publen);

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
/*
 * For backwards compatibility. Use ossl_EVP_PKEY_get1_encoded_public_key in
 * preference
 */
#  define ossl_EVP_PKEY_get1_tls_encodedpoint(pkey, ppt) \
          ossl_EVP_PKEY_get1_encoded_public_key((pkey), (ppt))
# endif

size_t ossl_EVP_PKEY_get1_encoded_public_key(ossl_EVP_PKEY *pkey, unsigned char **ppub);

/* calls methods */
int ossl_EVP_CIPHER_param_to_asn1(ossl_EVP_CIPHER_CTX *c, ossl_ASN1_TYPE *type);
int ossl_EVP_CIPHER_asn1_to_param(ossl_EVP_CIPHER_CTX *c, ossl_ASN1_TYPE *type);

/* These are used by ossl_EVP_CIPHER methods */
int ossl_EVP_CIPHER_set_asn1_iv(ossl_EVP_CIPHER_CTX *c, ossl_ASN1_TYPE *type);
int ossl_EVP_CIPHER_get_asn1_iv(ossl_EVP_CIPHER_CTX *c, ossl_ASN1_TYPE *type);

/* PKCS5 password based encryption */
int ossl_PKCS5_PBE_keyivgen(ossl_EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
                       ossl_ASN1_TYPE *param, const ossl_EVP_CIPHER *cipher,
                       const ossl_EVP_MD *md, int en_de);
int ossl_PKCS5_PBE_keyivgen_ex(ossl_EVP_CIPHER_CTX *cctx, const char *pass, int passlen,
                          ossl_ASN1_TYPE *param, const ossl_EVP_CIPHER *cipher,
                          const ossl_EVP_MD *md, int en_de, ossl_OSSL_LIB_CTX *libctx,
                          const char *propq);
int ossl_PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen,
                           const unsigned char *salt, int saltlen, int iter,
                           int keylen, unsigned char *out);
int ossl_PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
                      const unsigned char *salt, int saltlen, int iter,
                      const ossl_EVP_MD *digest, int keylen, unsigned char *out);
int ossl_PKCS5_v2_PBE_keyivgen(ossl_EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
                          ossl_ASN1_TYPE *param, const ossl_EVP_CIPHER *cipher,
                          const ossl_EVP_MD *md, int en_de);
int ossl_PKCS5_v2_PBE_keyivgen_ex(ossl_EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
                             ossl_ASN1_TYPE *param, const ossl_EVP_CIPHER *cipher,
                             const ossl_EVP_MD *md, int en_de,
                             ossl_OSSL_LIB_CTX *libctx, const char *propq);

#ifndef ossl_OPENSSL_NO_SCRYPT
int ossl_EVP_PBE_scrypt(const char *pass, size_t passlen,
                   const unsigned char *salt, size_t saltlen,
                   uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem,
                   unsigned char *key, size_t keylen);
int ossl_EVP_PBE_scrypt_ex(const char *pass, size_t passlen,
                      const unsigned char *salt, size_t saltlen,
                      uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem,
                      unsigned char *key, size_t keylen,
                      ossl_OSSL_LIB_CTX *ctx, const char *propq);

int ossl_PKCS5_v2_scrypt_keyivgen(ossl_EVP_CIPHER_CTX *ctx, const char *pass,
                             int passlen, ossl_ASN1_TYPE *param,
                             const ossl_EVP_CIPHER *c, const ossl_EVP_MD *md, int en_de);
int ossl_PKCS5_v2_scrypt_keyivgen_ex(ossl_EVP_CIPHER_CTX *ctx, const char *pass,
                                int passlen, ossl_ASN1_TYPE *param,
                                const ossl_EVP_CIPHER *c, const ossl_EVP_MD *md, int en_de,
                                ossl_OSSL_LIB_CTX *libctx, const char *propq);
#endif

void ossl_PKCS5_PBE_add(void);

int ossl_EVP_PBE_CipherInit(ossl_ASN1_OBJECT *pbe_obj, const char *pass, int passlen,
                       ossl_ASN1_TYPE *param, ossl_EVP_CIPHER_CTX *ctx, int en_de);

int ossl_EVP_PBE_CipherInit_ex(ossl_ASN1_OBJECT *pbe_obj, const char *pass, int passlen,
                          ossl_ASN1_TYPE *param, ossl_EVP_CIPHER_CTX *ctx, int en_de,
                          ossl_OSSL_LIB_CTX *libctx, const char *propq);

/* PBE type */

/* Can appear as the outermost AlgorithmIdentifier */
# define ossl_EVP_PBE_TYPE_OUTER      0x0
/* Is an PRF type OID */
# define ossl_EVP_PBE_TYPE_PRF        0x1
/* Is a PKCS#5 v2.0 KDF */
# define ossl_EVP_PBE_TYPE_KDF        0x2

int ossl_EVP_PBE_alg_add_type(int pbe_type, int pbe_nid, int cipher_nid,
                         int md_nid, ossl_EVP_PBE_KEYGEN *keygen);
int ossl_EVP_PBE_alg_add(int nid, const ossl_EVP_CIPHER *cipher, const ossl_EVP_MD *md,
                    ossl_EVP_PBE_KEYGEN *keygen);
int ossl_EVP_PBE_find(int type, int pbe_nid, int *pcnid, int *pmnid,
                 ossl_EVP_PBE_KEYGEN **pkeygen);
int ossl_EVP_PBE_find_ex(int type, int pbe_nid, int *pcnid, int *pmnid,
                    ossl_EVP_PBE_KEYGEN **pkeygen, ossl_EVP_PBE_KEYGEN_EX **pkeygen_ex);
void ossl_EVP_PBE_cleanup(void);
int ossl_EVP_PBE_get(int *ptype, int *ppbe_nid, size_t num);

# define ossl_ASN1_PKEY_ALIAS         0x1
# define ossl_ASN1_PKEY_DYNAMIC       0x2
# define ossl_ASN1_PKEY_SIGPARAM_NULL 0x4

# define ossl_ASN1_PKEY_CTRL_PKCS7_SIGN       0x1
# define ossl_ASN1_PKEY_CTRL_PKCS7_ENCRYPT    0x2
# define ossl_ASN1_PKEY_CTRL_DEFAULT_MD_NID   0x3
# define ossl_ASN1_PKEY_CTRL_CMS_SIGN         0x5
# define ossl_ASN1_PKEY_CTRL_CMS_ENVELOPE     0x7
# define ossl_ASN1_PKEY_CTRL_CMS_RI_TYPE      0x8

# define ossl_ASN1_PKEY_CTRL_SET1_TLS_ENCPT   0x9
# define ossl_ASN1_PKEY_CTRL_GET1_TLS_ENCPT   0xa
# define ossl_ASN1_PKEY_CTRL_CMS_IS_RI_TYPE_SUPPORTED 0xb

int ossl_EVP_PKEY_asn1_get_count(void);
const ossl_EVP_PKEY_ASN1_METHOD *ossl_EVP_PKEY_asn1_get0(int idx);
const ossl_EVP_PKEY_ASN1_METHOD *ossl_EVP_PKEY_asn1_find(ossl_ENGINE **pe, int type);
const ossl_EVP_PKEY_ASN1_METHOD *ossl_EVP_PKEY_asn1_find_str(ossl_ENGINE **pe,
                                                   const char *str, int len);
int ossl_EVP_PKEY_asn1_add0(const ossl_EVP_PKEY_ASN1_METHOD *ameth);
int ossl_EVP_PKEY_asn1_add_alias(int to, int from);
int ossl_EVP_PKEY_asn1_get0_info(int *ppkey_id, int *pkey_base_id,
                            int *ppkey_flags, const char **pinfo,
                            const char **ppem_str,
                            const ossl_EVP_PKEY_ASN1_METHOD *ameth);

const ossl_EVP_PKEY_ASN1_METHOD *ossl_EVP_PKEY_get0_asn1(const ossl_EVP_PKEY *pkey);
ossl_EVP_PKEY_ASN1_METHOD *ossl_EVP_PKEY_asn1_new(int id, int flags,
                                        const char *pem_str,
                                        const char *info);
void ossl_EVP_PKEY_asn1_copy(ossl_EVP_PKEY_ASN1_METHOD *dst,
                        const ossl_EVP_PKEY_ASN1_METHOD *src);
void ossl_EVP_PKEY_asn1_free(ossl_EVP_PKEY_ASN1_METHOD *ameth);
void ossl_EVP_PKEY_asn1_set_public(ossl_EVP_PKEY_ASN1_METHOD *ameth,
                              int (*pub_decode) (ossl_EVP_PKEY *pk,
                                                 const ossl_X509_PUBKEY *pub),
                              int (*pub_encode) (ossl_X509_PUBKEY *pub,
                                                 const ossl_EVP_PKEY *pk),
                              int (*pub_cmp) (const ossl_EVP_PKEY *a,
                                              const ossl_EVP_PKEY *b),
                              int (*pub_print) (ossl_BIO *out,
                                                const ossl_EVP_PKEY *pkey,
                                                int indent, ossl_ASN1_PCTX *pctx),
                              int (*pkey_size) (const ossl_EVP_PKEY *pk),
                              int (*pkey_bits) (const ossl_EVP_PKEY *pk));
void ossl_EVP_PKEY_asn1_set_private(ossl_EVP_PKEY_ASN1_METHOD *ameth,
                               int (*priv_decode) (ossl_EVP_PKEY *pk,
                                                   const ossl_PKCS8_PRIV_KEY_INFO
                                                   *p8inf),
                               int (*priv_encode) (ossl_PKCS8_PRIV_KEY_INFO *p8,
                                                   const ossl_EVP_PKEY *pk),
                               int (*priv_print) (ossl_BIO *out,
                                                  const ossl_EVP_PKEY *pkey,
                                                  int indent,
                                                  ossl_ASN1_PCTX *pctx));
void ossl_EVP_PKEY_asn1_set_param(ossl_EVP_PKEY_ASN1_METHOD *ameth,
                             int (*param_decode) (ossl_EVP_PKEY *pkey,
                                                  const unsigned char **pder,
                                                  int derlen),
                             int (*param_encode) (const ossl_EVP_PKEY *pkey,
                                                  unsigned char **pder),
                             int (*param_missing) (const ossl_EVP_PKEY *pk),
                             int (*param_copy) (ossl_EVP_PKEY *to,
                                                const ossl_EVP_PKEY *from),
                             int (*param_cmp) (const ossl_EVP_PKEY *a,
                                               const ossl_EVP_PKEY *b),
                             int (*param_print) (ossl_BIO *out,
                                                 const ossl_EVP_PKEY *pkey,
                                                 int indent,
                                                 ossl_ASN1_PCTX *pctx));

void ossl_EVP_PKEY_asn1_set_free(ossl_EVP_PKEY_ASN1_METHOD *ameth,
                            void (*pkey_free) (ossl_EVP_PKEY *pkey));
void ossl_EVP_PKEY_asn1_set_ctrl(ossl_EVP_PKEY_ASN1_METHOD *ameth,
                            int (*pkey_ctrl) (ossl_EVP_PKEY *pkey, int op,
                                              long arg1, void *arg2));
void ossl_EVP_PKEY_asn1_set_item(ossl_EVP_PKEY_ASN1_METHOD *ameth,
                            int (*item_verify) (ossl_EVP_MD_CTX *ctx,
                                                const ossl_ASN1_ITEM *it,
                                                const void *data,
                                                const ossl_X509_ALGOR *a,
                                                const ossl_ASN1_BIT_STRING *sig,
                                                ossl_EVP_PKEY *pkey),
                            int (*item_sign) (ossl_EVP_MD_CTX *ctx,
                                              const ossl_ASN1_ITEM *it,
                                              const void *data,
                                              ossl_X509_ALGOR *alg1,
                                              ossl_X509_ALGOR *alg2,
                                              ossl_ASN1_BIT_STRING *sig));

void ossl_EVP_PKEY_asn1_set_siginf(ossl_EVP_PKEY_ASN1_METHOD *ameth,
                              int (*siginf_set) (ossl_X509_SIG_INFO *siginf,
                                                 const ossl_X509_ALGOR *alg,
                                                 const ossl_ASN1_STRING *sig));

void ossl_EVP_PKEY_asn1_set_check(ossl_EVP_PKEY_ASN1_METHOD *ameth,
                             int (*pkey_check) (const ossl_EVP_PKEY *pk));

void ossl_EVP_PKEY_asn1_set_public_check(ossl_EVP_PKEY_ASN1_METHOD *ameth,
                                    int (*pkey_pub_check) (const ossl_EVP_PKEY *pk));

void ossl_EVP_PKEY_asn1_set_param_check(ossl_EVP_PKEY_ASN1_METHOD *ameth,
                                   int (*pkey_param_check) (const ossl_EVP_PKEY *pk));

void ossl_EVP_PKEY_asn1_set_set_priv_key(ossl_EVP_PKEY_ASN1_METHOD *ameth,
                                    int (*set_priv_key) (ossl_EVP_PKEY *pk,
                                                         const unsigned char
                                                            *priv,
                                                         size_t len));
void ossl_EVP_PKEY_asn1_set_set_pub_key(ossl_EVP_PKEY_ASN1_METHOD *ameth,
                                   int (*set_pub_key) (ossl_EVP_PKEY *pk,
                                                       const unsigned char *pub,
                                                       size_t len));
void ossl_EVP_PKEY_asn1_set_get_priv_key(ossl_EVP_PKEY_ASN1_METHOD *ameth,
                                    int (*get_priv_key) (const ossl_EVP_PKEY *pk,
                                                         unsigned char *priv,
                                                         size_t *len));
void ossl_EVP_PKEY_asn1_set_get_pub_key(ossl_EVP_PKEY_ASN1_METHOD *ameth,
                                   int (*get_pub_key) (const ossl_EVP_PKEY *pk,
                                                       unsigned char *pub,
                                                       size_t *len));

void ossl_EVP_PKEY_asn1_set_security_bits(ossl_EVP_PKEY_ASN1_METHOD *ameth,
                                     int (*pkey_security_bits) (const ossl_EVP_PKEY
                                                                *pk));

int ossl_EVP_PKEY_CTX_get_signature_md(ossl_EVP_PKEY_CTX *ctx, const ossl_EVP_MD **md);
int ossl_EVP_PKEY_CTX_set_signature_md(ossl_EVP_PKEY_CTX *ctx, const ossl_EVP_MD *md);

int ossl_EVP_PKEY_CTX_set1_id(ossl_EVP_PKEY_CTX *ctx, const void *id, int len);
int ossl_EVP_PKEY_CTX_get1_id(ossl_EVP_PKEY_CTX *ctx, void *id);
int ossl_EVP_PKEY_CTX_get1_id_len(ossl_EVP_PKEY_CTX *ctx, size_t *id_len);

int ossl_EVP_PKEY_CTX_set_kem_op(ossl_EVP_PKEY_CTX *ctx, const char *op);

const char *ossl_EVP_PKEY_get0_type_name(const ossl_EVP_PKEY *key);

# define ossl_EVP_PKEY_OP_UNDEFINED           0
# define ossl_EVP_PKEY_OP_PARAMGEN            (1<<1)
# define ossl_EVP_PKEY_OP_KEYGEN              (1<<2)
# define ossl_EVP_PKEY_OP_FROMDATA            (1<<3)
# define ossl_EVP_PKEY_OP_SIGN                (1<<4)
# define ossl_EVP_PKEY_OP_VERIFY              (1<<5)
# define ossl_EVP_PKEY_OP_VERIFYRECOVER       (1<<6)
# define ossl_EVP_PKEY_OP_SIGNCTX             (1<<7)
# define ossl_EVP_PKEY_OP_VERIFYCTX           (1<<8)
# define ossl_EVP_PKEY_OP_ENCRYPT             (1<<9)
# define ossl_EVP_PKEY_OP_DECRYPT             (1<<10)
# define ossl_EVP_PKEY_OP_DERIVE              (1<<11)
# define ossl_EVP_PKEY_OP_ENCAPSULATE         (1<<12)
# define ossl_EVP_PKEY_OP_DECAPSULATE         (1<<13)

# define ossl_EVP_PKEY_OP_TYPE_SIG    \
        (ossl_EVP_PKEY_OP_SIGN | ossl_EVP_PKEY_OP_VERIFY | ossl_EVP_PKEY_OP_VERIFYRECOVER \
                | ossl_EVP_PKEY_OP_SIGNCTX | ossl_EVP_PKEY_OP_VERIFYCTX)

# define ossl_EVP_PKEY_OP_TYPE_CRYPT \
        (ossl_EVP_PKEY_OP_ENCRYPT | ossl_EVP_PKEY_OP_DECRYPT)

# define ossl_EVP_PKEY_OP_TYPE_NOGEN \
        (ossl_EVP_PKEY_OP_TYPE_SIG | ossl_EVP_PKEY_OP_TYPE_CRYPT | ossl_EVP_PKEY_OP_DERIVE)

# define ossl_EVP_PKEY_OP_TYPE_GEN \
        (ossl_EVP_PKEY_OP_PARAMGEN | ossl_EVP_PKEY_OP_KEYGEN)


int ossl_EVP_PKEY_CTX_set_mac_key(ossl_EVP_PKEY_CTX *ctx, const unsigned char *key,
                             int keylen);

# define ossl_EVP_PKEY_CTRL_MD                1
# define ossl_EVP_PKEY_CTRL_PEER_KEY          2
# define ossl_EVP_PKEY_CTRL_SET_MAC_KEY       6
# define ossl_EVP_PKEY_CTRL_DIGESTINIT        7
/* Used by GOST key encryption in TLS */
# define ossl_EVP_PKEY_CTRL_SET_IV            8
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_EVP_PKEY_CTRL_PKCS7_ENCRYPT     3
#  define ossl_EVP_PKEY_CTRL_PKCS7_DECRYPT     4
#  define ossl_EVP_PKEY_CTRL_PKCS7_SIGN        5
#  define ossl_EVP_PKEY_CTRL_CMS_ENCRYPT       9
#  define ossl_EVP_PKEY_CTRL_CMS_DECRYPT       10
#  define ossl_EVP_PKEY_CTRL_CMS_SIGN          11
# endif
# define ossl_EVP_PKEY_CTRL_CIPHER            12
# define ossl_EVP_PKEY_CTRL_GET_MD            13
# define ossl_EVP_PKEY_CTRL_SET_DIGEST_SIZE   14
# define ossl_EVP_PKEY_CTRL_SET1_ID           15
# define ossl_EVP_PKEY_CTRL_GET1_ID           16
# define ossl_EVP_PKEY_CTRL_GET1_ID_LEN       17

# define ossl_EVP_PKEY_ALG_CTRL               0x1000

# define ossl_EVP_PKEY_FLAG_AUTOARGLEN        2
/*
 * Method handles all operations: don't assume any digest related defaults.
 */
# define ossl_EVP_PKEY_FLAG_SIGCTX_CUSTOM     4
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_EVP_PKEY_METHOD *ossl_EVP_PKEY_meth_find(int type);
ossl_OSSL_DEPRECATEDIN_3_0 ossl_EVP_PKEY_METHOD *ossl_EVP_PKEY_meth_new(int id, int flags);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_get0_info(int *ppkey_id, int *pflags,
                                              const ossl_EVP_PKEY_METHOD *meth);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_copy(ossl_EVP_PKEY_METHOD *dst,
                                         const ossl_EVP_PKEY_METHOD *src);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_free(ossl_EVP_PKEY_METHOD *pmeth);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EVP_PKEY_meth_add0(const ossl_EVP_PKEY_METHOD *pmeth);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EVP_PKEY_meth_remove(const ossl_EVP_PKEY_METHOD *pmeth);
ossl_OSSL_DEPRECATEDIN_3_0 size_t ossl_EVP_PKEY_meth_get_count(void);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_EVP_PKEY_METHOD *ossl_EVP_PKEY_meth_get0(size_t idx);
# endif

ossl_EVP_KEYMGMT *ossl_EVP_KEYMGMT_fetch(ossl_OSSL_LIB_CTX *ctx, const char *algorithm,
                               const char *properties);
int ossl_EVP_KEYMGMT_up_ref(ossl_EVP_KEYMGMT *keymgmt);
void ossl_EVP_KEYMGMT_free(ossl_EVP_KEYMGMT *keymgmt);
const ossl_OSSL_PROVIDER *ossl_EVP_KEYMGMT_get0_provider(const ossl_EVP_KEYMGMT *keymgmt);
const char *ossl_EVP_KEYMGMT_get0_name(const ossl_EVP_KEYMGMT *keymgmt);
const char *ossl_EVP_KEYMGMT_get0_description(const ossl_EVP_KEYMGMT *keymgmt);
int ossl_EVP_KEYMGMT_is_a(const ossl_EVP_KEYMGMT *keymgmt, const char *name);
void ossl_EVP_KEYMGMT_do_all_provided(ossl_OSSL_LIB_CTX *libctx,
                                 void (*fn)(ossl_EVP_KEYMGMT *keymgmt, void *arg),
                                 void *arg);
int ossl_EVP_KEYMGMT_names_do_all(const ossl_EVP_KEYMGMT *keymgmt,
                             void (*fn)(const char *name, void *data),
                             void *data);
const ossl_OSSL_PARAM *ossl_EVP_KEYMGMT_gettable_params(const ossl_EVP_KEYMGMT *keymgmt);
const ossl_OSSL_PARAM *ossl_EVP_KEYMGMT_settable_params(const ossl_EVP_KEYMGMT *keymgmt);
const ossl_OSSL_PARAM *ossl_EVP_KEYMGMT_gen_settable_params(const ossl_EVP_KEYMGMT *keymgmt);

ossl_EVP_PKEY_CTX *ossl_EVP_PKEY_CTX_new(ossl_EVP_PKEY *pkey, ossl_ENGINE *e);
ossl_EVP_PKEY_CTX *ossl_EVP_PKEY_CTX_new_id(int id, ossl_ENGINE *e);
ossl_EVP_PKEY_CTX *ossl_EVP_PKEY_CTX_new_from_name(ossl_OSSL_LIB_CTX *libctx,
                                         const char *name,
                                         const char *propquery);
ossl_EVP_PKEY_CTX *ossl_EVP_PKEY_CTX_new_from_pkey(ossl_OSSL_LIB_CTX *libctx,
                                         ossl_EVP_PKEY *pkey, const char *propquery);
ossl_EVP_PKEY_CTX *ossl_EVP_PKEY_CTX_dup(const ossl_EVP_PKEY_CTX *ctx);
void ossl_EVP_PKEY_CTX_free(ossl_EVP_PKEY_CTX *ctx);
int ossl_EVP_PKEY_CTX_is_a(ossl_EVP_PKEY_CTX *ctx, const char *keytype);

int ossl_EVP_PKEY_CTX_get_params(ossl_EVP_PKEY_CTX *ctx, ossl_OSSL_PARAM *params);
const ossl_OSSL_PARAM *ossl_EVP_PKEY_CTX_gettable_params(const ossl_EVP_PKEY_CTX *ctx);
int ossl_EVP_PKEY_CTX_set_params(ossl_EVP_PKEY_CTX *ctx, const ossl_OSSL_PARAM *params);
const ossl_OSSL_PARAM *ossl_EVP_PKEY_CTX_settable_params(const ossl_EVP_PKEY_CTX *ctx);
int ossl_EVP_PKEY_CTX_ctrl(ossl_EVP_PKEY_CTX *ctx, int keytype, int optype,
                      int cmd, int p1, void *p2);
int ossl_EVP_PKEY_CTX_ctrl_str(ossl_EVP_PKEY_CTX *ctx, const char *type,
                          const char *value);
int ossl_EVP_PKEY_CTX_ctrl_uint64(ossl_EVP_PKEY_CTX *ctx, int keytype, int optype,
                             int cmd, uint64_t value);

int ossl_EVP_PKEY_CTX_str2ctrl(ossl_EVP_PKEY_CTX *ctx, int cmd, const char *str);
int ossl_EVP_PKEY_CTX_hex2ctrl(ossl_EVP_PKEY_CTX *ctx, int cmd, const char *hex);

int ossl_EVP_PKEY_CTX_md(ossl_EVP_PKEY_CTX *ctx, int optype, int cmd, const char *md);

int ossl_EVP_PKEY_CTX_get_operation(ossl_EVP_PKEY_CTX *ctx);
void ossl_EVP_PKEY_CTX_set0_keygen_info(ossl_EVP_PKEY_CTX *ctx, int *dat, int datlen);

ossl_EVP_PKEY *ossl_EVP_PKEY_new_mac_key(int type, ossl_ENGINE *e,
                               const unsigned char *key, int keylen);
ossl_EVP_PKEY *ossl_EVP_PKEY_new_raw_private_key_ex(ossl_OSSL_LIB_CTX *libctx,
                                          const char *keytype,
                                          const char *propq,
                                          const unsigned char *priv, size_t len);
ossl_EVP_PKEY *ossl_EVP_PKEY_new_raw_private_key(int type, ossl_ENGINE *e,
                                       const unsigned char *priv,
                                       size_t len);
ossl_EVP_PKEY *ossl_EVP_PKEY_new_raw_public_key_ex(ossl_OSSL_LIB_CTX *libctx,
                                         const char *keytype, const char *propq,
                                         const unsigned char *pub, size_t len);
ossl_EVP_PKEY *ossl_EVP_PKEY_new_raw_public_key(int type, ossl_ENGINE *e,
                                      const unsigned char *pub,
                                      size_t len);
int ossl_EVP_PKEY_get_raw_private_key(const ossl_EVP_PKEY *pkey, unsigned char *priv,
                                 size_t *len);
int ossl_EVP_PKEY_get_raw_public_key(const ossl_EVP_PKEY *pkey, unsigned char *pub,
                                size_t *len);

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0
ossl_EVP_PKEY *ossl_EVP_PKEY_new_CMAC_key(ossl_ENGINE *e, const unsigned char *priv,
                                size_t len, const ossl_EVP_CIPHER *cipher);
# endif

void ossl_EVP_PKEY_CTX_set_data(ossl_EVP_PKEY_CTX *ctx, void *data);
void *ossl_EVP_PKEY_CTX_get_data(const ossl_EVP_PKEY_CTX *ctx);
ossl_EVP_PKEY *ossl_EVP_PKEY_CTX_get0_pkey(ossl_EVP_PKEY_CTX *ctx);

ossl_EVP_PKEY *ossl_EVP_PKEY_CTX_get0_peerkey(ossl_EVP_PKEY_CTX *ctx);

void ossl_EVP_PKEY_CTX_set_app_data(ossl_EVP_PKEY_CTX *ctx, void *data);
void *ossl_EVP_PKEY_CTX_get_app_data(ossl_EVP_PKEY_CTX *ctx);

void ossl_EVP_SIGNATURE_free(ossl_EVP_SIGNATURE *signature);
int ossl_EVP_SIGNATURE_up_ref(ossl_EVP_SIGNATURE *signature);
ossl_OSSL_PROVIDER *ossl_EVP_SIGNATURE_get0_provider(const ossl_EVP_SIGNATURE *signature);
ossl_EVP_SIGNATURE *ossl_EVP_SIGNATURE_fetch(ossl_OSSL_LIB_CTX *ctx, const char *algorithm,
                                   const char *properties);
int ossl_EVP_SIGNATURE_is_a(const ossl_EVP_SIGNATURE *signature, const char *name);
const char *ossl_EVP_SIGNATURE_get0_name(const ossl_EVP_SIGNATURE *signature);
const char *ossl_EVP_SIGNATURE_get0_description(const ossl_EVP_SIGNATURE *signature);
void ossl_EVP_SIGNATURE_do_all_provided(ossl_OSSL_LIB_CTX *libctx,
                                   void (*fn)(ossl_EVP_SIGNATURE *signature,
                                              void *data),
                                   void *data);
int ossl_EVP_SIGNATURE_names_do_all(const ossl_EVP_SIGNATURE *signature,
                               void (*fn)(const char *name, void *data),
                               void *data);
const ossl_OSSL_PARAM *ossl_EVP_SIGNATURE_gettable_ctx_params(const ossl_EVP_SIGNATURE *sig);
const ossl_OSSL_PARAM *ossl_EVP_SIGNATURE_settable_ctx_params(const ossl_EVP_SIGNATURE *sig);

void ossl_EVP_ASYM_CIPHER_free(ossl_EVP_ASYM_CIPHER *cipher);
int ossl_EVP_ASYM_CIPHER_up_ref(ossl_EVP_ASYM_CIPHER *cipher);
ossl_OSSL_PROVIDER *ossl_EVP_ASYM_CIPHER_get0_provider(const ossl_EVP_ASYM_CIPHER *cipher);
ossl_EVP_ASYM_CIPHER *ossl_EVP_ASYM_CIPHER_fetch(ossl_OSSL_LIB_CTX *ctx, const char *algorithm,
                                       const char *properties);
int ossl_EVP_ASYM_CIPHER_is_a(const ossl_EVP_ASYM_CIPHER *cipher, const char *name);
const char *ossl_EVP_ASYM_CIPHER_get0_name(const ossl_EVP_ASYM_CIPHER *cipher);
const char *ossl_EVP_ASYM_CIPHER_get0_description(const ossl_EVP_ASYM_CIPHER *cipher);
void ossl_EVP_ASYM_CIPHER_do_all_provided(ossl_OSSL_LIB_CTX *libctx,
                                     void (*fn)(ossl_EVP_ASYM_CIPHER *cipher,
                                                void *arg),
                                     void *arg);
int ossl_EVP_ASYM_CIPHER_names_do_all(const ossl_EVP_ASYM_CIPHER *cipher,
                                 void (*fn)(const char *name, void *data),
                                 void *data);
const ossl_OSSL_PARAM *ossl_EVP_ASYM_CIPHER_gettable_ctx_params(const ossl_EVP_ASYM_CIPHER *ciph);
const ossl_OSSL_PARAM *ossl_EVP_ASYM_CIPHER_settable_ctx_params(const ossl_EVP_ASYM_CIPHER *ciph);

void ossl_EVP_KEM_free(ossl_EVP_KEM *wrap);
int ossl_EVP_KEM_up_ref(ossl_EVP_KEM *wrap);
ossl_OSSL_PROVIDER *ossl_EVP_KEM_get0_provider(const ossl_EVP_KEM *wrap);
ossl_EVP_KEM *ossl_EVP_KEM_fetch(ossl_OSSL_LIB_CTX *ctx, const char *algorithm,
                       const char *properties);
int ossl_EVP_KEM_is_a(const ossl_EVP_KEM *wrap, const char *name);
const char *ossl_EVP_KEM_get0_name(const ossl_EVP_KEM *wrap);
const char *ossl_EVP_KEM_get0_description(const ossl_EVP_KEM *wrap);
void ossl_EVP_KEM_do_all_provided(ossl_OSSL_LIB_CTX *libctx,
                             void (*fn)(ossl_EVP_KEM *wrap, void *arg), void *arg);
int ossl_EVP_KEM_names_do_all(const ossl_EVP_KEM *wrap,
                         void (*fn)(const char *name, void *data), void *data);
const ossl_OSSL_PARAM *ossl_EVP_KEM_gettable_ctx_params(const ossl_EVP_KEM *kem);
const ossl_OSSL_PARAM *ossl_EVP_KEM_settable_ctx_params(const ossl_EVP_KEM *kem);

int ossl_EVP_PKEY_sign_init(ossl_EVP_PKEY_CTX *ctx);
int ossl_EVP_PKEY_sign_init_ex(ossl_EVP_PKEY_CTX *ctx, const ossl_OSSL_PARAM params[]);
int ossl_EVP_PKEY_sign(ossl_EVP_PKEY_CTX *ctx,
                  unsigned char *sig, size_t *siglen,
                  const unsigned char *tbs, size_t tbslen);
int ossl_EVP_PKEY_verify_init(ossl_EVP_PKEY_CTX *ctx);
int ossl_EVP_PKEY_verify_init_ex(ossl_EVP_PKEY_CTX *ctx, const ossl_OSSL_PARAM params[]);
int ossl_EVP_PKEY_verify(ossl_EVP_PKEY_CTX *ctx,
                    const unsigned char *sig, size_t siglen,
                    const unsigned char *tbs, size_t tbslen);
int ossl_EVP_PKEY_verify_recover_init(ossl_EVP_PKEY_CTX *ctx);
int ossl_EVP_PKEY_verify_recover_init_ex(ossl_EVP_PKEY_CTX *ctx,
                                    const ossl_OSSL_PARAM params[]);
int ossl_EVP_PKEY_verify_recover(ossl_EVP_PKEY_CTX *ctx,
                            unsigned char *rout, size_t *routlen,
                            const unsigned char *sig, size_t siglen);
int ossl_EVP_PKEY_encrypt_init(ossl_EVP_PKEY_CTX *ctx);
int ossl_EVP_PKEY_encrypt_init_ex(ossl_EVP_PKEY_CTX *ctx, const ossl_OSSL_PARAM params[]);
int ossl_EVP_PKEY_encrypt(ossl_EVP_PKEY_CTX *ctx,
                     unsigned char *out, size_t *outlen,
                     const unsigned char *in, size_t inlen);
int ossl_EVP_PKEY_decrypt_init(ossl_EVP_PKEY_CTX *ctx);
int ossl_EVP_PKEY_decrypt_init_ex(ossl_EVP_PKEY_CTX *ctx, const ossl_OSSL_PARAM params[]);
int ossl_EVP_PKEY_decrypt(ossl_EVP_PKEY_CTX *ctx,
                     unsigned char *out, size_t *outlen,
                     const unsigned char *in, size_t inlen);

int ossl_EVP_PKEY_derive_init(ossl_EVP_PKEY_CTX *ctx);
int ossl_EVP_PKEY_derive_init_ex(ossl_EVP_PKEY_CTX *ctx, const ossl_OSSL_PARAM params[]);
int ossl_EVP_PKEY_derive_set_peer_ex(ossl_EVP_PKEY_CTX *ctx, ossl_EVP_PKEY *peer,
                                int validate_peer);
int ossl_EVP_PKEY_derive_set_peer(ossl_EVP_PKEY_CTX *ctx, ossl_EVP_PKEY *peer);
int ossl_EVP_PKEY_derive(ossl_EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);

int ossl_EVP_PKEY_encapsulate_init(ossl_EVP_PKEY_CTX *ctx, const ossl_OSSL_PARAM params[]);
int ossl_EVP_PKEY_encapsulate(ossl_EVP_PKEY_CTX *ctx,
                         unsigned char *wrappedkey, size_t *wrappedkeylen,
                         unsigned char *genkey, size_t *genkeylen);
int ossl_EVP_PKEY_decapsulate_init(ossl_EVP_PKEY_CTX *ctx, const ossl_OSSL_PARAM params[]);
int ossl_EVP_PKEY_decapsulate(ossl_EVP_PKEY_CTX *ctx,
                         unsigned char *unwrapped, size_t *unwrappedlen,
                         const unsigned char *wrapped, size_t wrappedlen);

typedef int ossl_EVP_PKEY_gen_cb(ossl_EVP_PKEY_CTX *ctx);

int ossl_EVP_PKEY_fromdata_init(ossl_EVP_PKEY_CTX *ctx);
int ossl_EVP_PKEY_fromdata(ossl_EVP_PKEY_CTX *ctx, ossl_EVP_PKEY **ppkey, int selection,
                      ossl_OSSL_PARAM param[]);
const ossl_OSSL_PARAM *ossl_EVP_PKEY_fromdata_settable(ossl_EVP_PKEY_CTX *ctx, int selection);

int ossl_EVP_PKEY_todata(const ossl_EVP_PKEY *pkey, int selection, ossl_OSSL_PARAM **params);
int ossl_EVP_PKEY_export(const ossl_EVP_PKEY *pkey, int selection,
                    ossl_OSSL_CALLBACK *export_cb, void *export_cbarg);

const ossl_OSSL_PARAM *ossl_EVP_PKEY_gettable_params(const ossl_EVP_PKEY *pkey);
int ossl_EVP_PKEY_get_params(const ossl_EVP_PKEY *pkey, ossl_OSSL_PARAM params[]);
int ossl_EVP_PKEY_get_int_param(const ossl_EVP_PKEY *pkey, const char *key_name,
                           int *out);
int ossl_EVP_PKEY_get_size_t_param(const ossl_EVP_PKEY *pkey, const char *key_name,
                              size_t *out);
int ossl_EVP_PKEY_get_bn_param(const ossl_EVP_PKEY *pkey, const char *key_name,
                          ossl_BIGNUM **bn);
int ossl_EVP_PKEY_get_utf8_string_param(const ossl_EVP_PKEY *pkey, const char *key_name,
                                    char *str, size_t max_buf_sz, size_t *out_sz);
int ossl_EVP_PKEY_get_octet_string_param(const ossl_EVP_PKEY *pkey, const char *key_name,
                                    unsigned char *buf, size_t max_buf_sz,
                                    size_t *out_sz);

const ossl_OSSL_PARAM *ossl_EVP_PKEY_settable_params(const ossl_EVP_PKEY *pkey);
int ossl_EVP_PKEY_set_params(ossl_EVP_PKEY *pkey, ossl_OSSL_PARAM params[]);
int ossl_EVP_PKEY_set_int_param(ossl_EVP_PKEY *pkey, const char *key_name, int in);
int ossl_EVP_PKEY_set_size_t_param(ossl_EVP_PKEY *pkey, const char *key_name, size_t in);
int ossl_EVP_PKEY_set_bn_param(ossl_EVP_PKEY *pkey, const char *key_name,
                          const ossl_BIGNUM *bn);
int ossl_EVP_PKEY_set_utf8_string_param(ossl_EVP_PKEY *pkey, const char *key_name,
                                   const char *str);
int ossl_EVP_PKEY_set_octet_string_param(ossl_EVP_PKEY *pkey, const char *key_name,
                                    const unsigned char *buf, size_t bsize);

int ossl_EVP_PKEY_get_ec_point_conv_form(const ossl_EVP_PKEY *pkey);
int ossl_EVP_PKEY_get_field_type(const ossl_EVP_PKEY *pkey);

ossl_EVP_PKEY *ossl_EVP_PKEY_Q_keygen(ossl_OSSL_LIB_CTX *libctx, const char *propq,
                            const char *type, ...);
int ossl_EVP_PKEY_paramgen_init(ossl_EVP_PKEY_CTX *ctx);
int ossl_EVP_PKEY_paramgen(ossl_EVP_PKEY_CTX *ctx, ossl_EVP_PKEY **ppkey);
int ossl_EVP_PKEY_keygen_init(ossl_EVP_PKEY_CTX *ctx);
int ossl_EVP_PKEY_keygen(ossl_EVP_PKEY_CTX *ctx, ossl_EVP_PKEY **ppkey);
int ossl_EVP_PKEY_generate(ossl_EVP_PKEY_CTX *ctx, ossl_EVP_PKEY **ppkey);
int ossl_EVP_PKEY_check(ossl_EVP_PKEY_CTX *ctx);
int ossl_EVP_PKEY_public_check(ossl_EVP_PKEY_CTX *ctx);
int ossl_EVP_PKEY_public_check_quick(ossl_EVP_PKEY_CTX *ctx);
int ossl_EVP_PKEY_param_check(ossl_EVP_PKEY_CTX *ctx);
int ossl_EVP_PKEY_param_check_quick(ossl_EVP_PKEY_CTX *ctx);
int ossl_EVP_PKEY_private_check(ossl_EVP_PKEY_CTX *ctx);
int ossl_EVP_PKEY_pairwise_check(ossl_EVP_PKEY_CTX *ctx);

# define ossl_EVP_PKEY_get_ex_new_index(l, p, newf, dupf, freef) \
    ossl_CRYPTO_get_ex_new_index(ossl_CRYPTO_EX_INDEX_EVP_PKEY, l, p, newf, dupf, freef)
int ossl_EVP_PKEY_set_ex_data(ossl_EVP_PKEY *key, int idx, void *arg);
void *ossl_EVP_PKEY_get_ex_data(const ossl_EVP_PKEY *key, int idx);

void ossl_EVP_PKEY_CTX_set_cb(ossl_EVP_PKEY_CTX *ctx, ossl_EVP_PKEY_gen_cb *cb);
ossl_EVP_PKEY_gen_cb *ossl_EVP_PKEY_CTX_get_cb(ossl_EVP_PKEY_CTX *ctx);

int ossl_EVP_PKEY_CTX_get_keygen_info(ossl_EVP_PKEY_CTX *ctx, int idx);
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_set_init(ossl_EVP_PKEY_METHOD *pmeth,
                                             int (*init) (ossl_EVP_PKEY_CTX *ctx));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_set_copy
    (ossl_EVP_PKEY_METHOD *pmeth, int (*copy) (ossl_EVP_PKEY_CTX *dst,
                                          const ossl_EVP_PKEY_CTX *src));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_set_cleanup
    (ossl_EVP_PKEY_METHOD *pmeth, void (*cleanup) (ossl_EVP_PKEY_CTX *ctx));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_set_paramgen
    (ossl_EVP_PKEY_METHOD *pmeth, int (*paramgen_init) (ossl_EVP_PKEY_CTX *ctx),
     int (*paramgen) (ossl_EVP_PKEY_CTX *ctx, ossl_EVP_PKEY *pkey));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_set_keygen
    (ossl_EVP_PKEY_METHOD *pmeth, int (*keygen_init) (ossl_EVP_PKEY_CTX *ctx),
     int (*keygen) (ossl_EVP_PKEY_CTX *ctx, ossl_EVP_PKEY *pkey));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_set_sign
    (ossl_EVP_PKEY_METHOD *pmeth, int (*sign_init) (ossl_EVP_PKEY_CTX *ctx),
     int (*sign) (ossl_EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                  const unsigned char *tbs, size_t tbslen));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_set_verify
    (ossl_EVP_PKEY_METHOD *pmeth, int (*verify_init) (ossl_EVP_PKEY_CTX *ctx),
     int (*verify) (ossl_EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen,
                    const unsigned char *tbs, size_t tbslen));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_set_verify_recover
    (ossl_EVP_PKEY_METHOD *pmeth, int (*verify_recover_init) (ossl_EVP_PKEY_CTX *ctx),
     int (*verify_recover) (ossl_EVP_PKEY_CTX *ctx, unsigned char *sig,
                            size_t *siglen, const unsigned char *tbs,
                            size_t tbslen));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_set_signctx
    (ossl_EVP_PKEY_METHOD *pmeth, int (*signctx_init) (ossl_EVP_PKEY_CTX *ctx,
                                                  ossl_EVP_MD_CTX *mctx),
     int (*signctx) (ossl_EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                     ossl_EVP_MD_CTX *mctx));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_set_verifyctx
    (ossl_EVP_PKEY_METHOD *pmeth, int (*verifyctx_init) (ossl_EVP_PKEY_CTX *ctx,
                                                    ossl_EVP_MD_CTX *mctx),
     int (*verifyctx) (ossl_EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
                       ossl_EVP_MD_CTX *mctx));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_set_encrypt
    (ossl_EVP_PKEY_METHOD *pmeth, int (*encrypt_init) (ossl_EVP_PKEY_CTX *ctx),
     int (*encryptfn) (ossl_EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                       const unsigned char *in, size_t inlen));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_set_decrypt
    (ossl_EVP_PKEY_METHOD *pmeth, int (*decrypt_init) (ossl_EVP_PKEY_CTX *ctx),
     int (*decrypt) (ossl_EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                     const unsigned char *in, size_t inlen));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_set_derive
    (ossl_EVP_PKEY_METHOD *pmeth, int (*derive_init) (ossl_EVP_PKEY_CTX *ctx),
     int (*derive) (ossl_EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_set_ctrl
    (ossl_EVP_PKEY_METHOD *pmeth, int (*ctrl) (ossl_EVP_PKEY_CTX *ctx, int type, int p1,
                                          void *p2),
     int (*ctrl_str) (ossl_EVP_PKEY_CTX *ctx, const char *type, const char *value));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_set_digestsign
    (ossl_EVP_PKEY_METHOD *pmeth,
     int (*digestsign) (ossl_EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                        const unsigned char *tbs, size_t tbslen));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_set_digestverify
    (ossl_EVP_PKEY_METHOD *pmeth,
     int (*digestverify) (ossl_EVP_MD_CTX *ctx, const unsigned char *sig,
                          size_t siglen, const unsigned char *tbs,
                          size_t tbslen));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_set_check
    (ossl_EVP_PKEY_METHOD *pmeth, int (*check) (ossl_EVP_PKEY *pkey));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_set_public_check
    (ossl_EVP_PKEY_METHOD *pmeth, int (*check) (ossl_EVP_PKEY *pkey));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_set_param_check
    (ossl_EVP_PKEY_METHOD *pmeth, int (*check) (ossl_EVP_PKEY *pkey));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_set_digest_custom
    (ossl_EVP_PKEY_METHOD *pmeth, int (*digest_custom) (ossl_EVP_PKEY_CTX *ctx,
                                                   ossl_EVP_MD_CTX *mctx));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_get_init
    (const ossl_EVP_PKEY_METHOD *pmeth, int (**pinit) (ossl_EVP_PKEY_CTX *ctx));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_get_copy
    (const ossl_EVP_PKEY_METHOD *pmeth, int (**pcopy) (ossl_EVP_PKEY_CTX *dst,
                                                  const ossl_EVP_PKEY_CTX *src));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_get_cleanup
    (const ossl_EVP_PKEY_METHOD *pmeth, void (**pcleanup) (ossl_EVP_PKEY_CTX *ctx));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_get_paramgen
    (const ossl_EVP_PKEY_METHOD *pmeth, int (**pparamgen_init) (ossl_EVP_PKEY_CTX *ctx),
     int (**pparamgen) (ossl_EVP_PKEY_CTX *ctx, ossl_EVP_PKEY *pkey));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_get_keygen
    (const ossl_EVP_PKEY_METHOD *pmeth, int (**pkeygen_init) (ossl_EVP_PKEY_CTX *ctx),
     int (**pkeygen) (ossl_EVP_PKEY_CTX *ctx, ossl_EVP_PKEY *pkey));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_get_sign
    (const ossl_EVP_PKEY_METHOD *pmeth, int (**psign_init) (ossl_EVP_PKEY_CTX *ctx),
     int (**psign) (ossl_EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                    const unsigned char *tbs, size_t tbslen));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_get_verify
    (const ossl_EVP_PKEY_METHOD *pmeth, int (**pverify_init) (ossl_EVP_PKEY_CTX *ctx),
     int (**pverify) (ossl_EVP_PKEY_CTX *ctx, const unsigned char *sig,
                      size_t siglen, const unsigned char *tbs, size_t tbslen));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_get_verify_recover
    (const ossl_EVP_PKEY_METHOD *pmeth,
     int (**pverify_recover_init) (ossl_EVP_PKEY_CTX *ctx),
     int (**pverify_recover) (ossl_EVP_PKEY_CTX *ctx, unsigned char *sig,
                              size_t *siglen, const unsigned char *tbs,
                              size_t tbslen));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_get_signctx
    (const ossl_EVP_PKEY_METHOD *pmeth,
     int (**psignctx_init) (ossl_EVP_PKEY_CTX *ctx, ossl_EVP_MD_CTX *mctx),
     int (**psignctx) (ossl_EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                       ossl_EVP_MD_CTX *mctx));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_get_verifyctx
    (const ossl_EVP_PKEY_METHOD *pmeth,
     int (**pverifyctx_init) (ossl_EVP_PKEY_CTX *ctx, ossl_EVP_MD_CTX *mctx),
     int (**pverifyctx) (ossl_EVP_PKEY_CTX *ctx, const unsigned char *sig,
                          int siglen, ossl_EVP_MD_CTX *mctx));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_get_encrypt
    (const ossl_EVP_PKEY_METHOD *pmeth, int (**pencrypt_init) (ossl_EVP_PKEY_CTX *ctx),
     int (**pencryptfn) (ossl_EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                         const unsigned char *in, size_t inlen));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_get_decrypt
    (const ossl_EVP_PKEY_METHOD *pmeth, int (**pdecrypt_init) (ossl_EVP_PKEY_CTX *ctx),
     int (**pdecrypt) (ossl_EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                       const unsigned char *in, size_t inlen));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_get_derive
    (const ossl_EVP_PKEY_METHOD *pmeth, int (**pderive_init) (ossl_EVP_PKEY_CTX *ctx),
     int (**pderive) (ossl_EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_get_ctrl
    (const ossl_EVP_PKEY_METHOD *pmeth,
     int (**pctrl) (ossl_EVP_PKEY_CTX *ctx, int type, int p1, void *p2),
     int (**pctrl_str) (ossl_EVP_PKEY_CTX *ctx, const char *type,
                        const char *value));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_get_digestsign
    (const ossl_EVP_PKEY_METHOD *pmeth,
     int (**digestsign) (ossl_EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                         const unsigned char *tbs, size_t tbslen));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_get_digestverify
    (const ossl_EVP_PKEY_METHOD *pmeth,
     int (**digestverify) (ossl_EVP_MD_CTX *ctx, const unsigned char *sig,
                           size_t siglen, const unsigned char *tbs,
                           size_t tbslen));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_get_check
    (const ossl_EVP_PKEY_METHOD *pmeth, int (**pcheck) (ossl_EVP_PKEY *pkey));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_get_public_check
    (const ossl_EVP_PKEY_METHOD *pmeth, int (**pcheck) (ossl_EVP_PKEY *pkey));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_get_param_check
    (const ossl_EVP_PKEY_METHOD *pmeth, int (**pcheck) (ossl_EVP_PKEY *pkey));
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EVP_PKEY_meth_get_digest_custom
    (const ossl_EVP_PKEY_METHOD *pmeth,
     int (**pdigest_custom) (ossl_EVP_PKEY_CTX *ctx, ossl_EVP_MD_CTX *mctx));
# endif

void ossl_EVP_KEYEXCH_free(ossl_EVP_KEYEXCH *exchange);
int ossl_EVP_KEYEXCH_up_ref(ossl_EVP_KEYEXCH *exchange);
ossl_EVP_KEYEXCH *ossl_EVP_KEYEXCH_fetch(ossl_OSSL_LIB_CTX *ctx, const char *algorithm,
                               const char *properties);
ossl_OSSL_PROVIDER *ossl_EVP_KEYEXCH_get0_provider(const ossl_EVP_KEYEXCH *exchange);
int ossl_EVP_KEYEXCH_is_a(const ossl_EVP_KEYEXCH *keyexch, const char *name);
const char *ossl_EVP_KEYEXCH_get0_name(const ossl_EVP_KEYEXCH *keyexch);
const char *ossl_EVP_KEYEXCH_get0_description(const ossl_EVP_KEYEXCH *keyexch);
void ossl_EVP_KEYEXCH_do_all_provided(ossl_OSSL_LIB_CTX *libctx,
                                 void (*fn)(ossl_EVP_KEYEXCH *keyexch, void *data),
                                 void *data);
int ossl_EVP_KEYEXCH_names_do_all(const ossl_EVP_KEYEXCH *keyexch,
                             void (*fn)(const char *name, void *data),
                             void *data);
const ossl_OSSL_PARAM *ossl_EVP_KEYEXCH_gettable_ctx_params(const ossl_EVP_KEYEXCH *keyexch);
const ossl_OSSL_PARAM *ossl_EVP_KEYEXCH_settable_ctx_params(const ossl_EVP_KEYEXCH *keyexch);

void ossl_EVP_add_alg_module(void);

int ossl_EVP_PKEY_CTX_set_group_name(ossl_EVP_PKEY_CTX *ctx, const char *name);
int ossl_EVP_PKEY_CTX_get_group_name(ossl_EVP_PKEY_CTX *ctx, char *name, size_t namelen);
int ossl_EVP_PKEY_get_group_name(const ossl_EVP_PKEY *pkey, char *name, size_t name_sz,
                            size_t *gname_len);

ossl_OSSL_LIB_CTX *ossl_EVP_PKEY_CTX_get0_libctx(ossl_EVP_PKEY_CTX *ctx);
const char *ossl_EVP_PKEY_CTX_get0_propq(const ossl_EVP_PKEY_CTX *ctx);
const ossl_OSSL_PROVIDER *ossl_EVP_PKEY_CTX_get0_provider(const ossl_EVP_PKEY_CTX *ctx);

# ifdef  __cplusplus
}
# endif
#endif
