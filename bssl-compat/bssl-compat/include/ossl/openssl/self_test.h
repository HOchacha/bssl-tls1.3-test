/*
 * Copyright 2019-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_SELF_TEST_H
# define ossl_OPENSSL_SELF_TEST_H
# pragma once

# include "ossl/openssl/core.h" /* ossl_OSSL_CALLBACK */

# ifdef __cplusplus
extern "C" {
# endif

/* The test event phases */
# define ossl_OSSL_SELF_TEST_PHASE_NONE     "None"
# define ossl_OSSL_SELF_TEST_PHASE_START    "Start"
# define ossl_OSSL_SELF_TEST_PHASE_CORRUPT  "Corrupt"
# define ossl_OSSL_SELF_TEST_PHASE_PASS     "Pass"
# define ossl_OSSL_SELF_TEST_PHASE_FAIL     "Fail"

/* Test event categories */
# define ossl_OSSL_SELF_TEST_TYPE_NONE               "None"
# define ossl_OSSL_SELF_TEST_TYPE_MODULE_INTEGRITY   "Module_Integrity"
# define ossl_OSSL_SELF_TEST_TYPE_INSTALL_INTEGRITY  "Install_Integrity"
# define ossl_OSSL_SELF_TEST_TYPE_CRNG               "Continuous_RNG_Test"
# define ossl_OSSL_SELF_TEST_TYPE_PCT                "Conditional_PCT"
# define ossl_OSSL_SELF_TEST_TYPE_KAT_CIPHER         "KAT_Cipher"
# define ossl_OSSL_SELF_TEST_TYPE_KAT_ASYM_CIPHER    "KAT_AsymmetricCipher"
# define ossl_OSSL_SELF_TEST_TYPE_KAT_DIGEST         "KAT_Digest"
# define ossl_OSSL_SELF_TEST_TYPE_KAT_SIGNATURE      "KAT_Signature"
# define ossl_OSSL_SELF_TEST_TYPE_PCT_SIGNATURE      "PCT_Signature"
# define ossl_OSSL_SELF_TEST_TYPE_KAT_KDF            "KAT_KDF"
# define ossl_OSSL_SELF_TEST_TYPE_KAT_KA             "KAT_KA"
# define ossl_OSSL_SELF_TEST_TYPE_DRBG               "DRBG"

/* Test event sub categories */
# define ossl_OSSL_SELF_TEST_DESC_NONE           "None"
# define ossl_OSSL_SELF_TEST_DESC_INTEGRITY_HMAC "ossl_HMAC"
# define ossl_OSSL_SELF_TEST_DESC_PCT_RSA_PKCS1  "ossl_RSA"
# define ossl_OSSL_SELF_TEST_DESC_PCT_ECDSA      "ECDSA"
# define ossl_OSSL_SELF_TEST_DESC_PCT_DSA        "ossl_DSA"
# define ossl_OSSL_SELF_TEST_DESC_CIPHER_AES_GCM "ossl_AES_GCM"
# define ossl_OSSL_SELF_TEST_DESC_CIPHER_AES_ECB "ossl_AES_ECB_Decrypt"
# define ossl_OSSL_SELF_TEST_DESC_CIPHER_TDES    "TDES"
# define ossl_OSSL_SELF_TEST_DESC_ASYM_RSA_ENC   "RSA_Encrypt"
# define ossl_OSSL_SELF_TEST_DESC_ASYM_RSA_DEC   "RSA_Decrypt"
# define ossl_OSSL_SELF_TEST_DESC_MD_SHA1        "ossl_SHA1"
# define ossl_OSSL_SELF_TEST_DESC_MD_SHA2        "SHA2"
# define ossl_OSSL_SELF_TEST_DESC_MD_SHA3        "SHA3"
# define ossl_OSSL_SELF_TEST_DESC_SIGN_DSA       "ossl_DSA"
# define ossl_OSSL_SELF_TEST_DESC_SIGN_RSA       "ossl_RSA"
# define ossl_OSSL_SELF_TEST_DESC_SIGN_ECDSA     "ECDSA"
# define ossl_OSSL_SELF_TEST_DESC_DRBG_CTR       "CTR"
# define ossl_OSSL_SELF_TEST_DESC_DRBG_HASH      "HASH"
# define ossl_OSSL_SELF_TEST_DESC_DRBG_HMAC      "ossl_HMAC"
# define ossl_OSSL_SELF_TEST_DESC_KA_DH          "ossl_DH"
# define ossl_OSSL_SELF_TEST_DESC_KA_ECDH        "ECDH"
# define ossl_OSSL_SELF_TEST_DESC_KDF_HKDF       "HKDF"
# define ossl_OSSL_SELF_TEST_DESC_KDF_SSKDF      "SSKDF"
# define ossl_OSSL_SELF_TEST_DESC_KDF_X963KDF    "X963KDF"
# define ossl_OSSL_SELF_TEST_DESC_KDF_X942KDF    "X942KDF"
# define ossl_OSSL_SELF_TEST_DESC_KDF_PBKDF2     "PBKDF2"
# define ossl_OSSL_SELF_TEST_DESC_KDF_SSHKDF     "SSHKDF"
# define ossl_OSSL_SELF_TEST_DESC_KDF_TLS12_PRF  "TLS12_PRF"
# define ossl_OSSL_SELF_TEST_DESC_KDF_KBKDF      "KBKDF"
# define ossl_OSSL_SELF_TEST_DESC_KDF_TLS13_EXTRACT  "TLS13_KDF_EXTRACT"
# define ossl_OSSL_SELF_TEST_DESC_KDF_TLS13_EXPAND   "TLS13_KDF_EXPAND"
# define ossl_OSSL_SELF_TEST_DESC_RNG            "RNG"

void ossl_OSSL_SELF_TEST_set_callback(ossl_OSSL_LIB_CTX *libctx, ossl_OSSL_CALLBACK *cb,
                                 void *cbarg);
void ossl_OSSL_SELF_TEST_get_callback(ossl_OSSL_LIB_CTX *libctx, ossl_OSSL_CALLBACK **cb,
                                 void **cbarg);

ossl_OSSL_SELF_TEST *ossl_OSSL_SELF_TEST_new(ossl_OSSL_CALLBACK *cb, void *cbarg);
void ossl_OSSL_SELF_TEST_free(ossl_OSSL_SELF_TEST *st);

void ossl_OSSL_SELF_TEST_onbegin(ossl_OSSL_SELF_TEST *st, const char *type,
                            const char *desc);
int ossl_OSSL_SELF_TEST_oncorrupt_byte(ossl_OSSL_SELF_TEST *st, unsigned char *bytes);
void ossl_OSSL_SELF_TEST_onend(ossl_OSSL_SELF_TEST *st, int ret);

# ifdef __cplusplus
}
# endif
#endif /* ossl_OPENSSL_SELF_TEST_H */
