/*
 * Copyright 2019-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_CORE_NAMES_H
# define ossl_OPENSSL_CORE_NAMES_H
# pragma once

# ifdef __cplusplus
extern "C" {
# endif

/* Well known parameter names that core passes to providers */
#define ossl_OSSL_PROV_PARAM_CORE_VERSION         "openssl-version" /* utf8_ptr */
#define ossl_OSSL_PROV_PARAM_CORE_PROV_NAME       "provider-name"   /* utf8_ptr */
#define ossl_OSSL_PROV_PARAM_CORE_MODULE_FILENAME "module-filename" /* utf8_ptr */

/* Well known parameter names that Providers can define */
#define ossl_OSSL_PROV_PARAM_NAME            "name"                /* utf8_ptr */
#define ossl_OSSL_PROV_PARAM_VERSION         "version"             /* utf8_ptr */
#define ossl_OSSL_PROV_PARAM_BUILDINFO       "buildinfo"           /* utf8_ptr */
#define ossl_OSSL_PROV_PARAM_STATUS          "status"              /* uint */
#define ossl_OSSL_PROV_PARAM_SECURITY_CHECKS "security-checks"     /* uint */

/* Self test callback parameters */
#define ossl_OSSL_PROV_PARAM_SELF_TEST_PHASE  "st-phase" /* utf8_string */
#define ossl_OSSL_PROV_PARAM_SELF_TEST_TYPE   "st-type"  /* utf8_string */
#define ossl_OSSL_PROV_PARAM_SELF_TEST_DESC   "st-desc"  /* utf8_string */

/*-
 * Provider-native object abstractions
 *
 * These are used when a provider wants to pass object data or an object
 * reference back to libcrypto.  This is only useful for provider functions
 * that take a callback to which an ossl_OSSL_PARAM array with these parameters
 * can be passed.
 *
 * This set of parameter names is explained in detail in provider-object(7)
 * (doc/man7/provider-object.pod)
 */
#define ossl_OSSL_OBJECT_PARAM_TYPE              "type"      /* INTEGER */
#define ossl_OSSL_OBJECT_PARAM_DATA_TYPE         "data-type" /* UTF8_STRING */
#define ossl_OSSL_OBJECT_PARAM_DATA_STRUCTURE    "data-structure" /* UTF8_STRING */
#define ossl_OSSL_OBJECT_PARAM_REFERENCE         "reference" /* OCTET_STRING */
#define ossl_OSSL_OBJECT_PARAM_DATA              "data" /* OCTET_STRING or UTF8_STRING */
#define ossl_OSSL_OBJECT_PARAM_DESC              "desc"      /* UTF8_STRING */

/*
 * Algorithm parameters
 * If "engine" or "properties" are specified, they should always be paired
 * with the algorithm type.
 * Note these are common names that are shared by many types (such as kdf, mac,
 * and pkey) e.g: see ossl_OSSL_MAC_PARAM_DIGEST below.
 */
#define ossl_OSSL_ALG_PARAM_DIGEST       "digest"    /* utf8_string */
#define ossl_OSSL_ALG_PARAM_CIPHER       "cipher"    /* utf8_string */
#define ossl_OSSL_ALG_PARAM_ENGINE       "engine"    /* utf8_string */
#define ossl_OSSL_ALG_PARAM_MAC          "mac"       /* utf8_string */
#define ossl_OSSL_ALG_PARAM_PROPERTIES   "properties"/* utf8_string */

/* cipher parameters */
#define ossl_OSSL_CIPHER_PARAM_PADDING              "padding"      /* uint */
#define ossl_OSSL_CIPHER_PARAM_USE_BITS             "use-bits"     /* uint */
#define ossl_OSSL_CIPHER_PARAM_TLS_VERSION          "tls-version"  /* uint */
#define ossl_OSSL_CIPHER_PARAM_TLS_MAC              "tls-mac"      /* octet_ptr */
#define ossl_OSSL_CIPHER_PARAM_TLS_MAC_SIZE         "tls-mac-size" /* size_t */
#define ossl_OSSL_CIPHER_PARAM_MODE                 "mode"         /* uint */
#define ossl_OSSL_CIPHER_PARAM_BLOCK_SIZE           "blocksize"    /* size_t */
#define ossl_OSSL_CIPHER_PARAM_AEAD                 "aead"         /* int, 0 or 1 */
#define ossl_OSSL_CIPHER_PARAM_CUSTOM_IV            "custom-iv"    /* int, 0 or 1 */
#define ossl_OSSL_CIPHER_PARAM_CTS                  "cts"          /* int, 0 or 1 */
#define ossl_OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK      "tls-multi"    /* int, 0 or 1 */
#define ossl_OSSL_CIPHER_PARAM_HAS_RAND_KEY         "has-randkey"  /* int, 0 or 1 */
#define ossl_OSSL_CIPHER_PARAM_KEYLEN               "keylen"       /* size_t */
#define ossl_OSSL_CIPHER_PARAM_IVLEN                "ivlen"        /* size_t */
#define ossl_OSSL_CIPHER_PARAM_IV                   "iv"           /* octet_string OR octet_ptr */
#define ossl_OSSL_CIPHER_PARAM_UPDATED_IV           "updated-iv"   /* octet_string OR octet_ptr */
#define ossl_OSSL_CIPHER_PARAM_NUM                  "num"          /* uint */
#define ossl_OSSL_CIPHER_PARAM_ROUNDS               "rounds"       /* uint */
#define ossl_OSSL_CIPHER_PARAM_AEAD_TAG             "tag"          /* octet_string */
#define ossl_OSSL_CIPHER_PARAM_AEAD_TLS1_AAD        "tlsaad"       /* octet_string */
#define ossl_OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD    "tlsaadpad"    /* size_t */
#define ossl_OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED   "tlsivfixed"   /* octet_string */
#define ossl_OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN "tlsivgen"     /* octet_string */
#define ossl_OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV "tlsivinv"     /* octet_string */
#define ossl_OSSL_CIPHER_PARAM_AEAD_IVLEN           ossl_OSSL_CIPHER_PARAM_IVLEN
#define ossl_OSSL_CIPHER_PARAM_AEAD_TAGLEN          "taglen"       /* size_t */
#define ossl_OSSL_CIPHER_PARAM_AEAD_MAC_KEY         "mackey"       /* octet_string */
#define ossl_OSSL_CIPHER_PARAM_RANDOM_KEY           "randkey"      /* octet_string */
#define ossl_OSSL_CIPHER_PARAM_RC2_KEYBITS          "keybits"      /* size_t */
#define ossl_OSSL_CIPHER_PARAM_SPEED                "speed"        /* uint */
#define ossl_OSSL_CIPHER_PARAM_CTS_MODE             "cts_mode"     /* utf8_string */
/* For passing the AlgorithmIdentifier parameter in DER form */
#define ossl_OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS  "alg_id_param" /* octet_string */

#define ossl_OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_SEND_FRAGMENT                    \
    "tls1multi_maxsndfrag" /* uint */
#define ossl_OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_BUFSIZE                          \
    "tls1multi_maxbufsz"   /* size_t */
#define ossl_OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE                           \
    "tls1multi_interleave" /* uint */
#define ossl_OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD                                  \
    "tls1multi_aad"        /* octet_string */
#define ossl_OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD_PACKLEN                          \
    "tls1multi_aadpacklen" /* uint */
#define ossl_OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC                                  \
    "tls1multi_enc"        /* octet_string */
#define ossl_OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_IN                               \
    "tls1multi_encin"      /* octet_string */
#define ossl_OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_LEN                              \
    "tls1multi_enclen"     /* size_t */

/* ossl_OSSL_CIPHER_PARAM_CTS_MODE Values */
#define ossl_OSSL_CIPHER_CTS_MODE_CS1 "CS1"
#define ossl_OSSL_CIPHER_CTS_MODE_CS2 "CS2"
#define ossl_OSSL_CIPHER_CTS_MODE_CS3 "CS3"

/* digest parameters */
#define ossl_OSSL_DIGEST_PARAM_XOFLEN       "xoflen"        /* size_t */
#define ossl_OSSL_DIGEST_PARAM_SSL3_MS      "ssl3-ms"       /* octet string */
#define ossl_OSSL_DIGEST_PARAM_PAD_TYPE     "pad-type"      /* uint */
#define ossl_OSSL_DIGEST_PARAM_MICALG       "micalg"        /* utf8 string */
#define ossl_OSSL_DIGEST_PARAM_BLOCK_SIZE   "blocksize"     /* size_t */
#define ossl_OSSL_DIGEST_PARAM_SIZE         "size"          /* size_t */
#define ossl_OSSL_DIGEST_PARAM_XOF          "xof"           /* int, 0 or 1 */
#define ossl_OSSL_DIGEST_PARAM_ALGID_ABSENT "algid-absent"  /* int, 0 or 1 */

/* Known DIGEST names (not a complete list) */
#define ossl_OSSL_DIGEST_NAME_MD5            "ossl_MD5"
#define ossl_OSSL_DIGEST_NAME_MD5_SHA1       "ossl_MD5-ossl_SHA1"
#define ossl_OSSL_DIGEST_NAME_SHA1           "ossl_SHA1"
#define ossl_OSSL_DIGEST_NAME_SHA2_224       "SHA2-224"
#define ossl_OSSL_DIGEST_NAME_SHA2_256       "SHA2-256"
#define ossl_OSSL_DIGEST_NAME_SHA2_384       "SHA2-384"
#define ossl_OSSL_DIGEST_NAME_SHA2_512       "SHA2-512"
#define ossl_OSSL_DIGEST_NAME_SHA2_512_224   "SHA2-512/224"
#define ossl_OSSL_DIGEST_NAME_SHA2_512_256   "SHA2-512/256"
#define ossl_OSSL_DIGEST_NAME_MD2            "MD2"
#define ossl_OSSL_DIGEST_NAME_MD4            "ossl_MD4"
#define ossl_OSSL_DIGEST_NAME_MDC2           "ossl_MDC2"
#define ossl_OSSL_DIGEST_NAME_RIPEMD160      "ossl_RIPEMD160"
#define ossl_OSSL_DIGEST_NAME_SHA3_224       "SHA3-224"
#define ossl_OSSL_DIGEST_NAME_SHA3_256       "SHA3-256"
#define ossl_OSSL_DIGEST_NAME_SHA3_384       "SHA3-384"
#define ossl_OSSL_DIGEST_NAME_SHA3_512       "SHA3-512"
#define ossl_OSSL_DIGEST_NAME_KECCAK_KMAC128 "KECCAK-KMAC-128"
#define ossl_OSSL_DIGEST_NAME_KECCAK_KMAC256 "KECCAK-KMAC-256"
#define ossl_OSSL_DIGEST_NAME_SM3            "SM3"

/* MAC parameters */
#define ossl_OSSL_MAC_PARAM_KEY            "key"            /* octet string */
#define ossl_OSSL_MAC_PARAM_IV             "iv"             /* octet string */
#define ossl_OSSL_MAC_PARAM_CUSTOM         "custom"         /* utf8 string */
#define ossl_OSSL_MAC_PARAM_SALT           "salt"           /* octet string */
#define ossl_OSSL_MAC_PARAM_XOF            "xof"            /* int, 0 or 1 */
#define ossl_OSSL_MAC_PARAM_DIGEST_NOINIT  "digest-noinit"  /* int, 0 or 1 */
#define ossl_OSSL_MAC_PARAM_DIGEST_ONESHOT "digest-oneshot" /* int, 0 or 1 */
#define ossl_OSSL_MAC_PARAM_C_ROUNDS       "c-rounds"       /* unsigned int */
#define ossl_OSSL_MAC_PARAM_D_ROUNDS       "d-rounds"       /* unsigned int */

/*
 * If "engine" or "properties" are specified, they should always be paired
 * with "cipher" or "digest".
 */
#define ossl_OSSL_MAC_PARAM_CIPHER           ossl_OSSL_ALG_PARAM_CIPHER     /* utf8 string */
#define ossl_OSSL_MAC_PARAM_DIGEST           ossl_OSSL_ALG_PARAM_DIGEST     /* utf8 string */
#define ossl_OSSL_MAC_PARAM_PROPERTIES       ossl_OSSL_ALG_PARAM_PROPERTIES /* utf8 string */
#define ossl_OSSL_MAC_PARAM_SIZE             "size"                    /* size_t */
#define ossl_OSSL_MAC_PARAM_BLOCK_SIZE       "block-size"              /* size_t */
#define ossl_OSSL_MAC_PARAM_TLS_DATA_SIZE    "tls-data-size"           /* size_t */

/* Known MAC names */
#define ossl_OSSL_MAC_NAME_BLAKE2BMAC    "BLAKE2BMAC"
#define ossl_OSSL_MAC_NAME_BLAKE2SMAC    "BLAKE2SMAC"
#define ossl_OSSL_MAC_NAME_CMAC          "CMAC"
#define ossl_OSSL_MAC_NAME_GMAC          "GMAC"
#define ossl_OSSL_MAC_NAME_HMAC          "ossl_HMAC"
#define ossl_OSSL_MAC_NAME_KMAC128       "KMAC128"
#define ossl_OSSL_MAC_NAME_KMAC256       "KMAC256"
#define ossl_OSSL_MAC_NAME_POLY1305      "POLY1305"
#define ossl_OSSL_MAC_NAME_SIPHASH       "SIPHASH"

/* KDF / PRF parameters */
#define ossl_OSSL_KDF_PARAM_SECRET       "secret"    /* octet string */
#define ossl_OSSL_KDF_PARAM_KEY          "key"       /* octet string */
#define ossl_OSSL_KDF_PARAM_SALT         "salt"      /* octet string */
#define ossl_OSSL_KDF_PARAM_PASSWORD     "pass"      /* octet string */
#define ossl_OSSL_KDF_PARAM_PREFIX       "prefix"    /* octet string */
#define ossl_OSSL_KDF_PARAM_LABEL        "label"     /* octet string */
#define ossl_OSSL_KDF_PARAM_DATA         "data"      /* octet string */
#define ossl_OSSL_KDF_PARAM_DIGEST       ossl_OSSL_ALG_PARAM_DIGEST     /* utf8 string */
#define ossl_OSSL_KDF_PARAM_CIPHER       ossl_OSSL_ALG_PARAM_CIPHER     /* utf8 string */
#define ossl_OSSL_KDF_PARAM_MAC          ossl_OSSL_ALG_PARAM_MAC        /* utf8 string */
#define ossl_OSSL_KDF_PARAM_MAC_SIZE     "maclen"    /* size_t */
#define ossl_OSSL_KDF_PARAM_PROPERTIES   ossl_OSSL_ALG_PARAM_PROPERTIES /* utf8 string */
#define ossl_OSSL_KDF_PARAM_ITER         "iter"      /* unsigned int */
#define ossl_OSSL_KDF_PARAM_MODE         "mode"      /* utf8 string or int */
#define ossl_OSSL_KDF_PARAM_PKCS5        "pkcs5"     /* int */
#define ossl_OSSL_KDF_PARAM_UKM          "ukm"       /* octet string */
#define ossl_OSSL_KDF_PARAM_CEK_ALG      "cekalg"    /* utf8 string */
#define ossl_OSSL_KDF_PARAM_SCRYPT_N     "n"         /* uint64_t */
#define ossl_OSSL_KDF_PARAM_SCRYPT_R     "r"         /* uint32_t */
#define ossl_OSSL_KDF_PARAM_SCRYPT_P     "p"         /* uint32_t */
#define ossl_OSSL_KDF_PARAM_SCRYPT_MAXMEM "maxmem_bytes" /* uint64_t */
#define ossl_OSSL_KDF_PARAM_INFO         "info"      /* octet string */
#define ossl_OSSL_KDF_PARAM_SEED         "seed"      /* octet string */
#define ossl_OSSL_KDF_PARAM_SSHKDF_XCGHASH "xcghash" /* octet string */
#define ossl_OSSL_KDF_PARAM_SSHKDF_SESSION_ID "session_id" /* octet string */
#define ossl_OSSL_KDF_PARAM_SSHKDF_TYPE  "type"      /* int */
#define ossl_OSSL_KDF_PARAM_SIZE         "size"      /* size_t */
#define ossl_OSSL_KDF_PARAM_CONSTANT     "constant"  /* octet string */
#define ossl_OSSL_KDF_PARAM_PKCS12_ID    "id"        /* int */
#define ossl_OSSL_KDF_PARAM_KBKDF_USE_L  "use-l"             /* int */
#define ossl_OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR  "use-separator"     /* int */
#define ossl_OSSL_KDF_PARAM_X942_ACVPINFO        "acvp-info"
#define ossl_OSSL_KDF_PARAM_X942_PARTYUINFO      "partyu-info"
#define ossl_OSSL_KDF_PARAM_X942_PARTYVINFO      "partyv-info"
#define ossl_OSSL_KDF_PARAM_X942_SUPP_PUBINFO    "supp-pubinfo"
#define ossl_OSSL_KDF_PARAM_X942_SUPP_PRIVINFO   "supp-privinfo"
#define ossl_OSSL_KDF_PARAM_X942_USE_KEYBITS     "use-keybits"

/* Known KDF names */
#define ossl_OSSL_KDF_NAME_HKDF           "HKDF"
#define ossl_OSSL_KDF_NAME_TLS1_3_KDF     "TLS13-KDF"
#define ossl_OSSL_KDF_NAME_PBKDF1         "PBKDF1"
#define ossl_OSSL_KDF_NAME_PBKDF2         "PBKDF2"
#define ossl_OSSL_KDF_NAME_SCRYPT         "SCRYPT"
#define ossl_OSSL_KDF_NAME_SSHKDF         "SSHKDF"
#define ossl_OSSL_KDF_NAME_SSKDF          "SSKDF"
#define ossl_OSSL_KDF_NAME_TLS1_PRF       "TLS1-PRF"
#define ossl_OSSL_KDF_NAME_X942KDF_ASN1   "X942KDF-ASN1"
#define ossl_OSSL_KDF_NAME_X942KDF_CONCAT "X942KDF-CONCAT"
#define ossl_OSSL_KDF_NAME_X963KDF        "X963KDF"
#define ossl_OSSL_KDF_NAME_KBKDF          "KBKDF"
#define ossl_OSSL_KDF_NAME_KRB5KDF        "KRB5KDF"

/* Known RAND names */
#define ossl_OSSL_RAND_PARAM_STATE                   "state"
#define ossl_OSSL_RAND_PARAM_STRENGTH                "strength"
#define ossl_OSSL_RAND_PARAM_MAX_REQUEST             "max_request"
#define ossl_OSSL_RAND_PARAM_TEST_ENTROPY            "test_entropy"
#define ossl_OSSL_RAND_PARAM_TEST_NONCE              "test_nonce"

/* RAND/DRBG names */
#define ossl_OSSL_DRBG_PARAM_RESEED_REQUESTS         "reseed_requests"
#define ossl_OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL    "reseed_time_interval"
#define ossl_OSSL_DRBG_PARAM_MIN_ENTROPYLEN          "min_entropylen"
#define ossl_OSSL_DRBG_PARAM_MAX_ENTROPYLEN          "max_entropylen"
#define ossl_OSSL_DRBG_PARAM_MIN_NONCELEN            "min_noncelen"
#define ossl_OSSL_DRBG_PARAM_MAX_NONCELEN            "max_noncelen"
#define ossl_OSSL_DRBG_PARAM_MAX_PERSLEN             "max_perslen"
#define ossl_OSSL_DRBG_PARAM_MAX_ADINLEN             "max_adinlen"
#define ossl_OSSL_DRBG_PARAM_RESEED_COUNTER          "reseed_counter"
#define ossl_OSSL_DRBG_PARAM_RESEED_TIME             "reseed_time"
#define ossl_OSSL_DRBG_PARAM_PROPERTIES              ossl_OSSL_ALG_PARAM_PROPERTIES
#define ossl_OSSL_DRBG_PARAM_DIGEST                  ossl_OSSL_ALG_PARAM_DIGEST
#define ossl_OSSL_DRBG_PARAM_CIPHER                  ossl_OSSL_ALG_PARAM_CIPHER
#define ossl_OSSL_DRBG_PARAM_MAC                     ossl_OSSL_ALG_PARAM_MAC
#define ossl_OSSL_DRBG_PARAM_USE_DF                  "use_derivation_function"

/* DRBG call back parameters */
#define ossl_OSSL_DRBG_PARAM_ENTROPY_REQUIRED        "entropy_required"
#define ossl_OSSL_DRBG_PARAM_PREDICTION_RESISTANCE   "prediction_resistance"
#define ossl_OSSL_DRBG_PARAM_MIN_LENGTH              "minium_length"
#define ossl_OSSL_DRBG_PARAM_MAX_LENGTH              "maxium_length"
#define ossl_OSSL_DRBG_PARAM_RANDOM_DATA             "random_data"
#define ossl_OSSL_DRBG_PARAM_SIZE                    "size"

/* PKEY parameters */
/* Common PKEY parameters */
#define ossl_OSSL_PKEY_PARAM_BITS                "bits" /* integer */
#define ossl_OSSL_PKEY_PARAM_MAX_SIZE            "max-size" /* integer */
#define ossl_OSSL_PKEY_PARAM_SECURITY_BITS       "security-bits" /* integer */
#define ossl_OSSL_PKEY_PARAM_DIGEST              ossl_OSSL_ALG_PARAM_DIGEST
#define ossl_OSSL_PKEY_PARAM_CIPHER              ossl_OSSL_ALG_PARAM_CIPHER /* utf8 string */
#define ossl_OSSL_PKEY_PARAM_ENGINE              ossl_OSSL_ALG_PARAM_ENGINE /* utf8 string */
#define ossl_OSSL_PKEY_PARAM_PROPERTIES          ossl_OSSL_ALG_PARAM_PROPERTIES
#define ossl_OSSL_PKEY_PARAM_DEFAULT_DIGEST      "default-digest" /* utf8 string */
#define ossl_OSSL_PKEY_PARAM_MANDATORY_DIGEST    "mandatory-digest" /* utf8 string */
#define ossl_OSSL_PKEY_PARAM_PAD_MODE            "pad-mode"
#define ossl_OSSL_PKEY_PARAM_DIGEST_SIZE         "digest-size"
#define ossl_OSSL_PKEY_PARAM_MASKGENFUNC         "mgf"
#define ossl_OSSL_PKEY_PARAM_MGF1_DIGEST         "mgf1-digest"
#define ossl_OSSL_PKEY_PARAM_MGF1_PROPERTIES     "mgf1-properties"
#define ossl_OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY  "encoded-pub-key"
#define ossl_OSSL_PKEY_PARAM_GROUP_NAME          "group"
#define ossl_OSSL_PKEY_PARAM_DIST_ID             "distid"
#define ossl_OSSL_PKEY_PARAM_PUB_KEY             "pub"
#define ossl_OSSL_PKEY_PARAM_PRIV_KEY            "priv"

/* Diffie-Hellman/ossl_DSA Parameters */
#define ossl_OSSL_PKEY_PARAM_FFC_P               "p"
#define ossl_OSSL_PKEY_PARAM_FFC_G               "g"
#define ossl_OSSL_PKEY_PARAM_FFC_Q               "q"
#define ossl_OSSL_PKEY_PARAM_FFC_GINDEX          "gindex"
#define ossl_OSSL_PKEY_PARAM_FFC_PCOUNTER        "pcounter"
#define ossl_OSSL_PKEY_PARAM_FFC_SEED            "seed"
#define ossl_OSSL_PKEY_PARAM_FFC_COFACTOR        "j"
#define ossl_OSSL_PKEY_PARAM_FFC_H               "hindex"
#define ossl_OSSL_PKEY_PARAM_FFC_VALIDATE_PQ     "validate-pq"
#define ossl_OSSL_PKEY_PARAM_FFC_VALIDATE_G      "validate-g"
#define ossl_OSSL_PKEY_PARAM_FFC_VALIDATE_LEGACY "validate-legacy"

/* Diffie-Hellman params */
#define ossl_OSSL_PKEY_PARAM_DH_GENERATOR        "safeprime-generator"
#define ossl_OSSL_PKEY_PARAM_DH_PRIV_LEN         "priv_len"

/* Elliptic Curve Domain Parameters */
#define ossl_OSSL_PKEY_PARAM_EC_PUB_X     "qx"
#define ossl_OSSL_PKEY_PARAM_EC_PUB_Y     "qy"

/* Elliptic Curve Explicit Domain Parameters */
#define ossl_OSSL_PKEY_PARAM_EC_FIELD_TYPE                   "field-type"
#define ossl_OSSL_PKEY_PARAM_EC_P                            "p"
#define ossl_OSSL_PKEY_PARAM_EC_A                            "a"
#define ossl_OSSL_PKEY_PARAM_EC_B                            "b"
#define ossl_OSSL_PKEY_PARAM_EC_GENERATOR                    "generator"
#define ossl_OSSL_PKEY_PARAM_EC_ORDER                        "order"
#define ossl_OSSL_PKEY_PARAM_EC_COFACTOR                     "cofactor"
#define ossl_OSSL_PKEY_PARAM_EC_SEED                         "seed"
#define ossl_OSSL_PKEY_PARAM_EC_CHAR2_M                      "m"
#define ossl_OSSL_PKEY_PARAM_EC_CHAR2_TYPE                   "basis-type"
#define ossl_OSSL_PKEY_PARAM_EC_CHAR2_TP_BASIS               "tp"
#define ossl_OSSL_PKEY_PARAM_EC_CHAR2_PP_K1                  "k1"
#define ossl_OSSL_PKEY_PARAM_EC_CHAR2_PP_K2                  "k2"
#define ossl_OSSL_PKEY_PARAM_EC_CHAR2_PP_K3                  "k3"
#define ossl_OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS "decoded-from-explicit"

/* Elliptic Curve Key Parameters */
#define ossl_OSSL_PKEY_PARAM_USE_COFACTOR_FLAG "use-cofactor-flag"
#define ossl_OSSL_PKEY_PARAM_USE_COFACTOR_ECDH \
    ossl_OSSL_PKEY_PARAM_USE_COFACTOR_FLAG

/* ossl_RSA Keys */
/*
 * n, e, d are the usual public and private key components
 *
 * rsa-num is the number of factors, including p and q
 * rsa-factor is used for each factor: p, q, r_i (i = 3, ...)
 * rsa-exponent is used for each exponent: dP, dQ, d_i (i = 3, ...)
 * rsa-coefficient is used for each coefficient: qInv, t_i (i = 3, ...)
 *
 * The number of rsa-factor items must be equal to the number of rsa-exponent
 * items, and the number of rsa-coefficients must be one less.
 * (the base i for the coefficients is 2, not 1, at least as implied by
 * RFC 8017)
 */
#define ossl_OSSL_PKEY_PARAM_RSA_N           "n"
#define ossl_OSSL_PKEY_PARAM_RSA_E           "e"
#define ossl_OSSL_PKEY_PARAM_RSA_D           "d"
#define ossl_OSSL_PKEY_PARAM_RSA_FACTOR      "rsa-factor"
#define ossl_OSSL_PKEY_PARAM_RSA_EXPONENT    "rsa-exponent"
#define ossl_OSSL_PKEY_PARAM_RSA_COEFFICIENT "rsa-coefficient"
#define ossl_OSSL_PKEY_PARAM_RSA_FACTOR1      ossl_OSSL_PKEY_PARAM_RSA_FACTOR"1"
#define ossl_OSSL_PKEY_PARAM_RSA_FACTOR2      ossl_OSSL_PKEY_PARAM_RSA_FACTOR"2"
#define ossl_OSSL_PKEY_PARAM_RSA_FACTOR3      ossl_OSSL_PKEY_PARAM_RSA_FACTOR"3"
#define ossl_OSSL_PKEY_PARAM_RSA_FACTOR4      ossl_OSSL_PKEY_PARAM_RSA_FACTOR"4"
#define ossl_OSSL_PKEY_PARAM_RSA_FACTOR5      ossl_OSSL_PKEY_PARAM_RSA_FACTOR"5"
#define ossl_OSSL_PKEY_PARAM_RSA_FACTOR6      ossl_OSSL_PKEY_PARAM_RSA_FACTOR"6"
#define ossl_OSSL_PKEY_PARAM_RSA_FACTOR7      ossl_OSSL_PKEY_PARAM_RSA_FACTOR"7"
#define ossl_OSSL_PKEY_PARAM_RSA_FACTOR8      ossl_OSSL_PKEY_PARAM_RSA_FACTOR"8"
#define ossl_OSSL_PKEY_PARAM_RSA_FACTOR9      ossl_OSSL_PKEY_PARAM_RSA_FACTOR"9"
#define ossl_OSSL_PKEY_PARAM_RSA_FACTOR10     ossl_OSSL_PKEY_PARAM_RSA_FACTOR"10"
#define ossl_OSSL_PKEY_PARAM_RSA_EXPONENT1    ossl_OSSL_PKEY_PARAM_RSA_EXPONENT"1"
#define ossl_OSSL_PKEY_PARAM_RSA_EXPONENT2    ossl_OSSL_PKEY_PARAM_RSA_EXPONENT"2"
#define ossl_OSSL_PKEY_PARAM_RSA_EXPONENT3    ossl_OSSL_PKEY_PARAM_RSA_EXPONENT"3"
#define ossl_OSSL_PKEY_PARAM_RSA_EXPONENT4    ossl_OSSL_PKEY_PARAM_RSA_EXPONENT"4"
#define ossl_OSSL_PKEY_PARAM_RSA_EXPONENT5    ossl_OSSL_PKEY_PARAM_RSA_EXPONENT"5"
#define ossl_OSSL_PKEY_PARAM_RSA_EXPONENT6    ossl_OSSL_PKEY_PARAM_RSA_EXPONENT"6"
#define ossl_OSSL_PKEY_PARAM_RSA_EXPONENT7    ossl_OSSL_PKEY_PARAM_RSA_EXPONENT"7"
#define ossl_OSSL_PKEY_PARAM_RSA_EXPONENT8    ossl_OSSL_PKEY_PARAM_RSA_EXPONENT"8"
#define ossl_OSSL_PKEY_PARAM_RSA_EXPONENT9    ossl_OSSL_PKEY_PARAM_RSA_EXPONENT"9"
#define ossl_OSSL_PKEY_PARAM_RSA_EXPONENT10   ossl_OSSL_PKEY_PARAM_RSA_EXPONENT"10"
#define ossl_OSSL_PKEY_PARAM_RSA_COEFFICIENT1 ossl_OSSL_PKEY_PARAM_RSA_COEFFICIENT"1"
#define ossl_OSSL_PKEY_PARAM_RSA_COEFFICIENT2 ossl_OSSL_PKEY_PARAM_RSA_COEFFICIENT"2"
#define ossl_OSSL_PKEY_PARAM_RSA_COEFFICIENT3 ossl_OSSL_PKEY_PARAM_RSA_COEFFICIENT"3"
#define ossl_OSSL_PKEY_PARAM_RSA_COEFFICIENT4 ossl_OSSL_PKEY_PARAM_RSA_COEFFICIENT"4"
#define ossl_OSSL_PKEY_PARAM_RSA_COEFFICIENT5 ossl_OSSL_PKEY_PARAM_RSA_COEFFICIENT"5"
#define ossl_OSSL_PKEY_PARAM_RSA_COEFFICIENT6 ossl_OSSL_PKEY_PARAM_RSA_COEFFICIENT"6"
#define ossl_OSSL_PKEY_PARAM_RSA_COEFFICIENT7 ossl_OSSL_PKEY_PARAM_RSA_COEFFICIENT"7"
#define ossl_OSSL_PKEY_PARAM_RSA_COEFFICIENT8 ossl_OSSL_PKEY_PARAM_RSA_COEFFICIENT"8"
#define ossl_OSSL_PKEY_PARAM_RSA_COEFFICIENT9 ossl_OSSL_PKEY_PARAM_RSA_COEFFICIENT"9"

/* ossl_RSA padding modes */
#define ossl_OSSL_PKEY_RSA_PAD_MODE_NONE    "none"
#define ossl_OSSL_PKEY_RSA_PAD_MODE_PKCSV15 "pkcs1"
#define ossl_OSSL_PKEY_RSA_PAD_MODE_OAEP    "oaep"
#define ossl_OSSL_PKEY_RSA_PAD_MODE_X931    "x931"
#define ossl_OSSL_PKEY_RSA_PAD_MODE_PSS     "pss"

/* ossl_RSA pss padding salt length */
#define ossl_OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST "digest"
#define ossl_OSSL_PKEY_RSA_PSS_SALT_LEN_MAX    "max"
#define ossl_OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO   "auto"

/* Key generation parameters */
#define ossl_OSSL_PKEY_PARAM_RSA_BITS             ossl_OSSL_PKEY_PARAM_BITS
#define ossl_OSSL_PKEY_PARAM_RSA_PRIMES           "primes"
#define ossl_OSSL_PKEY_PARAM_RSA_DIGEST           ossl_OSSL_PKEY_PARAM_DIGEST
#define ossl_OSSL_PKEY_PARAM_RSA_DIGEST_PROPS     ossl_OSSL_PKEY_PARAM_PROPERTIES
#define ossl_OSSL_PKEY_PARAM_RSA_MASKGENFUNC      ossl_OSSL_PKEY_PARAM_MASKGENFUNC
#define ossl_OSSL_PKEY_PARAM_RSA_MGF1_DIGEST      ossl_OSSL_PKEY_PARAM_MGF1_DIGEST
#define ossl_OSSL_PKEY_PARAM_RSA_PSS_SALTLEN      "saltlen"

/* Key generation parameters */
#define ossl_OSSL_PKEY_PARAM_FFC_TYPE         "type"
#define ossl_OSSL_PKEY_PARAM_FFC_PBITS        "pbits"
#define ossl_OSSL_PKEY_PARAM_FFC_QBITS        "qbits"
#define ossl_OSSL_PKEY_PARAM_FFC_DIGEST       ossl_OSSL_PKEY_PARAM_DIGEST
#define ossl_OSSL_PKEY_PARAM_FFC_DIGEST_PROPS ossl_OSSL_PKEY_PARAM_PROPERTIES

#define ossl_OSSL_PKEY_PARAM_EC_ENCODING                "encoding" /* utf8_string */
#define ossl_OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT "point-format"
#define ossl_OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE        "group-check"
#define ossl_OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC          "include-public"

/* ossl_OSSL_PKEY_PARAM_EC_ENCODING values */
#define ossl_OSSL_PKEY_EC_ENCODING_EXPLICIT  "explicit"
#define ossl_OSSL_PKEY_EC_ENCODING_GROUP     "named_curve"

#define ossl_OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED "uncompressed"
#define ossl_OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED   "compressed"
#define ossl_OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_HYBRID       "hybrid"

#define ossl_OSSL_PKEY_EC_GROUP_CHECK_DEFAULT     "default"
#define ossl_OSSL_PKEY_EC_GROUP_CHECK_NAMED       "named"
#define ossl_OSSL_PKEY_EC_GROUP_CHECK_NAMED_NIST  "named-nist"

/* Key Exchange parameters */
#define ossl_OSSL_EXCHANGE_PARAM_PAD                   "pad" /* uint */
#define ossl_OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE "ecdh-cofactor-mode" /* int */
#define ossl_OSSL_EXCHANGE_PARAM_KDF_TYPE              "kdf-type" /* utf8_string */
#define ossl_OSSL_EXCHANGE_PARAM_KDF_DIGEST            "kdf-digest" /* utf8_string */
#define ossl_OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS      "kdf-digest-props" /* utf8_string */
#define ossl_OSSL_EXCHANGE_PARAM_KDF_OUTLEN            "kdf-outlen" /* size_t */
/* The following parameter is an octet_string on set and an octet_ptr on get */
#define ossl_OSSL_EXCHANGE_PARAM_KDF_UKM               "kdf-ukm"

/* Signature parameters */
#define ossl_OSSL_SIGNATURE_PARAM_ALGORITHM_ID       "algorithm-id"
#define ossl_OSSL_SIGNATURE_PARAM_PAD_MODE           ossl_OSSL_PKEY_PARAM_PAD_MODE
#define ossl_OSSL_SIGNATURE_PARAM_DIGEST             ossl_OSSL_PKEY_PARAM_DIGEST
#define ossl_OSSL_SIGNATURE_PARAM_PROPERTIES         ossl_OSSL_PKEY_PARAM_PROPERTIES
#define ossl_OSSL_SIGNATURE_PARAM_PSS_SALTLEN        "saltlen"
#define ossl_OSSL_SIGNATURE_PARAM_MGF1_DIGEST        ossl_OSSL_PKEY_PARAM_MGF1_DIGEST
#define ossl_OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES    \
    ossl_OSSL_PKEY_PARAM_MGF1_PROPERTIES
#define ossl_OSSL_SIGNATURE_PARAM_DIGEST_SIZE        ossl_OSSL_PKEY_PARAM_DIGEST_SIZE

/* Asym cipher parameters */
#define ossl_OSSL_ASYM_CIPHER_PARAM_DIGEST                   ossl_OSSL_PKEY_PARAM_DIGEST
#define ossl_OSSL_ASYM_CIPHER_PARAM_PROPERTIES               ossl_OSSL_PKEY_PARAM_PROPERTIES
#define ossl_OSSL_ASYM_CIPHER_PARAM_ENGINE                   ossl_OSSL_PKEY_PARAM_ENGINE
#define ossl_OSSL_ASYM_CIPHER_PARAM_PAD_MODE                 ossl_OSSL_PKEY_PARAM_PAD_MODE
#define ossl_OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST              \
    ossl_OSSL_PKEY_PARAM_MGF1_DIGEST
#define ossl_OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS        \
    ossl_OSSL_PKEY_PARAM_MGF1_PROPERTIES
#define ossl_OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST              ossl_OSSL_ALG_PARAM_DIGEST
#define ossl_OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS        "digest-props"
/* The following parameter is an octet_string on set and an octet_ptr on get */
#define ossl_OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL               "oaep-label"
#define ossl_OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION       "tls-client-version"
#define ossl_OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION   "tls-negotiated-version"

/*
 * Encoder / decoder parameters
 */
#define ossl_OSSL_ENCODER_PARAM_CIPHER           ossl_OSSL_ALG_PARAM_CIPHER
#define ossl_OSSL_ENCODER_PARAM_PROPERTIES       ossl_OSSL_ALG_PARAM_PROPERTIES
/* Currently PVK only, but reusable for others as needed */
#define ossl_OSSL_ENCODER_PARAM_ENCRYPT_LEVEL    "encrypt-level"
#define ossl_OSSL_ENCODER_PARAM_SAVE_PARAMETERS  "save-parameters" /* integer */

#define ossl_OSSL_DECODER_PARAM_PROPERTIES       ossl_OSSL_ALG_PARAM_PROPERTIES

/* Passphrase callback parameters */
#define ossl_OSSL_PASSPHRASE_PARAM_INFO      "info"

/* Keygen callback parameters, from provider to libcrypto */
#define ossl_OSSL_GEN_PARAM_POTENTIAL            "potential" /* integer */
#define ossl_OSSL_GEN_PARAM_ITERATION            "iteration" /* integer */

/* ACVP Test parameters : These should not be used normally */
#define ossl_OSSL_PKEY_PARAM_RSA_TEST_XP1 "xp1"
#define ossl_OSSL_PKEY_PARAM_RSA_TEST_XP2 "xp2"
#define ossl_OSSL_PKEY_PARAM_RSA_TEST_XP  "xp"
#define ossl_OSSL_PKEY_PARAM_RSA_TEST_XQ1 "xq1"
#define ossl_OSSL_PKEY_PARAM_RSA_TEST_XQ2 "xq2"
#define ossl_OSSL_PKEY_PARAM_RSA_TEST_XQ  "xq"
#define ossl_OSSL_PKEY_PARAM_RSA_TEST_P1  "p1"
#define ossl_OSSL_PKEY_PARAM_RSA_TEST_P2  "p2"
#define ossl_OSSL_PKEY_PARAM_RSA_TEST_Q1  "q1"
#define ossl_OSSL_PKEY_PARAM_RSA_TEST_Q2  "q2"
#define ossl_OSSL_SIGNATURE_PARAM_KAT "kat"

/* KEM parameters */
#define ossl_OSSL_KEM_PARAM_OPERATION            "operation"

/* ossl_OSSL_KEM_PARAM_OPERATION values */
#define ossl_OSSL_KEM_PARAM_OPERATION_RSASVE     "RSASVE"

/* Capabilities */

/* TLS-GROUP Capability */
#define ossl_OSSL_CAPABILITY_TLS_GROUP_NAME              "tls-group-name"
#define ossl_OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL     "tls-group-name-internal"
#define ossl_OSSL_CAPABILITY_TLS_GROUP_ID                "tls-group-id"
#define ossl_OSSL_CAPABILITY_TLS_GROUP_ALG               "tls-group-alg"
#define ossl_OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS     "tls-group-sec-bits"
#define ossl_OSSL_CAPABILITY_TLS_GROUP_IS_KEM            "tls-group-is-kem"
#define ossl_OSSL_CAPABILITY_TLS_GROUP_MIN_TLS           "tls-min-tls"
#define ossl_OSSL_CAPABILITY_TLS_GROUP_MAX_TLS           "tls-max-tls"
#define ossl_OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS          "tls-min-dtls"
#define ossl_OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS          "tls-max-dtls"

/*-
 * storemgmt parameters
 */

/*
 * Used by storemgmt_ctx_set_params():
 *
 * - ossl_OSSL_STORE_PARAM_EXPECT is an INTEGER, and the value is any of the
 *   ossl_OSSL_STORE_INFO numbers.  This is used to set the expected type of
 *   object loaded.
 *
 * - ossl_OSSL_STORE_PARAM_SUBJECT, ossl_OSSL_STORE_PARAM_ISSUER,
 *   ossl_OSSL_STORE_PARAM_SERIAL, ossl_OSSL_STORE_PARAM_FINGERPRINT,
 *   ossl_OSSL_STORE_PARAM_DIGEST, ossl_OSSL_STORE_PARAM_ALIAS
 *   are used as search criteria.
 *   (ossl_OSSL_STORE_PARAM_DIGEST is used with ossl_OSSL_STORE_PARAM_FINGERPRINT)
 */
#define ossl_OSSL_STORE_PARAM_EXPECT     "expect"       /* INTEGER */
#define ossl_OSSL_STORE_PARAM_SUBJECT    "subject" /* DER blob => OCTET_STRING */
#define ossl_OSSL_STORE_PARAM_ISSUER     "name" /* DER blob => OCTET_STRING */
#define ossl_OSSL_STORE_PARAM_SERIAL     "serial"       /* INTEGER */
#define ossl_OSSL_STORE_PARAM_DIGEST     "digest"       /* UTF8_STRING */
#define ossl_OSSL_STORE_PARAM_FINGERPRINT "fingerprint" /* OCTET_STRING */
#define ossl_OSSL_STORE_PARAM_ALIAS      "alias"        /* UTF8_STRING */

/* You may want to pass properties for the provider implementation to use */
#define ossl_OSSL_STORE_PARAM_PROPERTIES "properties"   /* utf8_string */
/* ossl_OSSL_DECODER input type if a decoder is used by the store */
#define ossl_OSSL_STORE_PARAM_INPUT_TYPE "input-type"   /* UTF8_STRING */

# ifdef __cplusplus
}
# endif

#endif
