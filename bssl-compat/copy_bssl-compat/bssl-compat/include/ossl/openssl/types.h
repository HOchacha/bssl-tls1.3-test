/*
 * Copyright 2001-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_TYPES_H
# define ossl_OPENSSL_TYPES_H
# pragma once

# include <limits.h>

# ifdef  __cplusplus
extern "C" {
# endif

# include "ossl/openssl/e_os2.h"
# include "ossl/openssl/safestack.h"
# include "ossl/openssl/macros.h"

typedef struct ossl_ossl_provider_st ossl_OSSL_PROVIDER; /* Provider Object */

# ifdef NO_ASN1_TYPEDEFS
#  define ossl_ASN1_INTEGER            ossl_ASN1_STRING
#  define ossl_ASN1_ENUMERATED         ossl_ASN1_STRING
#  define ossl_ASN1_BIT_STRING         ossl_ASN1_STRING
#  define ossl_ASN1_OCTET_STRING       ossl_ASN1_STRING
#  define ossl_ASN1_PRINTABLESTRING    ossl_ASN1_STRING
#  define ossl_ASN1_T61STRING          ossl_ASN1_STRING
#  define ossl_ASN1_IA5STRING          ossl_ASN1_STRING
#  define ossl_ASN1_UTCTIME            ossl_ASN1_STRING
#  define ossl_ASN1_GENERALIZEDTIME    ossl_ASN1_STRING
#  define ossl_ASN1_TIME               ossl_ASN1_STRING
#  define ossl_ASN1_GENERALSTRING      ossl_ASN1_STRING
#  define ossl_ASN1_UNIVERSALSTRING    ossl_ASN1_STRING
#  define ossl_ASN1_BMPSTRING          ossl_ASN1_STRING
#  define ossl_ASN1_VISIBLESTRING      ossl_ASN1_STRING
#  define ossl_ASN1_UTF8STRING         ossl_ASN1_STRING
#  define ossl_ASN1_BOOLEAN            int
#  define ossl_ASN1_NULL               int
# else
typedef struct ossl_asn1_string_st ossl_ASN1_INTEGER;
typedef struct ossl_asn1_string_st ossl_ASN1_ENUMERATED;
typedef struct ossl_asn1_string_st ossl_ASN1_BIT_STRING;
typedef struct ossl_asn1_string_st ossl_ASN1_OCTET_STRING;
typedef struct ossl_asn1_string_st ossl_ASN1_PRINTABLESTRING;
typedef struct ossl_asn1_string_st ossl_ASN1_T61STRING;
typedef struct ossl_asn1_string_st ossl_ASN1_IA5STRING;
typedef struct ossl_asn1_string_st ossl_ASN1_GENERALSTRING;
typedef struct ossl_asn1_string_st ossl_ASN1_UNIVERSALSTRING;
typedef struct ossl_asn1_string_st ossl_ASN1_BMPSTRING;
typedef struct ossl_asn1_string_st ossl_ASN1_UTCTIME;
typedef struct ossl_asn1_string_st ossl_ASN1_TIME;
typedef struct ossl_asn1_string_st ossl_ASN1_GENERALIZEDTIME;
typedef struct ossl_asn1_string_st ossl_ASN1_VISIBLESTRING;
typedef struct ossl_asn1_string_st ossl_ASN1_UTF8STRING;
typedef struct ossl_asn1_string_st ossl_ASN1_STRING;
typedef int ossl_ASN1_BOOLEAN;
typedef int ossl_ASN1_NULL;
# endif

typedef struct ossl_asn1_type_st ossl_ASN1_TYPE;
typedef struct ossl_asn1_object_st ossl_ASN1_OBJECT;
typedef struct ossl_asn1_string_table_st ossl_ASN1_STRING_TABLE;

typedef struct ossl_ASN1_ITEM_st ossl_ASN1_ITEM;
typedef struct ossl_asn1_pctx_st ossl_ASN1_PCTX;
typedef struct ossl_asn1_sctx_st ossl_ASN1_SCTX;

# ifdef _WIN32
#  undef ossl_X509_NAME
#  undef ossl_X509_EXTENSIONS
#  undef ossl_PKCS7_ISSUER_AND_SERIAL
#  undef ossl_PKCS7_SIGNER_INFO
#  undef ossl_OCSP_REQUEST
#  undef ossl_OCSP_RESPONSE
# endif

# ifdef ossl_BIGNUM
#  undef ossl_BIGNUM
# endif

typedef struct ossl_bio_st ossl_BIO;
typedef struct ossl_bignum_st ossl_BIGNUM;
typedef struct ossl_bignum_ctx ossl_BN_CTX;
typedef struct ossl_bn_blinding_st ossl_BN_BLINDING;
typedef struct ossl_bn_mont_ctx_st ossl_BN_MONT_CTX;
typedef struct ossl_bn_recp_ctx_st ossl_BN_RECP_CTX;
typedef struct ossl_bn_gencb_st ossl_BN_GENCB;

typedef struct ossl_buf_mem_st ossl_BUF_MEM;

ossl_STACK_OF(ossl_BIGNUM);
ossl_STACK_OF(BIGNUM_const);

typedef struct ossl_err_state_st ossl_ERR_STATE;

typedef struct ossl_evp_cipher_st ossl_EVP_CIPHER;
typedef struct ossl_evp_cipher_ctx_st ossl_EVP_CIPHER_CTX;
typedef struct ossl_evp_md_st ossl_EVP_MD;
typedef struct ossl_evp_md_ctx_st ossl_EVP_MD_CTX;
typedef struct ossl_evp_mac_st ossl_EVP_MAC;
typedef struct ossl_evp_mac_ctx_st ossl_EVP_MAC_CTX;
typedef struct ossl_evp_pkey_st ossl_EVP_PKEY;

typedef struct ossl_evp_pkey_asn1_method_st ossl_EVP_PKEY_ASN1_METHOD;

typedef struct ossl_evp_pkey_method_st ossl_EVP_PKEY_METHOD;
typedef struct ossl_evp_pkey_ctx_st ossl_EVP_PKEY_CTX;

typedef struct ossl_evp_keymgmt_st ossl_EVP_KEYMGMT;

typedef struct ossl_evp_kdf_st ossl_EVP_KDF;
typedef struct ossl_evp_kdf_ctx_st ossl_EVP_KDF_CTX;

typedef struct ossl_evp_rand_st ossl_EVP_RAND;
typedef struct ossl_evp_rand_ctx_st ossl_EVP_RAND_CTX;

typedef struct ossl_evp_keyexch_st ossl_EVP_KEYEXCH;

typedef struct ossl_evp_signature_st ossl_EVP_SIGNATURE;

typedef struct ossl_evp_asym_cipher_st ossl_EVP_ASYM_CIPHER;

typedef struct ossl_evp_kem_st ossl_EVP_KEM;

typedef struct ossl_evp_Encode_Ctx_st ossl_EVP_ENCODE_CTX;

typedef struct ossl_hmac_ctx_st ossl_HMAC_CTX;

typedef struct ossl_dh_st ossl_DH;
typedef struct ossl_dh_method ossl_DH_METHOD;

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
typedef struct ossl_dsa_st ossl_DSA;
typedef struct ossl_dsa_method ossl_DSA_METHOD;
# endif

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
typedef struct ossl_rsa_st ossl_RSA;
typedef struct ossl_rsa_meth_st ossl_RSA_METHOD;
# endif
typedef struct ossl_rsa_pss_params_st ossl_RSA_PSS_PARAMS;

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
typedef struct ossl_ec_key_st ossl_EC_KEY;
typedef struct ossl_ec_key_method_st ossl_EC_KEY_METHOD;
# endif

typedef struct ossl_rand_meth_st ossl_RAND_METHOD;
typedef struct ossl_rand_drbg_st ossl_RAND_DRBG;

typedef struct ossl_ssl_dane_st ossl_SSL_DANE;
typedef struct ossl_x509_st ossl_X509;
typedef struct ossl_X509_algor_st ossl_X509_ALGOR;
typedef struct ossl_X509_crl_st ossl_X509_CRL;
typedef struct ossl_x509_crl_method_st ossl_X509_CRL_METHOD;
typedef struct ossl_x509_revoked_st ossl_X509_REVOKED;
typedef struct ossl_X509_name_st ossl_X509_NAME;
typedef struct ossl_X509_pubkey_st ossl_X509_PUBKEY;
typedef struct ossl_x509_store_st ossl_X509_STORE;
typedef struct ossl_x509_store_ctx_st ossl_X509_STORE_CTX;

typedef struct ossl_x509_object_st ossl_X509_OBJECT;
typedef struct ossl_x509_lookup_st ossl_X509_LOOKUP;
typedef struct ossl_x509_lookup_method_st ossl_X509_LOOKUP_METHOD;
typedef struct ossl_X509_VERIFY_PARAM_st ossl_X509_VERIFY_PARAM;

typedef struct ossl_x509_sig_info_st ossl_X509_SIG_INFO;

typedef struct ossl_pkcs8_priv_key_info_st ossl_PKCS8_PRIV_KEY_INFO;

typedef struct ossl_v3_ext_ctx ossl_X509V3_CTX;
typedef struct ossl_conf_st ossl_CONF;
typedef struct ossl_ossl_init_settings_st ossl_OPENSSL_INIT_SETTINGS;

typedef struct ossl_ui_st ossl_UI;
typedef struct ossl_ui_method_st ossl_UI_METHOD;

typedef struct ossl_engine_st ossl_ENGINE;
typedef struct ossl_ssl_st ossl_SSL;
typedef struct ossl_ssl_ctx_st ossl_SSL_CTX;

typedef struct ossl_comp_ctx_st ossl_COMP_CTX;
typedef struct ossl_comp_method_st ossl_COMP_METHOD;

typedef struct ossl_X509_POLICY_NODE_st ossl_X509_POLICY_NODE;
typedef struct ossl_X509_POLICY_LEVEL_st ossl_X509_POLICY_LEVEL;
typedef struct ossl_X509_POLICY_TREE_st ossl_X509_POLICY_TREE;
typedef struct ossl_X509_POLICY_CACHE_st ossl_X509_POLICY_CACHE;

typedef struct ossl_AUTHORITY_KEYID_st ossl_AUTHORITY_KEYID;
typedef struct ossl_DIST_POINT_st ossl_DIST_POINT;
typedef struct ossl_ISSUING_DIST_POINT_st ossl_ISSUING_DIST_POINT;
typedef struct ossl_NAME_CONSTRAINTS_st ossl_NAME_CONSTRAINTS;

typedef struct ossl_crypto_ex_data_st ossl_CRYPTO_EX_DATA;

typedef struct ossl_ossl_http_req_ctx_st ossl_OSSL_HTTP_REQ_CTX;
typedef struct ossl_ocsp_response_st ossl_OCSP_RESPONSE;
typedef struct ossl_ocsp_responder_id_st ossl_OCSP_RESPID;

typedef struct ossl_sct_st ossl_SCT;
typedef struct ossl_sct_ctx_st ossl_SCT_CTX;
typedef struct ossl_ctlog_st ossl_CTLOG;
typedef struct ossl_ctlog_store_st ossl_CTLOG_STORE;
typedef struct ossl_ct_policy_eval_ctx_st ossl_CT_POLICY_EVAL_CTX;

typedef struct ossl_ossl_store_info_st ossl_OSSL_STORE_INFO;
typedef struct ossl_ossl_store_search_st ossl_OSSL_STORE_SEARCH;

typedef struct ossl_ossl_lib_ctx_st ossl_OSSL_LIB_CTX;

typedef struct ossl_ossl_dispatch_st ossl_OSSL_DISPATCH;
typedef struct ossl_ossl_item_st ossl_OSSL_ITEM;
typedef struct ossl_ossl_algorithm_st ossl_OSSL_ALGORITHM;
typedef struct ossl_ossl_param_st ossl_OSSL_PARAM;
typedef struct ossl_ossl_param_bld_st ossl_OSSL_PARAM_BLD;

typedef int ossl_pem_password_cb (char *buf, int size, int rwflag, void *userdata);

typedef struct ossl_ossl_encoder_st ossl_OSSL_ENCODER;
typedef struct ossl_ossl_encoder_ctx_st ossl_OSSL_ENCODER_CTX;
typedef struct ossl_ossl_decoder_st ossl_OSSL_DECODER;
typedef struct ossl_ossl_decoder_ctx_st ossl_OSSL_DECODER_CTX;

typedef struct ossl_ossl_self_test_st ossl_OSSL_SELF_TEST;

#ifdef  __cplusplus
}
#endif

#endif /* ossl_OPENSSL_TYPES_H */
