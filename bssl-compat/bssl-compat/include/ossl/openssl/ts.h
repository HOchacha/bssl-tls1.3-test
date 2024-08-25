/*
 * Copyright 2006-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_TS_H
# define ossl_OPENSSL_TS_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_TS_H
# endif

# include "ossl/openssl/opensslconf.h"

# ifndef ossl_OPENSSL_NO_TS
# include "ossl/openssl/symhacks.h"
# include "ossl/openssl/buffer.h"
# include "ossl/openssl/evp.h"
# include "ossl/openssl/bio.h"
# include "ossl/openssl/asn1.h"
# include "ossl/openssl/safestack.h"
# include "ossl/openssl/rsa.h"
# include "ossl/openssl/dsa.h"
# include "ossl/openssl/dh.h"
# include "ossl/openssl/tserr.h"
# include "ossl/openssl/ess.h"
# ifdef  __cplusplus
extern "C" {
# endif

# include "ossl/openssl/x509.h"
# include "ossl/openssl/x509v3.h"

typedef struct ossl_TS_msg_imprint_st ossl_TS_MSG_IMPRINT;
typedef struct ossl_TS_req_st ossl_TS_REQ;
typedef struct ossl_TS_accuracy_st ossl_TS_ACCURACY;
typedef struct ossl_TS_tst_info_st ossl_TS_TST_INFO;

/* Possible values for status. */
# define ossl_TS_STATUS_GRANTED                       0
# define ossl_TS_STATUS_GRANTED_WITH_MODS             1
# define ossl_TS_STATUS_REJECTION                     2
# define ossl_TS_STATUS_WAITING                       3
# define ossl_TS_STATUS_REVOCATION_WARNING            4
# define ossl_TS_STATUS_REVOCATION_NOTIFICATION       5

/* Possible values for failure_info. */
# define ossl_TS_INFO_BAD_ALG                 0
# define ossl_TS_INFO_BAD_REQUEST             2
# define ossl_TS_INFO_BAD_DATA_FORMAT         5
# define ossl_TS_INFO_TIME_NOT_AVAILABLE      14
# define ossl_TS_INFO_UNACCEPTED_POLICY       15
# define ossl_TS_INFO_UNACCEPTED_EXTENSION    16
# define ossl_TS_INFO_ADD_INFO_NOT_AVAILABLE  17
# define ossl_TS_INFO_SYSTEM_FAILURE          25


typedef struct ossl_TS_status_info_st ossl_TS_STATUS_INFO;

typedef struct ossl_TS_resp_st ossl_TS_RESP;

ossl_DECLARE_ASN1_ALLOC_FUNCTIONS(ossl_TS_REQ)
ossl_DECLARE_ASN1_ENCODE_FUNCTIONS_only(ossl_TS_REQ, ossl_TS_REQ)
ossl_DECLARE_ASN1_DUP_FUNCTION(ossl_TS_REQ)

#ifndef ossl_OPENSSL_NO_STDIO
ossl_TS_REQ *ossl_d2i_TS_REQ_fp(FILE *fp, ossl_TS_REQ **a);
int ossl_i2d_TS_REQ_fp(FILE *fp, const ossl_TS_REQ *a);
#endif
ossl_TS_REQ *ossl_d2i_TS_REQ_bio(ossl_BIO *fp, ossl_TS_REQ **a);
int ossl_i2d_TS_REQ_bio(ossl_BIO *fp, const ossl_TS_REQ *a);

ossl_DECLARE_ASN1_ALLOC_FUNCTIONS(ossl_TS_MSG_IMPRINT)
ossl_DECLARE_ASN1_ENCODE_FUNCTIONS_only(ossl_TS_MSG_IMPRINT, ossl_TS_MSG_IMPRINT)
ossl_DECLARE_ASN1_DUP_FUNCTION(ossl_TS_MSG_IMPRINT)

#ifndef ossl_OPENSSL_NO_STDIO
ossl_TS_MSG_IMPRINT *ossl_d2i_TS_MSG_IMPRINT_fp(FILE *fp, ossl_TS_MSG_IMPRINT **a);
int ossl_i2d_TS_MSG_IMPRINT_fp(FILE *fp, const ossl_TS_MSG_IMPRINT *a);
#endif
ossl_TS_MSG_IMPRINT *ossl_d2i_TS_MSG_IMPRINT_bio(ossl_BIO *bio, ossl_TS_MSG_IMPRINT **a);
int ossl_i2d_TS_MSG_IMPRINT_bio(ossl_BIO *bio, const ossl_TS_MSG_IMPRINT *a);

ossl_DECLARE_ASN1_ALLOC_FUNCTIONS(ossl_TS_RESP)
ossl_DECLARE_ASN1_ENCODE_FUNCTIONS_only(ossl_TS_RESP, ossl_TS_RESP)
ossl_DECLARE_ASN1_DUP_FUNCTION(ossl_TS_RESP)

#ifndef ossl_OPENSSL_NO_STDIO
ossl_TS_RESP *ossl_d2i_TS_RESP_fp(FILE *fp, ossl_TS_RESP **a);
int ossl_i2d_TS_RESP_fp(FILE *fp, const ossl_TS_RESP *a);
#endif
ossl_TS_RESP *ossl_d2i_TS_RESP_bio(ossl_BIO *bio, ossl_TS_RESP **a);
int ossl_i2d_TS_RESP_bio(ossl_BIO *bio, const ossl_TS_RESP *a);

ossl_DECLARE_ASN1_ALLOC_FUNCTIONS(ossl_TS_STATUS_INFO)
ossl_DECLARE_ASN1_ENCODE_FUNCTIONS_only(ossl_TS_STATUS_INFO, ossl_TS_STATUS_INFO)
ossl_DECLARE_ASN1_DUP_FUNCTION(ossl_TS_STATUS_INFO)

ossl_DECLARE_ASN1_ALLOC_FUNCTIONS(ossl_TS_TST_INFO)
ossl_DECLARE_ASN1_ENCODE_FUNCTIONS_only(ossl_TS_TST_INFO, ossl_TS_TST_INFO)
ossl_DECLARE_ASN1_DUP_FUNCTION(ossl_TS_TST_INFO)
ossl_TS_TST_INFO *ossl_PKCS7_to_TS_TST_INFO(ossl_PKCS7 *token);

#ifndef ossl_OPENSSL_NO_STDIO
ossl_TS_TST_INFO *ossl_d2i_TS_TST_INFO_fp(FILE *fp, ossl_TS_TST_INFO **a);
int ossl_i2d_TS_TST_INFO_fp(FILE *fp, const ossl_TS_TST_INFO *a);
#endif
ossl_TS_TST_INFO *ossl_d2i_TS_TST_INFO_bio(ossl_BIO *bio, ossl_TS_TST_INFO **a);
int ossl_i2d_TS_TST_INFO_bio(ossl_BIO *bio, const ossl_TS_TST_INFO *a);

ossl_DECLARE_ASN1_ALLOC_FUNCTIONS(ossl_TS_ACCURACY)
ossl_DECLARE_ASN1_ENCODE_FUNCTIONS_only(ossl_TS_ACCURACY, ossl_TS_ACCURACY)
ossl_DECLARE_ASN1_DUP_FUNCTION(ossl_TS_ACCURACY)

int ossl_TS_REQ_set_version(ossl_TS_REQ *a, long version);
long ossl_TS_REQ_get_version(const ossl_TS_REQ *a);

int ossl_TS_STATUS_INFO_set_status(ossl_TS_STATUS_INFO *a, int i);
const ossl_ASN1_INTEGER *ossl_TS_STATUS_INFO_get0_status(const ossl_TS_STATUS_INFO *a);

const ossl_STACK_OF(ossl_ASN1_UTF8STRING) *
ossl_TS_STATUS_INFO_get0_text(const ossl_TS_STATUS_INFO *a);

const ossl_ASN1_BIT_STRING *
ossl_TS_STATUS_INFO_get0_failure_info(const ossl_TS_STATUS_INFO *a);

int ossl_TS_REQ_set_msg_imprint(ossl_TS_REQ *a, ossl_TS_MSG_IMPRINT *msg_imprint);
ossl_TS_MSG_IMPRINT *ossl_TS_REQ_get_msg_imprint(ossl_TS_REQ *a);

int ossl_TS_MSG_IMPRINT_set_algo(ossl_TS_MSG_IMPRINT *a, ossl_X509_ALGOR *alg);
ossl_X509_ALGOR *ossl_TS_MSG_IMPRINT_get_algo(ossl_TS_MSG_IMPRINT *a);

int ossl_TS_MSG_IMPRINT_set_msg(ossl_TS_MSG_IMPRINT *a, unsigned char *d, int len);
ossl_ASN1_OCTET_STRING *ossl_TS_MSG_IMPRINT_get_msg(ossl_TS_MSG_IMPRINT *a);

int ossl_TS_REQ_set_policy_id(ossl_TS_REQ *a, const ossl_ASN1_OBJECT *policy);
ossl_ASN1_OBJECT *ossl_TS_REQ_get_policy_id(ossl_TS_REQ *a);

int ossl_TS_REQ_set_nonce(ossl_TS_REQ *a, const ossl_ASN1_INTEGER *nonce);
const ossl_ASN1_INTEGER *ossl_TS_REQ_get_nonce(const ossl_TS_REQ *a);

int ossl_TS_REQ_set_cert_req(ossl_TS_REQ *a, int cert_req);
int ossl_TS_REQ_get_cert_req(const ossl_TS_REQ *a);

ossl_STACK_OF(ossl_X509_EXTENSION) *ossl_TS_REQ_get_exts(ossl_TS_REQ *a);
void ossl_TS_REQ_ext_free(ossl_TS_REQ *a);
int ossl_TS_REQ_get_ext_count(ossl_TS_REQ *a);
int ossl_TS_REQ_get_ext_by_NID(ossl_TS_REQ *a, int nid, int lastpos);
int ossl_TS_REQ_get_ext_by_OBJ(ossl_TS_REQ *a, const ossl_ASN1_OBJECT *obj, int lastpos);
int ossl_TS_REQ_get_ext_by_critical(ossl_TS_REQ *a, int crit, int lastpos);
ossl_X509_EXTENSION *ossl_TS_REQ_get_ext(ossl_TS_REQ *a, int loc);
ossl_X509_EXTENSION *ossl_TS_REQ_delete_ext(ossl_TS_REQ *a, int loc);
int ossl_TS_REQ_add_ext(ossl_TS_REQ *a, ossl_X509_EXTENSION *ex, int loc);
void *ossl_TS_REQ_get_ext_d2i(ossl_TS_REQ *a, int nid, int *crit, int *idx);

/* Function declarations for ossl_TS_REQ defined in ts/ts_req_print.c */

int ossl_TS_REQ_print_bio(ossl_BIO *bio, ossl_TS_REQ *a);

/* Function declarations for ossl_TS_RESP defined in ts/ts_resp_utils.c */

int ossl_TS_RESP_set_status_info(ossl_TS_RESP *a, ossl_TS_STATUS_INFO *info);
ossl_TS_STATUS_INFO *ossl_TS_RESP_get_status_info(ossl_TS_RESP *a);

/* Caller loses ownership of ossl_PKCS7 and ossl_TS_TST_INFO objects. */
void ossl_TS_RESP_set_tst_info(ossl_TS_RESP *a, ossl_PKCS7 *p7, ossl_TS_TST_INFO *tst_info);
ossl_PKCS7 *ossl_TS_RESP_get_token(ossl_TS_RESP *a);
ossl_TS_TST_INFO *ossl_TS_RESP_get_tst_info(ossl_TS_RESP *a);

int ossl_TS_TST_INFO_set_version(ossl_TS_TST_INFO *a, long version);
long ossl_TS_TST_INFO_get_version(const ossl_TS_TST_INFO *a);

int ossl_TS_TST_INFO_set_policy_id(ossl_TS_TST_INFO *a, ossl_ASN1_OBJECT *policy_id);
ossl_ASN1_OBJECT *ossl_TS_TST_INFO_get_policy_id(ossl_TS_TST_INFO *a);

int ossl_TS_TST_INFO_set_msg_imprint(ossl_TS_TST_INFO *a, ossl_TS_MSG_IMPRINT *msg_imprint);
ossl_TS_MSG_IMPRINT *ossl_TS_TST_INFO_get_msg_imprint(ossl_TS_TST_INFO *a);

int ossl_TS_TST_INFO_set_serial(ossl_TS_TST_INFO *a, const ossl_ASN1_INTEGER *serial);
const ossl_ASN1_INTEGER *ossl_TS_TST_INFO_get_serial(const ossl_TS_TST_INFO *a);

int ossl_TS_TST_INFO_set_time(ossl_TS_TST_INFO *a, const ossl_ASN1_GENERALIZEDTIME *gtime);
const ossl_ASN1_GENERALIZEDTIME *ossl_TS_TST_INFO_get_time(const ossl_TS_TST_INFO *a);

int ossl_TS_TST_INFO_set_accuracy(ossl_TS_TST_INFO *a, ossl_TS_ACCURACY *accuracy);
ossl_TS_ACCURACY *ossl_TS_TST_INFO_get_accuracy(ossl_TS_TST_INFO *a);

int ossl_TS_ACCURACY_set_seconds(ossl_TS_ACCURACY *a, const ossl_ASN1_INTEGER *seconds);
const ossl_ASN1_INTEGER *ossl_TS_ACCURACY_get_seconds(const ossl_TS_ACCURACY *a);

int ossl_TS_ACCURACY_set_millis(ossl_TS_ACCURACY *a, const ossl_ASN1_INTEGER *millis);
const ossl_ASN1_INTEGER *ossl_TS_ACCURACY_get_millis(const ossl_TS_ACCURACY *a);

int ossl_TS_ACCURACY_set_micros(ossl_TS_ACCURACY *a, const ossl_ASN1_INTEGER *micros);
const ossl_ASN1_INTEGER *ossl_TS_ACCURACY_get_micros(const ossl_TS_ACCURACY *a);

int ossl_TS_TST_INFO_set_ordering(ossl_TS_TST_INFO *a, int ordering);
int ossl_TS_TST_INFO_get_ordering(const ossl_TS_TST_INFO *a);

int ossl_TS_TST_INFO_set_nonce(ossl_TS_TST_INFO *a, const ossl_ASN1_INTEGER *nonce);
const ossl_ASN1_INTEGER *ossl_TS_TST_INFO_get_nonce(const ossl_TS_TST_INFO *a);

int ossl_TS_TST_INFO_set_tsa(ossl_TS_TST_INFO *a, ossl_GENERAL_NAME *tsa);
ossl_GENERAL_NAME *ossl_TS_TST_INFO_get_tsa(ossl_TS_TST_INFO *a);

ossl_STACK_OF(ossl_X509_EXTENSION) *ossl_TS_TST_INFO_get_exts(ossl_TS_TST_INFO *a);
void ossl_TS_TST_INFO_ext_free(ossl_TS_TST_INFO *a);
int ossl_TS_TST_INFO_get_ext_count(ossl_TS_TST_INFO *a);
int ossl_TS_TST_INFO_get_ext_by_NID(ossl_TS_TST_INFO *a, int nid, int lastpos);
int ossl_TS_TST_INFO_get_ext_by_OBJ(ossl_TS_TST_INFO *a, const ossl_ASN1_OBJECT *obj,
                               int lastpos);
int ossl_TS_TST_INFO_get_ext_by_critical(ossl_TS_TST_INFO *a, int crit, int lastpos);
ossl_X509_EXTENSION *ossl_TS_TST_INFO_get_ext(ossl_TS_TST_INFO *a, int loc);
ossl_X509_EXTENSION *ossl_TS_TST_INFO_delete_ext(ossl_TS_TST_INFO *a, int loc);
int ossl_TS_TST_INFO_add_ext(ossl_TS_TST_INFO *a, ossl_X509_EXTENSION *ex, int loc);
void *ossl_TS_TST_INFO_get_ext_d2i(ossl_TS_TST_INFO *a, int nid, int *crit, int *idx);

/*
 * Declarations related to response generation, defined in ts/ts_resp_sign.c.
 */

/* Optional flags for response generation. */

/* Don't include the TSA name in response. */
# define ossl_TS_TSA_NAME             0x01

/* Set ordering to true in response. */
# define ossl_TS_ORDERING             0x02

/*
 * Include the signer certificate and the other specified certificates in
 * the ESS signing certificate attribute beside the ossl_PKCS7 signed data.
 * Only the signer certificates is included by default.
 */
# define ossl_TS_ESS_CERT_ID_CHAIN    0x04

/* Forward declaration. */
struct ossl_TS_resp_ctx;

/* This must return a unique number less than 160 bits long. */
typedef ossl_ASN1_INTEGER *(*ossl_TS_serial_cb) (struct ossl_TS_resp_ctx *, void *);

/*
 * This must return the seconds and microseconds since Jan 1, 1970 in the sec
 * and usec variables allocated by the caller. Return non-zero for success
 * and zero for failure.
 */
typedef int (*ossl_TS_time_cb) (struct ossl_TS_resp_ctx *, void *, long *sec,
                           long *usec);

/*
 * This must process the given extension. It can modify the ossl_TS_TST_INFO
 * object of the context. Return values: !0 (processed), 0 (error, it must
 * set the status info/failure info of the response).
 */
typedef int (*ossl_TS_extension_cb) (struct ossl_TS_resp_ctx *, ossl_X509_EXTENSION *,
                                void *);

typedef struct ossl_TS_resp_ctx ossl_TS_RESP_CTX;

/* Creates a response context that can be used for generating responses. */
ossl_TS_RESP_CTX *ossl_TS_RESP_CTX_new(void);
ossl_TS_RESP_CTX *ossl_TS_RESP_CTX_new_ex(ossl_OSSL_LIB_CTX *libctx, const char *propq);
void ossl_TS_RESP_CTX_free(ossl_TS_RESP_CTX *ctx);

/* This parameter must be set. */
int ossl_TS_RESP_CTX_set_signer_cert(ossl_TS_RESP_CTX *ctx, ossl_X509 *signer);

/* This parameter must be set. */
int ossl_TS_RESP_CTX_set_signer_key(ossl_TS_RESP_CTX *ctx, ossl_EVP_PKEY *key);

int ossl_TS_RESP_CTX_set_signer_digest(ossl_TS_RESP_CTX *ctx,
                                  const ossl_EVP_MD *signer_digest);
int ossl_TS_RESP_CTX_set_ess_cert_id_digest(ossl_TS_RESP_CTX *ctx, const ossl_EVP_MD *md);

/* This parameter must be set. */
int ossl_TS_RESP_CTX_set_def_policy(ossl_TS_RESP_CTX *ctx, const ossl_ASN1_OBJECT *def_policy);

/* No additional certs are included in the response by default. */
int ossl_TS_RESP_CTX_set_certs(ossl_TS_RESP_CTX *ctx, ossl_STACK_OF(ossl_X509) *certs);

/*
 * Adds a new acceptable policy, only the default policy is accepted by
 * default.
 */
int ossl_TS_RESP_CTX_add_policy(ossl_TS_RESP_CTX *ctx, const ossl_ASN1_OBJECT *policy);

/*
 * Adds a new acceptable message digest. Note that no message digests are
 * accepted by default. The md argument is shared with the caller.
 */
int ossl_TS_RESP_CTX_add_md(ossl_TS_RESP_CTX *ctx, const ossl_EVP_MD *md);

/* Accuracy is not included by default. */
int ossl_TS_RESP_CTX_set_accuracy(ossl_TS_RESP_CTX *ctx,
                             int secs, int millis, int micros);

/*
 * Clock precision digits, i.e. the number of decimal digits: '0' means sec,
 * '3' msec, '6' usec, and so on. Default is 0.
 */
int ossl_TS_RESP_CTX_set_clock_precision_digits(ossl_TS_RESP_CTX *ctx,
                                           unsigned clock_precision_digits);
/* At most we accept usec precision. */
# define ossl_TS_MAX_CLOCK_PRECISION_DIGITS   6

/* Maximum status message length */
# define ossl_TS_MAX_STATUS_LENGTH   (1024 * 1024)

/* No flags are set by default. */
void ossl_TS_RESP_CTX_add_flags(ossl_TS_RESP_CTX *ctx, int flags);

/* Default callback always returns a constant. */
void ossl_TS_RESP_CTX_set_serial_cb(ossl_TS_RESP_CTX *ctx, ossl_TS_serial_cb cb, void *data);

/* Default callback uses the gettimeofday() and gmtime() system calls. */
void ossl_TS_RESP_CTX_set_time_cb(ossl_TS_RESP_CTX *ctx, ossl_TS_time_cb cb, void *data);

/*
 * Default callback rejects all extensions. The extension callback is called
 * when the ossl_TS_TST_INFO object is already set up and not signed yet.
 */
/* FIXME: extension handling is not tested yet. */
void ossl_TS_RESP_CTX_set_extension_cb(ossl_TS_RESP_CTX *ctx,
                                  ossl_TS_extension_cb cb, void *data);

/* The following methods can be used in the callbacks. */
int ossl_TS_RESP_CTX_set_status_info(ossl_TS_RESP_CTX *ctx,
                                int status, const char *text);

/* Sets the status info only if it is still ossl_TS_STATUS_GRANTED. */
int ossl_TS_RESP_CTX_set_status_info_cond(ossl_TS_RESP_CTX *ctx,
                                     int status, const char *text);

int ossl_TS_RESP_CTX_add_failure_info(ossl_TS_RESP_CTX *ctx, int failure);

/* The get methods below can be used in the extension callback. */
ossl_TS_REQ *ossl_TS_RESP_CTX_get_request(ossl_TS_RESP_CTX *ctx);

ossl_TS_TST_INFO *ossl_TS_RESP_CTX_get_tst_info(ossl_TS_RESP_CTX *ctx);

/*
 * Creates the signed ossl_TS_TST_INFO and puts it in ossl_TS_RESP.
 * In case of errors it sets the status info properly.
 * Returns NULL only in case of memory allocation/fatal error.
 */
ossl_TS_RESP *ossl_TS_RESP_create_response(ossl_TS_RESP_CTX *ctx, ossl_BIO *req_bio);

/*
 * Declarations related to response verification,
 * they are defined in ts/ts_resp_verify.c.
 */

int ossl_TS_RESP_verify_signature(ossl_PKCS7 *token, ossl_STACK_OF(ossl_X509) *certs,
                             ossl_X509_STORE *store, ossl_X509 **signer_out);

/* Context structure for the generic verify method. */

/* Verify the signer's certificate and the signature of the response. */
# define ossl_TS_VFY_SIGNATURE        (1u << 0)
/* Verify the version number of the response. */
# define ossl_TS_VFY_VERSION          (1u << 1)
/* Verify if the policy supplied by the user matches the policy of the TSA. */
# define ossl_TS_VFY_POLICY           (1u << 2)
/*
 * Verify the message imprint provided by the user. This flag should not be
 * specified with ossl_TS_VFY_DATA.
 */
# define ossl_TS_VFY_IMPRINT          (1u << 3)
/*
 * Verify the message imprint computed by the verify method from the user
 * provided data and the MD algorithm of the response. This flag should not
 * be specified with ossl_TS_VFY_IMPRINT.
 */
# define ossl_TS_VFY_DATA             (1u << 4)
/* Verify the nonce value. */
# define ossl_TS_VFY_NONCE            (1u << 5)
/* Verify if the TSA name field matches the signer certificate. */
# define ossl_TS_VFY_SIGNER           (1u << 6)
/* Verify if the TSA name field equals to the user provided name. */
# define ossl_TS_VFY_TSA_NAME         (1u << 7)

/* You can use the following convenience constants. */
# define ossl_TS_VFY_ALL_IMPRINT      (ossl_TS_VFY_SIGNATURE       \
                                 | ossl_TS_VFY_VERSION       \
                                 | ossl_TS_VFY_POLICY        \
                                 | ossl_TS_VFY_IMPRINT       \
                                 | ossl_TS_VFY_NONCE         \
                                 | ossl_TS_VFY_SIGNER        \
                                 | ossl_TS_VFY_TSA_NAME)
# define ossl_TS_VFY_ALL_DATA         (ossl_TS_VFY_SIGNATURE       \
                                 | ossl_TS_VFY_VERSION       \
                                 | ossl_TS_VFY_POLICY        \
                                 | ossl_TS_VFY_DATA          \
                                 | ossl_TS_VFY_NONCE         \
                                 | ossl_TS_VFY_SIGNER        \
                                 | ossl_TS_VFY_TSA_NAME)

typedef struct ossl_TS_verify_ctx ossl_TS_VERIFY_CTX;

int ossl_TS_RESP_verify_response(ossl_TS_VERIFY_CTX *ctx, ossl_TS_RESP *response);
int ossl_TS_RESP_verify_token(ossl_TS_VERIFY_CTX *ctx, ossl_PKCS7 *token);

/*
 * Declarations related to response verification context,
 */
ossl_TS_VERIFY_CTX *ossl_TS_VERIFY_CTX_new(void);
void ossl_TS_VERIFY_CTX_init(ossl_TS_VERIFY_CTX *ctx);
void ossl_TS_VERIFY_CTX_free(ossl_TS_VERIFY_CTX *ctx);
void ossl_TS_VERIFY_CTX_cleanup(ossl_TS_VERIFY_CTX *ctx);
int ossl_TS_VERIFY_CTX_set_flags(ossl_TS_VERIFY_CTX *ctx, int f);
int ossl_TS_VERIFY_CTX_add_flags(ossl_TS_VERIFY_CTX *ctx, int f);
ossl_BIO *ossl_TS_VERIFY_CTX_set_data(ossl_TS_VERIFY_CTX *ctx, ossl_BIO *b);
unsigned char *ossl_TS_VERIFY_CTX_set_imprint(ossl_TS_VERIFY_CTX *ctx,
                                         unsigned char *hexstr, long len);
ossl_X509_STORE *ossl_TS_VERIFY_CTX_set_store(ossl_TS_VERIFY_CTX *ctx, ossl_X509_STORE *s);
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_TS_VERIFY_CTS_set_certs(ctx, cert) ossl_TS_VERIFY_CTX_set_certs(ctx,cert)
# endif
ossl_STACK_OF(ossl_X509) *ossl_TS_VERIFY_CTX_set_certs(ossl_TS_VERIFY_CTX *ctx, ossl_STACK_OF(ossl_X509) *certs);

/*-
 * If ctx is NULL, it allocates and returns a new object, otherwise
 * it returns ctx. It initialises all the members as follows:
 * flags = ossl_TS_VFY_ALL_IMPRINT & ~(ossl_TS_VFY_TSA_NAME | ossl_TS_VFY_SIGNATURE)
 * certs = NULL
 * store = NULL
 * policy = policy from the request or NULL if absent (in this case
 *      ossl_TS_VFY_POLICY is cleared from flags as well)
 * md_alg = MD algorithm from request
 * imprint, imprint_len = imprint from request
 * data = NULL
 * nonce, nonce_len = nonce from the request or NULL if absent (in this case
 *      ossl_TS_VFY_NONCE is cleared from flags as well)
 * tsa_name = NULL
 * Important: after calling this method ossl_TS_VFY_SIGNATURE should be added!
 */
ossl_TS_VERIFY_CTX *ossl_TS_REQ_to_TS_VERIFY_CTX(ossl_TS_REQ *req, ossl_TS_VERIFY_CTX *ctx);

/* Function declarations for ossl_TS_RESP defined in ts/ts_resp_print.c */

int ossl_TS_RESP_print_bio(ossl_BIO *bio, ossl_TS_RESP *a);
int ossl_TS_STATUS_INFO_print_bio(ossl_BIO *bio, ossl_TS_STATUS_INFO *a);
int ossl_TS_TST_INFO_print_bio(ossl_BIO *bio, ossl_TS_TST_INFO *a);

/* Common utility functions defined in ts/ts_lib.c */

int ossl_TS_ASN1_INTEGER_print_bio(ossl_BIO *bio, const ossl_ASN1_INTEGER *num);
int ossl_TS_OBJ_print_bio(ossl_BIO *bio, const ossl_ASN1_OBJECT *obj);
int ossl_TS_ext_print_bio(ossl_BIO *bio, const ossl_STACK_OF(ossl_X509_EXTENSION) *extensions);
int ossl_TS_X509_ALGOR_print_bio(ossl_BIO *bio, const ossl_X509_ALGOR *alg);
int ossl_TS_MSG_IMPRINT_print_bio(ossl_BIO *bio, ossl_TS_MSG_IMPRINT *msg);

/*
 * Function declarations for handling configuration options, defined in
 * ts/ts_conf.c
 */

ossl_X509 *ossl_TS_CONF_load_cert(const char *file);
ossl_STACK_OF(ossl_X509) *ossl_TS_CONF_load_certs(const char *file);
ossl_EVP_PKEY *ossl_TS_CONF_load_key(const char *file, const char *pass);
const char *ossl_TS_CONF_get_tsa_section(ossl_CONF *conf, const char *section);
int ossl_TS_CONF_set_serial(ossl_CONF *conf, const char *section, ossl_TS_serial_cb cb,
                       ossl_TS_RESP_CTX *ctx);
#ifndef ossl_OPENSSL_NO_ENGINE
int ossl_TS_CONF_set_crypto_device(ossl_CONF *conf, const char *section,
                              const char *device);
int ossl_TS_CONF_set_default_engine(const char *name);
#endif
int ossl_TS_CONF_set_signer_cert(ossl_CONF *conf, const char *section,
                            const char *cert, ossl_TS_RESP_CTX *ctx);
int ossl_TS_CONF_set_certs(ossl_CONF *conf, const char *section, const char *certs,
                      ossl_TS_RESP_CTX *ctx);
int ossl_TS_CONF_set_signer_key(ossl_CONF *conf, const char *section,
                           const char *key, const char *pass,
                           ossl_TS_RESP_CTX *ctx);
int ossl_TS_CONF_set_signer_digest(ossl_CONF *conf, const char *section,
                               const char *md, ossl_TS_RESP_CTX *ctx);
int ossl_TS_CONF_set_def_policy(ossl_CONF *conf, const char *section,
                           const char *policy, ossl_TS_RESP_CTX *ctx);
int ossl_TS_CONF_set_policies(ossl_CONF *conf, const char *section, ossl_TS_RESP_CTX *ctx);
int ossl_TS_CONF_set_digests(ossl_CONF *conf, const char *section, ossl_TS_RESP_CTX *ctx);
int ossl_TS_CONF_set_accuracy(ossl_CONF *conf, const char *section, ossl_TS_RESP_CTX *ctx);
int ossl_TS_CONF_set_clock_precision_digits(const ossl_CONF *conf, const char *section,
                                       ossl_TS_RESP_CTX *ctx);
int ossl_TS_CONF_set_ordering(ossl_CONF *conf, const char *section, ossl_TS_RESP_CTX *ctx);
int ossl_TS_CONF_set_tsa_name(ossl_CONF *conf, const char *section, ossl_TS_RESP_CTX *ctx);
int ossl_TS_CONF_set_ess_cert_id_chain(ossl_CONF *conf, const char *section,
                                  ossl_TS_RESP_CTX *ctx);
int ossl_TS_CONF_set_ess_cert_id_digest(ossl_CONF *conf, const char *section,
                                      ossl_TS_RESP_CTX *ctx);

#  ifdef  __cplusplus
}
#  endif
# endif
#endif
