/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_PEM_H
# define ossl_OPENSSL_PEM_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_PEM_H
# endif

# include "ossl/openssl/e_os2.h"
# include "ossl/openssl/bio.h"
# include "ossl/openssl/safestack.h"
# include "ossl/openssl/evp.h"
# include "ossl/openssl/x509.h"
# include "ossl/openssl/pemerr.h"

#ifdef  __cplusplus
extern "C" {
#endif

# define ossl_PEM_BUFSIZE             1024

# define ossl_PEM_STRING_X509_OLD     "ossl_X509 CERTIFICATE"
# define ossl_PEM_STRING_X509         "CERTIFICATE"
# define ossl_PEM_STRING_X509_TRUSTED "TRUSTED CERTIFICATE"
# define ossl_PEM_STRING_X509_REQ_OLD "NEW CERTIFICATE REQUEST"
# define ossl_PEM_STRING_X509_REQ     "CERTIFICATE REQUEST"
# define ossl_PEM_STRING_X509_CRL     "ossl_X509 CRL"
# define ossl_PEM_STRING_EVP_PKEY     "ANY PRIVATE KEY"
# define ossl_PEM_STRING_PUBLIC       "PUBLIC KEY"
# define ossl_PEM_STRING_RSA          "ossl_RSA PRIVATE KEY"
# define ossl_PEM_STRING_RSA_PUBLIC   "ossl_RSA PUBLIC KEY"
# define ossl_PEM_STRING_DSA          "ossl_DSA PRIVATE KEY"
# define ossl_PEM_STRING_DSA_PUBLIC   "ossl_DSA PUBLIC KEY"
# define ossl_PEM_STRING_PKCS7        "ossl_PKCS7"
# define ossl_PEM_STRING_PKCS7_SIGNED "PKCS #7 SIGNED DATA"
# define ossl_PEM_STRING_PKCS8        "ENCRYPTED PRIVATE KEY"
# define ossl_PEM_STRING_PKCS8INF     "PRIVATE KEY"
# define ossl_PEM_STRING_DHPARAMS     "ossl_DH PARAMETERS"
# define ossl_PEM_STRING_DHXPARAMS    "X9.42 ossl_DH PARAMETERS"
# define ossl_PEM_STRING_SSL_SESSION  "ossl_SSL SESSION PARAMETERS"
# define ossl_PEM_STRING_DSAPARAMS    "ossl_DSA PARAMETERS"
# define ossl_PEM_STRING_ECDSA_PUBLIC "ECDSA PUBLIC KEY"
# define ossl_PEM_STRING_ECPARAMETERS "EC PARAMETERS"
# define ossl_PEM_STRING_ECPRIVATEKEY "EC PRIVATE KEY"
# define ossl_PEM_STRING_PARAMETERS   "PARAMETERS"
# define ossl_PEM_STRING_CMS          "CMS"

# define ossl_PEM_TYPE_ENCRYPTED      10
# define ossl_PEM_TYPE_MIC_ONLY       20
# define ossl_PEM_TYPE_MIC_CLEAR      30
# define ossl_PEM_TYPE_CLEAR          40

/*
 * These macros make the ossl_PEM_read/ossl_PEM_write functions easier to maintain and
 * write. Now they are all implemented with either: ossl_IMPLEMENT_PEM_rw(...) or
 * ossl_IMPLEMENT_PEM_rw_cb(...)
 */

# define ossl_PEM_read_cb_fnsig(name, type, INTYPE, readname)                \
    type *ossl_PEM_##readname##_##name(INTYPE *out, type **x,                \
                                 ossl_pem_password_cb *cb, void *u)
# define ossl_PEM_read_cb_ex_fnsig(name, type, INTYPE, readname)             \
    type *ossl_PEM_##readname##_##name##_ex(INTYPE *out, type **x,           \
                                       ossl_pem_password_cb *cb, void *u,    \
                                       ossl_OSSL_LIB_CTX *libctx,            \
                                       const char *propq)

# define ossl_PEM_write_fnsig(name, type, OUTTYPE, writename)                \
    int ossl_PEM_##writename##_##name(OUTTYPE *out, const type *x)
# define ossl_PEM_write_cb_fnsig(name, type, OUTTYPE, writename)             \
    int ossl_PEM_##writename##_##name(OUTTYPE *out, const type *x,           \
                                 const ossl_EVP_CIPHER *enc,                 \
                                 const unsigned char *kstr, int klen,   \
                                 ossl_pem_password_cb *cb, void *u)
# define ossl_PEM_write_ex_fnsig(name, type, OUTTYPE, writename)             \
    int ossl_PEM_##writename##_##name##_ex(OUTTYPE *out, const type *x,      \
                                      ossl_OSSL_LIB_CTX *libctx,             \
                                      const char *propq)
# define ossl_PEM_write_cb_ex_fnsig(name, type, OUTTYPE, writename)          \
    int ossl_PEM_##writename##_##name##_ex(OUTTYPE *out, const type *x,      \
                                      const ossl_EVP_CIPHER *enc,            \
                                      const unsigned char *kstr, int klen, \
                                      ossl_pem_password_cb *cb, void *u,     \
                                      ossl_OSSL_LIB_CTX *libctx,             \
                                      const char *propq)

# ifdef ossl_OPENSSL_NO_STDIO

#  define ossl_IMPLEMENT_PEM_read_fp(name, type, str, asn1) /**/
#  define ossl_IMPLEMENT_PEM_write_fp(name, type, str, asn1) /**/
#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#   define ossl_IMPLEMENT_PEM_write_fp_const(name, type, str, asn1) /**/
#  endif
#  define ossl_IMPLEMENT_PEM_write_cb_fp(name, type, str, asn1) /**/
#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#   define ossl_IMPLEMENT_PEM_write_cb_fp_const(name, type, str, asn1) /**/
#  endif
# else

#  define ossl_IMPLEMENT_PEM_read_fp(name, type, str, asn1)                  \
    type *ossl_PEM_read_##name(FILE *fp, type **x, ossl_pem_password_cb *cb, void *u) \
    {                                                                   \
        return ossl_PEM_ASN1_read((ossl_d2i_of_void *)ossl_d2i_##asn1, str, fp,        \
                             (void **)x, cb, u);                        \
    }

#  define ossl_IMPLEMENT_PEM_write_fp(name, type, str, asn1)                 \
    ossl_PEM_write_fnsig(name, type, FILE, write)                            \
    {                                                                   \
        return ossl_PEM_ASN1_write((ossl_i2d_of_void *)ossl_i2d_##asn1, str, out,      \
                              x, NULL, NULL, 0, NULL, NULL);            \
    }

#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#   define ossl_IMPLEMENT_PEM_write_fp_const(name, type, str, asn1)  \
    ossl_IMPLEMENT_PEM_write_fp(name, type, str, asn1)
#  endif

#  define ossl_IMPLEMENT_PEM_write_cb_fp(name, type, str, asn1)              \
    ossl_PEM_write_cb_fnsig(name, type, FILE, write)                         \
    {                                                                   \
        return ossl_PEM_ASN1_write((ossl_i2d_of_void *)ossl_i2d_##asn1, str, out,      \
                              x, enc, kstr, klen, cb, u);               \
    }

#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#   define ossl_IMPLEMENT_PEM_write_cb_fp_const(name, type, str, asn1)       \
    ossl_IMPLEMENT_PEM_write_cb_fp(name, type, str, asn1)
#  endif
# endif

# define ossl_IMPLEMENT_PEM_read_bio(name, type, str, asn1)                  \
    type *ossl_PEM_read_bio_##name(ossl_BIO *bp, type **x,                        \
                              ossl_pem_password_cb *cb, void *u)             \
    {                                                                   \
        return ossl_PEM_ASN1_read_bio((ossl_d2i_of_void *)ossl_d2i_##asn1, str, bp,    \
                                 (void **)x, cb, u);                    \
    }

# define ossl_IMPLEMENT_PEM_write_bio(name, type, str, asn1)                 \
    ossl_PEM_write_fnsig(name, type, ossl_BIO, write_bio)                         \
    {                                                                   \
        return ossl_PEM_ASN1_write_bio((ossl_i2d_of_void *)ossl_i2d_##asn1, str, out,  \
                                  x, NULL,NULL,0,NULL,NULL);            \
    }

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_IMPLEMENT_PEM_write_bio_const(name, type, str, asn1)   \
    ossl_IMPLEMENT_PEM_write_bio(name, type, str, asn1)
# endif

# define ossl_IMPLEMENT_PEM_write_cb_bio(name, type, str, asn1)              \
    ossl_PEM_write_cb_fnsig(name, type, ossl_BIO, write_bio)                      \
    {                                                                   \
        return ossl_PEM_ASN1_write_bio((ossl_i2d_of_void *)ossl_i2d_##asn1, str, out,  \
                                  x, enc, kstr, klen, cb, u);           \
    }

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_IMPLEMENT_PEM_write_cb_bio_const(name, type, str, asn1)  \
    ossl_IMPLEMENT_PEM_write_cb_bio(name, type, str, asn1)
# endif

# define ossl_IMPLEMENT_PEM_write(name, type, str, asn1) \
        ossl_IMPLEMENT_PEM_write_bio(name, type, str, asn1) \
        ossl_IMPLEMENT_PEM_write_fp(name, type, str, asn1)

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_IMPLEMENT_PEM_write_const(name, type, str, asn1) \
        ossl_IMPLEMENT_PEM_write_bio_const(name, type, str, asn1) \
        ossl_IMPLEMENT_PEM_write_fp_const(name, type, str, asn1)
# endif

# define ossl_IMPLEMENT_PEM_write_cb(name, type, str, asn1) \
        ossl_IMPLEMENT_PEM_write_cb_bio(name, type, str, asn1) \
        ossl_IMPLEMENT_PEM_write_cb_fp(name, type, str, asn1)

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_IMPLEMENT_PEM_write_cb_const(name, type, str, asn1) \
        ossl_IMPLEMENT_PEM_write_cb_bio_const(name, type, str, asn1) \
        ossl_IMPLEMENT_PEM_write_cb_fp_const(name, type, str, asn1)
# endif

# define ossl_IMPLEMENT_PEM_read(name, type, str, asn1) \
        ossl_IMPLEMENT_PEM_read_bio(name, type, str, asn1) \
        ossl_IMPLEMENT_PEM_read_fp(name, type, str, asn1)

# define ossl_IMPLEMENT_PEM_rw(name, type, str, asn1) \
        ossl_IMPLEMENT_PEM_read(name, type, str, asn1) \
        ossl_IMPLEMENT_PEM_write(name, type, str, asn1)

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_IMPLEMENT_PEM_rw_const(name, type, str, asn1) \
        ossl_IMPLEMENT_PEM_read(name, type, str, asn1) \
        ossl_IMPLEMENT_PEM_write_const(name, type, str, asn1)
# endif

# define ossl_IMPLEMENT_PEM_rw_cb(name, type, str, asn1) \
        ossl_IMPLEMENT_PEM_read(name, type, str, asn1) \
        ossl_IMPLEMENT_PEM_write_cb(name, type, str, asn1)

/* These are the same except they are for the declarations */

/*
 * The mysterious 'extern' that's passed to some macros is innocuous,
 * and is there to quiet pre-C99 compilers that may complain about empty
 * arguments in macro calls.
 */
# if defined(ossl_OPENSSL_NO_STDIO)

#  define ossl_DECLARE_PEM_read_fp_attr(attr, name, type) /**/
#  define ossl_DECLARE_PEM_read_fp_ex_attr(attr, name, type) /**/
#  define ossl_DECLARE_PEM_write_fp_attr(attr, name, type) /**/
#  define ossl_DECLARE_PEM_write_fp_ex_attr(attr, name, type) /**/
#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#   define ossl_DECLARE_PEM_write_fp_const_attr(attr, name, type) /**/
#  endif
#  define ossl_DECLARE_PEM_write_cb_fp_attr(attr, name, type) /**/
#  define ossl_DECLARE_PEM_write_cb_fp_ex_attr(attr, name, type) /**/

# else

#  define ossl_DECLARE_PEM_read_fp_attr(attr, name, type)                        \
    attr ossl_PEM_read_cb_fnsig(name, type, FILE, read);
#  define ossl_DECLARE_PEM_read_fp_ex_attr(attr, name, type)                     \
    attr ossl_PEM_read_cb_fnsig(name, type, FILE, read);                         \
    attr ossl_PEM_read_cb_ex_fnsig(name, type, FILE, read);

#  define ossl_DECLARE_PEM_write_fp_attr(attr, name, type)                       \
    attr ossl_PEM_write_fnsig(name, type, FILE, write);
#  define ossl_DECLARE_PEM_write_fp_ex_attr(attr, name, type)                    \
    attr ossl_PEM_write_fnsig(name, type, FILE, write);                          \
    attr ossl_PEM_write_ex_fnsig(name, type, FILE, write);
#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#   define ossl_DECLARE_PEM_write_fp_const_attr(attr, name, type)                \
    attr ossl_PEM_write_fnsig(name, type, FILE, write);
#  endif
#  define ossl_DECLARE_PEM_write_cb_fp_attr(attr, name, type)                    \
    attr ossl_PEM_write_cb_fnsig(name, type, FILE, write);
#  define ossl_DECLARE_PEM_write_cb_fp_ex_attr(attr, name, type)                 \
    attr ossl_PEM_write_cb_fnsig(name, type, FILE, write);                       \
    attr ossl_PEM_write_cb_ex_fnsig(name, type, FILE, write);

# endif

# define ossl_DECLARE_PEM_read_fp(name, type)                                    \
    ossl_DECLARE_PEM_read_fp_attr(extern, name, type)
# define ossl_DECLARE_PEM_write_fp(name, type)                                   \
    ossl_DECLARE_PEM_write_fp_attr(extern, name, type)
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#   define ossl_DECLARE_PEM_write_fp_const(name, type)                           \
    ossl_DECLARE_PEM_write_fp_const_attr(extern, name, type)
# endif
# define ossl_DECLARE_PEM_write_cb_fp(name, type)                                \
    ossl_DECLARE_PEM_write_cb_fp_attr(extern, name, type)

#  define ossl_DECLARE_PEM_read_bio_attr(attr, name, type)                       \
    attr ossl_PEM_read_cb_fnsig(name, type, ossl_BIO, read_bio);
#  define ossl_DECLARE_PEM_read_bio_ex_attr(attr, name, type)                    \
    attr ossl_PEM_read_cb_fnsig(name, type, ossl_BIO, read_bio);                      \
    attr ossl_PEM_read_cb_ex_fnsig(name, type, ossl_BIO, read_bio);
# define ossl_DECLARE_PEM_read_bio(name, type)                                   \
    ossl_DECLARE_PEM_read_bio_attr(extern, name, type)
# define ossl_DECLARE_PEM_read_bio_ex(name, type)                                \
    ossl_DECLARE_PEM_read_bio_ex_attr(extern, name, type)

# define ossl_DECLARE_PEM_write_bio_attr(attr, name, type)                       \
    attr ossl_PEM_write_fnsig(name, type, ossl_BIO, write_bio);
# define ossl_DECLARE_PEM_write_bio_ex_attr(attr, name, type)                    \
    attr ossl_PEM_write_fnsig(name, type, ossl_BIO, write_bio);                       \
    attr ossl_PEM_write_ex_fnsig(name, type, ossl_BIO, write_bio);
# define ossl_DECLARE_PEM_write_bio(name, type)                                  \
    ossl_DECLARE_PEM_write_bio_attr(extern, name, type)
# define ossl_DECLARE_PEM_write_bio_ex(name, type)                               \
    ossl_DECLARE_PEM_write_bio_ex_attr(extern, name, type)

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_DECLARE_PEM_write_bio_const_attr(attr, name, type)                \
    attr ossl_PEM_write_fnsig(name, type, ossl_BIO, write_bio);
#  define ossl_DECLARE_PEM_write_bio_const(name, type)      \
    ossl_DECLARE_PEM_write_bio_const_attr(extern, name, type)
# endif

# define ossl_DECLARE_PEM_write_cb_bio_attr(attr, name, type)                    \
    attr ossl_PEM_write_cb_fnsig(name, type, ossl_BIO, write_bio);
# define ossl_DECLARE_PEM_write_cb_bio_ex_attr(attr, name, type)                 \
    attr ossl_PEM_write_cb_fnsig(name, type, ossl_BIO, write_bio);                    \
    attr ossl_PEM_write_cb_ex_fnsig(name, type, ossl_BIO, write_bio);
# define ossl_DECLARE_PEM_write_cb_bio(name, type)                               \
    ossl_DECLARE_PEM_write_cb_bio_attr(extern, name, type)
# define ossl_DECLARE_PEM_write_cb_ex_bio(name, type)                            \
    ossl_DECLARE_PEM_write_cb_bio_ex_attr(extern, name, type)

# define ossl_DECLARE_PEM_write_attr(attr, name, type)                           \
    ossl_DECLARE_PEM_write_bio_attr(attr, name, type)                            \
    ossl_DECLARE_PEM_write_fp_attr(attr, name, type)
# define ossl_DECLARE_PEM_write_ex_attr(attr, name, type)                        \
    ossl_DECLARE_PEM_write_bio_ex_attr(attr, name, type)                         \
    ossl_DECLARE_PEM_write_fp_ex_attr(attr, name, type)
# define ossl_DECLARE_PEM_write(name, type) \
    ossl_DECLARE_PEM_write_attr(extern, name, type)
# define ossl_DECLARE_PEM_write_ex(name, type) \
    ossl_DECLARE_PEM_write_ex_attr(extern, name, type)
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_DECLARE_PEM_write_const_attr(attr, name, type)                    \
    ossl_DECLARE_PEM_write_bio_const_attr(attr, name, type)                      \
    ossl_DECLARE_PEM_write_fp_const_attr(attr, name, type)
#  define ossl_DECLARE_PEM_write_const(name, type)                               \
    ossl_DECLARE_PEM_write_const_attr(extern, name, type)
# endif
# define ossl_DECLARE_PEM_write_cb_attr(attr, name, type)                        \
    ossl_DECLARE_PEM_write_cb_bio_attr(attr, name, type)                         \
    ossl_DECLARE_PEM_write_cb_fp_attr(attr, name, type)
# define ossl_DECLARE_PEM_write_cb_ex_attr(attr, name, type)                     \
    ossl_DECLARE_PEM_write_cb_bio_ex_attr(attr, name, type)                      \
    ossl_DECLARE_PEM_write_cb_fp_ex_attr(attr, name, type)
# define ossl_DECLARE_PEM_write_cb(name, type)                                   \
    ossl_DECLARE_PEM_write_cb_attr(extern, name, type)
# define ossl_DECLARE_PEM_write_cb_ex(name, type)                                \
    ossl_DECLARE_PEM_write_cb_ex_attr(extern, name, type)
# define ossl_DECLARE_PEM_read_attr(attr, name, type)                            \
    ossl_DECLARE_PEM_read_bio_attr(attr, name, type)                             \
    ossl_DECLARE_PEM_read_fp_attr(attr, name, type)
# define ossl_DECLARE_PEM_read_ex_attr(attr, name, type)                         \
    ossl_DECLARE_PEM_read_bio_ex_attr(attr, name, type)                          \
    ossl_DECLARE_PEM_read_fp_ex_attr(attr, name, type)
# define ossl_DECLARE_PEM_read(name, type)                                       \
    ossl_DECLARE_PEM_read_attr(extern, name, type)
# define ossl_DECLARE_PEM_read_ex(name, type)                                    \
    ossl_DECLARE_PEM_read_ex_attr(extern, name, type)
# define ossl_DECLARE_PEM_rw_attr(attr, name, type)                              \
    ossl_DECLARE_PEM_read_attr(attr, name, type)                                 \
    ossl_DECLARE_PEM_write_attr(attr, name, type)
# define ossl_DECLARE_PEM_rw_ex_attr(attr, name, type)                           \
    ossl_DECLARE_PEM_read_ex_attr(attr, name, type)                              \
    ossl_DECLARE_PEM_write_ex_attr(attr, name, type)
# define ossl_DECLARE_PEM_rw(name, type) \
    ossl_DECLARE_PEM_rw_attr(extern, name, type)
# define ossl_DECLARE_PEM_rw_ex(name, type) \
    ossl_DECLARE_PEM_rw_ex_attr(extern, name, type)
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_DECLARE_PEM_rw_const_attr(attr, name, type)                       \
    ossl_DECLARE_PEM_read_attr(attr, name, type)                                 \
    ossl_DECLARE_PEM_write_const_attr(attr, name, type)
#  define ossl_DECLARE_PEM_rw_const(name, type) \
    ossl_DECLARE_PEM_rw_const_attr(extern, name, type)
# endif
# define ossl_DECLARE_PEM_rw_cb_attr(attr, name, type)                           \
    ossl_DECLARE_PEM_read_attr(attr, name, type)                                 \
    ossl_DECLARE_PEM_write_cb_attr(attr, name, type)
# define ossl_DECLARE_PEM_rw_cb_ex_attr(attr, name, type)                        \
    ossl_DECLARE_PEM_read_ex_attr(attr, name, type)                              \
    ossl_DECLARE_PEM_write_cb_ex_attr(attr, name, type)
# define ossl_DECLARE_PEM_rw_cb(name, type) \
    ossl_DECLARE_PEM_rw_cb_attr(extern, name, type)
# define ossl_DECLARE_PEM_rw_cb_ex(name, type) \
    ossl_DECLARE_PEM_rw_cb_ex_attr(extern, name, type)

int ossl_PEM_get_EVP_CIPHER_INFO(char *header, ossl_EVP_CIPHER_INFO *cipher);
int ossl_PEM_do_header(ossl_EVP_CIPHER_INFO *cipher, unsigned char *data, long *len,
                  ossl_pem_password_cb *callback, void *u);

int ossl_PEM_read_bio(ossl_BIO *bp, char **name, char **header,
                 unsigned char **data, long *len);
#   define ossl_PEM_FLAG_SECURE             0x1
#   define ossl_PEM_FLAG_EAY_COMPATIBLE     0x2
#   define ossl_PEM_FLAG_ONLY_B64           0x4
int ossl_PEM_read_bio_ex(ossl_BIO *bp, char **name, char **header,
                    unsigned char **data, long *len, unsigned int flags);
int ossl_PEM_bytes_read_bio_secmem(unsigned char **pdata, long *plen, char **pnm,
                              const char *name, ossl_BIO *bp, ossl_pem_password_cb *cb,
                              void *u);
int ossl_PEM_write_bio(ossl_BIO *bp, const char *name, const char *hdr,
                  const unsigned char *data, long len);
int ossl_PEM_bytes_read_bio(unsigned char **pdata, long *plen, char **pnm,
                       const char *name, ossl_BIO *bp, ossl_pem_password_cb *cb,
                       void *u);
void *ossl_PEM_ASN1_read_bio(ossl_d2i_of_void *d2i, const char *name, ossl_BIO *bp, void **x,
                        ossl_pem_password_cb *cb, void *u);
int ossl_PEM_ASN1_write_bio(ossl_i2d_of_void *i2d, const char *name, ossl_BIO *bp,
                       const void *x, const ossl_EVP_CIPHER *enc,
                       const unsigned char *kstr, int klen,
                       ossl_pem_password_cb *cb, void *u);

ossl_STACK_OF(ossl_X509_INFO) *ossl_PEM_X509_INFO_read_bio(ossl_BIO *bp, ossl_STACK_OF(ossl_X509_INFO) *sk,
                                            ossl_pem_password_cb *cb, void *u);
ossl_STACK_OF(ossl_X509_INFO)
*ossl_PEM_X509_INFO_read_bio_ex(ossl_BIO *bp, ossl_STACK_OF(ossl_X509_INFO) *sk,
                           ossl_pem_password_cb *cb, void *u, ossl_OSSL_LIB_CTX *libctx,
                           const char *propq);

int ossl_PEM_X509_INFO_write_bio(ossl_BIO *bp, const ossl_X509_INFO *xi, ossl_EVP_CIPHER *enc,
                            const unsigned char *kstr, int klen,
                            ossl_pem_password_cb *cd, void *u);

#ifndef ossl_OPENSSL_NO_STDIO
int ossl_PEM_read(FILE *fp, char **name, char **header,
             unsigned char **data, long *len);
int ossl_PEM_write(FILE *fp, const char *name, const char *hdr,
              const unsigned char *data, long len);
void *ossl_PEM_ASN1_read(ossl_d2i_of_void *d2i, const char *name, FILE *fp, void **x,
                    ossl_pem_password_cb *cb, void *u);
int ossl_PEM_ASN1_write(ossl_i2d_of_void *i2d, const char *name, FILE *fp,
                   const void *x, const ossl_EVP_CIPHER *enc,
                   const unsigned char *kstr, int klen,
                   ossl_pem_password_cb *callback, void *u);
ossl_STACK_OF(ossl_X509_INFO) *ossl_PEM_X509_INFO_read(FILE *fp, ossl_STACK_OF(ossl_X509_INFO) *sk,
                                        ossl_pem_password_cb *cb, void *u);
ossl_STACK_OF(ossl_X509_INFO)
*ossl_PEM_X509_INFO_read_ex(FILE *fp, ossl_STACK_OF(ossl_X509_INFO) *sk, ossl_pem_password_cb *cb,
                       void *u, ossl_OSSL_LIB_CTX *libctx, const char *propq);
#endif

int ossl_PEM_SignInit(ossl_EVP_MD_CTX *ctx, ossl_EVP_MD *type);
int ossl_PEM_SignUpdate(ossl_EVP_MD_CTX *ctx, const unsigned char *d, unsigned int cnt);
int ossl_PEM_SignFinal(ossl_EVP_MD_CTX *ctx, unsigned char *sigret,
                  unsigned int *siglen, ossl_EVP_PKEY *pkey);

/* The default ossl_pem_password_cb that's used internally */
int ossl_PEM_def_callback(char *buf, int num, int rwflag, void *userdata);
void ossl_PEM_proc_type(char *buf, int type);
void ossl_PEM_dek_info(char *buf, const char *type, int len, const char *str);

# include "ossl/openssl/symhacks.h"

ossl_DECLARE_PEM_rw(ossl_X509, ossl_X509)
ossl_DECLARE_PEM_rw(X509_AUX, ossl_X509)
ossl_DECLARE_PEM_rw(ossl_X509_REQ, ossl_X509_REQ)
ossl_DECLARE_PEM_write(X509_REQ_NEW, ossl_X509_REQ)
ossl_DECLARE_PEM_rw(ossl_X509_CRL, ossl_X509_CRL)
ossl_DECLARE_PEM_rw(ossl_X509_PUBKEY, ossl_X509_PUBKEY)
ossl_DECLARE_PEM_rw(ossl_PKCS7, ossl_PKCS7)
ossl_DECLARE_PEM_rw(ossl_NETSCAPE_CERT_SEQUENCE, ossl_NETSCAPE_CERT_SEQUENCE)
ossl_DECLARE_PEM_rw(PKCS8, ossl_X509_SIG)
ossl_DECLARE_PEM_rw(ossl_PKCS8_PRIV_KEY_INFO, ossl_PKCS8_PRIV_KEY_INFO)
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_DECLARE_PEM_rw_cb_attr(ossl_OSSL_DEPRECATEDIN_3_0, ossl_RSAPrivateKey, ossl_RSA)
ossl_DECLARE_PEM_rw_attr(ossl_OSSL_DEPRECATEDIN_3_0, ossl_RSAPublicKey, ossl_RSA)
ossl_DECLARE_PEM_rw_attr(ossl_OSSL_DEPRECATEDIN_3_0, RSA_PUBKEY, ossl_RSA)
# endif
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  ifndef ossl_OPENSSL_NO_DSA
ossl_DECLARE_PEM_rw_cb_attr(ossl_OSSL_DEPRECATEDIN_3_0, DSAPrivateKey, ossl_DSA)
ossl_DECLARE_PEM_rw_attr(ossl_OSSL_DEPRECATEDIN_3_0, DSA_PUBKEY, ossl_DSA)
ossl_DECLARE_PEM_rw_attr(ossl_OSSL_DEPRECATEDIN_3_0, DSAparams, ossl_DSA)
#  endif
# endif

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  ifndef ossl_OPENSSL_NO_EC
ossl_DECLARE_PEM_rw_attr(ossl_OSSL_DEPRECATEDIN_3_0, ECPKParameters, ossl_EC_GROUP)
ossl_DECLARE_PEM_rw_cb_attr(ossl_OSSL_DEPRECATEDIN_3_0, ECPrivateKey, ossl_EC_KEY)
ossl_DECLARE_PEM_rw_attr(ossl_OSSL_DEPRECATEDIN_3_0, EC_PUBKEY, ossl_EC_KEY)
#  endif
# endif

# ifndef ossl_OPENSSL_NO_DH
#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_DECLARE_PEM_rw_attr(ossl_OSSL_DEPRECATEDIN_3_0, ossl_DHparams, ossl_DH)
ossl_DECLARE_PEM_write_attr(ossl_OSSL_DEPRECATEDIN_3_0, DHxparams, ossl_DH)
#  endif
# endif
ossl_DECLARE_PEM_rw_cb_ex(PrivateKey, ossl_EVP_PKEY)
ossl_DECLARE_PEM_rw_ex(PUBKEY, ossl_EVP_PKEY)

int ossl_PEM_write_bio_PrivateKey_traditional(ossl_BIO *bp, const ossl_EVP_PKEY *x,
                                         const ossl_EVP_CIPHER *enc,
                                         const unsigned char *kstr, int klen,
                                         ossl_pem_password_cb *cb, void *u);

/* Why do these take a signed char *kstr? */
int ossl_PEM_write_bio_PKCS8PrivateKey_nid(ossl_BIO *bp, const ossl_EVP_PKEY *x, int nid,
                                      const char *kstr, int klen,
                                      ossl_pem_password_cb *cb, void *u);
int ossl_PEM_write_bio_PKCS8PrivateKey(ossl_BIO *, const ossl_EVP_PKEY *, const ossl_EVP_CIPHER *,
                                  const char *kstr, int klen,
                                  ossl_pem_password_cb *cb, void *u);
int ossl_i2d_PKCS8PrivateKey_bio(ossl_BIO *bp, const ossl_EVP_PKEY *x, const ossl_EVP_CIPHER *enc,
                            const char *kstr, int klen,
                            ossl_pem_password_cb *cb, void *u);
int ossl_i2d_PKCS8PrivateKey_nid_bio(ossl_BIO *bp, const ossl_EVP_PKEY *x, int nid,
                                const char *kstr, int klen,
                                ossl_pem_password_cb *cb, void *u);
ossl_EVP_PKEY *ossl_d2i_PKCS8PrivateKey_bio(ossl_BIO *bp, ossl_EVP_PKEY **x, ossl_pem_password_cb *cb,
                                  void *u);

# ifndef ossl_OPENSSL_NO_STDIO
int ossl_i2d_PKCS8PrivateKey_fp(FILE *fp, const ossl_EVP_PKEY *x, const ossl_EVP_CIPHER *enc,
                           const char *kstr, int klen,
                           ossl_pem_password_cb *cb, void *u);
int ossl_i2d_PKCS8PrivateKey_nid_fp(FILE *fp, const ossl_EVP_PKEY *x, int nid,
                               const char *kstr, int klen,
                               ossl_pem_password_cb *cb, void *u);
int ossl_PEM_write_PKCS8PrivateKey_nid(FILE *fp, const ossl_EVP_PKEY *x, int nid,
                                  const char *kstr, int klen,
                                  ossl_pem_password_cb *cb, void *u);

ossl_EVP_PKEY *ossl_d2i_PKCS8PrivateKey_fp(FILE *fp, ossl_EVP_PKEY **x, ossl_pem_password_cb *cb,
                                 void *u);

int ossl_PEM_write_PKCS8PrivateKey(FILE *fp, const ossl_EVP_PKEY *x, const ossl_EVP_CIPHER *enc,
                              const char *kstr, int klen,
                              ossl_pem_password_cb *cd, void *u);
# endif
ossl_EVP_PKEY *ossl_PEM_read_bio_Parameters_ex(ossl_BIO *bp, ossl_EVP_PKEY **x,
                                     ossl_OSSL_LIB_CTX *libctx, const char *propq);
ossl_EVP_PKEY *ossl_PEM_read_bio_Parameters(ossl_BIO *bp, ossl_EVP_PKEY **x);
int ossl_PEM_write_bio_Parameters(ossl_BIO *bp, const ossl_EVP_PKEY *x);

ossl_EVP_PKEY *ossl_b2i_PrivateKey(const unsigned char **in, long length);
ossl_EVP_PKEY *ossl_b2i_PublicKey(const unsigned char **in, long length);
ossl_EVP_PKEY *ossl_b2i_PrivateKey_bio(ossl_BIO *in);
ossl_EVP_PKEY *ossl_b2i_PublicKey_bio(ossl_BIO *in);
int ossl_i2b_PrivateKey_bio(ossl_BIO *out, const ossl_EVP_PKEY *pk);
int ossl_i2b_PublicKey_bio(ossl_BIO *out, const ossl_EVP_PKEY *pk);
ossl_EVP_PKEY *ossl_b2i_PVK_bio(ossl_BIO *in, ossl_pem_password_cb *cb, void *u);
ossl_EVP_PKEY *ossl_b2i_PVK_bio_ex(ossl_BIO *in, ossl_pem_password_cb *cb, void *u,
                         ossl_OSSL_LIB_CTX *libctx, const char *propq);
int ossl_i2b_PVK_bio(ossl_BIO *out, const ossl_EVP_PKEY *pk, int enclevel,
                ossl_pem_password_cb *cb, void *u);
int ossl_i2b_PVK_bio_ex(ossl_BIO *out, const ossl_EVP_PKEY *pk, int enclevel,
                   ossl_pem_password_cb *cb, void *u,
                   ossl_OSSL_LIB_CTX *libctx, const char *propq);

# ifdef  __cplusplus
}
# endif
#endif
