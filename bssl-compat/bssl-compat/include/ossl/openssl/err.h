/*
 * Copyright 1995-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */



#ifndef ossl_OPENSSL_ERR_H
# define ossl_OPENSSL_ERR_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_ERR_H
# endif

# include "ossl/openssl/e_os2.h"

# ifndef ossl_OPENSSL_NO_STDIO
#  include <stdio.h>
#  include <stdlib.h>
# endif

# include "ossl/openssl/types.h"
# include "ossl/openssl/bio.h"
# include "ossl/openssl/lhash.h"
# include "ossl/openssl/cryptoerr_legacy.h"

#ifdef  __cplusplus
extern "C" {
#endif

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  ifndef ossl_OPENSSL_NO_FILENAMES
#   define ossl_ERR_PUT_error(l,f,r,fn,ln)      ossl_ERR_put_error(l,f,r,fn,ln)
#  else
#   define ossl_ERR_PUT_error(l,f,r,fn,ln)      ossl_ERR_put_error(l,f,r,NULL,0)
#  endif
# endif

# include <limits.h>
# include <errno.h>

# define ossl_ERR_TXT_MALLOCED        0x01
# define ossl_ERR_TXT_STRING          0x02

# if !defined(ossl_OPENSSL_NO_DEPRECATED_3_0) || defined(OSSL_FORCE_ERR_STATE)
#  define ossl_ERR_FLAG_MARK           0x01
#  define ossl_ERR_FLAG_CLEAR          0x02

#  define ossl_ERR_NUM_ERRORS  16
struct ossl_err_state_st {
    int err_flags[ossl_ERR_NUM_ERRORS];
    int err_marks[ossl_ERR_NUM_ERRORS];
    unsigned long err_buffer[ossl_ERR_NUM_ERRORS];
    char *err_data[ossl_ERR_NUM_ERRORS];
    size_t err_data_size[ossl_ERR_NUM_ERRORS];
    int err_data_flags[ossl_ERR_NUM_ERRORS];
    char *err_file[ossl_ERR_NUM_ERRORS];
    int err_line[ossl_ERR_NUM_ERRORS];
    char *err_func[ossl_ERR_NUM_ERRORS];
    int top, bottom;
};
# endif

/* library */
# define ossl_ERR_LIB_NONE            1
# define ossl_ERR_LIB_SYS             2
# define ossl_ERR_LIB_BN              3
# define ossl_ERR_LIB_RSA             4
# define ossl_ERR_LIB_DH              5
# define ossl_ERR_LIB_EVP             6
# define ossl_ERR_LIB_BUF             7
# define ossl_ERR_LIB_OBJ             8
# define ossl_ERR_LIB_PEM             9
# define ossl_ERR_LIB_DSA             10
# define ossl_ERR_LIB_X509            11
/* #define ERR_LIB_METH         12 */
# define ossl_ERR_LIB_ASN1            13
# define ossl_ERR_LIB_CONF            14
# define ossl_ERR_LIB_CRYPTO          15
# define ossl_ERR_LIB_EC              16
# define ossl_ERR_LIB_SSL             20
/* #define ERR_LIB_SSL23        21 */
/* #define ERR_LIB_SSL2         22 */
/* #define ERR_LIB_SSL3         23 */
/* #define ERR_LIB_RSAREF       30 */
/* #define ERR_LIB_PROXY        31 */
# define ossl_ERR_LIB_BIO             32
# define ossl_ERR_LIB_PKCS7           33
# define ossl_ERR_LIB_X509V3          34
# define ossl_ERR_LIB_PKCS12          35
# define ossl_ERR_LIB_RAND            36
# define ossl_ERR_LIB_DSO             37
# define ossl_ERR_LIB_ENGINE          38
# define ossl_ERR_LIB_OCSP            39
# define ossl_ERR_LIB_UI              40
# define ossl_ERR_LIB_COMP            41
# define ossl_ERR_LIB_ECDSA           42
# define ossl_ERR_LIB_ECDH            43
# define ossl_ERR_LIB_OSSL_STORE      44
# define ossl_ERR_LIB_FIPS            45
# define ossl_ERR_LIB_CMS             46
# define ossl_ERR_LIB_TS              47
# define ossl_ERR_LIB_HMAC            48
/* # define ERR_LIB_JPAKE       49 */
# define ossl_ERR_LIB_CT              50
# define ossl_ERR_LIB_ASYNC           51
# define ossl_ERR_LIB_KDF             52
# define ossl_ERR_LIB_SM2             53
# define ossl_ERR_LIB_ESS             54
# define ossl_ERR_LIB_PROP            55
# define ossl_ERR_LIB_CRMF            56
# define ossl_ERR_LIB_PROV            57
# define ossl_ERR_LIB_CMP             58
# define ossl_ERR_LIB_OSSL_ENCODER    59
# define ossl_ERR_LIB_OSSL_DECODER    60
# define ossl_ERR_LIB_HTTP            61

# define ossl_ERR_LIB_USER            128

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_ASN1err(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_ASN1, (r), NULL)
#  define ossl_ASYNCerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_ASYNC, (r), NULL)
#  define ossl_BIOerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_BIO, (r), NULL)
#  define ossl_BNerr(f, r)  ossl_ERR_raise_data(ossl_ERR_LIB_BN, (r), NULL)
#  define ossl_BUFerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_BUF, (r), NULL)
#  define ossl_CMPerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_CMP, (r), NULL)
#  define ossl_CMSerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_CMS, (r), NULL)
#  define ossl_COMPerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_COMP, (r), NULL)
#  define ossl_CONFerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_CONF, (r), NULL)
#  define ossl_CRMFerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_CRMF, (r), NULL)
#  define ossl_CRYPTOerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_CRYPTO, (r), NULL)
#  define ossl_CTerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_CT, (r), NULL)
#  define ossl_DHerr(f, r)  ossl_ERR_raise_data(ossl_ERR_LIB_DH, (r), NULL)
#  define ossl_DSAerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_DSA, (r), NULL)
#  define ossl_DSOerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_DSO, (r), NULL)
#  define ossl_ECDHerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_ECDH, (r), NULL)
#  define ossl_ECDSAerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_ECDSA, (r), NULL)
#  define ossl_ECerr(f, r)  ossl_ERR_raise_data(ossl_ERR_LIB_EC, (r), NULL)
#  define ossl_ENGINEerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_ENGINE, (r), NULL)
#  define ossl_ESSerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_ESS, (r), NULL)
#  define ossl_EVPerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_EVP, (r), NULL)
#  define ossl_FIPSerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_FIPS, (r), NULL)
#  define ossl_HMACerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_HMAC, (r), NULL)
#  define ossl_HTTPerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_HTTP, (r), NULL)
#  define ossl_KDFerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_KDF, (r), NULL)
#  define ossl_OBJerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_OBJ, (r), NULL)
#  define ossl_OCSPerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_OCSP, (r), NULL)
#  define ossl_OSSL_STOREerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_OSSL_STORE, (r), NULL)
#  define ossl_PEMerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_PEM, (r), NULL)
#  define ossl_PKCS12err(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_PKCS12, (r), NULL)
#  define ossl_PKCS7err(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_PKCS7, (r), NULL)
#  define ossl_PROPerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_PROP, (r), NULL)
#  define ossl_PROVerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_PROV, (r), NULL)
#  define ossl_RANDerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_RAND, (r), NULL)
#  define ossl_RSAerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_RSA, (r), NULL)
#  define ossl_KDFerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_KDF, (r), NULL)
#  define ossl_SM2err(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_SM2, (r), NULL)
#  define ossl_SSLerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_SSL, (r), NULL)
#  define ossl_SYSerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_SYS, (r), NULL)
#  define ossl_TSerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_TS, (r), NULL)
#  define ossl_UIerr(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_UI, (r), NULL)
#  define ossl_X509V3err(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_X509V3, (r), NULL)
#  define ossl_X509err(f, r) ossl_ERR_raise_data(ossl_ERR_LIB_X509, (r), NULL)
# endif

/*-
 * The error code packs differently depending on if it records a system
 * error or an OpenSSL error.
 *
 * A system error packs like this (we follow POSIX and only allow positive
 * numbers that fit in an |int|):
 *
 * +-+-------------------------------------------------------------+
 * |1|                     system error number                     |
 * +-+-------------------------------------------------------------+
 *
 * An OpenSSL error packs like this:
 *
 * <---------------------------- 32 bits -------------------------->
 *    <--- 8 bits ---><------------------ 23 bits ----------------->
 * +-+---------------+---------------------------------------------+
 * |0|    library    |                    reason                   |
 * +-+---------------+---------------------------------------------+
 *
 * A few of the reason bits are reserved as flags with special meaning:
 *
 *                    <5 bits-<>--------- 19 bits ----------------->
 *                   +-------+-+-----------------------------------+
 *                   | rflags| |          reason                   |
 *                   +-------+-+-----------------------------------+
 *                            ^
 *                            |
 *                           ossl_ERR_RFLAG_FATAL = ossl_ERR_R_FATAL
 *
 * The reason flags are part of the overall reason code for practical
 * reasons, as they provide an easy way to place different types of
 * reason codes in different numeric ranges.
 *
 * The currently known reason flags are:
 *
 * ossl_ERR_RFLAG_FATAL      Flags that the reason code is considered fatal.
 *                      For backward compatibility reasons, this flag
 *                      is also the code for ossl_ERR_R_FATAL (that reason
 *                      code served the dual purpose of flag and reason
 *                      code in one in pre-3.0 OpenSSL).
 * ossl_ERR_RFLAG_COMMON     Flags that the reason code is common to all
 *                      libraries.  All ERR_R_ macros must use this flag,
 *                      and no other _R_ macro is allowed to use it.
 */

/* Macros to help decode recorded system errors */
# define ossl_ERR_SYSTEM_FLAG                ((unsigned int)INT_MAX + 1)
# define ossl_ERR_SYSTEM_MASK                ((unsigned int)INT_MAX)

/*
 * Macros to help decode recorded OpenSSL errors
 * As expressed above, RFLAGS and REASON overlap by one bit to allow
 * ossl_ERR_R_FATAL to use ossl_ERR_RFLAG_FATAL as its reason code.
 */
# define ossl_ERR_LIB_OFFSET                 23L
# define ossl_ERR_LIB_MASK                   0xFF
# define ossl_ERR_RFLAGS_OFFSET              18L
# define ossl_ERR_RFLAGS_MASK                0x1F
# define ossl_ERR_REASON_MASK                0X7FFFFF

/*
 * Reason flags are defined pre-shifted to easily combine with the reason
 * number.
 */
# define ossl_ERR_RFLAG_FATAL                (0x1 << ossl_ERR_RFLAGS_OFFSET)
# define ossl_ERR_RFLAG_COMMON               (0x2 << ossl_ERR_RFLAGS_OFFSET)

# define ossl_ERR_SYSTEM_ERROR(errcode)      (((errcode) & ossl_ERR_SYSTEM_FLAG) != 0)

static ossl_ossl_unused ossl_ossl_inline int ossl_ERR_GET_LIB(unsigned long errcode)
{
    if (ossl_ERR_SYSTEM_ERROR(errcode))
        return ossl_ERR_LIB_SYS;
    return (errcode >> ossl_ERR_LIB_OFFSET) & ossl_ERR_LIB_MASK;
}

static ossl_ossl_unused ossl_ossl_inline int ossl_ERR_GET_RFLAGS(unsigned long errcode)
{
    if (ossl_ERR_SYSTEM_ERROR(errcode))
        return 0;
    return errcode & (ossl_ERR_RFLAGS_MASK << ossl_ERR_RFLAGS_OFFSET);
}

static ossl_ossl_unused ossl_ossl_inline int ossl_ERR_GET_REASON(unsigned long errcode)
{
    if (ossl_ERR_SYSTEM_ERROR(errcode))
        return errcode & ossl_ERR_SYSTEM_MASK;
    return errcode & ossl_ERR_REASON_MASK;
}

static ossl_ossl_unused ossl_ossl_inline int ossl_ERR_FATAL_ERROR(unsigned long errcode)
{
    return (ossl_ERR_GET_RFLAGS(errcode) & ossl_ERR_RFLAG_FATAL) != 0;
}

static ossl_ossl_unused ossl_ossl_inline int ossl_ERR_COMMON_ERROR(unsigned long errcode)
{
    return (ossl_ERR_GET_RFLAGS(errcode) & ossl_ERR_RFLAG_COMMON) != 0;
}

/*
 * ossl_ERR_PACK is a helper macro to properly pack OpenSSL error codes and may
 * only be used for that purpose.  System errors are packed internally.
 * ossl_ERR_PACK takes reason flags and reason code combined in |reason|.
 * ossl_ERR_PACK ignores |func|, that parameter is just legacy from pre-3.0 OpenSSL.
 */
# define ossl_ERR_PACK(lib,func,reason)                                      \
    ( (((unsigned long)(lib)    & ossl_ERR_LIB_MASK   ) << ossl_ERR_LIB_OFFSET) | \
      (((unsigned long)(reason) & ossl_ERR_REASON_MASK)) )

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_SYS_F_FOPEN             0
#  define ossl_SYS_F_CONNECT           0
#  define ossl_SYS_F_GETSERVBYNAME     0
#  define ossl_SYS_F_SOCKET            0
#  define ossl_SYS_F_IOCTLSOCKET       0
#  define ossl_SYS_F_BIND              0
#  define ossl_SYS_F_LISTEN            0
#  define ossl_SYS_F_ACCEPT            0
#  define ossl_SYS_F_WSASTARTUP        0
#  define ossl_SYS_F_OPENDIR           0
#  define ossl_SYS_F_FREAD             0
#  define ossl_SYS_F_GETADDRINFO       0
#  define ossl_SYS_F_GETNAMEINFO       0
#  define ossl_SYS_F_SETSOCKOPT        0
#  define ossl_SYS_F_GETSOCKOPT        0
#  define ossl_SYS_F_GETSOCKNAME       0
#  define ossl_SYS_F_GETHOSTBYNAME     0
#  define ossl_SYS_F_FFLUSH            0
#  define ossl_SYS_F_OPEN              0
#  define ossl_SYS_F_CLOSE             0
#  define ossl_SYS_F_IOCTL             0
#  define ossl_SYS_F_STAT              0
#  define ossl_SYS_F_FCNTL             0
#  define ossl_SYS_F_FSTAT             0
#  define ossl_SYS_F_SENDFILE          0
# endif

/*
 * All ERR_R_ codes must be combined with ossl_ERR_RFLAG_COMMON.
 */

/* "we came from here" global reason codes, range 1..255 */
# define ossl_ERR_R_SYS_LIB          (ossl_ERR_LIB_SYS/* 2 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_BN_LIB           (ossl_ERR_LIB_BN/* 3 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_RSA_LIB          (ossl_ERR_LIB_RSA/* 4 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_DH_LIB           (ossl_ERR_LIB_DH/* 5 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_EVP_LIB          (ossl_ERR_LIB_EVP/* 6 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_BUF_LIB          (ossl_ERR_LIB_BUF/* 7 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_OBJ_LIB          (ossl_ERR_LIB_OBJ/* 8 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_PEM_LIB          (ossl_ERR_LIB_PEM/* 9 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_DSA_LIB          (ossl_ERR_LIB_DSA/* 10 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_X509_LIB         (ossl_ERR_LIB_X509/* 11 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_ASN1_LIB         (ossl_ERR_LIB_ASN1/* 13 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_CONF_LIB         (ossl_ERR_LIB_CONF/* 14 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_CRYPTO_LIB       (ossl_ERR_LIB_CRYPTO/* 15 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_EC_LIB           (ossl_ERR_LIB_EC/* 16 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_SSL_LIB          (ossl_ERR_LIB_SSL/* 20 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_BIO_LIB          (ossl_ERR_LIB_BIO/* 32 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_PKCS7_LIB        (ossl_ERR_LIB_PKCS7/* 33 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_X509V3_LIB       (ossl_ERR_LIB_X509V3/* 34 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_PKCS12_LIB       (ossl_ERR_LIB_PKCS12/* 35 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_RAND_LIB         (ossl_ERR_LIB_RAND/* 36 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_DSO_LIB          (ossl_ERR_LIB_DSO/* 37 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_ENGINE_LIB       (ossl_ERR_LIB_ENGINE/* 38 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_UI_LIB           (ossl_ERR_LIB_UI/* 40 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_ECDSA_LIB        (ossl_ERR_LIB_ECDSA/* 42 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_OSSL_STORE_LIB   (ossl_ERR_LIB_OSSL_STORE/* 44 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_CMS_LIB          (ossl_ERR_LIB_CMS/* 46 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_TS_LIB           (ossl_ERR_LIB_TS/* 47 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_CT_LIB           (ossl_ERR_LIB_CT/* 50 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_PROV_LIB         (ossl_ERR_LIB_PROV/* 57 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_ESS_LIB          (ossl_ERR_LIB_ESS/* 54 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_CMP_LIB          (ossl_ERR_LIB_CMP/* 58 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_OSSL_ENCODER_LIB (ossl_ERR_LIB_OSSL_ENCODER/* 59 */ | ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_OSSL_DECODER_LIB (ossl_ERR_LIB_OSSL_DECODER/* 60 */ | ossl_ERR_RFLAG_COMMON)

/* Other common error codes, range 256..2^ossl_ERR_RFLAGS_OFFSET-1 */
# define ossl_ERR_R_FATAL                             (ossl_ERR_RFLAG_FATAL|ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_MALLOC_FAILURE                    (256|ossl_ERR_R_FATAL)
# define ossl_ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED       (257|ossl_ERR_R_FATAL)
# define ossl_ERR_R_PASSED_NULL_PARAMETER             (258|ossl_ERR_R_FATAL)
# define ossl_ERR_R_INTERNAL_ERROR                    (259|ossl_ERR_R_FATAL)
# define ossl_ERR_R_DISABLED                          (260|ossl_ERR_R_FATAL)
# define ossl_ERR_R_INIT_FAIL                         (261|ossl_ERR_R_FATAL)
# define ossl_ERR_R_PASSED_INVALID_ARGUMENT           (262|ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_OPERATION_FAIL                    (263|ossl_ERR_R_FATAL)
# define ossl_ERR_R_INVALID_PROVIDER_FUNCTIONS        (264|ossl_ERR_R_FATAL)
# define ossl_ERR_R_INTERRUPTED_OR_CANCELLED          (265|ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_NESTED_ASN1_ERROR                 (266|ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_MISSING_ASN1_EOS                  (267|ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_UNSUPPORTED                       (268|ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_FETCH_FAILED                      (269|ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_INVALID_PROPERTY_DEFINITION       (270|ossl_ERR_RFLAG_COMMON)
# define ossl_ERR_R_UNABLE_TO_GET_READ_LOCK           (271|ossl_ERR_R_FATAL)
# define ossl_ERR_R_UNABLE_TO_GET_WRITE_LOCK          (272|ossl_ERR_R_FATAL)

typedef struct ossl_ERR_string_data_st {
    unsigned long error;
    const char *string;
} ossl_ERR_STRING_DATA;

ossl_DEFINE_LHASH_OF_INTERNAL(ossl_ERR_STRING_DATA);
#define ossl_lh_ERR_STRING_DATA_new(hfn, cmp) ((ossl_LHASH_OF(ossl_ERR_STRING_DATA) *)ossl_OPENSSL_LH_new(ossl_ossl_check_ERR_STRING_DATA_lh_hashfunc_type(hfn), ossl_ossl_check_ERR_STRING_DATA_lh_compfunc_type(cmp)))
#define ossl_lh_ERR_STRING_DATA_free(lh) ossl_OPENSSL_LH_free(ossl_ossl_check_ERR_STRING_DATA_lh_type(lh))
#define ossl_lh_ERR_STRING_DATA_flush(lh) ossl_OPENSSL_LH_flush(ossl_ossl_check_ERR_STRING_DATA_lh_type(lh))
#define ossl_lh_ERR_STRING_DATA_insert(lh, ptr) ((ossl_ERR_STRING_DATA *)ossl_OPENSSL_LH_insert(ossl_ossl_check_ERR_STRING_DATA_lh_type(lh), ossl_ossl_check_ERR_STRING_DATA_lh_plain_type(ptr)))
#define ossl_lh_ERR_STRING_DATA_delete(lh, ptr) ((ossl_ERR_STRING_DATA *)ossl_OPENSSL_LH_delete(ossl_ossl_check_ERR_STRING_DATA_lh_type(lh), ossl_ossl_check_const_ERR_STRING_DATA_lh_plain_type(ptr)))
#define ossl_lh_ERR_STRING_DATA_retrieve(lh, ptr) ((ossl_ERR_STRING_DATA *)ossl_OPENSSL_LH_retrieve(ossl_ossl_check_ERR_STRING_DATA_lh_type(lh), ossl_ossl_check_const_ERR_STRING_DATA_lh_plain_type(ptr)))
#define ossl_lh_ERR_STRING_DATA_error(lh) ossl_OPENSSL_LH_error(ossl_ossl_check_ERR_STRING_DATA_lh_type(lh))
#define ossl_lh_ERR_STRING_DATA_num_items(lh) ossl_OPENSSL_LH_num_items(ossl_ossl_check_ERR_STRING_DATA_lh_type(lh))
#define ossl_lh_ERR_STRING_DATA_node_stats_bio(lh, out) ossl_OPENSSL_LH_node_stats_bio(ossl_ossl_check_const_ERR_STRING_DATA_lh_type(lh), out)
#define ossl_lh_ERR_STRING_DATA_node_usage_stats_bio(lh, out) ossl_OPENSSL_LH_node_usage_stats_bio(ossl_ossl_check_const_ERR_STRING_DATA_lh_type(lh), out)
#define ossl_lh_ERR_STRING_DATA_stats_bio(lh, out) ossl_OPENSSL_LH_stats_bio(ossl_ossl_check_const_ERR_STRING_DATA_lh_type(lh), out)
#define ossl_lh_ERR_STRING_DATA_get_down_load(lh) ossl_OPENSSL_LH_get_down_load(ossl_ossl_check_ERR_STRING_DATA_lh_type(lh))
#define ossl_lh_ERR_STRING_DATA_set_down_load(lh, dl) ossl_OPENSSL_LH_set_down_load(ossl_ossl_check_ERR_STRING_DATA_lh_type(lh), dl)
#define ossl_lh_ERR_STRING_DATA_doall(lh, dfn) ossl_OPENSSL_LH_doall(ossl_ossl_check_ERR_STRING_DATA_lh_type(lh), ossl_ossl_check_ERR_STRING_DATA_lh_doallfunc_type(dfn))


/* 12 lines and some on an 80 column terminal */
#define ossl_ERR_MAX_DATA_SIZE       1024

/* Building blocks */
void ossl_ERR_new(void);
void ossl_ERR_set_debug(const char *file, int line, const char *func);
void ossl_ERR_set_error(int lib, int reason, const char *fmt, ...);
void ossl_ERR_vset_error(int lib, int reason, const char *fmt, va_list args);

/* Main error raising functions */
# define ossl_ERR_raise(lib, reason) ossl_ERR_raise_data((lib),(reason),NULL)
# define ossl_ERR_raise_data                                         \
    (ossl_ERR_new(),                                                 \
     ossl_ERR_set_debug(ossl_OPENSSL_FILE,ossl_OPENSSL_LINE,ossl_OPENSSL_FUNC),     \
     ossl_ERR_set_error)

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
/* Backward compatibility */
#  define ossl_ERR_put_error(lib, func, reason, file, line)          \
    (ossl_ERR_new(),                                                 \
     ossl_ERR_set_debug((file), (line), ossl_OPENSSL_FUNC),               \
     ossl_ERR_set_error((lib), (reason), NULL))
# endif

void ossl_ERR_set_error_data(char *data, int flags);

unsigned long ossl_ERR_get_error(void);
unsigned long ossl_ERR_get_error_all(const char **file, int *line,
                                const char **func,
                                const char **data, int *flags);
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0
unsigned long ossl_ERR_get_error_line(const char **file, int *line);
ossl_OSSL_DEPRECATEDIN_3_0
unsigned long ossl_ERR_get_error_line_data(const char **file, int *line,
                                      const char **data, int *flags);
#endif
unsigned long ossl_ERR_peek_error(void);
unsigned long ossl_ERR_peek_error_line(const char **file, int *line);
unsigned long ossl_ERR_peek_error_func(const char **func);
unsigned long ossl_ERR_peek_error_data(const char **data, int *flags);
unsigned long ossl_ERR_peek_error_all(const char **file, int *line,
                                 const char **func,
                                 const char **data, int *flags);
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0
unsigned long ossl_ERR_peek_error_line_data(const char **file, int *line,
                                       const char **data, int *flags);
# endif
unsigned long ossl_ERR_peek_last_error(void);
unsigned long ossl_ERR_peek_last_error_line(const char **file, int *line);
unsigned long ossl_ERR_peek_last_error_func(const char **func);
unsigned long ossl_ERR_peek_last_error_data(const char **data, int *flags);
unsigned long ossl_ERR_peek_last_error_all(const char **file, int *line,
                                      const char **func,
                                      const char **data, int *flags);
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0
unsigned long ossl_ERR_peek_last_error_line_data(const char **file, int *line,
                                            const char **data, int *flags);
# endif

void ossl_ERR_clear_error(void);

char *ossl_ERR_error_string(unsigned long e, char *buf);
void ossl_ERR_error_string_n(unsigned long e, char *buf, size_t len);
const char *ossl_ERR_lib_error_string(unsigned long e);
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 const char *ossl_ERR_func_error_string(unsigned long e);
# endif
const char *ossl_ERR_reason_error_string(unsigned long e);

void ossl_ERR_print_errors_cb(int (*cb) (const char *str, size_t len, void *u),
                         void *u);
# ifndef ossl_OPENSSL_NO_STDIO
void ossl_ERR_print_errors_fp(FILE *fp);
# endif
void ossl_ERR_print_errors(ossl_BIO *bp);

void ossl_ERR_add_error_data(int num, ...);
void ossl_ERR_add_error_vdata(int num, va_list args);
void ossl_ERR_add_error_txt(const char *sepr, const char *txt);
void ossl_ERR_add_error_mem_bio(const char *sep, ossl_BIO *bio);

int ossl_ERR_load_strings(int lib, ossl_ERR_STRING_DATA *str);
int ossl_ERR_load_strings_const(const ossl_ERR_STRING_DATA *str);
int ossl_ERR_unload_strings(int lib, ossl_ERR_STRING_DATA *str);

#ifndef ossl_OPENSSL_NO_DEPRECATED_1_1_0
# define ossl_ERR_load_crypto_strings() \
    ossl_OPENSSL_init_crypto(ossl_OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL)
# define ossl_ERR_free_strings() while(0) continue
#endif
#ifndef ossl_OPENSSL_NO_DEPRECATED_1_1_0
ossl_OSSL_DEPRECATEDIN_1_1_0 void ossl_ERR_remove_thread_state(void *);
#endif
#ifndef ossl_OPENSSL_NO_DEPRECATED_1_0_0
ossl_OSSL_DEPRECATEDIN_1_0_0 void ossl_ERR_remove_state(unsigned long pid);
#endif
#ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 ossl_ERR_STATE *ossl_ERR_get_state(void);
#endif

int ossl_ERR_get_next_error_library(void);

int ossl_ERR_set_mark(void);
int ossl_ERR_pop_to_mark(void);
int ossl_ERR_clear_last_mark(void);

#ifdef  __cplusplus
}
#endif

#endif
