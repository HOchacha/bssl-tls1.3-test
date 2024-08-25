/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_SSL3_H
# define ossl_OPENSSL_SSL3_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_SSL3_H
# endif

# include "ossl/openssl/comp.h"
# include "ossl/openssl/buffer.h"
# include "ossl/openssl/evp.h"
# include "ossl/openssl/ssl.h"

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * Signalling cipher suite value from RFC 5746
 * (TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
 */
# define ossl_SSL3_CK_SCSV                            0x030000FF

/*
 * Signalling cipher suite value from draft-ietf-tls-downgrade-scsv-00
 * (TLS_FALLBACK_SCSV)
 */
# define ossl_SSL3_CK_FALLBACK_SCSV                   0x03005600

# define ossl_SSL3_CK_RSA_NULL_MD5                    0x03000001
# define ossl_SSL3_CK_RSA_NULL_SHA                    0x03000002
# define ossl_SSL3_CK_RSA_RC4_40_MD5                  0x03000003
# define ossl_SSL3_CK_RSA_RC4_128_MD5                 0x03000004
# define ossl_SSL3_CK_RSA_RC4_128_SHA                 0x03000005
# define ossl_SSL3_CK_RSA_RC2_40_MD5                  0x03000006
# define ossl_SSL3_CK_RSA_IDEA_128_SHA                0x03000007
# define ossl_SSL3_CK_RSA_DES_40_CBC_SHA              0x03000008
# define ossl_SSL3_CK_RSA_DES_64_CBC_SHA              0x03000009
# define ossl_SSL3_CK_RSA_DES_192_CBC3_SHA            0x0300000A

# define ossl_SSL3_CK_DH_DSS_DES_40_CBC_SHA           0x0300000B
# define ossl_SSL3_CK_DH_DSS_DES_64_CBC_SHA           0x0300000C
# define ossl_SSL3_CK_DH_DSS_DES_192_CBC3_SHA         0x0300000D
# define ossl_SSL3_CK_DH_RSA_DES_40_CBC_SHA           0x0300000E
# define ossl_SSL3_CK_DH_RSA_DES_64_CBC_SHA           0x0300000F
# define ossl_SSL3_CK_DH_RSA_DES_192_CBC3_SHA         0x03000010

# define ossl_SSL3_CK_DHE_DSS_DES_40_CBC_SHA          0x03000011
# define ossl_SSL3_CK_EDH_DSS_DES_40_CBC_SHA          ossl_SSL3_CK_DHE_DSS_DES_40_CBC_SHA
# define ossl_SSL3_CK_DHE_DSS_DES_64_CBC_SHA          0x03000012
# define ossl_SSL3_CK_EDH_DSS_DES_64_CBC_SHA          ossl_SSL3_CK_DHE_DSS_DES_64_CBC_SHA
# define ossl_SSL3_CK_DHE_DSS_DES_192_CBC3_SHA        0x03000013
# define ossl_SSL3_CK_EDH_DSS_DES_192_CBC3_SHA        ossl_SSL3_CK_DHE_DSS_DES_192_CBC3_SHA
# define ossl_SSL3_CK_DHE_RSA_DES_40_CBC_SHA          0x03000014
# define ossl_SSL3_CK_EDH_RSA_DES_40_CBC_SHA          ossl_SSL3_CK_DHE_RSA_DES_40_CBC_SHA
# define ossl_SSL3_CK_DHE_RSA_DES_64_CBC_SHA          0x03000015
# define ossl_SSL3_CK_EDH_RSA_DES_64_CBC_SHA          ossl_SSL3_CK_DHE_RSA_DES_64_CBC_SHA
# define ossl_SSL3_CK_DHE_RSA_DES_192_CBC3_SHA        0x03000016
# define ossl_SSL3_CK_EDH_RSA_DES_192_CBC3_SHA        ossl_SSL3_CK_DHE_RSA_DES_192_CBC3_SHA

# define ossl_SSL3_CK_ADH_RC4_40_MD5                  0x03000017
# define ossl_SSL3_CK_ADH_RC4_128_MD5                 0x03000018
# define ossl_SSL3_CK_ADH_DES_40_CBC_SHA              0x03000019
# define ossl_SSL3_CK_ADH_DES_64_CBC_SHA              0x0300001A
# define ossl_SSL3_CK_ADH_DES_192_CBC_SHA             0x0300001B

/* a bundle of RFC standard cipher names, generated from ssl3_ciphers[] */
# define ossl_SSL3_RFC_RSA_NULL_MD5                   "TLS_RSA_WITH_NULL_MD5"
# define ossl_SSL3_RFC_RSA_NULL_SHA                   "TLS_RSA_WITH_NULL_SHA"
# define ossl_SSL3_RFC_RSA_DES_192_CBC3_SHA           "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
# define ossl_SSL3_RFC_DHE_DSS_DES_192_CBC3_SHA       "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"
# define ossl_SSL3_RFC_DHE_RSA_DES_192_CBC3_SHA       "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
# define ossl_SSL3_RFC_ADH_DES_192_CBC_SHA            "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"
# define ossl_SSL3_RFC_RSA_IDEA_128_SHA               "TLS_RSA_WITH_IDEA_CBC_SHA"
# define ossl_SSL3_RFC_RSA_RC4_128_MD5                "TLS_RSA_WITH_RC4_128_MD5"
# define ossl_SSL3_RFC_RSA_RC4_128_SHA                "TLS_RSA_WITH_RC4_128_SHA"
# define ossl_SSL3_RFC_ADH_RC4_128_MD5                "TLS_DH_anon_WITH_RC4_128_MD5"

# define ossl_SSL3_TXT_RSA_NULL_MD5                   "NULL-ossl_MD5"
# define ossl_SSL3_TXT_RSA_NULL_SHA                   "NULL-SHA"
# define ossl_SSL3_TXT_RSA_RC4_40_MD5                 "EXP-ossl_RC4-ossl_MD5"
# define ossl_SSL3_TXT_RSA_RC4_128_MD5                "ossl_RC4-ossl_MD5"
# define ossl_SSL3_TXT_RSA_RC4_128_SHA                "ossl_RC4-SHA"
# define ossl_SSL3_TXT_RSA_RC2_40_MD5                 "EXP-RC2-CBC-ossl_MD5"
# define ossl_SSL3_TXT_RSA_IDEA_128_SHA               "IDEA-CBC-SHA"
# define ossl_SSL3_TXT_RSA_DES_40_CBC_SHA             "EXP-DES-CBC-SHA"
# define ossl_SSL3_TXT_RSA_DES_64_CBC_SHA             "DES-CBC-SHA"
# define ossl_SSL3_TXT_RSA_DES_192_CBC3_SHA           "DES-CBC3-SHA"

# define ossl_SSL3_TXT_DH_DSS_DES_40_CBC_SHA          "EXP-ossl_DH-DSS-DES-CBC-SHA"
# define ossl_SSL3_TXT_DH_DSS_DES_64_CBC_SHA          "ossl_DH-DSS-DES-CBC-SHA"
# define ossl_SSL3_TXT_DH_DSS_DES_192_CBC3_SHA        "ossl_DH-DSS-DES-CBC3-SHA"
# define ossl_SSL3_TXT_DH_RSA_DES_40_CBC_SHA          "EXP-ossl_DH-ossl_RSA-DES-CBC-SHA"
# define ossl_SSL3_TXT_DH_RSA_DES_64_CBC_SHA          "ossl_DH-ossl_RSA-DES-CBC-SHA"
# define ossl_SSL3_TXT_DH_RSA_DES_192_CBC3_SHA        "ossl_DH-ossl_RSA-DES-CBC3-SHA"

# define ossl_SSL3_TXT_DHE_DSS_DES_40_CBC_SHA         "EXP-DHE-DSS-DES-CBC-SHA"
# define ossl_SSL3_TXT_DHE_DSS_DES_64_CBC_SHA         "DHE-DSS-DES-CBC-SHA"
# define ossl_SSL3_TXT_DHE_DSS_DES_192_CBC3_SHA       "DHE-DSS-DES-CBC3-SHA"
# define ossl_SSL3_TXT_DHE_RSA_DES_40_CBC_SHA         "EXP-DHE-ossl_RSA-DES-CBC-SHA"
# define ossl_SSL3_TXT_DHE_RSA_DES_64_CBC_SHA         "DHE-ossl_RSA-DES-CBC-SHA"
# define ossl_SSL3_TXT_DHE_RSA_DES_192_CBC3_SHA       "DHE-ossl_RSA-DES-CBC3-SHA"

/*
 * This next block of six "EDH" labels is for backward compatibility with
 * older versions of OpenSSL.  New code should use the six "DHE" labels above
 * instead:
 */
# define ossl_SSL3_TXT_EDH_DSS_DES_40_CBC_SHA         "EXP-EDH-DSS-DES-CBC-SHA"
# define ossl_SSL3_TXT_EDH_DSS_DES_64_CBC_SHA         "EDH-DSS-DES-CBC-SHA"
# define ossl_SSL3_TXT_EDH_DSS_DES_192_CBC3_SHA       "EDH-DSS-DES-CBC3-SHA"
# define ossl_SSL3_TXT_EDH_RSA_DES_40_CBC_SHA         "EXP-EDH-ossl_RSA-DES-CBC-SHA"
# define ossl_SSL3_TXT_EDH_RSA_DES_64_CBC_SHA         "EDH-ossl_RSA-DES-CBC-SHA"
# define ossl_SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA       "EDH-ossl_RSA-DES-CBC3-SHA"

# define ossl_SSL3_TXT_ADH_RC4_40_MD5                 "EXP-ADH-ossl_RC4-ossl_MD5"
# define ossl_SSL3_TXT_ADH_RC4_128_MD5                "ADH-ossl_RC4-ossl_MD5"
# define ossl_SSL3_TXT_ADH_DES_40_CBC_SHA             "EXP-ADH-DES-CBC-SHA"
# define ossl_SSL3_TXT_ADH_DES_64_CBC_SHA             "ADH-DES-CBC-SHA"
# define ossl_SSL3_TXT_ADH_DES_192_CBC_SHA            "ADH-DES-CBC3-SHA"

# define ossl_SSL3_SSL_SESSION_ID_LENGTH              32
# define ossl_SSL3_MAX_SSL_SESSION_ID_LENGTH          32

# define ossl_SSL3_MASTER_SECRET_SIZE                 48
# define ossl_SSL3_RANDOM_SIZE                        32
# define ossl_SSL3_SESSION_ID_SIZE                    32
# define ossl_SSL3_RT_HEADER_LENGTH                   5

# define ossl_SSL3_HM_HEADER_LENGTH                  4

# ifndef ossl_SSL3_ALIGN_PAYLOAD
 /*
  * Some will argue that this increases memory footprint, but it's not
  * actually true. Point is that malloc has to return at least 64-bit aligned
  * pointers, meaning that allocating 5 bytes wastes 3 bytes in either case.
  * Suggested pre-gaping simply moves these wasted bytes from the end of
  * allocated region to its front, but makes data payload aligned, which
  * improves performance:-)
  */
#  define ossl_SSL3_ALIGN_PAYLOAD                     8
# else
#  if (ossl_SSL3_ALIGN_PAYLOAD&(ossl_SSL3_ALIGN_PAYLOAD-1))!=0
#   error "insane ossl_SSL3_ALIGN_PAYLOAD"
#   undef ossl_SSL3_ALIGN_PAYLOAD
#  endif
# endif

/*
 * This is the maximum MAC (digest) size used by the ossl_SSL library. Currently
 * maximum of 20 is used by ossl_SHA1, but we reserve for future extension for
 * 512-bit hashes.
 */

# define ossl_SSL3_RT_MAX_MD_SIZE                     64

/*
 * Maximum block size used in all ciphersuites. Currently 16 for AES.
 */

# define ossl_SSL_RT_MAX_CIPHER_BLOCK_SIZE            16

# define ossl_SSL3_RT_MAX_EXTRA                       (16384)

/* Maximum plaintext length: defined by ossl_SSL/TLS standards */
# define ossl_SSL3_RT_MAX_PLAIN_LENGTH                16384
/* Maximum compression overhead: defined by ossl_SSL/TLS standards */
# define ossl_SSL3_RT_MAX_COMPRESSED_OVERHEAD         1024

/*
 * The standards give a maximum encryption overhead of 1024 bytes. In
 * practice the value is lower than this. The overhead is the maximum number
 * of padding bytes (256) plus the mac size.
 */
# define ossl_SSL3_RT_MAX_ENCRYPTED_OVERHEAD        (256 + ossl_SSL3_RT_MAX_MD_SIZE)
# define ossl_SSL3_RT_MAX_TLS13_ENCRYPTED_OVERHEAD  256

/*
 * OpenSSL currently only uses a padding length of at most one block so the
 * send overhead is smaller.
 */

# define ossl_SSL3_RT_SEND_MAX_ENCRYPTED_OVERHEAD \
                        (ossl_SSL_RT_MAX_CIPHER_BLOCK_SIZE + ossl_SSL3_RT_MAX_MD_SIZE)

/* If compression isn't used don't include the compression overhead */

# ifdef ossl_OPENSSL_NO_COMP
#  define ossl_SSL3_RT_MAX_COMPRESSED_LENGTH           ossl_SSL3_RT_MAX_PLAIN_LENGTH
# else
#  define ossl_SSL3_RT_MAX_COMPRESSED_LENGTH   \
            (ossl_SSL3_RT_MAX_PLAIN_LENGTH+ossl_SSL3_RT_MAX_COMPRESSED_OVERHEAD)
# endif
# define ossl_SSL3_RT_MAX_ENCRYPTED_LENGTH    \
            (ossl_SSL3_RT_MAX_ENCRYPTED_OVERHEAD+ossl_SSL3_RT_MAX_COMPRESSED_LENGTH)
# define ossl_SSL3_RT_MAX_TLS13_ENCRYPTED_LENGTH \
            (ossl_SSL3_RT_MAX_PLAIN_LENGTH + ossl_SSL3_RT_MAX_TLS13_ENCRYPTED_OVERHEAD)
# define ossl_SSL3_RT_MAX_PACKET_SIZE         \
            (ossl_SSL3_RT_MAX_ENCRYPTED_LENGTH+ossl_SSL3_RT_HEADER_LENGTH)

# define ossl_SSL3_MD_CLIENT_FINISHED_CONST   "\x43\x4C\x4E\x54"
# define ossl_SSL3_MD_SERVER_FINISHED_CONST   "\x53\x52\x56\x52"

/* ossl_SSL3_VERSION is defined in prov_ssl.h */
# define ossl_SSL3_VERSION_MAJOR              0x03
# define ossl_SSL3_VERSION_MINOR              0x00

# define ossl_SSL3_RT_CHANGE_CIPHER_SPEC      20
# define ossl_SSL3_RT_ALERT                   21
# define ossl_SSL3_RT_HANDSHAKE               22
# define ossl_SSL3_RT_APPLICATION_DATA        23

/* Pseudo content types to indicate additional parameters */
# define ossl_TLS1_RT_CRYPTO                  0x1000
# define ossl_TLS1_RT_CRYPTO_PREMASTER        (ossl_TLS1_RT_CRYPTO | 0x1)
# define ossl_TLS1_RT_CRYPTO_CLIENT_RANDOM    (ossl_TLS1_RT_CRYPTO | 0x2)
# define ossl_TLS1_RT_CRYPTO_SERVER_RANDOM    (ossl_TLS1_RT_CRYPTO | 0x3)
# define ossl_TLS1_RT_CRYPTO_MASTER           (ossl_TLS1_RT_CRYPTO | 0x4)

# define ossl_TLS1_RT_CRYPTO_READ             0x0000
# define ossl_TLS1_RT_CRYPTO_WRITE            0x0100
# define ossl_TLS1_RT_CRYPTO_MAC              (ossl_TLS1_RT_CRYPTO | 0x5)
# define ossl_TLS1_RT_CRYPTO_KEY              (ossl_TLS1_RT_CRYPTO | 0x6)
# define ossl_TLS1_RT_CRYPTO_IV               (ossl_TLS1_RT_CRYPTO | 0x7)
# define ossl_TLS1_RT_CRYPTO_FIXED_IV         (ossl_TLS1_RT_CRYPTO | 0x8)

/* Pseudo content types for ossl_SSL/TLS header info */
# define ossl_SSL3_RT_HEADER                  0x100
# define ossl_SSL3_RT_INNER_CONTENT_TYPE      0x101

# define ossl_SSL3_AL_WARNING                 1
# define ossl_SSL3_AL_FATAL                   2

# define ossl_SSL3_AD_CLOSE_NOTIFY             0
# define ossl_SSL3_AD_UNEXPECTED_MESSAGE      10/* fatal */
# define ossl_SSL3_AD_BAD_RECORD_MAC          20/* fatal */
# define ossl_SSL3_AD_DECOMPRESSION_FAILURE   30/* fatal */
# define ossl_SSL3_AD_HANDSHAKE_FAILURE       40/* fatal */
# define ossl_SSL3_AD_NO_CERTIFICATE          41
# define ossl_SSL3_AD_BAD_CERTIFICATE         42
# define ossl_SSL3_AD_UNSUPPORTED_CERTIFICATE 43
# define ossl_SSL3_AD_CERTIFICATE_REVOKED     44
# define ossl_SSL3_AD_CERTIFICATE_EXPIRED     45
# define ossl_SSL3_AD_CERTIFICATE_UNKNOWN     46
# define ossl_SSL3_AD_ILLEGAL_PARAMETER       47/* fatal */

# define ossl_TLS1_HB_REQUEST         1
# define ossl_TLS1_HB_RESPONSE        2


# define ossl_SSL3_CT_RSA_SIGN                        1
# define ossl_SSL3_CT_DSS_SIGN                        2
# define ossl_SSL3_CT_RSA_FIXED_DH                    3
# define ossl_SSL3_CT_DSS_FIXED_DH                    4
# define ossl_SSL3_CT_RSA_EPHEMERAL_DH                5
# define ossl_SSL3_CT_DSS_EPHEMERAL_DH                6
# define ossl_SSL3_CT_FORTEZZA_DMS                    20
/*
 * ossl_SSL3_CT_NUMBER is used to size arrays and it must be large enough to
 * contain all of the cert types defined for *either* SSLv3 and TLSv1.
 */
# define ossl_SSL3_CT_NUMBER                  12

# if defined(ossl_TLS_CT_NUMBER)
#  if ossl_TLS_CT_NUMBER != ossl_SSL3_CT_NUMBER
#    error "ossl_SSL/TLS CT_NUMBER values do not match"
#  endif
# endif

/* No longer used as of OpenSSL 1.1.1 */
# define ossl_SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS       0x0001

/* Removed from OpenSSL 1.1.0 */
# define ossl_TLS1_FLAGS_TLS_PADDING_BUG              0x0

# define ossl_TLS1_FLAGS_SKIP_CERT_VERIFY             0x0010

/* Set if we encrypt then mac instead of usual mac then encrypt */
# define ossl_TLS1_FLAGS_ENCRYPT_THEN_MAC_READ        0x0100
# define ossl_TLS1_FLAGS_ENCRYPT_THEN_MAC             ossl_TLS1_FLAGS_ENCRYPT_THEN_MAC_READ

/* Set if extended master secret extension received from peer */
# define ossl_TLS1_FLAGS_RECEIVED_EXTMS               0x0200

# define ossl_TLS1_FLAGS_ENCRYPT_THEN_MAC_WRITE       0x0400

# define ossl_TLS1_FLAGS_STATELESS                    0x0800

/* Set if extended master secret extension required on renegotiation */
# define ossl_TLS1_FLAGS_REQUIRED_EXTMS               0x1000

# define ossl_SSL3_MT_HELLO_REQUEST                   0
# define ossl_SSL3_MT_CLIENT_HELLO                    1
# define ossl_SSL3_MT_SERVER_HELLO                    2
# define ossl_SSL3_MT_NEWSESSION_TICKET               4
# define ossl_SSL3_MT_END_OF_EARLY_DATA               5
# define ossl_SSL3_MT_ENCRYPTED_EXTENSIONS            8
# define ossl_SSL3_MT_CERTIFICATE                     11
# define ossl_SSL3_MT_SERVER_KEY_EXCHANGE             12
# define ossl_SSL3_MT_CERTIFICATE_REQUEST             13
# define ossl_SSL3_MT_SERVER_DONE                     14
# define ossl_SSL3_MT_CERTIFICATE_VERIFY              15
# define ossl_SSL3_MT_CLIENT_KEY_EXCHANGE             16
# define ossl_SSL3_MT_FINISHED                        20
# define ossl_SSL3_MT_CERTIFICATE_URL                 21
# define ossl_SSL3_MT_CERTIFICATE_STATUS              22
# define ossl_SSL3_MT_SUPPLEMENTAL_DATA               23
# define ossl_SSL3_MT_KEY_UPDATE                      24
# ifndef ossl_OPENSSL_NO_NEXTPROTONEG
#  define ossl_SSL3_MT_NEXT_PROTO                     67
# endif
# define ossl_SSL3_MT_MESSAGE_HASH                    254
# define ossl_DTLS1_MT_HELLO_VERIFY_REQUEST           3

/* Dummy message type for handling CCS like a normal handshake message */
# define ossl_SSL3_MT_CHANGE_CIPHER_SPEC              0x0101

# define ossl_SSL3_MT_CCS                             1

/* These are used when changing over to a new cipher */
# define ossl_SSL3_CC_READ            0x001
# define ossl_SSL3_CC_WRITE           0x002
# define ossl_SSL3_CC_CLIENT          0x010
# define ossl_SSL3_CC_SERVER          0x020
# define ossl_SSL3_CC_EARLY           0x040
# define ossl_SSL3_CC_HANDSHAKE       0x080
# define ossl_SSL3_CC_APPLICATION     0x100
# define ossl_SSL3_CHANGE_CIPHER_CLIENT_WRITE (ossl_SSL3_CC_CLIENT|ossl_SSL3_CC_WRITE)
# define ossl_SSL3_CHANGE_CIPHER_SERVER_READ  (ossl_SSL3_CC_SERVER|ossl_SSL3_CC_READ)
# define ossl_SSL3_CHANGE_CIPHER_CLIENT_READ  (ossl_SSL3_CC_CLIENT|ossl_SSL3_CC_READ)
# define ossl_SSL3_CHANGE_CIPHER_SERVER_WRITE (ossl_SSL3_CC_SERVER|ossl_SSL3_CC_WRITE)

#ifdef  __cplusplus
}
#endif
#endif
