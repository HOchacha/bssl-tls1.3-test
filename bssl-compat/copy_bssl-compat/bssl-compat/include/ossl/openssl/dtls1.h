/*
 * Copyright 2005-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_DTLS1_H
# define ossl_OPENSSL_DTLS1_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_DTLS1_H
# endif

# include "ossl/openssl/prov_ssl.h"

#ifdef  __cplusplus
extern "C" {
#endif

#include "ossl/openssl/opensslconf.h"

/* DTLS*_VERSION constants are defined in prov_ssl.h */
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_DTLS_MIN_VERSION                ossl_DTLS1_VERSION
#  define ossl_DTLS_MAX_VERSION                ossl_DTLS1_2_VERSION
# endif
# define ossl_DTLS1_VERSION_MAJOR             0xFE

/* Special value for method supporting multiple versions */
# define ossl_DTLS_ANY_VERSION                0x1FFFF

/* lengths of messages */

# define ossl_DTLS1_COOKIE_LENGTH                     255

# define ossl_DTLS1_RT_HEADER_LENGTH                  13

# define ossl_DTLS1_HM_HEADER_LENGTH                  12

# define ossl_DTLS1_HM_BAD_FRAGMENT                   -2
# define ossl_DTLS1_HM_FRAGMENT_RETRY                 -3

# define ossl_DTLS1_CCS_HEADER_LENGTH                  1

# define ossl_DTLS1_AL_HEADER_LENGTH                   2

# define ossl_DTLS1_TMO_ALERT_COUNT                     12

#ifdef  __cplusplus
}
#endif
#endif
