/*
 * Copyright 2011-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * DTLS code by Eric Rescorla <ekr@rtfm.com>
 *
 * Copyright (C) 2006, Network Resonance, Inc. Copyright (C) 2011, RTFM, Inc.
 */

#ifndef ossl_OPENSSL_SRTP_H
# define ossl_OPENSSL_SRTP_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_D1_SRTP_H
# endif

# include "ossl/openssl/ssl.h"

#ifdef  __cplusplus
extern "C" {
#endif

# define ossl_SRTP_AES128_CM_SHA1_80 0x0001
# define ossl_SRTP_AES128_CM_SHA1_32 0x0002
# define ossl_SRTP_AES128_F8_SHA1_80 0x0003
# define ossl_SRTP_AES128_F8_SHA1_32 0x0004
# define ossl_SRTP_NULL_SHA1_80      0x0005
# define ossl_SRTP_NULL_SHA1_32      0x0006

/* AEAD SRTP protection profiles from RFC 7714 */
# define ossl_SRTP_AEAD_AES_128_GCM  0x0007
# define ossl_SRTP_AEAD_AES_256_GCM  0x0008

# ifndef ossl_OPENSSL_NO_SRTP

ossl___owur int ossl_SSL_CTX_set_tlsext_use_srtp(ossl_SSL_CTX *ctx, const char *profiles);
ossl___owur int ossl_SSL_set_tlsext_use_srtp(ossl_SSL *ssl, const char *profiles);

ossl___owur ossl_STACK_OF(ossl_SRTP_PROTECTION_PROFILE) *ossl_SSL_get_srtp_profiles(ossl_SSL *ssl);
ossl___owur ossl_SRTP_PROTECTION_PROFILE *ossl_SSL_get_selected_srtp_profile(ossl_SSL *s);

# endif

#ifdef  __cplusplus
}
#endif

#endif
