/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_PROV_SSL_H
# define ossl_OPENSSL_PROV_SSL_H
# pragma once

# ifdef __cplusplus
extern "C" {
# endif

/* ossl_SSL/TLS related defines useful to providers */

# define ossl_SSL_MAX_MASTER_KEY_LENGTH 48

# define ossl_SSL3_VERSION                    0x0300
# define ossl_TLS1_VERSION                    0x0301
# define ossl_TLS1_1_VERSION                  0x0302
# define ossl_TLS1_2_VERSION                  0x0303
# define ossl_TLS1_3_VERSION                  0x0304
# define ossl_DTLS1_VERSION                   0xFEFF
# define ossl_DTLS1_2_VERSION                 0xFEFD
# define ossl_DTLS1_BAD_VER                   0x0100

# ifdef __cplusplus
}
# endif
#endif /* ossl_OPENSSL_PROV_SSL_H */
