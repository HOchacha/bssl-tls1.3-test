/*
 * Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_CORE_OBJECT_H
# define ossl_OPENSSL_CORE_OBJECT_H
# pragma once

# ifdef __cplusplus
extern "C" {
# endif

/*-
 * Known object types
 *
 * These numbers are used as values for the ossl_OSSL_PARAM parameter
 * ossl_OSSL_OBJECT_PARAM_TYPE.
 *
 * For most of these types, there's a corresponding libcrypto object type.
 * The corresponding type is indicated with a comment after the number.
 */
# define ossl_OSSL_OBJECT_UNKNOWN            0
# define ossl_OSSL_OBJECT_NAME               1 /* char * */
# define ossl_OSSL_OBJECT_PKEY               2 /* ossl_EVP_PKEY * */
# define ossl_OSSL_OBJECT_CERT               3 /* ossl_X509 * */
# define ossl_OSSL_OBJECT_CRL                4 /* ossl_X509_CRL * */

/*
 * The rest of the associated ossl_OSSL_PARAM elements is described in core_names.h
 */

# ifdef __cplusplus
}
# endif

#endif
