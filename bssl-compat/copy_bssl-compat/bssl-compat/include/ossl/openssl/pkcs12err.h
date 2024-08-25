/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_PKCS12ERR_H
# define ossl_OPENSSL_PKCS12ERR_H
# pragma once

# include "ossl/openssl/opensslconf.h"
# include "ossl/openssl/symhacks.h"
# include "ossl/openssl/cryptoerr_legacy.h"



/*
 * ossl_PKCS12 reason codes.
 */
# define ossl_PKCS12_R_CANT_PACK_STRUCTURE                     100
# define ossl_PKCS12_R_CONTENT_TYPE_NOT_DATA                   121
# define ossl_PKCS12_R_DECODE_ERROR                            101
# define ossl_PKCS12_R_ENCODE_ERROR                            102
# define ossl_PKCS12_R_ENCRYPT_ERROR                           103
# define ossl_PKCS12_R_ERROR_SETTING_ENCRYPTED_DATA_TYPE       120
# define ossl_PKCS12_R_INVALID_NULL_ARGUMENT                   104
# define ossl_PKCS12_R_INVALID_NULL_PKCS12_POINTER             105
# define ossl_PKCS12_R_INVALID_TYPE                            112
# define ossl_PKCS12_R_IV_GEN_ERROR                            106
# define ossl_PKCS12_R_KEY_GEN_ERROR                           107
# define ossl_PKCS12_R_MAC_ABSENT                              108
# define ossl_PKCS12_R_MAC_GENERATION_ERROR                    109
# define ossl_PKCS12_R_MAC_SETUP_ERROR                         110
# define ossl_PKCS12_R_MAC_STRING_SET_ERROR                    111
# define ossl_PKCS12_R_MAC_VERIFY_FAILURE                      113
# define ossl_PKCS12_R_PARSE_ERROR                             114
# define ossl_PKCS12_R_PKCS12_CIPHERFINAL_ERROR                116
# define ossl_PKCS12_R_UNKNOWN_DIGEST_ALGORITHM                118
# define ossl_PKCS12_R_UNSUPPORTED_PKCS12_MODE                 119

#endif
