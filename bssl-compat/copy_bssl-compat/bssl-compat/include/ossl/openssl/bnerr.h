/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_BNERR_H
# define ossl_OPENSSL_BNERR_H
# pragma once

# include "ossl/openssl/opensslconf.h"
# include "ossl/openssl/symhacks.h"
# include "ossl/openssl/cryptoerr_legacy.h"



/*
 * BN reason codes.
 */
# define ossl_BN_R_ARG2_LT_ARG3                                100
# define ossl_BN_R_BAD_RECIPROCAL                              101
# define ossl_BN_R_BIGNUM_TOO_LONG                             114
# define ossl_BN_R_BITS_TOO_SMALL                              118
# define ossl_BN_R_CALLED_WITH_EVEN_MODULUS                    102
# define ossl_BN_R_DIV_BY_ZERO                                 103
# define ossl_BN_R_ENCODING_ERROR                              104
# define ossl_BN_R_EXPAND_ON_STATIC_BIGNUM_DATA                105
# define ossl_BN_R_INPUT_NOT_REDUCED                           110
# define ossl_BN_R_INVALID_LENGTH                              106
# define ossl_BN_R_INVALID_RANGE                               115
# define ossl_BN_R_INVALID_SHIFT                               119
# define ossl_BN_R_NOT_A_SQUARE                                111
# define ossl_BN_R_NOT_INITIALIZED                             107
# define ossl_BN_R_NO_INVERSE                                  108
# define ossl_BN_R_NO_PRIME_CANDIDATE                          121
# define ossl_BN_R_NO_SOLUTION                                 116
# define ossl_BN_R_NO_SUITABLE_DIGEST                          120
# define ossl_BN_R_PRIVATE_KEY_TOO_LARGE                       117
# define ossl_BN_R_P_IS_NOT_PRIME                              112
# define ossl_BN_R_TOO_MANY_ITERATIONS                         113
# define ossl_BN_R_TOO_MANY_TEMPORARY_VARIABLES                109

#endif
