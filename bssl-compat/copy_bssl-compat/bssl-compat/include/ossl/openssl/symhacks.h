/*
 * Copyright 1999-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_SYMHACKS_H
# define ossl_OPENSSL_SYMHACKS_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_SYMHACKS_H
# endif

# include "ossl/openssl/e_os2.h"

/* Case insensitive linking causes problems.... */
# if defined(ossl_OPENSSL_SYS_VMS)
#  undef ossl_ERR_load_CRYPTO_strings
#  define ossl_ERR_load_CRYPTO_strings                 ERR_load_CRYPTOlib_strings
#  undef ossl_OCSP_crlID_new
#  define ossl_OCSP_crlID_new                          OCSP_crlID2_new

#  undef ossl_d2i_ECPARAMETERS
#  define ossl_d2i_ECPARAMETERS                        ossl_d2i_UC_ECPARAMETERS
#  undef ossl_i2d_ECPARAMETERS
#  define ossl_i2d_ECPARAMETERS                        ossl_i2d_UC_ECPARAMETERS
#  undef ossl_d2i_ECPKPARAMETERS
#  define ossl_d2i_ECPKPARAMETERS                      ossl_d2i_UC_ECPKPARAMETERS
#  undef ossl_i2d_ECPKPARAMETERS
#  define ossl_i2d_ECPKPARAMETERS                      ossl_i2d_UC_ECPKPARAMETERS

# endif

#endif                          /* ! defined HEADER_VMS_IDHACKS_H */
