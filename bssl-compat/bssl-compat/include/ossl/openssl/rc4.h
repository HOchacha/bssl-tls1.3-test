/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_RC4_H
# define ossl_OPENSSL_RC4_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_RC4_H
# endif

# include "ossl/openssl/opensslconf.h"

# ifndef ossl_OPENSSL_NO_RC4
#  include <stddef.h>
#  ifdef  __cplusplus
extern "C" {
#  endif

#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
typedef struct ossl_rc4_key_st {
    ossl_RC4_INT x, y;
    ossl_RC4_INT data[256];
} ossl_RC4_KEY;
#  endif
#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 const char *ossl_RC4_options(void);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_RC4_set_key(ossl_RC4_KEY *key, int len,
                                       const unsigned char *data);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_RC4(ossl_RC4_KEY *key, size_t len,
                               const unsigned char *indata,
                               unsigned char *outdata);
#  endif

#  ifdef  __cplusplus
}
#  endif
# endif

#endif
