/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_COMP_H
# define ossl_OPENSSL_COMP_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_COMP_H
# endif

# include "ossl/openssl/opensslconf.h"

# ifndef ossl_OPENSSL_NO_COMP
# include "ossl/openssl/crypto.h"
# include "ossl/openssl/comperr.h"
# ifdef  __cplusplus
extern "C" {
# endif



ossl_COMP_CTX *ossl_COMP_CTX_new(ossl_COMP_METHOD *meth);
const ossl_COMP_METHOD *ossl_COMP_CTX_get_method(const ossl_COMP_CTX *ctx);
int ossl_COMP_CTX_get_type(const ossl_COMP_CTX* comp);
int ossl_COMP_get_type(const ossl_COMP_METHOD *meth);
const char *ossl_COMP_get_name(const ossl_COMP_METHOD *meth);
void ossl_COMP_CTX_free(ossl_COMP_CTX *ctx);

int ossl_COMP_compress_block(ossl_COMP_CTX *ctx, unsigned char *out, int olen,
                        unsigned char *in, int ilen);
int ossl_COMP_expand_block(ossl_COMP_CTX *ctx, unsigned char *out, int olen,
                      unsigned char *in, int ilen);

ossl_COMP_METHOD *ossl_COMP_zlib(void);

#ifndef ossl_OPENSSL_NO_DEPRECATED_1_1_0
# define ossl_COMP_zlib_cleanup() while(0) continue
#endif

# ifdef ossl_OPENSSL_BIO_H
#  ifdef ZLIB
const ossl_BIO_METHOD *BIO_f_zlib(void);
#  endif
# endif


#  ifdef  __cplusplus
}
#  endif
# endif
#endif
