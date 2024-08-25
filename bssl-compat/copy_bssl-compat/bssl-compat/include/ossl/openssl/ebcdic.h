/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_EBCDIC_H
# define ossl_OPENSSL_EBCDIC_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_EBCDIC_H
# endif

# include <stdlib.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* Avoid name clashes with other applications */
# define ossl_os_toascii   _openssl_os_toascii
# define ossl_os_toebcdic  _openssl_os_toebcdic
# define ossl_ebcdic2ascii ossl__openssl_ebcdic2ascii
# define ossl_ascii2ebcdic ossl__openssl_ascii2ebcdic

extern const unsigned char ossl_os_toascii[256];
extern const unsigned char ossl_os_toebcdic[256];
void *ossl_ebcdic2ascii(void *dest, const void *srce, size_t count);
void *ossl_ascii2ebcdic(void *dest, const void *srce, size_t count);

#ifdef  __cplusplus
}
#endif
#endif
