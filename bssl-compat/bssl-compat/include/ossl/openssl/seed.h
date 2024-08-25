/*
 * Copyright 2007-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Copyright (c) 2007 KISA(Korea Information Security Agency). All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Neither the name of author nor the names of its contributors may
 *    be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef ossl_OPENSSL_SEED_H
# define ossl_OPENSSL_SEED_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_SEED_H
# endif

# include "ossl/openssl/opensslconf.h"

# ifndef ossl_OPENSSL_NO_SEED
#  include "ossl/openssl/e_os2.h"
#  include "ossl/openssl/crypto.h"
#  include <sys/types.h>

#  ifdef  __cplusplus
extern "C" {
#  endif

#  define ossl_SEED_BLOCK_SIZE 16
#  define ossl_SEED_KEY_LENGTH 16

#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
/* look whether we need 'long' to get 32 bits */
#   ifdef ossl_AES_LONG
#    ifndef SEED_LONG
#     define SEED_LONG 1
#    endif
#   endif


typedef struct ossl_seed_key_st {
#   ifdef SEED_LONG
    unsigned long data[32];
#   else
    unsigned int data[32];
#   endif
} ossl_SEED_KEY_SCHEDULE;
#  endif /* ossl_OPENSSL_NO_DEPRECATED_3_0 */
#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_SEED_set_key(const unsigned char rawkey[ossl_SEED_KEY_LENGTH],
                  ossl_SEED_KEY_SCHEDULE *ks);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_SEED_encrypt(const unsigned char s[ossl_SEED_BLOCK_SIZE],
                  unsigned char d[ossl_SEED_BLOCK_SIZE],
                  const ossl_SEED_KEY_SCHEDULE *ks);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_SEED_decrypt(const unsigned char s[ossl_SEED_BLOCK_SIZE],
                  unsigned char d[ossl_SEED_BLOCK_SIZE],
                  const ossl_SEED_KEY_SCHEDULE *ks);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_SEED_ecb_encrypt(const unsigned char *in,
                      unsigned char *out,
                      const ossl_SEED_KEY_SCHEDULE *ks, int enc);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_SEED_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t len,
                      const ossl_SEED_KEY_SCHEDULE *ks,
                      unsigned char ivec[ossl_SEED_BLOCK_SIZE],
                      int enc);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_SEED_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                         size_t len, const ossl_SEED_KEY_SCHEDULE *ks,
                         unsigned char ivec[ossl_SEED_BLOCK_SIZE],
                         int *num, int enc);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_SEED_ofb128_encrypt(const unsigned char *in, unsigned char *out,
                         size_t len, const ossl_SEED_KEY_SCHEDULE *ks,
                         unsigned char ivec[ossl_SEED_BLOCK_SIZE],
                         int *num);
#  endif

#  ifdef  __cplusplus
}
#  endif
# endif

#endif
