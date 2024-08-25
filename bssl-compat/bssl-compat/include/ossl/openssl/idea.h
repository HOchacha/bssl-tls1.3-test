/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_IDEA_H
# define ossl_OPENSSL_IDEA_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_IDEA_H
# endif

# include "ossl/openssl/opensslconf.h"

# ifndef ossl_OPENSSL_NO_IDEA
#  ifdef  __cplusplus
extern "C" {
#  endif

#  define ossl_IDEA_BLOCK      8
#  define ossl_IDEA_KEY_LENGTH 16

#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0

typedef unsigned int ossl_IDEA_INT;

#   define ossl_IDEA_ENCRYPT    1
#   define ossl_IDEA_DECRYPT    0

typedef struct ossl_idea_key_st {
    ossl_IDEA_INT data[9][6];
} ossl_IDEA_KEY_SCHEDULE;
#endif
#ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 const char *ossl_IDEA_options(void);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_IDEA_ecb_encrypt(const unsigned char *in,
                                            unsigned char *out,
                                            ossl_IDEA_KEY_SCHEDULE *ks);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_IDEA_set_encrypt_key(const unsigned char *key,
                                                ossl_IDEA_KEY_SCHEDULE *ks);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_IDEA_set_decrypt_key(ossl_IDEA_KEY_SCHEDULE *ek,
                                                ossl_IDEA_KEY_SCHEDULE *dk);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_IDEA_cbc_encrypt(const unsigned char *in,
                                            unsigned char *out, long length,
                                            ossl_IDEA_KEY_SCHEDULE *ks,
                                            unsigned char *iv, int enc);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_IDEA_cfb64_encrypt(const unsigned char *in,
                                              unsigned char *out, long length,
                                              ossl_IDEA_KEY_SCHEDULE *ks,
                                              unsigned char *iv, int *num,
                                              int enc);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_IDEA_ofb64_encrypt(const unsigned char *in,
                                              unsigned char *out, long length,
                                              ossl_IDEA_KEY_SCHEDULE *ks,
                                              unsigned char *iv, int *num);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_IDEA_encrypt(unsigned long *in,
                                        ossl_IDEA_KEY_SCHEDULE *ks);
#endif

#  ifndef ossl_OPENSSL_NO_DEPRECATED_1_1_0
#   define ossl_idea_options          ossl_IDEA_options
#   define ossl_idea_ecb_encrypt      ossl_IDEA_ecb_encrypt
#   define ossl_idea_set_encrypt_key  ossl_IDEA_set_encrypt_key
#   define ossl_idea_set_decrypt_key  ossl_IDEA_set_decrypt_key
#   define ossl_idea_cbc_encrypt      ossl_IDEA_cbc_encrypt
#   define ossl_idea_cfb64_encrypt    ossl_IDEA_cfb64_encrypt
#   define ossl_idea_ofb64_encrypt    ossl_IDEA_ofb64_encrypt
#   define ossl_idea_encrypt          ossl_IDEA_encrypt
#  endif

#  ifdef  __cplusplus
}
#  endif
# endif

#endif
