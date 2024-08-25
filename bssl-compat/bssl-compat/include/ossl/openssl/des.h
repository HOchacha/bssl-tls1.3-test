/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_DES_H
# define ossl_OPENSSL_DES_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_DES_H
# endif

# include "ossl/openssl/opensslconf.h"

# ifndef ossl_OPENSSL_NO_DES
#  ifdef  __cplusplus
extern "C" {
#  endif
#  include "ossl/openssl/e_os2.h"

#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
typedef unsigned int ossl_DES_LONG;

#   ifdef ossl_OPENSSL_BUILD_SHLIBCRYPTO
#    undef ossl_OPENSSL_EXTERN
#    define ossl_OPENSSL_EXTERN ossl_OPENSSL_EXPORT
#   endif

typedef unsigned char ossl_DES_cblock[8];
typedef /* const */ unsigned char ossl_const_DES_cblock[8];
/*
 * With "const", gcc 2.8.1 on Solaris thinks that ossl_DES_cblock * and
 * ossl_const_DES_cblock * are incompatible pointer types.
 */

typedef struct ossl_DES_ks {
    union {
        ossl_DES_cblock cblock;
        /*
         * make sure things are correct size on machines with 8 byte longs
         */
        ossl_DES_LONG deslong[2];
    } ks[16];
} ossl_DES_key_schedule;

#   define ossl_DES_KEY_SZ      (sizeof(ossl_DES_cblock))
#   define ossl_DES_SCHEDULE_SZ (sizeof(ossl_DES_key_schedule))

#   define ossl_DES_ENCRYPT     1
#   define ossl_DES_DECRYPT     0

#   define ossl_DES_CBC_MODE    0
#   define ossl_DES_PCBC_MODE   1

#   define ossl_DES_ecb2_encrypt(i,o,k1,k2,e) \
        ossl_DES_ecb3_encrypt((i),(o),(k1),(k2),(k1),(e))

#   define ossl_DES_ede2_cbc_encrypt(i,o,l,k1,k2,iv,e) \
        ossl_DES_ede3_cbc_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(e))

#   define ossl_DES_ede2_cfb64_encrypt(i,o,l,k1,k2,iv,n,e) \
        ossl_DES_ede3_cfb64_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(n),(e))

#   define ossl_DES_ede2_ofb64_encrypt(i,o,l,k1,k2,iv,n) \
        ossl_DES_ede3_ofb64_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(n))

#   define ossl_DES_fixup_key_parity ossl_DES_set_odd_parity
#  endif
#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 const char *ossl_DES_options(void);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_DES_ecb3_encrypt(ossl_const_DES_cblock *input, ossl_DES_cblock *output,
                      ossl_DES_key_schedule *ks1, ossl_DES_key_schedule *ks2,
                      ossl_DES_key_schedule *ks3, int enc);
ossl_OSSL_DEPRECATEDIN_3_0
ossl_DES_LONG ossl_DES_cbc_cksum(const unsigned char *input, ossl_DES_cblock *output,
                       long length, ossl_DES_key_schedule *schedule,
                       ossl_const_DES_cblock *ivec);
#  endif
/* ossl_DES_cbc_encrypt does not update the IV!  Use ossl_DES_ncbc_encrypt instead. */
#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_DES_cbc_encrypt(const unsigned char *input, unsigned char *output,
                     long length, ossl_DES_key_schedule *schedule, ossl_DES_cblock *ivec,
                     int enc);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_DES_ncbc_encrypt(const unsigned char *input, unsigned char *output,
                      long length, ossl_DES_key_schedule *schedule, ossl_DES_cblock *ivec,
                      int enc);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_DES_xcbc_encrypt(const unsigned char *input, unsigned char *output,
                      long length, ossl_DES_key_schedule *schedule, ossl_DES_cblock *ivec,
                      ossl_const_DES_cblock *inw, ossl_const_DES_cblock *outw, int enc);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_DES_cfb_encrypt(const unsigned char *in, unsigned char *out, int numbits,
                     long length, ossl_DES_key_schedule *schedule, ossl_DES_cblock *ivec,
                     int enc);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_DES_ecb_encrypt(ossl_const_DES_cblock *input, ossl_DES_cblock *output,
                     ossl_DES_key_schedule *ks, int enc);
#  endif

/*
 * This is the DES encryption function that gets called by just about every
 * other DES routine in the library.  You should not use this function except
 * to implement 'modes' of DES.  I say this because the functions that call
 * this routine do the conversion from 'char *' to long, and this needs to be
 * done to make sure 'non-aligned' memory access do not occur.  The
 * characters are loaded 'little endian'. Data is a pointer to 2 unsigned
 * long's and ks is the ossl_DES_key_schedule to use.  enc, is non zero specifies
 * encryption, zero if decryption.
 */
#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_DES_encrypt1(ossl_DES_LONG *data, ossl_DES_key_schedule *ks, int enc);
#  endif

/*
 * This functions is the same as ossl_DES_encrypt1() except that the DES initial
 * permutation (IP) and final permutation (FP) have been left out.  As for
 * ossl_DES_encrypt1(), you should not use this function. It is used by the
 * routines in the library that implement triple DES. IP() ossl_DES_encrypt2()
 * ossl_DES_encrypt2() ossl_DES_encrypt2() FP() is the same as ossl_DES_encrypt1()
 * ossl_DES_encrypt1() ossl_DES_encrypt1() except faster :-).
 */
#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_DES_encrypt2(ossl_DES_LONG *data, ossl_DES_key_schedule *ks, int enc);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_DES_encrypt3(ossl_DES_LONG *data, ossl_DES_key_schedule *ks1, ossl_DES_key_schedule *ks2,
                  ossl_DES_key_schedule *ks3);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_DES_decrypt3(ossl_DES_LONG *data, ossl_DES_key_schedule *ks1, ossl_DES_key_schedule *ks2,
                  ossl_DES_key_schedule *ks3);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_DES_ede3_cbc_encrypt(const unsigned char *input, unsigned char *output,
                          long length, ossl_DES_key_schedule *ks1,
                          ossl_DES_key_schedule *ks2, ossl_DES_key_schedule *ks3,
                          ossl_DES_cblock *ivec, int enc);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_DES_ede3_cfb64_encrypt(const unsigned char *in, unsigned char *out,
                            long length, ossl_DES_key_schedule *ks1,
                            ossl_DES_key_schedule *ks2, ossl_DES_key_schedule *ks3,
                            ossl_DES_cblock *ivec, int *num, int enc);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_DES_ede3_cfb_encrypt(const unsigned char *in, unsigned char *out,
                          int numbits, long length, ossl_DES_key_schedule *ks1,
                          ossl_DES_key_schedule *ks2, ossl_DES_key_schedule *ks3,
                          ossl_DES_cblock *ivec, int enc);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_DES_ede3_ofb64_encrypt(const unsigned char *in, unsigned char *out,
                            long length, ossl_DES_key_schedule *ks1,
                            ossl_DES_key_schedule *ks2, ossl_DES_key_schedule *ks3,
                            ossl_DES_cblock *ivec, int *num);
ossl_OSSL_DEPRECATEDIN_3_0
char *ossl_DES_fcrypt(const char *buf, const char *salt, char *ret);
ossl_OSSL_DEPRECATEDIN_3_0
char *ossl_DES_crypt(const char *buf, const char *salt);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_DES_ofb_encrypt(const unsigned char *in, unsigned char *out, int numbits,
                     long length, ossl_DES_key_schedule *schedule, ossl_DES_cblock *ivec);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_DES_pcbc_encrypt(const unsigned char *input, unsigned char *output,
                      long length, ossl_DES_key_schedule *schedule,
                      ossl_DES_cblock *ivec, int enc);
ossl_OSSL_DEPRECATEDIN_3_0
ossl_DES_LONG ossl_DES_quad_cksum(const unsigned char *input, ossl_DES_cblock output[],
                        long length, int out_count, ossl_DES_cblock *seed);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DES_random_key(ossl_DES_cblock *ret);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_DES_set_odd_parity(ossl_DES_cblock *key);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DES_check_key_parity(ossl_const_DES_cblock *key);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_DES_is_weak_key(ossl_const_DES_cblock *key);
#  endif
/*
 * ossl_DES_set_key (= set_key = ossl_DES_key_sched = key_sched) calls
 * ossl_DES_set_key_checked
 */
#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_DES_set_key(ossl_const_DES_cblock *key, ossl_DES_key_schedule *schedule);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_DES_key_sched(ossl_const_DES_cblock *key, ossl_DES_key_schedule *schedule);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_DES_set_key_checked(ossl_const_DES_cblock *key, ossl_DES_key_schedule *schedule);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_DES_set_key_unchecked(ossl_const_DES_cblock *key, ossl_DES_key_schedule *schedule);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_DES_string_to_key(const char *str, ossl_DES_cblock *key);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_DES_string_to_2keys(const char *str, ossl_DES_cblock *key1, ossl_DES_cblock *key2);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_DES_cfb64_encrypt(const unsigned char *in, unsigned char *out,
                       long length, ossl_DES_key_schedule *schedule,
                       ossl_DES_cblock *ivec, int *num, int enc);
ossl_OSSL_DEPRECATEDIN_3_0
void ossl_DES_ofb64_encrypt(const unsigned char *in, unsigned char *out,
                       long length, ossl_DES_key_schedule *schedule,
                       ossl_DES_cblock *ivec, int *num);
#  endif

#  ifdef  __cplusplus
}
#  endif
# endif

#endif
