/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_BN_H
# define ossl_OPENSSL_BN_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_BN_H
# endif

# include "ossl/openssl/e_os2.h"
# ifndef ossl_OPENSSL_NO_STDIO
#  include <stdio.h>
# endif
# include "ossl/openssl/opensslconf.h"
# include "ossl/openssl/types.h"
# include "ossl/openssl/crypto.h"
# include "ossl/openssl/bnerr.h"

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * 64-bit processor with LP64 ABI
 */
# ifdef ossl_SIXTY_FOUR_BIT_LONG
#  define ossl_BN_ULONG        unsigned long
#  define ossl_BN_BYTES        8
# endif

/*
 * 64-bit processor other than LP64 ABI
 */
# ifdef ossl_SIXTY_FOUR_BIT
#  define ossl_BN_ULONG        unsigned long long
#  define ossl_BN_BYTES        8
# endif

# ifdef ossl_THIRTY_TWO_BIT
#  define ossl_BN_ULONG        unsigned int
#  define ossl_BN_BYTES        4
# endif

# define ossl_BN_BITS2       (ossl_BN_BYTES * 8)
# define ossl_BN_BITS        (ossl_BN_BITS2 * 2)
# define ossl_BN_TBIT        ((ossl_BN_ULONG)1 << (ossl_BN_BITS2 - 1))

# define ossl_BN_FLG_MALLOCED         0x01
# define ossl_BN_FLG_STATIC_DATA      0x02

/*
 * avoid leaking exponent information through timing,
 * ossl_BN_mod_exp_mont() will call ossl_BN_mod_exp_mont_consttime,
 * ossl_BN_div() will call BN_div_no_branch,
 * ossl_BN_mod_inverse() will call bn_mod_inverse_no_branch.
 */
# define ossl_BN_FLG_CONSTTIME        0x04
# define ossl_BN_FLG_SECURE           0x08

# ifndef ossl_OPENSSL_NO_DEPRECATED_0_9_8
/* deprecated name for the flag */
#  define ossl_BN_FLG_EXP_CONSTTIME ossl_BN_FLG_CONSTTIME
#  define ossl_BN_FLG_FREE            0x8000 /* used for debugging */
# endif

void ossl_BN_set_flags(ossl_BIGNUM *b, int n);
int ossl_BN_get_flags(const ossl_BIGNUM *b, int n);

/* Values for |top| in ossl_BN_rand() */
#define ossl_BN_RAND_TOP_ANY    -1
#define ossl_BN_RAND_TOP_ONE     0
#define ossl_BN_RAND_TOP_TWO     1

/* Values for |bottom| in ossl_BN_rand() */
#define ossl_BN_RAND_BOTTOM_ANY  0
#define ossl_BN_RAND_BOTTOM_ODD  1

/*
 * get a clone of a ossl_BIGNUM with changed flags, for *temporary* use only (the
 * two BIGNUMs cannot be used in parallel!). Also only for *read only* use. The
 * value |dest| should be a newly allocated ossl_BIGNUM obtained via ossl_BN_new() that
 * has not been otherwise initialised or used.
 */
void ossl_BN_with_flags(ossl_BIGNUM *dest, const ossl_BIGNUM *b, int flags);

/* Wrapper function to make using ossl_BN_GENCB easier */
int ossl_BN_GENCB_call(ossl_BN_GENCB *cb, int a, int b);

ossl_BN_GENCB *ossl_BN_GENCB_new(void);
void ossl_BN_GENCB_free(ossl_BN_GENCB *cb);

/* Populate a ossl_BN_GENCB structure with an "old"-style callback */
void ossl_BN_GENCB_set_old(ossl_BN_GENCB *gencb, void (*callback) (int, int, void *),
                      void *cb_arg);

/* Populate a ossl_BN_GENCB structure with a "new"-style callback */
void ossl_BN_GENCB_set(ossl_BN_GENCB *gencb, int (*callback) (int, int, ossl_BN_GENCB *),
                  void *cb_arg);

void *ossl_BN_GENCB_get_arg(ossl_BN_GENCB *cb);

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_BN_prime_checks 0      /* default: select number of iterations based
                                  * on the size of the number */

/*
 * ossl_BN_prime_checks_for_size() returns the number of Miller-Rabin iterations
 * that will be done for checking that a random number is probably prime. The
 * error rate for accepting a composite number as prime depends on the size of
 * the prime |b|. The error rates used are for calculating an ossl_RSA key with 2 primes,
 * and so the level is what you would expect for a key of double the size of the
 * prime.
 *
 * This table is generated using the algorithm of FIPS PUB 186-4
 * Digital Signature Standard (DSS), section F.1, page 117.
 * (https://dx.doi.org/10.6028/NIST.FIPS.186-4)
 *
 * The following magma script was used to generate the output:
 * securitybits:=125;
 * k:=1024;
 * for t:=1 to 65 do
 *   for M:=3 to Floor(2*Sqrt(k-1)-1) do
 *     S:=0;
 *     // Sum over m
 *     for m:=3 to M do
 *       s:=0;
 *       // Sum over j
 *       for j:=2 to m do
 *         s+:=(RealField(32)!2)^-(j+(k-1)/j);
 *       end for;
 *       S+:=2^(m-(m-1)*t)*s;
 *     end for;
 *     A:=2^(k-2-M*t);
 *     B:=8*(Pi(RealField(32))^2-6)/3*2^(k-2)*S;
 *     pkt:=2.00743*Log(2)*k*2^-k*(A+B);
 *     seclevel:=Floor(-Log(2,pkt));
 *     if seclevel ge securitybits then
 *       printf "k: %5o, security: %o bits  (t: %o, M: %o)\n",k,seclevel,t,M;
 *       break;
 *     end if;
 *   end for;
 *   if seclevel ge securitybits then break; end if;
 * end for;
 *
 * It can be run online at:
 * http://magma.maths.usyd.edu.au/calc
 *
 * And will output:
 * k:  1024, security: 129 bits  (t: 6, M: 23)
 *
 * k is the number of bits of the prime, securitybits is the level we want to
 * reach.
 *
 * prime length | ossl_RSA key size | # MR tests | security level
 * -------------+--------------|------------+---------------
 *  (b) >= 6394 |     >= 12788 |          3 |        256 bit
 *  (b) >= 3747 |     >=  7494 |          3 |        192 bit
 *  (b) >= 1345 |     >=  2690 |          4 |        128 bit
 *  (b) >= 1080 |     >=  2160 |          5 |        128 bit
 *  (b) >=  852 |     >=  1704 |          5 |        112 bit
 *  (b) >=  476 |     >=   952 |          5 |         80 bit
 *  (b) >=  400 |     >=   800 |          6 |         80 bit
 *  (b) >=  347 |     >=   694 |          7 |         80 bit
 *  (b) >=  308 |     >=   616 |          8 |         80 bit
 *  (b) >=   55 |     >=   110 |         27 |         64 bit
 *  (b) >=    6 |     >=    12 |         34 |         64 bit
 */

#  define ossl_BN_prime_checks_for_size(b) ((b) >= 3747 ?  3 : \
                                      (b) >=  1345 ?  4 : \
                                      (b) >=  476 ?  5 : \
                                      (b) >=  400 ?  6 : \
                                      (b) >=  347 ?  7 : \
                                      (b) >=  308 ?  8 : \
                                      (b) >=  55  ? 27 : \
                                      /* b >= 6 */ 34)
# endif

# define ossl_BN_num_bytes(a) ((ossl_BN_num_bits(a)+7)/8)

int ossl_BN_abs_is_word(const ossl_BIGNUM *a, const ossl_BN_ULONG w);
int ossl_BN_is_zero(const ossl_BIGNUM *a);
int ossl_BN_is_one(const ossl_BIGNUM *a);
int ossl_BN_is_word(const ossl_BIGNUM *a, const ossl_BN_ULONG w);
int ossl_BN_is_odd(const ossl_BIGNUM *a);

# define ossl_BN_one(a)       (ossl_BN_set_word((a),1))

void ossl_BN_zero_ex(ossl_BIGNUM *a);

# if ossl_OPENSSL_API_LEVEL > 908
#  define ossl_BN_zero(a)      ossl_BN_zero_ex(a)
# else
#  define ossl_BN_zero(a)      (ossl_BN_set_word((a),0))
# endif

const ossl_BIGNUM *ossl_BN_value_one(void);
char *ossl_BN_options(void);
ossl_BN_CTX *ossl_BN_CTX_new_ex(ossl_OSSL_LIB_CTX *ctx);
ossl_BN_CTX *ossl_BN_CTX_new(void);
ossl_BN_CTX *ossl_BN_CTX_secure_new_ex(ossl_OSSL_LIB_CTX *ctx);
ossl_BN_CTX *ossl_BN_CTX_secure_new(void);
void ossl_BN_CTX_free(ossl_BN_CTX *c);
void ossl_BN_CTX_start(ossl_BN_CTX *ctx);
ossl_BIGNUM *ossl_BN_CTX_get(ossl_BN_CTX *ctx);
void ossl_BN_CTX_end(ossl_BN_CTX *ctx);
int ossl_BN_rand_ex(ossl_BIGNUM *rnd, int bits, int top, int bottom,
               unsigned int strength, ossl_BN_CTX *ctx);
int ossl_BN_rand(ossl_BIGNUM *rnd, int bits, int top, int bottom);
int ossl_BN_priv_rand_ex(ossl_BIGNUM *rnd, int bits, int top, int bottom,
                    unsigned int strength, ossl_BN_CTX *ctx);
int ossl_BN_priv_rand(ossl_BIGNUM *rnd, int bits, int top, int bottom);
int ossl_BN_rand_range_ex(ossl_BIGNUM *r, const ossl_BIGNUM *range, unsigned int strength,
                     ossl_BN_CTX *ctx);
int ossl_BN_rand_range(ossl_BIGNUM *rnd, const ossl_BIGNUM *range);
int ossl_BN_priv_rand_range_ex(ossl_BIGNUM *r, const ossl_BIGNUM *range,
                          unsigned int strength, ossl_BN_CTX *ctx);
int ossl_BN_priv_rand_range(ossl_BIGNUM *rnd, const ossl_BIGNUM *range);
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_BN_pseudo_rand(ossl_BIGNUM *rnd, int bits, int top, int bottom);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_BN_pseudo_rand_range(ossl_BIGNUM *rnd, const ossl_BIGNUM *range);
# endif
int ossl_BN_num_bits(const ossl_BIGNUM *a);
int ossl_BN_num_bits_word(ossl_BN_ULONG l);
int ossl_BN_security_bits(int L, int N);
ossl_BIGNUM *ossl_BN_new(void);
ossl_BIGNUM *ossl_BN_secure_new(void);
void ossl_BN_clear_free(ossl_BIGNUM *a);
ossl_BIGNUM *ossl_BN_copy(ossl_BIGNUM *a, const ossl_BIGNUM *b);
void ossl_BN_swap(ossl_BIGNUM *a, ossl_BIGNUM *b);
ossl_BIGNUM *ossl_BN_bin2bn(const unsigned char *s, int len, ossl_BIGNUM *ret);
int ossl_BN_bn2bin(const ossl_BIGNUM *a, unsigned char *to);
int ossl_BN_bn2binpad(const ossl_BIGNUM *a, unsigned char *to, int tolen);
ossl_BIGNUM *ossl_BN_lebin2bn(const unsigned char *s, int len, ossl_BIGNUM *ret);
int ossl_BN_bn2lebinpad(const ossl_BIGNUM *a, unsigned char *to, int tolen);
ossl_BIGNUM *ossl_BN_native2bn(const unsigned char *s, int len, ossl_BIGNUM *ret);
int ossl_BN_bn2nativepad(const ossl_BIGNUM *a, unsigned char *to, int tolen);
ossl_BIGNUM *ossl_BN_mpi2bn(const unsigned char *s, int len, ossl_BIGNUM *ret);
int ossl_BN_bn2mpi(const ossl_BIGNUM *a, unsigned char *to);
int ossl_BN_sub(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *b);
int ossl_BN_usub(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *b);
int ossl_BN_uadd(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *b);
int ossl_BN_add(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *b);
int ossl_BN_mul(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *b, ossl_BN_CTX *ctx);
int ossl_BN_sqr(ossl_BIGNUM *r, const ossl_BIGNUM *a, ossl_BN_CTX *ctx);
/** ossl_BN_set_negative sets sign of a ossl_BIGNUM
 * \param  b  pointer to the ossl_BIGNUM object
 * \param  n  0 if the ossl_BIGNUM b should be positive and a value != 0 otherwise
 */
void ossl_BN_set_negative(ossl_BIGNUM *b, int n);
/** ossl_BN_is_negative returns 1 if the ossl_BIGNUM is negative
 * \param  b  pointer to the ossl_BIGNUM object
 * \return 1 if a < 0 and 0 otherwise
 */
int ossl_BN_is_negative(const ossl_BIGNUM *b);

int ossl_BN_div(ossl_BIGNUM *dv, ossl_BIGNUM *rem, const ossl_BIGNUM *m, const ossl_BIGNUM *d,
           ossl_BN_CTX *ctx);
# define ossl_BN_mod(rem,m,d,ctx) ossl_BN_div(NULL,(rem),(m),(d),(ctx))
int ossl_BN_nnmod(ossl_BIGNUM *r, const ossl_BIGNUM *m, const ossl_BIGNUM *d, ossl_BN_CTX *ctx);
int ossl_BN_mod_add(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *b, const ossl_BIGNUM *m,
               ossl_BN_CTX *ctx);
int ossl_BN_mod_add_quick(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *b,
                     const ossl_BIGNUM *m);
int ossl_BN_mod_sub(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *b, const ossl_BIGNUM *m,
               ossl_BN_CTX *ctx);
int ossl_BN_mod_sub_quick(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *b,
                     const ossl_BIGNUM *m);
int ossl_BN_mod_mul(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *b, const ossl_BIGNUM *m,
               ossl_BN_CTX *ctx);
int ossl_BN_mod_sqr(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *m, ossl_BN_CTX *ctx);
int ossl_BN_mod_lshift1(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *m, ossl_BN_CTX *ctx);
int ossl_BN_mod_lshift1_quick(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *m);
int ossl_BN_mod_lshift(ossl_BIGNUM *r, const ossl_BIGNUM *a, int n, const ossl_BIGNUM *m,
                  ossl_BN_CTX *ctx);
int ossl_BN_mod_lshift_quick(ossl_BIGNUM *r, const ossl_BIGNUM *a, int n, const ossl_BIGNUM *m);

ossl_BN_ULONG ossl_BN_mod_word(const ossl_BIGNUM *a, ossl_BN_ULONG w);
ossl_BN_ULONG ossl_BN_div_word(ossl_BIGNUM *a, ossl_BN_ULONG w);
int ossl_BN_mul_word(ossl_BIGNUM *a, ossl_BN_ULONG w);
int ossl_BN_add_word(ossl_BIGNUM *a, ossl_BN_ULONG w);
int ossl_BN_sub_word(ossl_BIGNUM *a, ossl_BN_ULONG w);
int ossl_BN_set_word(ossl_BIGNUM *a, ossl_BN_ULONG w);
ossl_BN_ULONG ossl_BN_get_word(const ossl_BIGNUM *a);

int ossl_BN_cmp(const ossl_BIGNUM *a, const ossl_BIGNUM *b);
void ossl_BN_free(ossl_BIGNUM *a);
int ossl_BN_is_bit_set(const ossl_BIGNUM *a, int n);
int ossl_BN_lshift(ossl_BIGNUM *r, const ossl_BIGNUM *a, int n);
int ossl_BN_lshift1(ossl_BIGNUM *r, const ossl_BIGNUM *a);
int ossl_BN_exp(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *p, ossl_BN_CTX *ctx);

int ossl_BN_mod_exp(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *p,
               const ossl_BIGNUM *m, ossl_BN_CTX *ctx);
int ossl_BN_mod_exp_mont(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *p,
                    const ossl_BIGNUM *m, ossl_BN_CTX *ctx, ossl_BN_MONT_CTX *m_ctx);
int ossl_BN_mod_exp_mont_consttime(ossl_BIGNUM *rr, const ossl_BIGNUM *a, const ossl_BIGNUM *p,
                              const ossl_BIGNUM *m, ossl_BN_CTX *ctx,
                              ossl_BN_MONT_CTX *in_mont);
int ossl_BN_mod_exp_mont_word(ossl_BIGNUM *r, ossl_BN_ULONG a, const ossl_BIGNUM *p,
                         const ossl_BIGNUM *m, ossl_BN_CTX *ctx, ossl_BN_MONT_CTX *m_ctx);
int ossl_BN_mod_exp2_mont(ossl_BIGNUM *r, const ossl_BIGNUM *a1, const ossl_BIGNUM *p1,
                     const ossl_BIGNUM *a2, const ossl_BIGNUM *p2, const ossl_BIGNUM *m,
                     ossl_BN_CTX *ctx, ossl_BN_MONT_CTX *m_ctx);
int ossl_BN_mod_exp_simple(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *p,
                      const ossl_BIGNUM *m, ossl_BN_CTX *ctx);
int ossl_BN_mod_exp_mont_consttime_x2(ossl_BIGNUM *rr1, const ossl_BIGNUM *a1, const ossl_BIGNUM *p1,
                                 const ossl_BIGNUM *m1, ossl_BN_MONT_CTX *in_mont1,
                                 ossl_BIGNUM *rr2, const ossl_BIGNUM *a2, const ossl_BIGNUM *p2,
                                 const ossl_BIGNUM *m2, ossl_BN_MONT_CTX *in_mont2,
                                 ossl_BN_CTX *ctx);

int ossl_BN_mask_bits(ossl_BIGNUM *a, int n);
# ifndef ossl_OPENSSL_NO_STDIO
int ossl_BN_print_fp(FILE *fp, const ossl_BIGNUM *a);
# endif
int ossl_BN_print(ossl_BIO *bio, const ossl_BIGNUM *a);
int ossl_BN_reciprocal(ossl_BIGNUM *r, const ossl_BIGNUM *m, int len, ossl_BN_CTX *ctx);
int ossl_BN_rshift(ossl_BIGNUM *r, const ossl_BIGNUM *a, int n);
int ossl_BN_rshift1(ossl_BIGNUM *r, const ossl_BIGNUM *a);
void ossl_BN_clear(ossl_BIGNUM *a);
ossl_BIGNUM *ossl_BN_dup(const ossl_BIGNUM *a);
int ossl_BN_ucmp(const ossl_BIGNUM *a, const ossl_BIGNUM *b);
int ossl_BN_set_bit(ossl_BIGNUM *a, int n);
int ossl_BN_clear_bit(ossl_BIGNUM *a, int n);
char *ossl_BN_bn2hex(const ossl_BIGNUM *a);
char *ossl_BN_bn2dec(const ossl_BIGNUM *a);
int ossl_BN_hex2bn(ossl_BIGNUM **a, const char *str);
int ossl_BN_dec2bn(ossl_BIGNUM **a, const char *str);
int ossl_BN_asc2bn(ossl_BIGNUM **a, const char *str);
int ossl_BN_gcd(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *b, ossl_BN_CTX *ctx);
int ossl_BN_kronecker(const ossl_BIGNUM *a, const ossl_BIGNUM *b, ossl_BN_CTX *ctx); /* returns
                                                                  * -2 for
                                                                  * error */
ossl_BIGNUM *ossl_BN_mod_inverse(ossl_BIGNUM *ret,
                       const ossl_BIGNUM *a, const ossl_BIGNUM *n, ossl_BN_CTX *ctx);
ossl_BIGNUM *ossl_BN_mod_sqrt(ossl_BIGNUM *ret,
                    const ossl_BIGNUM *a, const ossl_BIGNUM *n, ossl_BN_CTX *ctx);

void ossl_BN_consttime_swap(ossl_BN_ULONG swap, ossl_BIGNUM *a, ossl_BIGNUM *b, int nwords);

/* Deprecated versions */
# ifndef ossl_OPENSSL_NO_DEPRECATED_0_9_8
ossl_OSSL_DEPRECATEDIN_0_9_8
ossl_BIGNUM *ossl_BN_generate_prime(ossl_BIGNUM *ret, int bits, int safe,
                          const ossl_BIGNUM *add, const ossl_BIGNUM *rem,
                          void (*callback) (int, int, void *),
                          void *cb_arg);
ossl_OSSL_DEPRECATEDIN_0_9_8
int ossl_BN_is_prime(const ossl_BIGNUM *p, int nchecks,
                void (*callback) (int, int, void *),
                ossl_BN_CTX *ctx, void *cb_arg);
ossl_OSSL_DEPRECATEDIN_0_9_8
int ossl_BN_is_prime_fasttest(const ossl_BIGNUM *p, int nchecks,
                         void (*callback) (int, int, void *),
                         ossl_BN_CTX *ctx, void *cb_arg,
                         int do_trial_division);
# endif
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_BN_is_prime_ex(const ossl_BIGNUM *p, int nchecks, ossl_BN_CTX *ctx, ossl_BN_GENCB *cb);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_BN_is_prime_fasttest_ex(const ossl_BIGNUM *p, int nchecks, ossl_BN_CTX *ctx,
                            int do_trial_division, ossl_BN_GENCB *cb);
# endif
/* Newer versions */
int ossl_BN_generate_prime_ex2(ossl_BIGNUM *ret, int bits, int safe,
                          const ossl_BIGNUM *add, const ossl_BIGNUM *rem, ossl_BN_GENCB *cb,
                          ossl_BN_CTX *ctx);
int ossl_BN_generate_prime_ex(ossl_BIGNUM *ret, int bits, int safe, const ossl_BIGNUM *add,
                         const ossl_BIGNUM *rem, ossl_BN_GENCB *cb);
int ossl_BN_check_prime(const ossl_BIGNUM *p, ossl_BN_CTX *ctx, ossl_BN_GENCB *cb);

# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_BN_X931_generate_Xpq(ossl_BIGNUM *Xp, ossl_BIGNUM *Xq, int nbits, ossl_BN_CTX *ctx);

ossl_OSSL_DEPRECATEDIN_3_0
int ossl_BN_X931_derive_prime_ex(ossl_BIGNUM *p, ossl_BIGNUM *p1, ossl_BIGNUM *p2,
                            const ossl_BIGNUM *Xp, const ossl_BIGNUM *Xp1,
                            const ossl_BIGNUM *Xp2, const ossl_BIGNUM *e, ossl_BN_CTX *ctx,
                            ossl_BN_GENCB *cb);
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_BN_X931_generate_prime_ex(ossl_BIGNUM *p, ossl_BIGNUM *p1, ossl_BIGNUM *p2, ossl_BIGNUM *Xp1,
                              ossl_BIGNUM *Xp2, const ossl_BIGNUM *Xp, const ossl_BIGNUM *e,
                              ossl_BN_CTX *ctx, ossl_BN_GENCB *cb);
# endif

ossl_BN_MONT_CTX *ossl_BN_MONT_CTX_new(void);
int ossl_BN_mod_mul_montgomery(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *b,
                          ossl_BN_MONT_CTX *mont, ossl_BN_CTX *ctx);
int ossl_BN_to_montgomery(ossl_BIGNUM *r, const ossl_BIGNUM *a, ossl_BN_MONT_CTX *mont,
                     ossl_BN_CTX *ctx);
int ossl_BN_from_montgomery(ossl_BIGNUM *r, const ossl_BIGNUM *a, ossl_BN_MONT_CTX *mont,
                       ossl_BN_CTX *ctx);
void ossl_BN_MONT_CTX_free(ossl_BN_MONT_CTX *mont);
int ossl_BN_MONT_CTX_set(ossl_BN_MONT_CTX *mont, const ossl_BIGNUM *mod, ossl_BN_CTX *ctx);
ossl_BN_MONT_CTX *ossl_BN_MONT_CTX_copy(ossl_BN_MONT_CTX *to, ossl_BN_MONT_CTX *from);
ossl_BN_MONT_CTX *ossl_BN_MONT_CTX_set_locked(ossl_BN_MONT_CTX **pmont, ossl_CRYPTO_RWLOCK *lock,
                                    const ossl_BIGNUM *mod, ossl_BN_CTX *ctx);

/* ossl_BN_BLINDING flags */
# define ossl_BN_BLINDING_NO_UPDATE   0x00000001
# define ossl_BN_BLINDING_NO_RECREATE 0x00000002

ossl_BN_BLINDING *ossl_BN_BLINDING_new(const ossl_BIGNUM *A, const ossl_BIGNUM *Ai, ossl_BIGNUM *mod);
void ossl_BN_BLINDING_free(ossl_BN_BLINDING *b);
int ossl_BN_BLINDING_update(ossl_BN_BLINDING *b, ossl_BN_CTX *ctx);
int ossl_BN_BLINDING_convert(ossl_BIGNUM *n, ossl_BN_BLINDING *b, ossl_BN_CTX *ctx);
int ossl_BN_BLINDING_invert(ossl_BIGNUM *n, ossl_BN_BLINDING *b, ossl_BN_CTX *ctx);
int ossl_BN_BLINDING_convert_ex(ossl_BIGNUM *n, ossl_BIGNUM *r, ossl_BN_BLINDING *b, ossl_BN_CTX *);
int ossl_BN_BLINDING_invert_ex(ossl_BIGNUM *n, const ossl_BIGNUM *r, ossl_BN_BLINDING *b,
                          ossl_BN_CTX *);

int ossl_BN_BLINDING_is_current_thread(ossl_BN_BLINDING *b);
void ossl_BN_BLINDING_set_current_thread(ossl_BN_BLINDING *b);
int ossl_BN_BLINDING_lock(ossl_BN_BLINDING *b);
int ossl_BN_BLINDING_unlock(ossl_BN_BLINDING *b);

unsigned long ossl_BN_BLINDING_get_flags(const ossl_BN_BLINDING *);
void ossl_BN_BLINDING_set_flags(ossl_BN_BLINDING *, unsigned long);
ossl_BN_BLINDING *ossl_BN_BLINDING_create_param(ossl_BN_BLINDING *b,
                                      const ossl_BIGNUM *e, ossl_BIGNUM *m, ossl_BN_CTX *ctx,
                                      int (*bn_mod_exp) (ossl_BIGNUM *r,
                                                         const ossl_BIGNUM *a,
                                                         const ossl_BIGNUM *p,
                                                         const ossl_BIGNUM *m,
                                                         ossl_BN_CTX *ctx,
                                                         ossl_BN_MONT_CTX *m_ctx),
                                      ossl_BN_MONT_CTX *m_ctx);
# ifndef ossl_OPENSSL_NO_DEPRECATED_0_9_8
ossl_OSSL_DEPRECATEDIN_0_9_8
void ossl_BN_set_params(int mul, int high, int low, int mont);
ossl_OSSL_DEPRECATEDIN_0_9_8
int ossl_BN_get_params(int which); /* 0, mul, 1 high, 2 low, 3 mont */
# endif

ossl_BN_RECP_CTX *ossl_BN_RECP_CTX_new(void);
void ossl_BN_RECP_CTX_free(ossl_BN_RECP_CTX *recp);
int ossl_BN_RECP_CTX_set(ossl_BN_RECP_CTX *recp, const ossl_BIGNUM *rdiv, ossl_BN_CTX *ctx);
int ossl_BN_mod_mul_reciprocal(ossl_BIGNUM *r, const ossl_BIGNUM *x, const ossl_BIGNUM *y,
                          ossl_BN_RECP_CTX *recp, ossl_BN_CTX *ctx);
int ossl_BN_mod_exp_recp(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *p,
                    const ossl_BIGNUM *m, ossl_BN_CTX *ctx);
int ossl_BN_div_recp(ossl_BIGNUM *dv, ossl_BIGNUM *rem, const ossl_BIGNUM *m,
                ossl_BN_RECP_CTX *recp, ossl_BN_CTX *ctx);

# ifndef ossl_OPENSSL_NO_EC2M

/*
 * Functions for arithmetic over binary polynomials represented by BIGNUMs.
 * The ossl_BIGNUM::neg property of BIGNUMs representing binary polynomials is
 * ignored. Note that input arguments are not const so that their bit arrays
 * can be expanded to the appropriate size if needed.
 */

/*
 * r = a + b
 */
int ossl_BN_GF2m_add(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *b);
#  define ossl_BN_GF2m_sub(r, a, b) ossl_BN_GF2m_add(r, a, b)
/*
 * r=a mod p
 */
int ossl_BN_GF2m_mod(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *p);
/* r = (a * b) mod p */
int ossl_BN_GF2m_mod_mul(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *b,
                    const ossl_BIGNUM *p, ossl_BN_CTX *ctx);
/* r = (a * a) mod p */
int ossl_BN_GF2m_mod_sqr(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *p, ossl_BN_CTX *ctx);
/* r = (1 / b) mod p */
int ossl_BN_GF2m_mod_inv(ossl_BIGNUM *r, const ossl_BIGNUM *b, const ossl_BIGNUM *p, ossl_BN_CTX *ctx);
/* r = (a / b) mod p */
int ossl_BN_GF2m_mod_div(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *b,
                    const ossl_BIGNUM *p, ossl_BN_CTX *ctx);
/* r = (a ^ b) mod p */
int ossl_BN_GF2m_mod_exp(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *b,
                    const ossl_BIGNUM *p, ossl_BN_CTX *ctx);
/* r = sqrt(a) mod p */
int ossl_BN_GF2m_mod_sqrt(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *p,
                     ossl_BN_CTX *ctx);
/* r^2 + r = a mod p */
int ossl_BN_GF2m_mod_solve_quad(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *p,
                           ossl_BN_CTX *ctx);
#  define ossl_BN_GF2m_cmp(a, b) ossl_BN_ucmp((a), (b))
/*-
 * Some functions allow for representation of the irreducible polynomials
 * as an unsigned int[], say p.  The irreducible f(t) is then of the form:
 *     t^p[0] + t^p[1] + ... + t^p[k]
 * where m = p[0] > p[1] > ... > p[k] = 0.
 */
/* r = a mod p */
int ossl_BN_GF2m_mod_arr(ossl_BIGNUM *r, const ossl_BIGNUM *a, const int p[]);
/* r = (a * b) mod p */
int ossl_BN_GF2m_mod_mul_arr(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *b,
                        const int p[], ossl_BN_CTX *ctx);
/* r = (a * a) mod p */
int ossl_BN_GF2m_mod_sqr_arr(ossl_BIGNUM *r, const ossl_BIGNUM *a, const int p[],
                        ossl_BN_CTX *ctx);
/* r = (1 / b) mod p */
int ossl_BN_GF2m_mod_inv_arr(ossl_BIGNUM *r, const ossl_BIGNUM *b, const int p[],
                        ossl_BN_CTX *ctx);
/* r = (a / b) mod p */
int ossl_BN_GF2m_mod_div_arr(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *b,
                        const int p[], ossl_BN_CTX *ctx);
/* r = (a ^ b) mod p */
int ossl_BN_GF2m_mod_exp_arr(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *b,
                        const int p[], ossl_BN_CTX *ctx);
/* r = sqrt(a) mod p */
int ossl_BN_GF2m_mod_sqrt_arr(ossl_BIGNUM *r, const ossl_BIGNUM *a,
                         const int p[], ossl_BN_CTX *ctx);
/* r^2 + r = a mod p */
int ossl_BN_GF2m_mod_solve_quad_arr(ossl_BIGNUM *r, const ossl_BIGNUM *a,
                               const int p[], ossl_BN_CTX *ctx);
int ossl_BN_GF2m_poly2arr(const ossl_BIGNUM *a, int p[], int max);
int ossl_BN_GF2m_arr2poly(const int p[], ossl_BIGNUM *a);

# endif

/*
 * faster mod functions for the 'NIST primes' 0 <= a < p^2
 */
int ossl_BN_nist_mod_192(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *p, ossl_BN_CTX *ctx);
int ossl_BN_nist_mod_224(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *p, ossl_BN_CTX *ctx);
int ossl_BN_nist_mod_256(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *p, ossl_BN_CTX *ctx);
int ossl_BN_nist_mod_384(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *p, ossl_BN_CTX *ctx);
int ossl_BN_nist_mod_521(ossl_BIGNUM *r, const ossl_BIGNUM *a, const ossl_BIGNUM *p, ossl_BN_CTX *ctx);

const ossl_BIGNUM *ossl_BN_get0_nist_prime_192(void);
const ossl_BIGNUM *ossl_BN_get0_nist_prime_224(void);
const ossl_BIGNUM *ossl_BN_get0_nist_prime_256(void);
const ossl_BIGNUM *ossl_BN_get0_nist_prime_384(void);
const ossl_BIGNUM *ossl_BN_get0_nist_prime_521(void);

int (*ossl_BN_nist_mod_func(const ossl_BIGNUM *p)) (ossl_BIGNUM *r, const ossl_BIGNUM *a,
                                          const ossl_BIGNUM *field, ossl_BN_CTX *ctx);

int ossl_BN_generate_dsa_nonce(ossl_BIGNUM *out, const ossl_BIGNUM *range,
                          const ossl_BIGNUM *priv, const unsigned char *message,
                          size_t message_len, ossl_BN_CTX *ctx);

/* Primes from RFC 2409 */
ossl_BIGNUM *ossl_BN_get_rfc2409_prime_768(ossl_BIGNUM *bn);
ossl_BIGNUM *ossl_BN_get_rfc2409_prime_1024(ossl_BIGNUM *bn);

/* Primes from RFC 3526 */
ossl_BIGNUM *ossl_BN_get_rfc3526_prime_1536(ossl_BIGNUM *bn);
ossl_BIGNUM *ossl_BN_get_rfc3526_prime_2048(ossl_BIGNUM *bn);
ossl_BIGNUM *ossl_BN_get_rfc3526_prime_3072(ossl_BIGNUM *bn);
ossl_BIGNUM *ossl_BN_get_rfc3526_prime_4096(ossl_BIGNUM *bn);
ossl_BIGNUM *ossl_BN_get_rfc3526_prime_6144(ossl_BIGNUM *bn);
ossl_BIGNUM *ossl_BN_get_rfc3526_prime_8192(ossl_BIGNUM *bn);

#  ifndef ossl_OPENSSL_NO_DEPRECATED_1_1_0
#   define ossl_get_rfc2409_prime_768 ossl_BN_get_rfc2409_prime_768
#   define ossl_get_rfc2409_prime_1024 ossl_BN_get_rfc2409_prime_1024
#   define ossl_get_rfc3526_prime_1536 ossl_BN_get_rfc3526_prime_1536
#   define ossl_get_rfc3526_prime_2048 ossl_BN_get_rfc3526_prime_2048
#   define ossl_get_rfc3526_prime_3072 ossl_BN_get_rfc3526_prime_3072
#   define ossl_get_rfc3526_prime_4096 ossl_BN_get_rfc3526_prime_4096
#   define ossl_get_rfc3526_prime_6144 ossl_BN_get_rfc3526_prime_6144
#   define ossl_get_rfc3526_prime_8192 ossl_BN_get_rfc3526_prime_8192
#  endif

int ossl_BN_bntest_rand(ossl_BIGNUM *rnd, int bits, int top, int bottom);


# ifdef  __cplusplus
}
# endif
#endif
