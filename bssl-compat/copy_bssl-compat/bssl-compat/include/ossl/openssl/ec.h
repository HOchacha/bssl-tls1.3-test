/*
 * Copyright 2002-2022 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_EC_H
# define ossl_OPENSSL_EC_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_EC_H
# endif

# include "ossl/openssl/opensslconf.h"
# include "ossl/openssl/types.h"

# include <string.h>

# ifdef  __cplusplus
extern "C" {
# endif

/* Values for ossl_EVP_PKEY_CTX_set_ec_param_enc() */
# define ossl_OPENSSL_EC_EXPLICIT_CURVE  0x000
# define ossl_OPENSSL_EC_NAMED_CURVE     0x001

int ossl_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ossl_EVP_PKEY_CTX *ctx, int nid);
int ossl_EVP_PKEY_CTX_set_ec_param_enc(ossl_EVP_PKEY_CTX *ctx, int param_enc);
int ossl_EVP_PKEY_CTX_set_ecdh_cofactor_mode(ossl_EVP_PKEY_CTX *ctx, int cofactor_mode);
int ossl_EVP_PKEY_CTX_get_ecdh_cofactor_mode(ossl_EVP_PKEY_CTX *ctx);

int ossl_EVP_PKEY_CTX_set_ecdh_kdf_type(ossl_EVP_PKEY_CTX *ctx, int kdf);
int ossl_EVP_PKEY_CTX_get_ecdh_kdf_type(ossl_EVP_PKEY_CTX *ctx);

int ossl_EVP_PKEY_CTX_set_ecdh_kdf_md(ossl_EVP_PKEY_CTX *ctx, const ossl_EVP_MD *md);
int ossl_EVP_PKEY_CTX_get_ecdh_kdf_md(ossl_EVP_PKEY_CTX *ctx, const ossl_EVP_MD **md);

int ossl_EVP_PKEY_CTX_set_ecdh_kdf_outlen(ossl_EVP_PKEY_CTX *ctx, int len);
int ossl_EVP_PKEY_CTX_get_ecdh_kdf_outlen(ossl_EVP_PKEY_CTX *ctx, int *len);

int ossl_EVP_PKEY_CTX_set0_ecdh_kdf_ukm(ossl_EVP_PKEY_CTX *ctx, unsigned char *ukm,
                                   int len);
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0
int ossl_EVP_PKEY_CTX_get0_ecdh_kdf_ukm(ossl_EVP_PKEY_CTX *ctx, unsigned char **ukm);
# endif

# define ossl_EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID    (ossl_EVP_PKEY_ALG_CTRL + 1)
# define ossl_EVP_PKEY_CTRL_EC_PARAM_ENC             (ossl_EVP_PKEY_ALG_CTRL + 2)
# define ossl_EVP_PKEY_CTRL_EC_ECDH_COFACTOR         (ossl_EVP_PKEY_ALG_CTRL + 3)
# define ossl_EVP_PKEY_CTRL_EC_KDF_TYPE              (ossl_EVP_PKEY_ALG_CTRL + 4)
# define ossl_EVP_PKEY_CTRL_EC_KDF_MD                (ossl_EVP_PKEY_ALG_CTRL + 5)
# define ossl_EVP_PKEY_CTRL_GET_EC_KDF_MD            (ossl_EVP_PKEY_ALG_CTRL + 6)
# define ossl_EVP_PKEY_CTRL_EC_KDF_OUTLEN            (ossl_EVP_PKEY_ALG_CTRL + 7)
# define ossl_EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN        (ossl_EVP_PKEY_ALG_CTRL + 8)
# define ossl_EVP_PKEY_CTRL_EC_KDF_UKM               (ossl_EVP_PKEY_ALG_CTRL + 9)
# define ossl_EVP_PKEY_CTRL_GET_EC_KDF_UKM           (ossl_EVP_PKEY_ALG_CTRL + 10)

/* KDF types */
# define ossl_EVP_PKEY_ECDH_KDF_NONE                      1
# define ossl_EVP_PKEY_ECDH_KDF_X9_63                     2
/*
 * The old name for ossl_EVP_PKEY_ECDH_KDF_X9_63
 *  The ECDH KDF specification has been mistakenly attributed to ANSI X9.62,
 *  it is actually specified in ANSI X9.63.
 *  This identifier is retained for backwards compatibility
 */
# define ossl_EVP_PKEY_ECDH_KDF_X9_62   ossl_EVP_PKEY_ECDH_KDF_X9_63

/** Enum for the point conversion form as defined in X9.62 (ECDSA)
 *  for the encoding of a elliptic curve point (x,y) */
typedef enum {
        /** the point is encoded as z||x, where the octet z specifies
         *  which solution of the quadratic equation y is  */
    ossl_POINT_CONVERSION_COMPRESSED = 2,
        /** the point is encoded as z||x||y, where z is the octet 0x04  */
    ossl_POINT_CONVERSION_UNCOMPRESSED = 4,
        /** the point is encoded as z||x||y, where the octet z specifies
         *  which solution of the quadratic equation y is  */
    ossl_POINT_CONVERSION_HYBRID = 6
} ossl_point_conversion_form_t;

const char *ossl_OSSL_EC_curve_nid2name(int nid);

# ifndef ossl_OPENSSL_NO_EC
#  include "ossl/openssl/asn1.h"
#  include "ossl/openssl/symhacks.h"
#  ifndef ossl_OPENSSL_NO_DEPRECATED_1_1_0
#   include "ossl/openssl/bn.h"
#  endif
#  include "ossl/openssl/ecerr.h"

#  ifndef ossl_OPENSSL_ECC_MAX_FIELD_BITS
#   define ossl_OPENSSL_ECC_MAX_FIELD_BITS 661
#  endif

#  include "ossl/openssl/params.h"
#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
typedef struct ossl_ec_method_st ossl_EC_METHOD;
#  endif
typedef struct ossl_ec_group_st ossl_EC_GROUP;
typedef struct ossl_ec_point_st ossl_EC_POINT;
typedef struct ossl_ecpk_parameters_st ossl_ECPKPARAMETERS;
typedef struct ossl_ec_parameters_st ossl_ECPARAMETERS;

/********************************************************************/
/*               EC_METHODs for curves over GF(p)                   */
/********************************************************************/

#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
/** Returns the basic GFp ec methods which provides the basis for the
 *  optimized methods.
 *  \return  ossl_EC_METHOD object
 */
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_EC_METHOD *ossl_EC_GFp_simple_method(void);

/** Returns GFp methods using montgomery multiplication.
 *  \return  ossl_EC_METHOD object
 */
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_EC_METHOD *ossl_EC_GFp_mont_method(void);

/** Returns GFp methods using optimized methods for NIST recommended curves
 *  \return  ossl_EC_METHOD object
 */
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_EC_METHOD *ossl_EC_GFp_nist_method(void);

#   ifndef ossl_OPENSSL_NO_EC_NISTP_64_GCC_128
/** Returns 64-bit optimized methods for nistp224
 *  \return  ossl_EC_METHOD object
 */
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_EC_METHOD *EC_GFp_nistp224_method(void);

/** Returns 64-bit optimized methods for nistp256
 *  \return  ossl_EC_METHOD object
 */
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_EC_METHOD *EC_GFp_nistp256_method(void);

/** Returns 64-bit optimized methods for nistp521
 *  \return  ossl_EC_METHOD object
 */
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_EC_METHOD *EC_GFp_nistp521_method(void);
#   endif /* ossl_OPENSSL_NO_EC_NISTP_64_GCC_128 */

#   ifndef ossl_OPENSSL_NO_EC2M
/********************************************************************/
/*           ossl_EC_METHOD for curves over GF(2^m)                      */
/********************************************************************/

/** Returns the basic GF2m ec method
 *  \return  ossl_EC_METHOD object
 */
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_EC_METHOD *ossl_EC_GF2m_simple_method(void);

#   endif

/********************************************************************/
/*                   ossl_EC_GROUP functions                             */
/********************************************************************/

/**
 *  Creates a new ossl_EC_GROUP object
 *  \param   meth   ossl_EC_METHOD to use
 *  \return  newly created ossl_EC_GROUP object or NULL in case of an error.
 */
ossl_OSSL_DEPRECATEDIN_3_0 ossl_EC_GROUP *ossl_EC_GROUP_new(const ossl_EC_METHOD *meth);

/** Clears and frees a ossl_EC_GROUP object
 *  \param  group  ossl_EC_GROUP object to be cleared and freed.
 */
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EC_GROUP_clear_free(ossl_EC_GROUP *group);

/** Returns the ossl_EC_METHOD of the ossl_EC_GROUP object.
 *  \param  group  ossl_EC_GROUP object
 *  \return ossl_EC_METHOD used in this ossl_EC_GROUP object.
 */
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_EC_METHOD *ossl_EC_GROUP_method_of(const ossl_EC_GROUP *group);

/** Returns the field type of the ossl_EC_METHOD.
 *  \param  meth  ossl_EC_METHOD object
 *  \return NID of the underlying field type OID.
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_METHOD_get_field_type(const ossl_EC_METHOD *meth);
#  endif /* ossl_OPENSSL_NO_DEPRECATED_3_0 */

/** Frees a ossl_EC_GROUP object
 *  \param  group  ossl_EC_GROUP object to be freed.
 */
void ossl_EC_GROUP_free(ossl_EC_GROUP *group);

/** Copies ossl_EC_GROUP objects. Note: both EC_GROUPs must use the same ossl_EC_METHOD.
 *  \param  dst  destination ossl_EC_GROUP object
 *  \param  src  source ossl_EC_GROUP object
 *  \return 1 on success and 0 if an error occurred.
 */
int ossl_EC_GROUP_copy(ossl_EC_GROUP *dst, const ossl_EC_GROUP *src);

/** Creates a new ossl_EC_GROUP object and copies the content
 *  form src to the newly created ossl_EC_KEY object
 *  \param  src  source ossl_EC_GROUP object
 *  \return newly created ossl_EC_GROUP object or NULL in case of an error.
 */
ossl_EC_GROUP *ossl_EC_GROUP_dup(const ossl_EC_GROUP *src);

/** Sets the generator and its order/cofactor of a ossl_EC_GROUP object.
 *  \param  group      ossl_EC_GROUP object
 *  \param  generator  ossl_EC_POINT object with the generator.
 *  \param  order      the order of the group generated by the generator.
 *  \param  cofactor   the index of the sub-group generated by the generator
 *                     in the group of all points on the elliptic curve.
 *  \return 1 on success and 0 if an error occurred
 */
int ossl_EC_GROUP_set_generator(ossl_EC_GROUP *group, const ossl_EC_POINT *generator,
                           const ossl_BIGNUM *order, const ossl_BIGNUM *cofactor);

/** Returns the generator of a ossl_EC_GROUP object.
 *  \param  group  ossl_EC_GROUP object
 *  \return the currently used generator (possibly NULL).
 */
const ossl_EC_POINT *ossl_EC_GROUP_get0_generator(const ossl_EC_GROUP *group);

/** Returns the montgomery data for order(Generator)
 *  \param  group  ossl_EC_GROUP object
 *  \return the currently used montgomery data (possibly NULL).
*/
ossl_BN_MONT_CTX *ossl_EC_GROUP_get_mont_data(const ossl_EC_GROUP *group);

/** Gets the order of a ossl_EC_GROUP
 *  \param  group  ossl_EC_GROUP object
 *  \param  order  ossl_BIGNUM to which the order is copied
 *  \param  ctx    unused
 *  \return 1 on success and 0 if an error occurred
 */
int ossl_EC_GROUP_get_order(const ossl_EC_GROUP *group, ossl_BIGNUM *order, ossl_BN_CTX *ctx);

/** Gets the order of an ossl_EC_GROUP
 *  \param  group  ossl_EC_GROUP object
 *  \return the group order
 */
const ossl_BIGNUM *ossl_EC_GROUP_get0_order(const ossl_EC_GROUP *group);

/** Gets the number of bits of the order of an ossl_EC_GROUP
 *  \param  group  ossl_EC_GROUP object
 *  \return number of bits of group order.
 */
int ossl_EC_GROUP_order_bits(const ossl_EC_GROUP *group);

/** Gets the cofactor of a ossl_EC_GROUP
 *  \param  group     ossl_EC_GROUP object
 *  \param  cofactor  ossl_BIGNUM to which the cofactor is copied
 *  \param  ctx       unused
 *  \return 1 on success and 0 if an error occurred
 */
int ossl_EC_GROUP_get_cofactor(const ossl_EC_GROUP *group, ossl_BIGNUM *cofactor,
                          ossl_BN_CTX *ctx);

/** Gets the cofactor of an ossl_EC_GROUP
 *  \param  group  ossl_EC_GROUP object
 *  \return the group cofactor
 */
const ossl_BIGNUM *ossl_EC_GROUP_get0_cofactor(const ossl_EC_GROUP *group);

/** Sets the name of a ossl_EC_GROUP object
 *  \param  group  ossl_EC_GROUP object
 *  \param  nid    NID of the curve name OID
 */
void ossl_EC_GROUP_set_curve_name(ossl_EC_GROUP *group, int nid);

/** Returns the curve name of a ossl_EC_GROUP object
 *  \param  group  ossl_EC_GROUP object
 *  \return NID of the curve name OID or 0 if not set.
 */
int ossl_EC_GROUP_get_curve_name(const ossl_EC_GROUP *group);

/** Gets the field of an ossl_EC_GROUP
 *  \param  group  ossl_EC_GROUP object
 *  \return the group field
 */
const ossl_BIGNUM *ossl_EC_GROUP_get0_field(const ossl_EC_GROUP *group);

/** Returns the field type of the ossl_EC_GROUP.
 *  \param  group  ossl_EC_GROUP object
 *  \return NID of the underlying field type OID.
 */
int ossl_EC_GROUP_get_field_type(const ossl_EC_GROUP *group);

void ossl_EC_GROUP_set_asn1_flag(ossl_EC_GROUP *group, int flag);
int ossl_EC_GROUP_get_asn1_flag(const ossl_EC_GROUP *group);

void ossl_EC_GROUP_set_point_conversion_form(ossl_EC_GROUP *group,
                                        ossl_point_conversion_form_t form);
ossl_point_conversion_form_t ossl_EC_GROUP_get_point_conversion_form(const ossl_EC_GROUP *);

unsigned char *ossl_EC_GROUP_get0_seed(const ossl_EC_GROUP *x);
size_t ossl_EC_GROUP_get_seed_len(const ossl_EC_GROUP *);
size_t ossl_EC_GROUP_set_seed(ossl_EC_GROUP *, const unsigned char *, size_t len);

/** Sets the parameters of an ec curve defined by y^2 = x^3 + a*x + b (for GFp)
 *  or y^2 + x*y = x^3 + a*x^2 + b (for GF2m)
 *  \param  group  ossl_EC_GROUP object
 *  \param  p      ossl_BIGNUM with the prime number (GFp) or the polynomial
 *                 defining the underlying field (GF2m)
 *  \param  a      ossl_BIGNUM with parameter a of the equation
 *  \param  b      ossl_BIGNUM with parameter b of the equation
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int ossl_EC_GROUP_set_curve(ossl_EC_GROUP *group, const ossl_BIGNUM *p, const ossl_BIGNUM *a,
                       const ossl_BIGNUM *b, ossl_BN_CTX *ctx);

/** Gets the parameters of the ec curve defined by y^2 = x^3 + a*x + b (for GFp)
 *  or y^2 + x*y = x^3 + a*x^2 + b (for GF2m)
 *  \param  group  ossl_EC_GROUP object
 *  \param  p      ossl_BIGNUM with the prime number (GFp) or the polynomial
 *                 defining the underlying field (GF2m)
 *  \param  a      ossl_BIGNUM for parameter a of the equation
 *  \param  b      ossl_BIGNUM for parameter b of the equation
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int ossl_EC_GROUP_get_curve(const ossl_EC_GROUP *group, ossl_BIGNUM *p, ossl_BIGNUM *a, ossl_BIGNUM *b,
                       ossl_BN_CTX *ctx);

#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
/** Sets the parameters of an ec curve. Synonym for ossl_EC_GROUP_set_curve
 *  \param  group  ossl_EC_GROUP object
 *  \param  p      ossl_BIGNUM with the prime number (GFp) or the polynomial
 *                 defining the underlying field (GF2m)
 *  \param  a      ossl_BIGNUM with parameter a of the equation
 *  \param  b      ossl_BIGNUM with parameter b of the equation
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_GROUP_set_curve_GFp(ossl_EC_GROUP *group,
                                                 const ossl_BIGNUM *p,
                                                 const ossl_BIGNUM *a,
                                                 const ossl_BIGNUM *b,
                                                 ossl_BN_CTX *ctx);

/** Gets the parameters of an ec curve. Synonym for ossl_EC_GROUP_get_curve
 *  \param  group  ossl_EC_GROUP object
 *  \param  p      ossl_BIGNUM with the prime number (GFp) or the polynomial
 *                 defining the underlying field (GF2m)
 *  \param  a      ossl_BIGNUM for parameter a of the equation
 *  \param  b      ossl_BIGNUM for parameter b of the equation
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_GROUP_get_curve_GFp(const ossl_EC_GROUP *group,
                                                 ossl_BIGNUM *p,
                                                 ossl_BIGNUM *a, ossl_BIGNUM *b,
                                                 ossl_BN_CTX *ctx);

#   ifndef ossl_OPENSSL_NO_EC2M
/** Sets the parameter of an ec curve. Synonym for ossl_EC_GROUP_set_curve
 *  \param  group  ossl_EC_GROUP object
 *  \param  p      ossl_BIGNUM with the prime number (GFp) or the polynomial
 *                 defining the underlying field (GF2m)
 *  \param  a      ossl_BIGNUM with parameter a of the equation
 *  \param  b      ossl_BIGNUM with parameter b of the equation
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_GROUP_set_curve_GF2m(ossl_EC_GROUP *group,
                                                  const ossl_BIGNUM *p,
                                                  const ossl_BIGNUM *a,
                                                  const ossl_BIGNUM *b,
                                                  ossl_BN_CTX *ctx);

/** Gets the parameters of an ec curve. Synonym for ossl_EC_GROUP_get_curve
 *  \param  group  ossl_EC_GROUP object
 *  \param  p      ossl_BIGNUM with the prime number (GFp) or the polynomial
 *                 defining the underlying field (GF2m)
 *  \param  a      ossl_BIGNUM for parameter a of the equation
 *  \param  b      ossl_BIGNUM for parameter b of the equation
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_GROUP_get_curve_GF2m(const ossl_EC_GROUP *group,
                                                  ossl_BIGNUM *p,
                                                  ossl_BIGNUM *a, ossl_BIGNUM *b,
                                                  ossl_BN_CTX *ctx);
#   endif /* ossl_OPENSSL_NO_EC2M */
#  endif /* ossl_OPENSSL_NO_DEPRECATED_3_0 */

/** Returns the number of bits needed to represent a field element
 *  \param  group  ossl_EC_GROUP object
 *  \return number of bits needed to represent a field element
 */
int ossl_EC_GROUP_get_degree(const ossl_EC_GROUP *group);

/** Checks whether the parameter in the ossl_EC_GROUP define a valid ec group
 *  \param  group  ossl_EC_GROUP object
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 if group is a valid ec group and 0 otherwise
 */
int ossl_EC_GROUP_check(const ossl_EC_GROUP *group, ossl_BN_CTX *ctx);

/** Checks whether the discriminant of the elliptic curve is zero or not
 *  \param  group  ossl_EC_GROUP object
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 if the discriminant is not zero and 0 otherwise
 */
int ossl_EC_GROUP_check_discriminant(const ossl_EC_GROUP *group, ossl_BN_CTX *ctx);

/** Compares two ossl_EC_GROUP objects
 *  \param  a    first ossl_EC_GROUP object
 *  \param  b    second ossl_EC_GROUP object
 *  \param  ctx  ossl_BN_CTX object (optional)
 *  \return 0 if the groups are equal, 1 if not, or -1 on error
 */
int ossl_EC_GROUP_cmp(const ossl_EC_GROUP *a, const ossl_EC_GROUP *b, ossl_BN_CTX *ctx);

/*
 * EC_GROUP_new_GF*() calls ossl_EC_GROUP_new() and EC_GROUP_set_GF*() after
 * choosing an appropriate ossl_EC_METHOD
 */

/** Creates a new ossl_EC_GROUP object with the specified parameters defined
 *  over GFp (defined by the equation y^2 = x^3 + a*x + b)
 *  \param  p    ossl_BIGNUM with the prime number
 *  \param  a    ossl_BIGNUM with the parameter a of the equation
 *  \param  b    ossl_BIGNUM with the parameter b of the equation
 *  \param  ctx  ossl_BN_CTX object (optional)
 *  \return newly created ossl_EC_GROUP object with the specified parameters
 */
ossl_EC_GROUP *ossl_EC_GROUP_new_curve_GFp(const ossl_BIGNUM *p, const ossl_BIGNUM *a,
                                 const ossl_BIGNUM *b, ossl_BN_CTX *ctx);
#  ifndef ossl_OPENSSL_NO_EC2M
/** Creates a new ossl_EC_GROUP object with the specified parameters defined
 *  over GF2m (defined by the equation y^2 + x*y = x^3 + a*x^2 + b)
 *  \param  p    ossl_BIGNUM with the polynomial defining the underlying field
 *  \param  a    ossl_BIGNUM with the parameter a of the equation
 *  \param  b    ossl_BIGNUM with the parameter b of the equation
 *  \param  ctx  ossl_BN_CTX object (optional)
 *  \return newly created ossl_EC_GROUP object with the specified parameters
 */
ossl_EC_GROUP *ossl_EC_GROUP_new_curve_GF2m(const ossl_BIGNUM *p, const ossl_BIGNUM *a,
                                  const ossl_BIGNUM *b, ossl_BN_CTX *ctx);
#  endif

/**
 * Creates a ossl_EC_GROUP object with a curve specified by parameters.
 * The parameters may be explicit or a named curve,
 *  \param  params A list of parameters describing the group.
 *  \param  libctx The associated library context or NULL for the default
 *                 context
 *  \param  propq  A property query string
 *  \return newly created ossl_EC_GROUP object with specified parameters or NULL
 *          if an error occurred
 */
ossl_EC_GROUP *ossl_EC_GROUP_new_from_params(const ossl_OSSL_PARAM params[],
                                   ossl_OSSL_LIB_CTX *libctx, const char *propq);

/**
 * Creates a ossl_EC_GROUP object with a curve specified by a NID
 *  \param  libctx The associated library context or NULL for the default
 *                 context
 *  \param  propq  A property query string
 *  \param  nid    NID of the OID of the curve name
 *  \return newly created ossl_EC_GROUP object with specified curve or NULL
 *          if an error occurred
 */
ossl_EC_GROUP *ossl_EC_GROUP_new_by_curve_name_ex(ossl_OSSL_LIB_CTX *libctx, const char *propq,
                                        int nid);

/**
 * Creates a ossl_EC_GROUP object with a curve specified by a NID. Same as
 * ossl_EC_GROUP_new_by_curve_name_ex but the libctx and propq are always
 * NULL.
 *  \param  nid    NID of the OID of the curve name
 *  \return newly created ossl_EC_GROUP object with specified curve or NULL
 *          if an error occurred
 */
ossl_EC_GROUP *ossl_EC_GROUP_new_by_curve_name(int nid);

/** Creates a new ossl_EC_GROUP object from an ossl_ECPARAMETERS object
 *  \param  params  pointer to the ossl_ECPARAMETERS object
 *  \return newly created ossl_EC_GROUP object with specified curve or NULL
 *          if an error occurred
 */
ossl_EC_GROUP *ossl_EC_GROUP_new_from_ecparameters(const ossl_ECPARAMETERS *params);

/** Creates an ossl_ECPARAMETERS object for the given ossl_EC_GROUP object.
 *  \param  group   pointer to the ossl_EC_GROUP object
 *  \param  params  pointer to an existing ossl_ECPARAMETERS object or NULL
 *  \return pointer to the new ossl_ECPARAMETERS object or NULL
 *          if an error occurred.
 */
ossl_ECPARAMETERS *ossl_EC_GROUP_get_ecparameters(const ossl_EC_GROUP *group,
                                        ossl_ECPARAMETERS *params);

/** Creates a new ossl_EC_GROUP object from an ossl_ECPKPARAMETERS object
 *  \param  params  pointer to an existing ossl_ECPKPARAMETERS object, or NULL
 *  \return newly created ossl_EC_GROUP object with specified curve, or NULL
 *          if an error occurred
 */
ossl_EC_GROUP *ossl_EC_GROUP_new_from_ecpkparameters(const ossl_ECPKPARAMETERS *params);

/** Creates an ossl_ECPKPARAMETERS object for the given ossl_EC_GROUP object.
 *  \param  group   pointer to the ossl_EC_GROUP object
 *  \param  params  pointer to an existing ossl_ECPKPARAMETERS object or NULL
 *  \return pointer to the new ossl_ECPKPARAMETERS object or NULL
 *          if an error occurred.
 */
ossl_ECPKPARAMETERS *ossl_EC_GROUP_get_ecpkparameters(const ossl_EC_GROUP *group,
                                            ossl_ECPKPARAMETERS *params);

/********************************************************************/
/*               handling of internal curves                        */
/********************************************************************/

typedef struct {
    int nid;
    const char *comment;
} ossl_EC_builtin_curve;

/*
 * EC_builtin_curves(ossl_EC_builtin_curve *r, size_t size) returns number of all
 * available curves or zero if a error occurred. In case r is not zero,
 * nitems ossl_EC_builtin_curve structures are filled with the data of the first
 * nitems internal groups
 */
size_t ossl_EC_get_builtin_curves(ossl_EC_builtin_curve *r, size_t nitems);

const char *ossl_EC_curve_nid2nist(int nid);
int ossl_EC_curve_nist2nid(const char *name);
int ossl_EC_GROUP_check_named_curve(const ossl_EC_GROUP *group, int nist_only,
                               ossl_BN_CTX *ctx);

/********************************************************************/
/*                    ossl_EC_POINT functions                            */
/********************************************************************/

/** Creates a new ossl_EC_POINT object for the specified ossl_EC_GROUP
 *  \param  group  ossl_EC_GROUP the underlying ossl_EC_GROUP object
 *  \return newly created ossl_EC_POINT object or NULL if an error occurred
 */
ossl_EC_POINT *ossl_EC_POINT_new(const ossl_EC_GROUP *group);

/** Frees a ossl_EC_POINT object
 *  \param  point  ossl_EC_POINT object to be freed
 */
void ossl_EC_POINT_free(ossl_EC_POINT *point);

/** Clears and frees a ossl_EC_POINT object
 *  \param  point  ossl_EC_POINT object to be cleared and freed
 */
void ossl_EC_POINT_clear_free(ossl_EC_POINT *point);

/** Copies ossl_EC_POINT object
 *  \param  dst  destination ossl_EC_POINT object
 *  \param  src  source ossl_EC_POINT object
 *  \return 1 on success and 0 if an error occurred
 */
int ossl_EC_POINT_copy(ossl_EC_POINT *dst, const ossl_EC_POINT *src);

/** Creates a new ossl_EC_POINT object and copies the content of the supplied
 *  ossl_EC_POINT
 *  \param  src    source ossl_EC_POINT object
 *  \param  group  underlying the ossl_EC_GROUP object
 *  \return newly created ossl_EC_POINT object or NULL if an error occurred
 */
ossl_EC_POINT *ossl_EC_POINT_dup(const ossl_EC_POINT *src, const ossl_EC_GROUP *group);

/** Sets a point to infinity (neutral element)
 *  \param  group  underlying ossl_EC_GROUP object
 *  \param  point  ossl_EC_POINT to set to infinity
 *  \return 1 on success and 0 if an error occurred
 */
int ossl_EC_POINT_set_to_infinity(const ossl_EC_GROUP *group, ossl_EC_POINT *point);

#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
/** Returns the ossl_EC_METHOD used in ossl_EC_POINT object
 *  \param  point  ossl_EC_POINT object
 *  \return the ossl_EC_METHOD used
 */
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_EC_METHOD *ossl_EC_POINT_method_of(const ossl_EC_POINT *point);

/** Sets the jacobian projective coordinates of a ossl_EC_POINT over GFp
 *  \param  group  underlying ossl_EC_GROUP object
 *  \param  p      ossl_EC_POINT object
 *  \param  x      ossl_BIGNUM with the x-coordinate
 *  \param  y      ossl_BIGNUM with the y-coordinate
 *  \param  z      ossl_BIGNUM with the z-coordinate
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_POINT_set_Jprojective_coordinates_GFp
                      (const ossl_EC_GROUP *group, ossl_EC_POINT *p,
                       const ossl_BIGNUM *x, const ossl_BIGNUM *y, const ossl_BIGNUM *z,
                       ossl_BN_CTX *ctx);

/** Gets the jacobian projective coordinates of a ossl_EC_POINT over GFp
 *  \param  group  underlying ossl_EC_GROUP object
 *  \param  p      ossl_EC_POINT object
 *  \param  x      ossl_BIGNUM for the x-coordinate
 *  \param  y      ossl_BIGNUM for the y-coordinate
 *  \param  z      ossl_BIGNUM for the z-coordinate
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_POINT_get_Jprojective_coordinates_GFp
                      (const ossl_EC_GROUP *group, const ossl_EC_POINT *p,
                       ossl_BIGNUM *x, ossl_BIGNUM *y, ossl_BIGNUM *z, ossl_BN_CTX *ctx);
#  endif /* ossl_OPENSSL_NO_DEPRECATED_3_0 */

/** Sets the affine coordinates of an ossl_EC_POINT
 *  \param  group  underlying ossl_EC_GROUP object
 *  \param  p      ossl_EC_POINT object
 *  \param  x      ossl_BIGNUM with the x-coordinate
 *  \param  y      ossl_BIGNUM with the y-coordinate
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int ossl_EC_POINT_set_affine_coordinates(const ossl_EC_GROUP *group, ossl_EC_POINT *p,
                                    const ossl_BIGNUM *x, const ossl_BIGNUM *y,
                                    ossl_BN_CTX *ctx);

/** Gets the affine coordinates of an ossl_EC_POINT.
 *  \param  group  underlying ossl_EC_GROUP object
 *  \param  p      ossl_EC_POINT object
 *  \param  x      ossl_BIGNUM for the x-coordinate
 *  \param  y      ossl_BIGNUM for the y-coordinate
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int ossl_EC_POINT_get_affine_coordinates(const ossl_EC_GROUP *group, const ossl_EC_POINT *p,
                                    ossl_BIGNUM *x, ossl_BIGNUM *y, ossl_BN_CTX *ctx);

#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
/** Sets the affine coordinates of an ossl_EC_POINT. A synonym of
 *  ossl_EC_POINT_set_affine_coordinates
 *  \param  group  underlying ossl_EC_GROUP object
 *  \param  p      ossl_EC_POINT object
 *  \param  x      ossl_BIGNUM with the x-coordinate
 *  \param  y      ossl_BIGNUM with the y-coordinate
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_POINT_set_affine_coordinates_GFp
                      (const ossl_EC_GROUP *group, ossl_EC_POINT *p,
                       const ossl_BIGNUM *x, const ossl_BIGNUM *y, ossl_BN_CTX *ctx);

/** Gets the affine coordinates of an ossl_EC_POINT. A synonym of
 *  ossl_EC_POINT_get_affine_coordinates
 *  \param  group  underlying ossl_EC_GROUP object
 *  \param  p      ossl_EC_POINT object
 *  \param  x      ossl_BIGNUM for the x-coordinate
 *  \param  y      ossl_BIGNUM for the y-coordinate
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_POINT_get_affine_coordinates_GFp
                      (const ossl_EC_GROUP *group, const ossl_EC_POINT *p,
                       ossl_BIGNUM *x, ossl_BIGNUM *y, ossl_BN_CTX *ctx);
#  endif /* ossl_OPENSSL_NO_DEPRECATED_3_0 */

/** Sets the x9.62 compressed coordinates of a ossl_EC_POINT
 *  \param  group  underlying ossl_EC_GROUP object
 *  \param  p      ossl_EC_POINT object
 *  \param  x      ossl_BIGNUM with x-coordinate
 *  \param  y_bit  integer with the y-Bit (either 0 or 1)
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int ossl_EC_POINT_set_compressed_coordinates(const ossl_EC_GROUP *group, ossl_EC_POINT *p,
                                        const ossl_BIGNUM *x, int y_bit,
                                        ossl_BN_CTX *ctx);

#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
/** Sets the x9.62 compressed coordinates of a ossl_EC_POINT. A synonym of
 *  ossl_EC_POINT_set_compressed_coordinates
 *  \param  group  underlying ossl_EC_GROUP object
 *  \param  p      ossl_EC_POINT object
 *  \param  x      ossl_BIGNUM with x-coordinate
 *  \param  y_bit  integer with the y-Bit (either 0 or 1)
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_POINT_set_compressed_coordinates_GFp
                      (const ossl_EC_GROUP *group, ossl_EC_POINT *p,
                       const ossl_BIGNUM *x, int y_bit, ossl_BN_CTX *ctx);
#   ifndef ossl_OPENSSL_NO_EC2M
/** Sets the affine coordinates of an ossl_EC_POINT. A synonym of
 *  ossl_EC_POINT_set_affine_coordinates
 *  \param  group  underlying ossl_EC_GROUP object
 *  \param  p      ossl_EC_POINT object
 *  \param  x      ossl_BIGNUM with the x-coordinate
 *  \param  y      ossl_BIGNUM with the y-coordinate
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_POINT_set_affine_coordinates_GF2m
                      (const ossl_EC_GROUP *group, ossl_EC_POINT *p,
                       const ossl_BIGNUM *x, const ossl_BIGNUM *y, ossl_BN_CTX *ctx);

/** Gets the affine coordinates of an ossl_EC_POINT. A synonym of
 *  ossl_EC_POINT_get_affine_coordinates
 *  \param  group  underlying ossl_EC_GROUP object
 *  \param  p      ossl_EC_POINT object
 *  \param  x      ossl_BIGNUM for the x-coordinate
 *  \param  y      ossl_BIGNUM for the y-coordinate
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_POINT_get_affine_coordinates_GF2m
                      (const ossl_EC_GROUP *group, const ossl_EC_POINT *p,
                       ossl_BIGNUM *x, ossl_BIGNUM *y, ossl_BN_CTX *ctx);

/** Sets the x9.62 compressed coordinates of a ossl_EC_POINT. A synonym of
 *  ossl_EC_POINT_set_compressed_coordinates
 *  \param  group  underlying ossl_EC_GROUP object
 *  \param  p      ossl_EC_POINT object
 *  \param  x      ossl_BIGNUM with x-coordinate
 *  \param  y_bit  integer with the y-Bit (either 0 or 1)
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_POINT_set_compressed_coordinates_GF2m
                      (const ossl_EC_GROUP *group, ossl_EC_POINT *p,
                       const ossl_BIGNUM *x, int y_bit, ossl_BN_CTX *ctx);
#   endif
#  endif /* ossl_OPENSSL_NO_DEPRECATED_3_0 */

/** Encodes a ossl_EC_POINT object to a octet string
 *  \param  group  underlying ossl_EC_GROUP object
 *  \param  p      ossl_EC_POINT object
 *  \param  form   point conversion form
 *  \param  buf    memory buffer for the result. If NULL the function returns
 *                 required buffer size.
 *  \param  len    length of the memory buffer
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t ossl_EC_POINT_point2oct(const ossl_EC_GROUP *group, const ossl_EC_POINT *p,
                          ossl_point_conversion_form_t form,
                          unsigned char *buf, size_t len, ossl_BN_CTX *ctx);

/** Decodes a ossl_EC_POINT from a octet string
 *  \param  group  underlying ossl_EC_GROUP object
 *  \param  p      ossl_EC_POINT object
 *  \param  buf    memory buffer with the encoded ec point
 *  \param  len    length of the encoded ec point
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int ossl_EC_POINT_oct2point(const ossl_EC_GROUP *group, ossl_EC_POINT *p,
                       const unsigned char *buf, size_t len, ossl_BN_CTX *ctx);

/** Encodes an ossl_EC_POINT object to an allocated octet string
 *  \param  group  underlying ossl_EC_GROUP object
 *  \param  point  ossl_EC_POINT object
 *  \param  form   point conversion form
 *  \param  pbuf   returns pointer to allocated buffer
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t ossl_EC_POINT_point2buf(const ossl_EC_GROUP *group, const ossl_EC_POINT *point,
                          ossl_point_conversion_form_t form,
                          unsigned char **pbuf, ossl_BN_CTX *ctx);

/* other interfaces to point2oct/oct2point: */
#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 ossl_BIGNUM *ossl_EC_POINT_point2bn(const ossl_EC_GROUP *,
                                                const ossl_EC_POINT *,
                                                ossl_point_conversion_form_t form,
                                                ossl_BIGNUM *, ossl_BN_CTX *);
ossl_OSSL_DEPRECATEDIN_3_0 ossl_EC_POINT *ossl_EC_POINT_bn2point(const ossl_EC_GROUP *,
                                                  const ossl_BIGNUM *,
                                                  ossl_EC_POINT *, ossl_BN_CTX *);
#  endif /* ossl_OPENSSL_NO_DEPRECATED_3_0 */

char *ossl_EC_POINT_point2hex(const ossl_EC_GROUP *, const ossl_EC_POINT *,
                         ossl_point_conversion_form_t form, ossl_BN_CTX *);
ossl_EC_POINT *ossl_EC_POINT_hex2point(const ossl_EC_GROUP *, const char *,
                             ossl_EC_POINT *, ossl_BN_CTX *);

/********************************************************************/
/*         functions for doing ossl_EC_POINT arithmetic                  */
/********************************************************************/

/** Computes the sum of two ossl_EC_POINT
 *  \param  group  underlying ossl_EC_GROUP object
 *  \param  r      ossl_EC_POINT object for the result (r = a + b)
 *  \param  a      ossl_EC_POINT object with the first summand
 *  \param  b      ossl_EC_POINT object with the second summand
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int ossl_EC_POINT_add(const ossl_EC_GROUP *group, ossl_EC_POINT *r, const ossl_EC_POINT *a,
                 const ossl_EC_POINT *b, ossl_BN_CTX *ctx);

/** Computes the double of a ossl_EC_POINT
 *  \param  group  underlying ossl_EC_GROUP object
 *  \param  r      ossl_EC_POINT object for the result (r = 2 * a)
 *  \param  a      ossl_EC_POINT object
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int ossl_EC_POINT_dbl(const ossl_EC_GROUP *group, ossl_EC_POINT *r, const ossl_EC_POINT *a,
                 ossl_BN_CTX *ctx);

/** Computes the inverse of a ossl_EC_POINT
 *  \param  group  underlying ossl_EC_GROUP object
 *  \param  a      ossl_EC_POINT object to be inverted (it's used for the result as well)
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int ossl_EC_POINT_invert(const ossl_EC_GROUP *group, ossl_EC_POINT *a, ossl_BN_CTX *ctx);

/** Checks whether the point is the neutral element of the group
 *  \param  group  the underlying ossl_EC_GROUP object
 *  \param  p      ossl_EC_POINT object
 *  \return 1 if the point is the neutral element and 0 otherwise
 */
int ossl_EC_POINT_is_at_infinity(const ossl_EC_GROUP *group, const ossl_EC_POINT *p);

/** Checks whether the point is on the curve
 *  \param  group  underlying ossl_EC_GROUP object
 *  \param  point  ossl_EC_POINT object to check
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 if the point is on the curve, 0 if not, or -1 on error
 */
int ossl_EC_POINT_is_on_curve(const ossl_EC_GROUP *group, const ossl_EC_POINT *point,
                         ossl_BN_CTX *ctx);

/** Compares two EC_POINTs
 *  \param  group  underlying ossl_EC_GROUP object
 *  \param  a      first ossl_EC_POINT object
 *  \param  b      second ossl_EC_POINT object
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 if the points are not equal, 0 if they are, or -1 on error
 */
int ossl_EC_POINT_cmp(const ossl_EC_GROUP *group, const ossl_EC_POINT *a, const ossl_EC_POINT *b,
                 ossl_BN_CTX *ctx);

#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_POINT_make_affine(const ossl_EC_GROUP *group,
                                               ossl_EC_POINT *point, ossl_BN_CTX *ctx);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_POINTs_make_affine(const ossl_EC_GROUP *group, size_t num,
                                                ossl_EC_POINT *points[], ossl_BN_CTX *ctx);

/** Computes r = generator * n + sum_{i=0}^{num-1} p[i] * m[i]
 *  \param  group  underlying ossl_EC_GROUP object
 *  \param  r      ossl_EC_POINT object for the result
 *  \param  n      ossl_BIGNUM with the multiplier for the group generator (optional)
 *  \param  num    number further summands
 *  \param  p      array of size num of ossl_EC_POINT objects
 *  \param  m      array of size num of ossl_BIGNUM objects
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_POINTs_mul(const ossl_EC_GROUP *group, ossl_EC_POINT *r,
                                        const ossl_BIGNUM *n, size_t num,
                                        const ossl_EC_POINT *p[], const ossl_BIGNUM *m[],
                                        ossl_BN_CTX *ctx);
#  endif /* ossl_OPENSSL_NO_DEPRECATED_3_0 */

/** Computes r = generator * n + q * m
 *  \param  group  underlying ossl_EC_GROUP object
 *  \param  r      ossl_EC_POINT object for the result
 *  \param  n      ossl_BIGNUM with the multiplier for the group generator (optional)
 *  \param  q      ossl_EC_POINT object with the first factor of the second summand
 *  \param  m      ossl_BIGNUM with the second factor of the second summand
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
int ossl_EC_POINT_mul(const ossl_EC_GROUP *group, ossl_EC_POINT *r, const ossl_BIGNUM *n,
                 const ossl_EC_POINT *q, const ossl_BIGNUM *m, ossl_BN_CTX *ctx);

#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
/** Stores multiples of generator for faster point multiplication
 *  \param  group  ossl_EC_GROUP object
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_GROUP_precompute_mult(ossl_EC_GROUP *group, ossl_BN_CTX *ctx);

/** Reports whether a precomputation has been done
 *  \param  group  ossl_EC_GROUP object
 *  \return 1 if a pre-computation has been done and 0 otherwise
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_GROUP_have_precompute_mult(const ossl_EC_GROUP *group);
#  endif /* ossl_OPENSSL_NO_DEPRECATED_3_0 */

/********************************************************************/
/*                       ASN1 stuff                                 */
/********************************************************************/

ossl_DECLARE_ASN1_ITEM(ossl_ECPKPARAMETERS)
ossl_DECLARE_ASN1_ALLOC_FUNCTIONS(ossl_ECPKPARAMETERS)
ossl_DECLARE_ASN1_ITEM(ossl_ECPARAMETERS)
ossl_DECLARE_ASN1_ALLOC_FUNCTIONS(ossl_ECPARAMETERS)

/*
 * ossl_EC_GROUP_get_basis_type() returns the NID of the basis type used to
 * represent the field elements
 */
int ossl_EC_GROUP_get_basis_type(const ossl_EC_GROUP *);
#  ifndef ossl_OPENSSL_NO_EC2M
int ossl_EC_GROUP_get_trinomial_basis(const ossl_EC_GROUP *, unsigned int *k);
int ossl_EC_GROUP_get_pentanomial_basis(const ossl_EC_GROUP *, unsigned int *k1,
                                   unsigned int *k2, unsigned int *k3);
#  endif

ossl_EC_GROUP *ossl_d2i_ECPKParameters(ossl_EC_GROUP **, const unsigned char **in, long len);
int ossl_i2d_ECPKParameters(const ossl_EC_GROUP *, unsigned char **out);

#  define ossl_d2i_ECPKParameters_bio(bp,x) \
    ossl_ASN1_d2i_bio_of(ossl_EC_GROUP, NULL, ossl_d2i_ECPKParameters, bp, x)
#  define ossl_i2d_ECPKParameters_bio(bp,x) \
    ossl_ASN1_i2d_bio_of(ossl_EC_GROUP, ossl_i2d_ECPKParameters, bp, x)
#  define ossl_d2i_ECPKParameters_fp(fp,x) \
    (ossl_EC_GROUP *)ossl_ASN1_d2i_fp(NULL, (ossl_d2i_of_void *)ossl_d2i_ECPKParameters, (fp), \
                            (void **)(x))
#  define ossl_i2d_ECPKParameters_fp(fp,x) \
    ossl_ASN1_i2d_fp((ossl_i2d_of_void *)ossl_i2d_ECPKParameters, (fp), (void *)(x))

#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_ECPKParameters_print(ossl_BIO *bp, const ossl_EC_GROUP *x,
                                               int off);
#   ifndef ossl_OPENSSL_NO_STDIO
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_ECPKParameters_print_fp(FILE *fp, const ossl_EC_GROUP *x,
                                                  int off);
#   endif
#  endif /* ossl_OPENSSL_NO_DEPRECATED_3_0 */

/********************************************************************/
/*                      ossl_EC_KEY functions                            */
/********************************************************************/

/* some values for the encoding_flag */
#  define ossl_EC_PKEY_NO_PARAMETERS   0x001
#  define ossl_EC_PKEY_NO_PUBKEY       0x002

/* some values for the flags field */
#  define ossl_EC_FLAG_SM2_RANGE              0x0004
#  define ossl_EC_FLAG_COFACTOR_ECDH          0x1000
#  define ossl_EC_FLAG_CHECK_NAMED_GROUP      0x2000
#  define ossl_EC_FLAG_CHECK_NAMED_GROUP_NIST 0x4000
#  define ossl_EC_FLAG_CHECK_NAMED_GROUP_MASK \
    (ossl_EC_FLAG_CHECK_NAMED_GROUP | ossl_EC_FLAG_CHECK_NAMED_GROUP_NIST)

/* Deprecated flags -  it was using 0x01..0x02 */
#  define ossl_EC_FLAG_NON_FIPS_ALLOW         0x0000
#  define ossl_EC_FLAG_FIPS_CHECKED           0x0000

#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
/**
 *  Creates a new ossl_EC_KEY object.
 *  \param  ctx  The library context for to use for this ossl_EC_KEY. May be NULL in
 *               which case the default library context is used.
 *  \return ossl_EC_KEY object or NULL if an error occurred.
 */
ossl_OSSL_DEPRECATEDIN_3_0 ossl_EC_KEY *ossl_EC_KEY_new_ex(ossl_OSSL_LIB_CTX *ctx, const char *propq);

/**
 *  Creates a new ossl_EC_KEY object. Same as calling ossl_EC_KEY_new_ex with a
 *  NULL library context
 *  \return ossl_EC_KEY object or NULL if an error occurred.
 */
ossl_OSSL_DEPRECATEDIN_3_0 ossl_EC_KEY *ossl_EC_KEY_new(void);

ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_KEY_get_flags(const ossl_EC_KEY *key);

ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EC_KEY_set_flags(ossl_EC_KEY *key, int flags);

ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EC_KEY_clear_flags(ossl_EC_KEY *key, int flags);

ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_KEY_decoded_from_explicit_params(const ossl_EC_KEY *key);

/**
 *  Creates a new ossl_EC_KEY object using a named curve as underlying
 *  ossl_EC_GROUP object.
 *  \param  ctx   The library context for to use for this ossl_EC_KEY. May be NULL in
 *                which case the default library context is used.
 *  \param  propq Any property query string
 *  \param  nid   NID of the named curve.
 *  \return ossl_EC_KEY object or NULL if an error occurred.
 */
ossl_OSSL_DEPRECATEDIN_3_0 ossl_EC_KEY *ossl_EC_KEY_new_by_curve_name_ex(ossl_OSSL_LIB_CTX *ctx,
                                                          const char *propq,
                                                          int nid);

/**
 *  Creates a new ossl_EC_KEY object using a named curve as underlying
 *  ossl_EC_GROUP object. Same as calling ossl_EC_KEY_new_by_curve_name_ex with a NULL
 *  library context and property query string.
 *  \param  nid  NID of the named curve.
 *  \return ossl_EC_KEY object or NULL if an error occurred.
 */
ossl_OSSL_DEPRECATEDIN_3_0 ossl_EC_KEY *ossl_EC_KEY_new_by_curve_name(int nid);

/** Frees a ossl_EC_KEY object.
 *  \param  key  ossl_EC_KEY object to be freed.
 */
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EC_KEY_free(ossl_EC_KEY *key);

/** Copies a ossl_EC_KEY object.
 *  \param  dst  destination ossl_EC_KEY object
 *  \param  src  src ossl_EC_KEY object
 *  \return dst or NULL if an error occurred.
 */
ossl_OSSL_DEPRECATEDIN_3_0 ossl_EC_KEY *ossl_EC_KEY_copy(ossl_EC_KEY *dst, const ossl_EC_KEY *src);

/** Creates a new ossl_EC_KEY object and copies the content from src to it.
 *  \param  src  the source ossl_EC_KEY object
 *  \return newly created ossl_EC_KEY object or NULL if an error occurred.
 */
ossl_OSSL_DEPRECATEDIN_3_0 ossl_EC_KEY *ossl_EC_KEY_dup(const ossl_EC_KEY *src);

/** Increases the internal reference count of a ossl_EC_KEY object.
 *  \param  key  ossl_EC_KEY object
 *  \return 1 on success and 0 if an error occurred.
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_KEY_up_ref(ossl_EC_KEY *key);

/** Returns the ossl_ENGINE object of a ossl_EC_KEY object
 *  \param  eckey  ossl_EC_KEY object
 *  \return the ossl_ENGINE object (possibly NULL).
 */
ossl_OSSL_DEPRECATEDIN_3_0 ossl_ENGINE *ossl_EC_KEY_get0_engine(const ossl_EC_KEY *eckey);

/** Returns the ossl_EC_GROUP object of a ossl_EC_KEY object
 *  \param  key  ossl_EC_KEY object
 *  \return the ossl_EC_GROUP object (possibly NULL).
 */
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_EC_GROUP *ossl_EC_KEY_get0_group(const ossl_EC_KEY *key);

/** Sets the ossl_EC_GROUP of a ossl_EC_KEY object.
 *  \param  key    ossl_EC_KEY object
 *  \param  group  ossl_EC_GROUP to use in the ossl_EC_KEY object (note: the ossl_EC_KEY
 *                 object will use an own copy of the ossl_EC_GROUP).
 *  \return 1 on success and 0 if an error occurred.
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_KEY_set_group(ossl_EC_KEY *key, const ossl_EC_GROUP *group);

/** Returns the private key of a ossl_EC_KEY object.
 *  \param  key  ossl_EC_KEY object
 *  \return a ossl_BIGNUM with the private key (possibly NULL).
 */
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_BIGNUM *ossl_EC_KEY_get0_private_key(const ossl_EC_KEY *key);

/** Sets the private key of a ossl_EC_KEY object.
 *  \param  key  ossl_EC_KEY object
 *  \param  prv  ossl_BIGNUM with the private key (note: the ossl_EC_KEY object
 *               will use an own copy of the ossl_BIGNUM).
 *  \return 1 on success and 0 if an error occurred.
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_KEY_set_private_key(ossl_EC_KEY *key, const ossl_BIGNUM *prv);

/** Returns the public key of a ossl_EC_KEY object.
 *  \param  key  the ossl_EC_KEY object
 *  \return a ossl_EC_POINT object with the public key (possibly NULL)
 */
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_EC_POINT *ossl_EC_KEY_get0_public_key(const ossl_EC_KEY *key);

/** Sets the public key of a ossl_EC_KEY object.
 *  \param  key  ossl_EC_KEY object
 *  \param  pub  ossl_EC_POINT object with the public key (note: the ossl_EC_KEY object
 *               will use an own copy of the ossl_EC_POINT object).
 *  \return 1 on success and 0 if an error occurred.
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_KEY_set_public_key(ossl_EC_KEY *key, const ossl_EC_POINT *pub);

ossl_OSSL_DEPRECATEDIN_3_0 unsigned ossl_EC_KEY_get_enc_flags(const ossl_EC_KEY *key);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EC_KEY_set_enc_flags(ossl_EC_KEY *eckey, unsigned int flags);
ossl_OSSL_DEPRECATEDIN_3_0 ossl_point_conversion_form_t ossl_EC_KEY_get_conv_form(const ossl_EC_KEY *key);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EC_KEY_set_conv_form(ossl_EC_KEY *eckey,
                                                ossl_point_conversion_form_t cform);
#  endif /*ossl_OPENSSL_NO_DEPRECATED_3_0 */

#  define ossl_EC_KEY_get_ex_new_index(l, p, newf, dupf, freef) \
    ossl_CRYPTO_get_ex_new_index(ossl_CRYPTO_EX_INDEX_EC_KEY, l, p, newf, dupf, freef)

#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_KEY_set_ex_data(ossl_EC_KEY *key, int idx, void *arg);
ossl_OSSL_DEPRECATEDIN_3_0 void *ossl_EC_KEY_get_ex_data(const ossl_EC_KEY *key, int idx);

/* wrapper functions for the underlying ossl_EC_GROUP object */
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EC_KEY_set_asn1_flag(ossl_EC_KEY *eckey, int asn1_flag);

/** Creates a table of pre-computed multiples of the generator to
 *  accelerate further ossl_EC_KEY operations.
 *  \param  key  ossl_EC_KEY object
 *  \param  ctx  ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred.
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_KEY_precompute_mult(ossl_EC_KEY *key, ossl_BN_CTX *ctx);

/** Creates a new ec private (and optional a new public) key.
 *  \param  key  ossl_EC_KEY object
 *  \return 1 on success and 0 if an error occurred.
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_KEY_generate_key(ossl_EC_KEY *key);

/** Verifies that a private and/or public key is valid.
 *  \param  key  the ossl_EC_KEY object
 *  \return 1 on success and 0 otherwise.
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_KEY_check_key(const ossl_EC_KEY *key);

/** Indicates if an ossl_EC_KEY can be used for signing.
 *  \param  eckey  the ossl_EC_KEY object
 *  \return 1 if can can sign and 0 otherwise.
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_KEY_can_sign(const ossl_EC_KEY *eckey);

/** Sets a public key from affine coordinates performing
 *  necessary NIST PKV tests.
 *  \param  key  the ossl_EC_KEY object
 *  \param  x    public key x coordinate
 *  \param  y    public key y coordinate
 *  \return 1 on success and 0 otherwise.
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_KEY_set_public_key_affine_coordinates(ossl_EC_KEY *key,
                                                                   ossl_BIGNUM *x,
                                                                   ossl_BIGNUM *y);

/** Encodes an ossl_EC_KEY public key to an allocated octet string
 *  \param  key    key to encode
 *  \param  form   point conversion form
 *  \param  pbuf   returns pointer to allocated buffer
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
ossl_OSSL_DEPRECATEDIN_3_0 size_t ossl_EC_KEY_key2buf(const ossl_EC_KEY *key,
                                            ossl_point_conversion_form_t form,
                                            unsigned char **pbuf, ossl_BN_CTX *ctx);

/** Decodes a ossl_EC_KEY public key from a octet string
 *  \param  key    key to decode
 *  \param  buf    memory buffer with the encoded ec point
 *  \param  len    length of the encoded ec point
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 */

ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_KEY_oct2key(ossl_EC_KEY *key, const unsigned char *buf,
                                         size_t len, ossl_BN_CTX *ctx);

/** Decodes an ossl_EC_KEY private key from an octet string
 *  \param  key    key to decode
 *  \param  buf    memory buffer with the encoded private key
 *  \param  len    length of the encoded key
 *  \return 1 on success and 0 if an error occurred
 */

ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_KEY_oct2priv(ossl_EC_KEY *key, const unsigned char *buf,
                                          size_t len);

/** Encodes a ossl_EC_KEY private key to an octet string
 *  \param  key    key to encode
 *  \param  buf    memory buffer for the result. If NULL the function returns
 *                 required buffer size.
 *  \param  len    length of the memory buffer
 *  \return the length of the encoded octet string or 0 if an error occurred
 */

ossl_OSSL_DEPRECATEDIN_3_0 size_t ossl_EC_KEY_priv2oct(const ossl_EC_KEY *key,
                                             unsigned char *buf, size_t len);

/** Encodes an ossl_EC_KEY private key to an allocated octet string
 *  \param  eckey  key to encode
 *  \param  pbuf   returns pointer to allocated buffer
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
ossl_OSSL_DEPRECATEDIN_3_0 size_t ossl_EC_KEY_priv2buf(const ossl_EC_KEY *eckey,
                                             unsigned char **pbuf);

/********************************************************************/
/*        de- and encoding functions for SEC1 ECPrivateKey          */
/********************************************************************/

/** Decodes a private key from a memory buffer.
 *  \param  key  a pointer to a ossl_EC_KEY object which should be used (or NULL)
 *  \param  in   pointer to memory with the DER encoded private key
 *  \param  len  length of the DER encoded private key
 *  \return the decoded private key or NULL if an error occurred.
 */
ossl_OSSL_DEPRECATEDIN_3_0 ossl_EC_KEY *ossl_d2i_ECPrivateKey(ossl_EC_KEY **key,
                                               const unsigned char **in,
                                               long len);

/** Encodes a private key object and stores the result in a buffer.
 *  \param  key  the ossl_EC_KEY object to encode
 *  \param  out  the buffer for the result (if NULL the function returns number
 *               of bytes needed).
 *  \return 1 on success and 0 if an error occurred.
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_i2d_ECPrivateKey(const ossl_EC_KEY *key,
                                           unsigned char **out);

/********************************************************************/
/*        de- and encoding functions for EC parameters              */
/********************************************************************/

/** Decodes ec parameter from a memory buffer.
 *  \param  key  a pointer to a ossl_EC_KEY object which should be used (or NULL)
 *  \param  in   pointer to memory with the DER encoded ec parameters
 *  \param  len  length of the DER encoded ec parameters
 *  \return a ossl_EC_KEY object with the decoded parameters or NULL if an error
 *          occurred.
 */
ossl_OSSL_DEPRECATEDIN_3_0 ossl_EC_KEY *ossl_d2i_ECParameters(ossl_EC_KEY **key,
                                               const unsigned char **in,
                                               long len);

/** Encodes ec parameter and stores the result in a buffer.
 *  \param  key  the ossl_EC_KEY object with ec parameters to encode
 *  \param  out  the buffer for the result (if NULL the function returns number
 *               of bytes needed).
 *  \return 1 on success and 0 if an error occurred.
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_i2d_ECParameters(const ossl_EC_KEY *key,
                                           unsigned char **out);

/********************************************************************/
/*         de- and encoding functions for EC public key             */
/*         (octet string, not DER -- hence 'o2i' and 'i2o')         */
/********************************************************************/

/** Decodes an ec public key from a octet string.
 *  \param  key  a pointer to a ossl_EC_KEY object which should be used
 *  \param  in   memory buffer with the encoded public key
 *  \param  len  length of the encoded public key
 *  \return ossl_EC_KEY object with decoded public key or NULL if an error
 *          occurred.
 */
ossl_OSSL_DEPRECATEDIN_3_0 ossl_EC_KEY *ossl_o2i_ECPublicKey(ossl_EC_KEY **key,
                                              const unsigned char **in, long len);

/** Encodes an ec public key in an octet string.
 *  \param  key  the ossl_EC_KEY object with the public key
 *  \param  out  the buffer for the result (if NULL the function returns number
 *               of bytes needed).
 *  \return 1 on success and 0 if an error occurred
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_i2o_ECPublicKey(const ossl_EC_KEY *key, unsigned char **out);

/** Prints out the ec parameters on human readable form.
 *  \param  bp   ossl_BIO object to which the information is printed
 *  \param  key  ossl_EC_KEY object
 *  \return 1 on success and 0 if an error occurred
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_ECParameters_print(ossl_BIO *bp, const ossl_EC_KEY *key);

/** Prints out the contents of a ossl_EC_KEY object
 *  \param  bp   ossl_BIO object to which the information is printed
 *  \param  key  ossl_EC_KEY object
 *  \param  off  line offset
 *  \return 1 on success and 0 if an error occurred
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_KEY_print(ossl_BIO *bp, const ossl_EC_KEY *key, int off);

#   ifndef ossl_OPENSSL_NO_STDIO
/** Prints out the ec parameters on human readable form.
 *  \param  fp   file descriptor to which the information is printed
 *  \param  key  ossl_EC_KEY object
 *  \return 1 on success and 0 if an error occurred
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_ECParameters_print_fp(FILE *fp, const ossl_EC_KEY *key);

/** Prints out the contents of a ossl_EC_KEY object
 *  \param  fp   file descriptor to which the information is printed
 *  \param  key  ossl_EC_KEY object
 *  \param  off  line offset
 *  \return 1 on success and 0 if an error occurred
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_KEY_print_fp(FILE *fp, const ossl_EC_KEY *key, int off);
#   endif /* ossl_OPENSSL_NO_STDIO */

ossl_OSSL_DEPRECATEDIN_3_0 const ossl_EC_KEY_METHOD *ossl_EC_KEY_OpenSSL(void);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_EC_KEY_METHOD *ossl_EC_KEY_get_default_method(void);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EC_KEY_set_default_method(const ossl_EC_KEY_METHOD *meth);
ossl_OSSL_DEPRECATEDIN_3_0 const ossl_EC_KEY_METHOD *ossl_EC_KEY_get_method(const ossl_EC_KEY *key);
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_EC_KEY_set_method(ossl_EC_KEY *key, const ossl_EC_KEY_METHOD *meth);
ossl_OSSL_DEPRECATEDIN_3_0 ossl_EC_KEY *ossl_EC_KEY_new_method(ossl_ENGINE *engine);

/** The old name for ecdh_KDF_X9_63
 *  The ECDH KDF specification has been mistakingly attributed to ANSI X9.62,
 *  it is actually specified in ANSI X9.63.
 *  This identifier is retained for backwards compatibility
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_ECDH_KDF_X9_62(unsigned char *out, size_t outlen,
                                         const unsigned char *Z, size_t Zlen,
                                         const unsigned char *sinfo,
                                         size_t sinfolen, const ossl_EVP_MD *md);

ossl_OSSL_DEPRECATEDIN_3_0 int ossl_ECDH_compute_key(void *out, size_t outlen,
                                           const ossl_EC_POINT *pub_key,
                                           const ossl_EC_KEY *ecdh,
                                           void *(*KDF)(const void *in,
                                                        size_t inlen, void *out,
                                                        size_t *outlen));
#  endif /* ossl_OPENSSL_NO_DEPRECATED_3_0 */

typedef struct ossl_ECDSA_SIG_st ossl_ECDSA_SIG;

/** Allocates and initialize a ossl_ECDSA_SIG structure
 *  \return pointer to a ossl_ECDSA_SIG structure or NULL if an error occurred
 */
ossl_ECDSA_SIG *ossl_ECDSA_SIG_new(void);

/** frees a ossl_ECDSA_SIG structure
 *  \param  sig  pointer to the ossl_ECDSA_SIG structure
 */
void ossl_ECDSA_SIG_free(ossl_ECDSA_SIG *sig);

/** ossl_i2d_ECDSA_SIG encodes content of ossl_ECDSA_SIG (note: this function modifies *pp
 *  (*pp += length of the DER encoded signature)).
 *  \param  sig  pointer to the ossl_ECDSA_SIG object
 *  \param  pp   pointer to a unsigned char pointer for the output or NULL
 *  \return the length of the DER encoded ossl_ECDSA_SIG object or a negative value
 *          on error
 */
ossl_DECLARE_ASN1_ENCODE_FUNCTIONS_only(ossl_ECDSA_SIG, ossl_ECDSA_SIG)

/** ossl_d2i_ECDSA_SIG decodes an ECDSA signature (note: this function modifies *pp
 *  (*pp += len)).
 *  \param  sig  pointer to ossl_ECDSA_SIG pointer (may be NULL)
 *  \param  pp   memory buffer with the DER encoded signature
 *  \param  len  length of the buffer
 *  \return pointer to the decoded ossl_ECDSA_SIG structure (or NULL)
 */

/** Accessor for r and s fields of ossl_ECDSA_SIG
 *  \param  sig  pointer to ossl_ECDSA_SIG structure
 *  \param  pr   pointer to ossl_BIGNUM pointer for r (may be NULL)
 *  \param  ps   pointer to ossl_BIGNUM pointer for s (may be NULL)
 */
void ossl_ECDSA_SIG_get0(const ossl_ECDSA_SIG *sig, const ossl_BIGNUM **pr, const ossl_BIGNUM **ps);

/** Accessor for r field of ossl_ECDSA_SIG
 *  \param  sig  pointer to ossl_ECDSA_SIG structure
 */
const ossl_BIGNUM *ossl_ECDSA_SIG_get0_r(const ossl_ECDSA_SIG *sig);

/** Accessor for s field of ossl_ECDSA_SIG
 *  \param  sig  pointer to ossl_ECDSA_SIG structure
 */
const ossl_BIGNUM *ossl_ECDSA_SIG_get0_s(const ossl_ECDSA_SIG *sig);

/** Setter for r and s fields of ossl_ECDSA_SIG
 *  \param  sig  pointer to ossl_ECDSA_SIG structure
 *  \param  r    pointer to ossl_BIGNUM for r
 *  \param  s    pointer to ossl_BIGNUM for s
 */
int ossl_ECDSA_SIG_set0(ossl_ECDSA_SIG *sig, ossl_BIGNUM *r, ossl_BIGNUM *s);

#  ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
/** Computes the ECDSA signature of the given hash value using
 *  the supplied private key and returns the created signature.
 *  \param  dgst      pointer to the hash value
 *  \param  dgst_len  length of the hash value
 *  \param  eckey     ossl_EC_KEY object containing a private EC key
 *  \return pointer to a ossl_ECDSA_SIG structure or NULL if an error occurred
 */
ossl_OSSL_DEPRECATEDIN_3_0 ossl_ECDSA_SIG *ossl_ECDSA_do_sign(const unsigned char *dgst,
                                               int dgst_len, ossl_EC_KEY *eckey);

/** Computes ECDSA signature of a given hash value using the supplied
 *  private key (note: sig must point to ossl_ECDSA_size(eckey) bytes of memory).
 *  \param  dgst     pointer to the hash value to sign
 *  \param  dgstlen  length of the hash value
 *  \param  kinv     ossl_BIGNUM with a pre-computed inverse k (optional)
 *  \param  rp       ossl_BIGNUM with a pre-computed rp value (optional),
 *                   see ossl_ECDSA_sign_setup
 *  \param  eckey    ossl_EC_KEY object containing a private EC key
 *  \return pointer to a ossl_ECDSA_SIG structure or NULL if an error occurred
 */
ossl_OSSL_DEPRECATEDIN_3_0 ossl_ECDSA_SIG *ossl_ECDSA_do_sign_ex(const unsigned char *dgst,
                                                  int dgstlen, const ossl_BIGNUM *kinv,
                                                  const ossl_BIGNUM *rp, ossl_EC_KEY *eckey);

/** Verifies that the supplied signature is a valid ECDSA
 *  signature of the supplied hash value using the supplied public key.
 *  \param  dgst      pointer to the hash value
 *  \param  dgst_len  length of the hash value
 *  \param  sig       ossl_ECDSA_SIG structure
 *  \param  eckey     ossl_EC_KEY object containing a public EC key
 *  \return 1 if the signature is valid, 0 if the signature is invalid
 *          and -1 on error
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_ECDSA_do_verify(const unsigned char *dgst, int dgst_len,
                                          const ossl_ECDSA_SIG *sig, ossl_EC_KEY *eckey);

/** Precompute parts of the signing operation
 *  \param  eckey  ossl_EC_KEY object containing a private EC key
 *  \param  ctx    ossl_BN_CTX object (optional)
 *  \param  kinv   ossl_BIGNUM pointer for the inverse of k
 *  \param  rp     ossl_BIGNUM pointer for x coordinate of k * generator
 *  \return 1 on success and 0 otherwise
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_ECDSA_sign_setup(ossl_EC_KEY *eckey, ossl_BN_CTX *ctx,
                                           ossl_BIGNUM **kinv, ossl_BIGNUM **rp);

/** Computes ECDSA signature of a given hash value using the supplied
 *  private key (note: sig must point to ossl_ECDSA_size(eckey) bytes of memory).
 *  \param  type     this parameter is ignored
 *  \param  dgst     pointer to the hash value to sign
 *  \param  dgstlen  length of the hash value
 *  \param  sig      memory for the DER encoded created signature
 *  \param  siglen   pointer to the length of the returned signature
 *  \param  eckey    ossl_EC_KEY object containing a private EC key
 *  \return 1 on success and 0 otherwise
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_ECDSA_sign(int type, const unsigned char *dgst,
                                     int dgstlen, unsigned char *sig,
                                     unsigned int *siglen, ossl_EC_KEY *eckey);

/** Computes ECDSA signature of a given hash value using the supplied
 *  private key (note: sig must point to ossl_ECDSA_size(eckey) bytes of memory).
 *  \param  type     this parameter is ignored
 *  \param  dgst     pointer to the hash value to sign
 *  \param  dgstlen  length of the hash value
 *  \param  sig      buffer to hold the DER encoded signature
 *  \param  siglen   pointer to the length of the returned signature
 *  \param  kinv     ossl_BIGNUM with a pre-computed inverse k (optional)
 *  \param  rp       ossl_BIGNUM with a pre-computed rp value (optional),
 *                   see ossl_ECDSA_sign_setup
 *  \param  eckey    ossl_EC_KEY object containing a private EC key
 *  \return 1 on success and 0 otherwise
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_ECDSA_sign_ex(int type, const unsigned char *dgst,
                                        int dgstlen, unsigned char *sig,
                                        unsigned int *siglen, const ossl_BIGNUM *kinv,
                                        const ossl_BIGNUM *rp, ossl_EC_KEY *eckey);

/** Verifies that the given signature is valid ECDSA signature
 *  of the supplied hash value using the specified public key.
 *  \param  type     this parameter is ignored
 *  \param  dgst     pointer to the hash value
 *  \param  dgstlen  length of the hash value
 *  \param  sig      pointer to the DER encoded signature
 *  \param  siglen   length of the DER encoded signature
 *  \param  eckey    ossl_EC_KEY object containing a public EC key
 *  \return 1 if the signature is valid, 0 if the signature is invalid
 *          and -1 on error
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_ECDSA_verify(int type, const unsigned char *dgst,
                                       int dgstlen, const unsigned char *sig,
                                       int siglen, ossl_EC_KEY *eckey);

/** Returns the maximum length of the DER encoded signature
 *  \param  eckey  ossl_EC_KEY object
 *  \return numbers of bytes required for the DER encoded signature
 */
ossl_OSSL_DEPRECATEDIN_3_0 int ossl_ECDSA_size(const ossl_EC_KEY *eckey);

/********************************************************************/
/*  ossl_EC_KEY_METHOD constructors, destructors, writers and accessors  */
/********************************************************************/

ossl_OSSL_DEPRECATEDIN_3_0 ossl_EC_KEY_METHOD *ossl_EC_KEY_METHOD_new(const ossl_EC_KEY_METHOD *meth);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EC_KEY_METHOD_free(ossl_EC_KEY_METHOD *meth);
ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EC_KEY_METHOD_set_init
                      (ossl_EC_KEY_METHOD *meth,
                       int (*init)(ossl_EC_KEY *key),
                       void (*finish)(ossl_EC_KEY *key),
                       int (*copy)(ossl_EC_KEY *dest, const ossl_EC_KEY *src),
                       int (*set_group)(ossl_EC_KEY *key, const ossl_EC_GROUP *grp),
                       int (*set_private)(ossl_EC_KEY *key, const ossl_BIGNUM *priv_key),
                       int (*set_public)(ossl_EC_KEY *key, const ossl_EC_POINT *pub_key));

ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EC_KEY_METHOD_set_keygen(ossl_EC_KEY_METHOD *meth,
                                                    int (*keygen)(ossl_EC_KEY *key));

ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EC_KEY_METHOD_set_compute_key
                      (ossl_EC_KEY_METHOD *meth,
                       int (*ckey)(unsigned char **psec, size_t *pseclen,
                                   const ossl_EC_POINT *pub_key, const ossl_EC_KEY *ecdh));

ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EC_KEY_METHOD_set_sign
                      (ossl_EC_KEY_METHOD *meth,
                       int (*sign)(int type, const unsigned char *dgst,
                                   int dlen, unsigned char *sig,
                                   unsigned int *siglen,
                                   const ossl_BIGNUM *kinv, const ossl_BIGNUM *r,
                                   ossl_EC_KEY *eckey),
                       int (*sign_setup)(ossl_EC_KEY *eckey, ossl_BN_CTX *ctx_in,
                                         ossl_BIGNUM **kinvp, ossl_BIGNUM **rp),
                       ossl_ECDSA_SIG *(*sign_sig)(const unsigned char *dgst,
                                              int dgst_len,
                                              const ossl_BIGNUM *in_kinv,
                                              const ossl_BIGNUM *in_r,
                                              ossl_EC_KEY *eckey));

ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EC_KEY_METHOD_set_verify
                      (ossl_EC_KEY_METHOD *meth,
                       int (*verify)(int type, const unsigned
                                     char *dgst, int dgst_len,
                                     const unsigned char *sigbuf,
                                     int sig_len, ossl_EC_KEY *eckey),
                       int (*verify_sig)(const unsigned char *dgst,
                                         int dgst_len, const ossl_ECDSA_SIG *sig,
                                         ossl_EC_KEY *eckey));

ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EC_KEY_METHOD_get_init
                      (const ossl_EC_KEY_METHOD *meth,
                       int (**pinit)(ossl_EC_KEY *key),
                       void (**pfinish)(ossl_EC_KEY *key),
                       int (**pcopy)(ossl_EC_KEY *dest, const ossl_EC_KEY *src),
                       int (**pset_group)(ossl_EC_KEY *key, const ossl_EC_GROUP *grp),
                       int (**pset_private)(ossl_EC_KEY *key, const ossl_BIGNUM *priv_key),
                       int (**pset_public)(ossl_EC_KEY *key, const ossl_EC_POINT *pub_key));

ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EC_KEY_METHOD_get_keygen
                      (const ossl_EC_KEY_METHOD *meth, int (**pkeygen)(ossl_EC_KEY *key));

ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EC_KEY_METHOD_get_compute_key
                      (const ossl_EC_KEY_METHOD *meth,
                       int (**pck)(unsigned char **psec,
                       size_t *pseclen,
                       const ossl_EC_POINT *pub_key,
                       const ossl_EC_KEY *ecdh));

ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EC_KEY_METHOD_get_sign
                      (const ossl_EC_KEY_METHOD *meth,
                       int (**psign)(int type, const unsigned char *dgst,
                                     int dlen, unsigned char *sig,
                                     unsigned int *siglen,
                                     const ossl_BIGNUM *kinv, const ossl_BIGNUM *r,
                                     ossl_EC_KEY *eckey),
                       int (**psign_setup)(ossl_EC_KEY *eckey, ossl_BN_CTX *ctx_in,
                                           ossl_BIGNUM **kinvp, ossl_BIGNUM **rp),
                       ossl_ECDSA_SIG *(**psign_sig)(const unsigned char *dgst,
                                                int dgst_len,
                                                const ossl_BIGNUM *in_kinv,
                                                const ossl_BIGNUM *in_r,
                                                ossl_EC_KEY *eckey));

ossl_OSSL_DEPRECATEDIN_3_0 void ossl_EC_KEY_METHOD_get_verify
                      (const ossl_EC_KEY_METHOD *meth,
                       int (**pverify)(int type, const unsigned
                                       char *dgst, int dgst_len,
                                       const unsigned char *sigbuf,
                                       int sig_len, ossl_EC_KEY *eckey),
                       int (**pverify_sig)(const unsigned char *dgst,
                                           int dgst_len,
                                           const ossl_ECDSA_SIG *sig,
                                           ossl_EC_KEY *eckey));
#  endif /* ossl_OPENSSL_NO_DEPRECATED_3_0 */

#  define ossl_EVP_EC_gen(curve) \
    ossl_EVP_PKEY_Q_keygen(NULL, NULL, "EC", (char *)(strstr(curve, "")))
    /* strstr is used to enable type checking for the variadic string arg */
#  define ossl_ECParameters_dup(x) ossl_ASN1_dup_of(ossl_EC_KEY, ossl_i2d_ECParameters, \
                                          ossl_d2i_ECParameters, x)

#  ifndef __cplusplus
#   if defined(__SUNPRO_C)
#    if __SUNPRO_C >= 0x520
#     pragma error_messages (default,E_ARRAY_OF_INCOMPLETE_NONAME,E_ARRAY_OF_INCOMPLETE)
#    endif
#   endif
#  endif

# endif
# ifdef  __cplusplus
}
# endif
#endif
