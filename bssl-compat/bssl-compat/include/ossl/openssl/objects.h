/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_OBJECTS_H
# define ossl_OPENSSL_OBJECTS_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_OBJECTS_H
# endif

# include "ossl/openssl/obj_mac.h"
# include "ossl/openssl/bio.h"
# include "ossl/openssl/asn1.h"
# include "ossl/openssl/objectserr.h"

# define ossl_OBJ_NAME_TYPE_UNDEF             0x00
# define ossl_OBJ_NAME_TYPE_MD_METH           0x01
# define ossl_OBJ_NAME_TYPE_CIPHER_METH       0x02
# define ossl_OBJ_NAME_TYPE_PKEY_METH         0x03
# define ossl_OBJ_NAME_TYPE_COMP_METH         0x04
# define ossl_OBJ_NAME_TYPE_MAC_METH          0x05
# define ossl_OBJ_NAME_TYPE_KDF_METH          0x06
# define ossl_OBJ_NAME_TYPE_NUM               0x07

# define ossl_OBJ_NAME_ALIAS                  0x8000

# define ossl_OBJ_BSEARCH_VALUE_ON_NOMATCH            0x01
# define ossl_OBJ_BSEARCH_FIRST_VALUE_ON_MATCH        0x02


#ifdef  __cplusplus
extern "C" {
#endif

typedef struct ossl_obj_name_st {
    int type;
    int alias;
    const char *name;
    const char *data;
} ossl_OBJ_NAME;

# define         ossl_OBJ_create_and_add_object(a,b,c) ossl_OBJ_create(a,b,c)

int ossl_OBJ_NAME_init(void);
int ossl_OBJ_NAME_new_index(unsigned long (*hash_func) (const char *),
                       int (*cmp_func) (const char *, const char *),
                       void (*free_func) (const char *, int, const char *));
const char *ossl_OBJ_NAME_get(const char *name, int type);
int ossl_OBJ_NAME_add(const char *name, int type, const char *data);
int ossl_OBJ_NAME_remove(const char *name, int type);
void ossl_OBJ_NAME_cleanup(int type); /* -1 for everything */
void ossl_OBJ_NAME_do_all(int type, void (*fn) (const ossl_OBJ_NAME *, void *arg),
                     void *arg);
void ossl_OBJ_NAME_do_all_sorted(int type,
                            void (*fn) (const ossl_OBJ_NAME *, void *arg),
                            void *arg);

ossl_DECLARE_ASN1_DUP_FUNCTION_name(ossl_ASN1_OBJECT, OBJ)
ossl_ASN1_OBJECT *ossl_OBJ_nid2obj(int n);
const char *ossl_OBJ_nid2ln(int n);
const char *ossl_OBJ_nid2sn(int n);
int ossl_OBJ_obj2nid(const ossl_ASN1_OBJECT *o);
ossl_ASN1_OBJECT *ossl_OBJ_txt2obj(const char *s, int no_name);
int ossl_OBJ_obj2txt(char *buf, int buf_len, const ossl_ASN1_OBJECT *a, int no_name);
int ossl_OBJ_txt2nid(const char *s);
int ossl_OBJ_ln2nid(const char *s);
int ossl_OBJ_sn2nid(const char *s);
int ossl_OBJ_cmp(const ossl_ASN1_OBJECT *a, const ossl_ASN1_OBJECT *b);
const void *ossl_OBJ_bsearch_(const void *key, const void *base, int num, int size,
                         int (*cmp) (const void *, const void *));
const void *ossl_OBJ_bsearch_ex_(const void *key, const void *base, int num,
                            int size,
                            int (*cmp) (const void *, const void *),
                            int flags);

# define ossl__DECLARE_OBJ_BSEARCH_CMP_FN(scope, type1, type2, nm)    \
  static int nm##_cmp_BSEARCH_CMP_FN(const void *, const void *); \
  static int nm##_cmp(type1 const *, type2 const *); \
  scope type2 * ossl_OBJ_bsearch_##nm(type1 *key, type2 const *base, int num)

# define ossl_DECLARE_OBJ_BSEARCH_CMP_FN(type1, type2, cmp)   \
  ossl__DECLARE_OBJ_BSEARCH_CMP_FN(static, type1, type2, cmp)
# define ossl_DECLARE_OBJ_BSEARCH_GLOBAL_CMP_FN(type1, type2, nm)     \
  type2 * ossl_OBJ_bsearch_##nm(type1 *key, type2 const *base, int num)

/*-
 * Unsolved problem: if a type is actually a pointer type, like
 * nid_triple is, then its impossible to get a const where you need
 * it. Consider:
 *
 * typedef int nid_triple[3];
 * const void *a_;
 * const nid_triple const *a = a_;
 *
 * The assignment discards a const because what you really want is:
 *
 * const int const * const *a = a_;
 *
 * But if you do that, you lose the fact that a is an array of 3 ints,
 * which breaks comparison functions.
 *
 * Thus we end up having to cast, sadly, or unpack the
 * declarations. Or, as I finally did in this case, declare nid_triple
 * to be a struct, which it should have been in the first place.
 *
 * Ben, August 2008.
 *
 * Also, strictly speaking not all types need be const, but handling
 * the non-constness means a lot of complication, and in practice
 * comparison routines do always not touch their arguments.
 */

# define ossl_IMPLEMENT_OBJ_BSEARCH_CMP_FN(type1, type2, nm)  \
  static int nm##_cmp_BSEARCH_CMP_FN(const void *a_, const void *b_)    \
      { \
      type1 const *a = a_; \
      type2 const *b = b_; \
      return nm##_cmp(a,b); \
      } \
  static type2 *ossl_OBJ_bsearch_##nm(type1 *key, type2 const *base, int num) \
      { \
      return (type2 *)ossl_OBJ_bsearch_(key, base, num, sizeof(type2), \
                                        nm##_cmp_BSEARCH_CMP_FN); \
      } \
      extern void dummy_prototype(void)

# define ossl_IMPLEMENT_OBJ_BSEARCH_GLOBAL_CMP_FN(type1, type2, nm)   \
  static int nm##_cmp_BSEARCH_CMP_FN(const void *a_, const void *b_)    \
      { \
      type1 const *a = a_; \
      type2 const *b = b_; \
      return nm##_cmp(a,b); \
      } \
  type2 *ossl_OBJ_bsearch_##nm(type1 *key, type2 const *base, int num) \
      { \
      return (type2 *)ossl_OBJ_bsearch_(key, base, num, sizeof(type2), \
                                        nm##_cmp_BSEARCH_CMP_FN); \
      } \
      extern void dummy_prototype(void)

# define ossl_OBJ_bsearch(type1,key,type2,base,num,cmp)                              \
  ((type2 *)ossl_OBJ_bsearch_(ossl_CHECKED_PTR_OF(type1,key),ossl_CHECKED_PTR_OF(type2,base), \
                         num,sizeof(type2),                             \
                         ((void)ossl_CHECKED_PTR_OF(type1,cmp##_type_1),     \
                          (void)ossl_CHECKED_PTR_OF(type2,cmp##_type_2),     \
                          cmp##_BSEARCH_CMP_FN)))

# define ossl_OBJ_bsearch_ex(type1,key,type2,base,num,cmp,flags)                      \
  ((type2 *)ossl_OBJ_bsearch_ex_(ossl_CHECKED_PTR_OF(type1,key),ossl_CHECKED_PTR_OF(type2,base), \
                         num,sizeof(type2),                             \
                         ((void)ossl_CHECKED_PTR_OF(type1,cmp##_type_1),     \
                          (void)type_2=ossl_CHECKED_PTR_OF(type2,cmp##_type_2), \
                          cmp##_BSEARCH_CMP_FN)),flags)

int ossl_OBJ_new_nid(int num);
int ossl_OBJ_add_object(const ossl_ASN1_OBJECT *obj);
int ossl_OBJ_create(const char *oid, const char *sn, const char *ln);
#ifndef ossl_OPENSSL_NO_DEPRECATED_1_1_0
# define ossl_OBJ_cleanup() while(0) continue
#endif
int ossl_OBJ_create_objects(ossl_BIO *in);

size_t ossl_OBJ_length(const ossl_ASN1_OBJECT *obj);
const unsigned char *ossl_OBJ_get0_data(const ossl_ASN1_OBJECT *obj);

int ossl_OBJ_find_sigid_algs(int signid, int *pdig_nid, int *ppkey_nid);
int ossl_OBJ_find_sigid_by_algs(int *psignid, int dig_nid, int pkey_nid);
int ossl_OBJ_add_sigid(int signid, int dig_id, int pkey_id);
void ossl_OBJ_sigid_free(void);


# ifdef  __cplusplus
}
# endif
#endif
