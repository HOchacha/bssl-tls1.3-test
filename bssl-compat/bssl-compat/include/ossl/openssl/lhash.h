/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */



/*
 * Header for dynamic hash table routines Author - Eric Young
 */

#ifndef ossl_OPENSSL_LHASH_H
# define ossl_OPENSSL_LHASH_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_LHASH_H
# endif

# include "ossl/openssl/e_os2.h"
# include "ossl/openssl/bio.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct ossl_lhash_node_st ossl_OPENSSL_LH_NODE;
typedef int (*ossl_OPENSSL_LH_COMPFUNC) (const void *, const void *);
typedef unsigned long (*ossl_OPENSSL_LH_HASHFUNC) (const void *);
typedef void (*ossl_OPENSSL_LH_DOALL_FUNC) (void *);
typedef void (*ossl_OPENSSL_LH_DOALL_FUNCARG) (void *, void *);
typedef struct ossl_lhash_st ossl_OPENSSL_LHASH;

/*
 * Macros for declaring and implementing type-safe wrappers for LHASH
 * callbacks. This way, callbacks can be provided to LHASH structures without
 * function pointer casting and the macro-defined callbacks provide
 * per-variable casting before deferring to the underlying type-specific
 * callbacks. NB: It is possible to place a "static" in front of both the
 * DECLARE and IMPLEMENT macros if the functions are strictly internal.
 */

/* First: "hash" functions */
# define ossl_DECLARE_LHASH_HASH_FN(name, o_type) \
        unsigned long name##_LHASH_HASH(const void *);
# define ossl_IMPLEMENT_LHASH_HASH_FN(name, o_type) \
        unsigned long name##_LHASH_HASH(const void *arg) { \
                const o_type *a = arg; \
                return name##_hash(a); }
# define ossl_LHASH_HASH_FN(name) name##_LHASH_HASH

/* Second: "compare" functions */
# define ossl_DECLARE_LHASH_COMP_FN(name, o_type) \
        int name##_LHASH_COMP(const void *, const void *);
# define ossl_IMPLEMENT_LHASH_COMP_FN(name, o_type) \
        int name##_LHASH_COMP(const void *arg1, const void *arg2) { \
                const o_type *a = arg1;             \
                const o_type *b = arg2; \
                return name##_cmp(a,b); }
# define ossl_LHASH_COMP_FN(name) name##_LHASH_COMP

/* Fourth: "doall_arg" functions */
# define ossl_DECLARE_LHASH_DOALL_ARG_FN(name, o_type, a_type) \
        void name##_LHASH_DOALL_ARG(void *, void *);
# define ossl_IMPLEMENT_LHASH_DOALL_ARG_FN(name, o_type, a_type) \
        void name##_LHASH_DOALL_ARG(void *arg1, void *arg2) { \
                o_type *a = arg1; \
                a_type *b = arg2; \
                name##_doall_arg(a, b); }
# define ossl_LHASH_DOALL_ARG_FN(name) name##_LHASH_DOALL_ARG


# define ossl_LH_LOAD_MULT    256

int ossl_OPENSSL_LH_error(ossl_OPENSSL_LHASH *lh);
ossl_OPENSSL_LHASH *ossl_OPENSSL_LH_new(ossl_OPENSSL_LH_HASHFUNC h, ossl_OPENSSL_LH_COMPFUNC c);
void ossl_OPENSSL_LH_free(ossl_OPENSSL_LHASH *lh);
void ossl_OPENSSL_LH_flush(ossl_OPENSSL_LHASH *lh);
void *ossl_OPENSSL_LH_insert(ossl_OPENSSL_LHASH *lh, void *data);
void *ossl_OPENSSL_LH_delete(ossl_OPENSSL_LHASH *lh, const void *data);
void *ossl_OPENSSL_LH_retrieve(ossl_OPENSSL_LHASH *lh, const void *data);
void ossl_OPENSSL_LH_doall(ossl_OPENSSL_LHASH *lh, ossl_OPENSSL_LH_DOALL_FUNC func);
void ossl_OPENSSL_LH_doall_arg(ossl_OPENSSL_LHASH *lh, ossl_OPENSSL_LH_DOALL_FUNCARG func, void *arg);
unsigned long ossl_OPENSSL_LH_strhash(const char *c);
unsigned long ossl_OPENSSL_LH_num_items(const ossl_OPENSSL_LHASH *lh);
unsigned long ossl_OPENSSL_LH_get_down_load(const ossl_OPENSSL_LHASH *lh);
void ossl_OPENSSL_LH_set_down_load(ossl_OPENSSL_LHASH *lh, unsigned long down_load);

# ifndef ossl_OPENSSL_NO_STDIO
void ossl_OPENSSL_LH_stats(const ossl_OPENSSL_LHASH *lh, FILE *fp);
void ossl_OPENSSL_LH_node_stats(const ossl_OPENSSL_LHASH *lh, FILE *fp);
void ossl_OPENSSL_LH_node_usage_stats(const ossl_OPENSSL_LHASH *lh, FILE *fp);
# endif
void ossl_OPENSSL_LH_stats_bio(const ossl_OPENSSL_LHASH *lh, ossl_BIO *out);
void ossl_OPENSSL_LH_node_stats_bio(const ossl_OPENSSL_LHASH *lh, ossl_BIO *out);
void ossl_OPENSSL_LH_node_usage_stats_bio(const ossl_OPENSSL_LHASH *lh, ossl_BIO *out);

# ifndef ossl_OPENSSL_NO_DEPRECATED_1_1_0
#  define ossl__LHASH ossl_OPENSSL_LHASH
#  define ossl_LHASH_NODE ossl_OPENSSL_LH_NODE
#  define ossl_lh_error ossl_OPENSSL_LH_error
#  define ossl_lh_new ossl_OPENSSL_LH_new
#  define ossl_lh_free ossl_OPENSSL_LH_free
#  define ossl_lh_insert ossl_OPENSSL_LH_insert
#  define ossl_lh_delete ossl_OPENSSL_LH_delete
#  define ossl_lh_retrieve ossl_OPENSSL_LH_retrieve
#  define ossl_lh_doall ossl_OPENSSL_LH_doall
#  define ossl_lh_doall_arg ossl_OPENSSL_LH_doall_arg
#  define ossl_lh_strhash ossl_OPENSSL_LH_strhash
#  define ossl_lh_num_items ossl_OPENSSL_LH_num_items
#  ifndef ossl_OPENSSL_NO_STDIO
#   define ossl_lh_stats ossl_OPENSSL_LH_stats
#   define ossl_lh_node_stats ossl_OPENSSL_LH_node_stats
#   define ossl_lh_node_usage_stats ossl_OPENSSL_LH_node_usage_stats
#  endif
#  define ossl_lh_stats_bio ossl_OPENSSL_LH_stats_bio
#  define ossl_lh_node_stats_bio ossl_OPENSSL_LH_node_stats_bio
#  define ossl_lh_node_usage_stats_bio ossl_OPENSSL_LH_node_usage_stats_bio
# endif

/* Type checking... */

# define ossl_LHASH_OF(type) struct lhash_st_##type

/* Helper macro for internal use */
# define ossl_DEFINE_LHASH_OF_INTERNAL(type) \
    ossl_LHASH_OF(type) { union lh_##type##_dummy { void* d1; unsigned long d2; int d3; } dummy; }; \
    typedef int (*lh_##type##_compfunc)(const type *a, const type *b); \
    typedef unsigned long (*lh_##type##_hashfunc)(const type *a); \
    typedef void (*lh_##type##_doallfunc)(type *a); \
    static ossl_ossl_unused ossl_ossl_inline type *ossl_ossl_check_##type##_lh_plain_type(type *ptr) \
    { \
        return ptr; \
    } \
    static ossl_ossl_unused ossl_ossl_inline const type *ossl_ossl_check_const_##type##_lh_plain_type(const type *ptr) \
    { \
        return ptr; \
    } \
    static ossl_ossl_unused ossl_ossl_inline const ossl_OPENSSL_LHASH *ossl_ossl_check_const_##type##_lh_type(const ossl_LHASH_OF(type) *lh) \
    { \
        return (const ossl_OPENSSL_LHASH *)lh; \
    } \
    static ossl_ossl_unused ossl_ossl_inline ossl_OPENSSL_LHASH *ossl_ossl_check_##type##_lh_type(ossl_LHASH_OF(type) *lh) \
    { \
        return (ossl_OPENSSL_LHASH *)lh; \
    } \
    static ossl_ossl_unused ossl_ossl_inline ossl_OPENSSL_LH_COMPFUNC ossl_ossl_check_##type##_lh_compfunc_type(lh_##type##_compfunc cmp) \
    { \
        return (ossl_OPENSSL_LH_COMPFUNC)cmp; \
    } \
    static ossl_ossl_unused ossl_ossl_inline ossl_OPENSSL_LH_HASHFUNC ossl_ossl_check_##type##_lh_hashfunc_type(lh_##type##_hashfunc hfn) \
    { \
        return (ossl_OPENSSL_LH_HASHFUNC)hfn; \
    } \
    static ossl_ossl_unused ossl_ossl_inline ossl_OPENSSL_LH_DOALL_FUNC ossl_ossl_check_##type##_lh_doallfunc_type(lh_##type##_doallfunc dfn) \
    { \
        return (ossl_OPENSSL_LH_DOALL_FUNC)dfn; \
    } \
    ossl_LHASH_OF(type)

# define ossl_DEFINE_LHASH_OF(type) \
    ossl_LHASH_OF(type) { union lh_##type##_dummy { void* d1; unsigned long d2; int d3; } dummy; }; \
    static ossl_ossl_unused ossl_ossl_inline ossl_LHASH_OF(type) *lh_##type##_new(unsigned long (*hfn)(const type *), \
                                                                   int (*cfn)(const type *, const type *)) \
    { \
        return (ossl_LHASH_OF(type) *) \
            ossl_OPENSSL_LH_new((ossl_OPENSSL_LH_HASHFUNC)hfn, (ossl_OPENSSL_LH_COMPFUNC)cfn); \
    } \
    static ossl_ossl_unused ossl_ossl_inline void lh_##type##_free(ossl_LHASH_OF(type) *lh) \
    { \
        ossl_OPENSSL_LH_free((ossl_OPENSSL_LHASH *)lh); \
    } \
    static ossl_ossl_unused ossl_ossl_inline void lh_##type##_flush(ossl_LHASH_OF(type) *lh) \
    { \
        ossl_OPENSSL_LH_flush((ossl_OPENSSL_LHASH *)lh); \
    } \
    static ossl_ossl_unused ossl_ossl_inline type *lh_##type##_insert(ossl_LHASH_OF(type) *lh, type *d) \
    { \
        return (type *)ossl_OPENSSL_LH_insert((ossl_OPENSSL_LHASH *)lh, d); \
    } \
    static ossl_ossl_unused ossl_ossl_inline type *lh_##type##_delete(ossl_LHASH_OF(type) *lh, const type *d) \
    { \
        return (type *)ossl_OPENSSL_LH_delete((ossl_OPENSSL_LHASH *)lh, d); \
    } \
    static ossl_ossl_unused ossl_ossl_inline type *lh_##type##_retrieve(ossl_LHASH_OF(type) *lh, const type *d) \
    { \
        return (type *)ossl_OPENSSL_LH_retrieve((ossl_OPENSSL_LHASH *)lh, d); \
    } \
    static ossl_ossl_unused ossl_ossl_inline int lh_##type##_error(ossl_LHASH_OF(type) *lh) \
    { \
        return ossl_OPENSSL_LH_error((ossl_OPENSSL_LHASH *)lh); \
    } \
    static ossl_ossl_unused ossl_ossl_inline unsigned long lh_##type##_num_items(ossl_LHASH_OF(type) *lh) \
    { \
        return ossl_OPENSSL_LH_num_items((ossl_OPENSSL_LHASH *)lh); \
    } \
    static ossl_ossl_unused ossl_ossl_inline void lh_##type##_node_stats_bio(const ossl_LHASH_OF(type) *lh, ossl_BIO *out) \
    { \
        ossl_OPENSSL_LH_node_stats_bio((const ossl_OPENSSL_LHASH *)lh, out); \
    } \
    static ossl_ossl_unused ossl_ossl_inline void lh_##type##_node_usage_stats_bio(const ossl_LHASH_OF(type) *lh, ossl_BIO *out) \
    { \
        ossl_OPENSSL_LH_node_usage_stats_bio((const ossl_OPENSSL_LHASH *)lh, out); \
    } \
    static ossl_ossl_unused ossl_ossl_inline void lh_##type##_stats_bio(const ossl_LHASH_OF(type) *lh, ossl_BIO *out) \
    { \
        ossl_OPENSSL_LH_stats_bio((const ossl_OPENSSL_LHASH *)lh, out); \
    } \
    static ossl_ossl_unused ossl_ossl_inline unsigned long lh_##type##_get_down_load(ossl_LHASH_OF(type) *lh) \
    { \
        return ossl_OPENSSL_LH_get_down_load((ossl_OPENSSL_LHASH *)lh); \
    } \
    static ossl_ossl_unused ossl_ossl_inline void lh_##type##_set_down_load(ossl_LHASH_OF(type) *lh, unsigned long dl) \
    { \
        ossl_OPENSSL_LH_set_down_load((ossl_OPENSSL_LHASH *)lh, dl); \
    } \
    static ossl_ossl_unused ossl_ossl_inline void lh_##type##_doall(ossl_LHASH_OF(type) *lh, \
                                                          void (*doall)(type *)) \
    { \
        ossl_OPENSSL_LH_doall((ossl_OPENSSL_LHASH *)lh, (ossl_OPENSSL_LH_DOALL_FUNC)doall); \
    } \
    static ossl_ossl_unused ossl_ossl_inline void lh_##type##_doall_arg(ossl_LHASH_OF(type) *lh, \
                                                              void (*doallarg)(type *, void *), \
                                                              void *arg) \
    { \
        ossl_OPENSSL_LH_doall_arg((ossl_OPENSSL_LHASH *)lh, \
                             (ossl_OPENSSL_LH_DOALL_FUNCARG)doallarg, arg); \
    } \
    ossl_LHASH_OF(type)

#define ossl_IMPLEMENT_LHASH_DOALL_ARG_CONST(type, argtype) \
    ossl_int_implement_lhash_doall(type, argtype, const type)

#define ossl_IMPLEMENT_LHASH_DOALL_ARG(type, argtype) \
    ossl_int_implement_lhash_doall(type, argtype, type)

#define ossl_int_implement_lhash_doall(type, argtype, cbargtype) \
    static ossl_ossl_unused ossl_ossl_inline void \
        lh_##type##_doall_##argtype(ossl_LHASH_OF(type) *lh, \
                                   void (*fn)(cbargtype *, argtype *), \
                                   argtype *arg) \
    { \
        ossl_OPENSSL_LH_doall_arg((ossl_OPENSSL_LHASH *)lh, (ossl_OPENSSL_LH_DOALL_FUNCARG)fn, (void *)arg); \
    } \
    ossl_LHASH_OF(type)

ossl_DEFINE_LHASH_OF_INTERNAL(ossl_OPENSSL_STRING);
#define ossl_lh_OPENSSL_STRING_new(hfn, cmp) ((ossl_LHASH_OF(ossl_OPENSSL_STRING) *)ossl_OPENSSL_LH_new(ossl_ossl_check_OPENSSL_STRING_lh_hashfunc_type(hfn), ossl_ossl_check_OPENSSL_STRING_lh_compfunc_type(cmp)))
#define ossl_lh_OPENSSL_STRING_free(lh) ossl_OPENSSL_LH_free(ossl_ossl_check_OPENSSL_STRING_lh_type(lh))
#define ossl_lh_OPENSSL_STRING_flush(lh) ossl_OPENSSL_LH_flush(ossl_ossl_check_OPENSSL_STRING_lh_type(lh))
#define ossl_lh_OPENSSL_STRING_insert(lh, ptr) ((ossl_OPENSSL_STRING *)ossl_OPENSSL_LH_insert(ossl_ossl_check_OPENSSL_STRING_lh_type(lh), ossl_ossl_check_OPENSSL_STRING_lh_plain_type(ptr)))
#define ossl_lh_OPENSSL_STRING_delete(lh, ptr) ((ossl_OPENSSL_STRING *)ossl_OPENSSL_LH_delete(ossl_ossl_check_OPENSSL_STRING_lh_type(lh), ossl_ossl_check_const_OPENSSL_STRING_lh_plain_type(ptr)))
#define ossl_lh_OPENSSL_STRING_retrieve(lh, ptr) ((ossl_OPENSSL_STRING *)ossl_OPENSSL_LH_retrieve(ossl_ossl_check_OPENSSL_STRING_lh_type(lh), ossl_ossl_check_const_OPENSSL_STRING_lh_plain_type(ptr)))
#define ossl_lh_OPENSSL_STRING_error(lh) ossl_OPENSSL_LH_error(ossl_ossl_check_OPENSSL_STRING_lh_type(lh))
#define ossl_lh_OPENSSL_STRING_num_items(lh) ossl_OPENSSL_LH_num_items(ossl_ossl_check_OPENSSL_STRING_lh_type(lh))
#define ossl_lh_OPENSSL_STRING_node_stats_bio(lh, out) ossl_OPENSSL_LH_node_stats_bio(ossl_ossl_check_const_OPENSSL_STRING_lh_type(lh), out)
#define ossl_lh_OPENSSL_STRING_node_usage_stats_bio(lh, out) ossl_OPENSSL_LH_node_usage_stats_bio(ossl_ossl_check_const_OPENSSL_STRING_lh_type(lh), out)
#define ossl_lh_OPENSSL_STRING_stats_bio(lh, out) ossl_OPENSSL_LH_stats_bio(ossl_ossl_check_const_OPENSSL_STRING_lh_type(lh), out)
#define ossl_lh_OPENSSL_STRING_get_down_load(lh) ossl_OPENSSL_LH_get_down_load(ossl_ossl_check_OPENSSL_STRING_lh_type(lh))
#define ossl_lh_OPENSSL_STRING_set_down_load(lh, dl) ossl_OPENSSL_LH_set_down_load(ossl_ossl_check_OPENSSL_STRING_lh_type(lh), dl)
#define ossl_lh_OPENSSL_STRING_doall(lh, dfn) ossl_OPENSSL_LH_doall(ossl_ossl_check_OPENSSL_STRING_lh_type(lh), ossl_ossl_check_OPENSSL_STRING_lh_doallfunc_type(dfn))
ossl_DEFINE_LHASH_OF_INTERNAL(ossl_OPENSSL_CSTRING);
#define ossl_lh_OPENSSL_CSTRING_new(hfn, cmp) ((ossl_LHASH_OF(ossl_OPENSSL_CSTRING) *)ossl_OPENSSL_LH_new(ossl_ossl_check_OPENSSL_CSTRING_lh_hashfunc_type(hfn), ossl_ossl_check_OPENSSL_CSTRING_lh_compfunc_type(cmp)))
#define ossl_lh_OPENSSL_CSTRING_free(lh) ossl_OPENSSL_LH_free(ossl_ossl_check_OPENSSL_CSTRING_lh_type(lh))
#define ossl_lh_OPENSSL_CSTRING_flush(lh) ossl_OPENSSL_LH_flush(ossl_ossl_check_OPENSSL_CSTRING_lh_type(lh))
#define ossl_lh_OPENSSL_CSTRING_insert(lh, ptr) ((ossl_OPENSSL_CSTRING *)ossl_OPENSSL_LH_insert(ossl_ossl_check_OPENSSL_CSTRING_lh_type(lh), ossl_ossl_check_OPENSSL_CSTRING_lh_plain_type(ptr)))
#define ossl_lh_OPENSSL_CSTRING_delete(lh, ptr) ((ossl_OPENSSL_CSTRING *)ossl_OPENSSL_LH_delete(ossl_ossl_check_OPENSSL_CSTRING_lh_type(lh), ossl_ossl_check_const_OPENSSL_CSTRING_lh_plain_type(ptr)))
#define ossl_lh_OPENSSL_CSTRING_retrieve(lh, ptr) ((ossl_OPENSSL_CSTRING *)ossl_OPENSSL_LH_retrieve(ossl_ossl_check_OPENSSL_CSTRING_lh_type(lh), ossl_ossl_check_const_OPENSSL_CSTRING_lh_plain_type(ptr)))
#define ossl_lh_OPENSSL_CSTRING_error(lh) ossl_OPENSSL_LH_error(ossl_ossl_check_OPENSSL_CSTRING_lh_type(lh))
#define ossl_lh_OPENSSL_CSTRING_num_items(lh) ossl_OPENSSL_LH_num_items(ossl_ossl_check_OPENSSL_CSTRING_lh_type(lh))
#define ossl_lh_OPENSSL_CSTRING_node_stats_bio(lh, out) ossl_OPENSSL_LH_node_stats_bio(ossl_ossl_check_const_OPENSSL_CSTRING_lh_type(lh), out)
#define ossl_lh_OPENSSL_CSTRING_node_usage_stats_bio(lh, out) ossl_OPENSSL_LH_node_usage_stats_bio(ossl_ossl_check_const_OPENSSL_CSTRING_lh_type(lh), out)
#define ossl_lh_OPENSSL_CSTRING_stats_bio(lh, out) ossl_OPENSSL_LH_stats_bio(ossl_ossl_check_const_OPENSSL_CSTRING_lh_type(lh), out)
#define ossl_lh_OPENSSL_CSTRING_get_down_load(lh) ossl_OPENSSL_LH_get_down_load(ossl_ossl_check_OPENSSL_CSTRING_lh_type(lh))
#define ossl_lh_OPENSSL_CSTRING_set_down_load(lh, dl) ossl_OPENSSL_LH_set_down_load(ossl_ossl_check_OPENSSL_CSTRING_lh_type(lh), dl)
#define ossl_lh_OPENSSL_CSTRING_doall(lh, dfn) ossl_OPENSSL_LH_doall(ossl_ossl_check_OPENSSL_CSTRING_lh_type(lh), ossl_ossl_check_OPENSSL_CSTRING_lh_doallfunc_type(dfn))


#ifdef  __cplusplus
}
#endif

#endif
