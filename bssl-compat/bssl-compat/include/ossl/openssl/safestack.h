/*
 * WARNING: do not edit!
 * Generated by Makefile from ../../../openssl/source/include/openssl/safestack.h.in
 *
 * Copyright 1999-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */



#ifndef ossl_OPENSSL_SAFESTACK_H
# define ossl_OPENSSL_SAFESTACK_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_SAFESTACK_H
# endif

# include "ossl/openssl/stack.h"
# include "ossl/openssl/e_os2.h"

#ifdef __cplusplus
extern "C" {
#endif

# define ossl_STACK_OF(type) struct stack_st_##type

/* Helper macro for internal use */
# define ossl_SKM_DEFINE_STACK_OF_INTERNAL(t1, t2, t3) \
    ossl_STACK_OF(t1); \
    typedef int (*ossl_sk_##t1##_compfunc)(const t3 * const *a, const t3 *const *b); \
    typedef void (*ossl_sk_##t1##_freefunc)(t3 *a); \
    typedef t3 * (*ossl_sk_##t1##_copyfunc)(const t3 *a); \
    static ossl_ossl_unused ossl_ossl_inline t2 *ossl_ossl_check_##t1##_type(t2 *ptr) \
    { \
        return ptr; \
    } \
    static ossl_ossl_unused ossl_ossl_inline const ossl_OPENSSL_STACK *ossl_ossl_check_const_##t1##_sk_type(const ossl_STACK_OF(t1) *sk) \
    { \
        return (const ossl_OPENSSL_STACK *)sk; \
    } \
    static ossl_ossl_unused ossl_ossl_inline ossl_OPENSSL_STACK *ossl_ossl_check_##t1##_sk_type(ossl_STACK_OF(t1) *sk) \
    { \
        return (ossl_OPENSSL_STACK *)sk; \
    } \
    static ossl_ossl_unused ossl_ossl_inline ossl_OPENSSL_sk_compfunc ossl_ossl_check_##t1##_compfunc_type(ossl_sk_##t1##_compfunc cmp) \
    { \
        return (ossl_OPENSSL_sk_compfunc)cmp; \
    } \
    static ossl_ossl_unused ossl_ossl_inline ossl_OPENSSL_sk_copyfunc ossl_ossl_check_##t1##_copyfunc_type(ossl_sk_##t1##_copyfunc cpy) \
    { \
        return (ossl_OPENSSL_sk_copyfunc)cpy; \
    } \
    static ossl_ossl_unused ossl_ossl_inline ossl_OPENSSL_sk_freefunc ossl_ossl_check_##t1##_freefunc_type(ossl_sk_##t1##_freefunc fr) \
    { \
        return (ossl_OPENSSL_sk_freefunc)fr; \
    }

# define ossl_SKM_DEFINE_STACK_OF(t1, t2, t3) \
    ossl_STACK_OF(t1); \
    typedef int (*ossl_sk_##t1##_compfunc)(const t3 * const *a, const t3 *const *b); \
    typedef void (*ossl_sk_##t1##_freefunc)(t3 *a); \
    typedef t3 * (*ossl_sk_##t1##_copyfunc)(const t3 *a); \
    static ossl_ossl_unused ossl_ossl_inline int ossl_sk_##t1##_num(const ossl_STACK_OF(t1) *sk) \
    { \
        return ossl_OPENSSL_sk_num((const ossl_OPENSSL_STACK *)sk); \
    } \
    static ossl_ossl_unused ossl_ossl_inline t2 *ossl_sk_##t1##_value(const ossl_STACK_OF(t1) *sk, int idx) \
    { \
        return (t2 *)ossl_OPENSSL_sk_value((const ossl_OPENSSL_STACK *)sk, idx); \
    } \
    static ossl_ossl_unused ossl_ossl_inline ossl_STACK_OF(t1) *ossl_sk_##t1##_new(ossl_sk_##t1##_compfunc compare) \
    { \
        return (ossl_STACK_OF(t1) *)ossl_OPENSSL_sk_new((ossl_OPENSSL_sk_compfunc)compare); \
    } \
    static ossl_ossl_unused ossl_ossl_inline ossl_STACK_OF(t1) *ossl_sk_##t1##_new_null(void) \
    { \
        return (ossl_STACK_OF(t1) *)ossl_OPENSSL_sk_new_null(); \
    } \
    static ossl_ossl_unused ossl_ossl_inline ossl_STACK_OF(t1) *ossl_sk_##t1##_new_reserve(ossl_sk_##t1##_compfunc compare, int n) \
    { \
        return (ossl_STACK_OF(t1) *)ossl_OPENSSL_sk_new_reserve((ossl_OPENSSL_sk_compfunc)compare, n); \
    } \
    static ossl_ossl_unused ossl_ossl_inline int ossl_sk_##t1##_reserve(ossl_STACK_OF(t1) *sk, int n) \
    { \
        return ossl_OPENSSL_sk_reserve((ossl_OPENSSL_STACK *)sk, n); \
    } \
    static ossl_ossl_unused ossl_ossl_inline void ossl_sk_##t1##_free(ossl_STACK_OF(t1) *sk) \
    { \
        ossl_OPENSSL_sk_free((ossl_OPENSSL_STACK *)sk); \
    } \
    static ossl_ossl_unused ossl_ossl_inline void ossl_sk_##t1##_zero(ossl_STACK_OF(t1) *sk) \
    { \
        ossl_OPENSSL_sk_zero((ossl_OPENSSL_STACK *)sk); \
    } \
    static ossl_ossl_unused ossl_ossl_inline t2 *ossl_sk_##t1##_delete(ossl_STACK_OF(t1) *sk, int i) \
    { \
        return (t2 *)ossl_OPENSSL_sk_delete((ossl_OPENSSL_STACK *)sk, i); \
    } \
    static ossl_ossl_unused ossl_ossl_inline t2 *ossl_sk_##t1##_delete_ptr(ossl_STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return (t2 *)ossl_OPENSSL_sk_delete_ptr((ossl_OPENSSL_STACK *)sk, \
                                           (const void *)ptr); \
    } \
    static ossl_ossl_unused ossl_ossl_inline int ossl_sk_##t1##_push(ossl_STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return ossl_OPENSSL_sk_push((ossl_OPENSSL_STACK *)sk, (const void *)ptr); \
    } \
    static ossl_ossl_unused ossl_ossl_inline int ossl_sk_##t1##_unshift(ossl_STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return ossl_OPENSSL_sk_unshift((ossl_OPENSSL_STACK *)sk, (const void *)ptr); \
    } \
    static ossl_ossl_unused ossl_ossl_inline t2 *ossl_sk_##t1##_pop(ossl_STACK_OF(t1) *sk) \
    { \
        return (t2 *)ossl_OPENSSL_sk_pop((ossl_OPENSSL_STACK *)sk); \
    } \
    static ossl_ossl_unused ossl_ossl_inline t2 *ossl_sk_##t1##_shift(ossl_STACK_OF(t1) *sk) \
    { \
        return (t2 *)ossl_OPENSSL_sk_shift((ossl_OPENSSL_STACK *)sk); \
    } \
    static ossl_ossl_unused ossl_ossl_inline void ossl_sk_##t1##_pop_free(ossl_STACK_OF(t1) *sk, ossl_sk_##t1##_freefunc freefunc) \
    { \
        ossl_OPENSSL_sk_pop_free((ossl_OPENSSL_STACK *)sk, (ossl_OPENSSL_sk_freefunc)freefunc); \
    } \
    static ossl_ossl_unused ossl_ossl_inline int ossl_sk_##t1##_insert(ossl_STACK_OF(t1) *sk, t2 *ptr, int idx) \
    { \
        return ossl_OPENSSL_sk_insert((ossl_OPENSSL_STACK *)sk, (const void *)ptr, idx); \
    } \
    static ossl_ossl_unused ossl_ossl_inline t2 *ossl_sk_##t1##_set(ossl_STACK_OF(t1) *sk, int idx, t2 *ptr) \
    { \
        return (t2 *)ossl_OPENSSL_sk_set((ossl_OPENSSL_STACK *)sk, idx, (const void *)ptr); \
    } \
    static ossl_ossl_unused ossl_ossl_inline int ossl_sk_##t1##_find(ossl_STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return ossl_OPENSSL_sk_find((ossl_OPENSSL_STACK *)sk, (const void *)ptr); \
    } \
    static ossl_ossl_unused ossl_ossl_inline int ossl_sk_##t1##_find_ex(ossl_STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return ossl_OPENSSL_sk_find_ex((ossl_OPENSSL_STACK *)sk, (const void *)ptr); \
    } \
    static ossl_ossl_unused ossl_ossl_inline int ossl_sk_##t1##_find_all(ossl_STACK_OF(t1) *sk, t2 *ptr, int *pnum) \
    { \
        return ossl_OPENSSL_sk_find_all((ossl_OPENSSL_STACK *)sk, (const void *)ptr, pnum); \
    } \
    static ossl_ossl_unused ossl_ossl_inline void ossl_sk_##t1##_sort(ossl_STACK_OF(t1) *sk) \
    { \
        ossl_OPENSSL_sk_sort((ossl_OPENSSL_STACK *)sk); \
    } \
    static ossl_ossl_unused ossl_ossl_inline int ossl_sk_##t1##_is_sorted(const ossl_STACK_OF(t1) *sk) \
    { \
        return ossl_OPENSSL_sk_is_sorted((const ossl_OPENSSL_STACK *)sk); \
    } \
    static ossl_ossl_unused ossl_ossl_inline ossl_STACK_OF(t1) * ossl_sk_##t1##_dup(const ossl_STACK_OF(t1) *sk) \
    { \
        return (ossl_STACK_OF(t1) *)ossl_OPENSSL_sk_dup((const ossl_OPENSSL_STACK *)sk); \
    } \
    static ossl_ossl_unused ossl_ossl_inline ossl_STACK_OF(t1) *ossl_sk_##t1##_deep_copy(const ossl_STACK_OF(t1) *sk, \
                                                    ossl_sk_##t1##_copyfunc copyfunc, \
                                                    ossl_sk_##t1##_freefunc freefunc) \
    { \
        return (ossl_STACK_OF(t1) *)ossl_OPENSSL_sk_deep_copy((const ossl_OPENSSL_STACK *)sk, \
                                            (ossl_OPENSSL_sk_copyfunc)copyfunc, \
                                            (ossl_OPENSSL_sk_freefunc)freefunc); \
    } \
    static ossl_ossl_unused ossl_ossl_inline ossl_sk_##t1##_compfunc ossl_sk_##t1##_set_cmp_func(ossl_STACK_OF(t1) *sk, ossl_sk_##t1##_compfunc compare) \
    { \
        return (ossl_sk_##t1##_compfunc)ossl_OPENSSL_sk_set_cmp_func((ossl_OPENSSL_STACK *)sk, (ossl_OPENSSL_sk_compfunc)compare); \
    }

# define ossl_DEFINE_STACK_OF(t) ossl_SKM_DEFINE_STACK_OF(t, t, t)
# define ossl_DEFINE_STACK_OF_CONST(t) ossl_SKM_DEFINE_STACK_OF(t, const t, t)
# define ossl_DEFINE_SPECIAL_STACK_OF(t1, t2) ossl_SKM_DEFINE_STACK_OF(t1, t2, t2)
# define ossl_DEFINE_SPECIAL_STACK_OF_CONST(t1, t2) \
            ossl_SKM_DEFINE_STACK_OF(t1, const t2, t2)

/*-
 * Strings are special: normally an lhash entry will point to a single
 * (somewhat) mutable object. In the case of strings:
 *
 * a) Instead of a single char, there is an array of chars, NUL-terminated.
 * b) The string may have be immutable.
 *
 * So, they need their own declarations. Especially important for
 * type-checking tools, such as Deputy.
 *
 * In practice, however, it appears to be hard to have a const
 * string. For now, I'm settling for dealing with the fact it is a
 * string at all.
 */
typedef char *ossl_OPENSSL_STRING;
typedef const char *ossl_OPENSSL_CSTRING;

/*-
 * Confusingly, ossl_LHASH_OF(STRING) deals with char ** throughout, but
 * ossl_STACK_OF(STRING) is really more like ossl_STACK_OF(char), only, as mentioned
 * above, instead of a single char each entry is a NUL-terminated array of
 * chars. So, we have to implement STRING specially for ossl_STACK_OF. This is
 * dealt with in the autogenerated macros below.
 */
ossl_SKM_DEFINE_STACK_OF_INTERNAL(ossl_OPENSSL_STRING, char, char)
#define ossl_sk_OPENSSL_STRING_num(sk) ossl_OPENSSL_sk_num(ossl_ossl_check_const_OPENSSL_STRING_sk_type(sk))
#define ossl_sk_OPENSSL_STRING_value(sk, idx) ((char *)ossl_OPENSSL_sk_value(ossl_ossl_check_const_OPENSSL_STRING_sk_type(sk), (idx)))
#define ossl_sk_OPENSSL_STRING_new(cmp) ((ossl_STACK_OF(ossl_OPENSSL_STRING) *)ossl_OPENSSL_sk_new(ossl_ossl_check_OPENSSL_STRING_compfunc_type(cmp)))
#define ossl_sk_OPENSSL_STRING_new_null() ((ossl_STACK_OF(ossl_OPENSSL_STRING) *)ossl_OPENSSL_sk_new_null())
#define ossl_sk_OPENSSL_STRING_new_reserve(cmp, n) ((ossl_STACK_OF(ossl_OPENSSL_STRING) *)ossl_OPENSSL_sk_new_reserve(ossl_ossl_check_OPENSSL_STRING_compfunc_type(cmp), (n)))
#define ossl_sk_OPENSSL_STRING_reserve(sk, n) ossl_OPENSSL_sk_reserve(ossl_ossl_check_OPENSSL_STRING_sk_type(sk), (n))
#define ossl_sk_OPENSSL_STRING_free(sk) ossl_OPENSSL_sk_free(ossl_ossl_check_OPENSSL_STRING_sk_type(sk))
#define ossl_sk_OPENSSL_STRING_zero(sk) ossl_OPENSSL_sk_zero(ossl_ossl_check_OPENSSL_STRING_sk_type(sk))
#define ossl_sk_OPENSSL_STRING_delete(sk, i) ((char *)ossl_OPENSSL_sk_delete(ossl_ossl_check_OPENSSL_STRING_sk_type(sk), (i)))
#define ossl_sk_OPENSSL_STRING_delete_ptr(sk, ptr) ((char *)ossl_OPENSSL_sk_delete_ptr(ossl_ossl_check_OPENSSL_STRING_sk_type(sk), ossl_ossl_check_OPENSSL_STRING_type(ptr)))
#define ossl_sk_OPENSSL_STRING_push(sk, ptr) ossl_OPENSSL_sk_push(ossl_ossl_check_OPENSSL_STRING_sk_type(sk), ossl_ossl_check_OPENSSL_STRING_type(ptr))
#define ossl_sk_OPENSSL_STRING_unshift(sk, ptr) ossl_OPENSSL_sk_unshift(ossl_ossl_check_OPENSSL_STRING_sk_type(sk), ossl_ossl_check_OPENSSL_STRING_type(ptr))
#define ossl_sk_OPENSSL_STRING_pop(sk) ((char *)ossl_OPENSSL_sk_pop(ossl_ossl_check_OPENSSL_STRING_sk_type(sk)))
#define ossl_sk_OPENSSL_STRING_shift(sk) ((char *)ossl_OPENSSL_sk_shift(ossl_ossl_check_OPENSSL_STRING_sk_type(sk)))
#define ossl_sk_OPENSSL_STRING_pop_free(sk, freefunc) ossl_OPENSSL_sk_pop_free(ossl_ossl_check_OPENSSL_STRING_sk_type(sk),ossl_ossl_check_OPENSSL_STRING_freefunc_type(freefunc))
#define ossl_sk_OPENSSL_STRING_insert(sk, ptr, idx) ossl_OPENSSL_sk_insert(ossl_ossl_check_OPENSSL_STRING_sk_type(sk), ossl_ossl_check_OPENSSL_STRING_type(ptr), (idx))
#define ossl_sk_OPENSSL_STRING_set(sk, idx, ptr) ((char *)ossl_OPENSSL_sk_set(ossl_ossl_check_OPENSSL_STRING_sk_type(sk), (idx), ossl_ossl_check_OPENSSL_STRING_type(ptr)))
#define ossl_sk_OPENSSL_STRING_find(sk, ptr) ossl_OPENSSL_sk_find(ossl_ossl_check_OPENSSL_STRING_sk_type(sk), ossl_ossl_check_OPENSSL_STRING_type(ptr))
#define ossl_sk_OPENSSL_STRING_find_ex(sk, ptr) ossl_OPENSSL_sk_find_ex(ossl_ossl_check_OPENSSL_STRING_sk_type(sk), ossl_ossl_check_OPENSSL_STRING_type(ptr))
#define ossl_sk_OPENSSL_STRING_find_all(sk, ptr, pnum) ossl_OPENSSL_sk_find_all(ossl_ossl_check_OPENSSL_STRING_sk_type(sk), ossl_ossl_check_OPENSSL_STRING_type(ptr), pnum)
#define ossl_sk_OPENSSL_STRING_sort(sk) ossl_OPENSSL_sk_sort(ossl_ossl_check_OPENSSL_STRING_sk_type(sk))
#define ossl_sk_OPENSSL_STRING_is_sorted(sk) ossl_OPENSSL_sk_is_sorted(ossl_ossl_check_const_OPENSSL_STRING_sk_type(sk))
#define ossl_sk_OPENSSL_STRING_dup(sk) ((ossl_STACK_OF(ossl_OPENSSL_STRING) *)ossl_OPENSSL_sk_dup(ossl_ossl_check_const_OPENSSL_STRING_sk_type(sk)))
#define ossl_sk_OPENSSL_STRING_deep_copy(sk, copyfunc, freefunc) ((ossl_STACK_OF(ossl_OPENSSL_STRING) *)ossl_OPENSSL_sk_deep_copy(ossl_ossl_check_const_OPENSSL_STRING_sk_type(sk), ossl_ossl_check_OPENSSL_STRING_copyfunc_type(copyfunc), ossl_ossl_check_OPENSSL_STRING_freefunc_type(freefunc)))
#define ossl_sk_OPENSSL_STRING_set_cmp_func(sk, cmp) ((ossl_sk_OPENSSL_STRING_compfunc)ossl_OPENSSL_sk_set_cmp_func(ossl_ossl_check_OPENSSL_STRING_sk_type(sk), ossl_ossl_check_OPENSSL_STRING_compfunc_type(cmp)))
ossl_SKM_DEFINE_STACK_OF_INTERNAL(ossl_OPENSSL_CSTRING, const char, char)
#define ossl_sk_OPENSSL_CSTRING_num(sk) ossl_OPENSSL_sk_num(ossl_ossl_check_const_OPENSSL_CSTRING_sk_type(sk))
#define ossl_sk_OPENSSL_CSTRING_value(sk, idx) ((const char *)ossl_OPENSSL_sk_value(ossl_ossl_check_const_OPENSSL_CSTRING_sk_type(sk), (idx)))
#define ossl_sk_OPENSSL_CSTRING_new(cmp) ((ossl_STACK_OF(ossl_OPENSSL_CSTRING) *)ossl_OPENSSL_sk_new(ossl_ossl_check_OPENSSL_CSTRING_compfunc_type(cmp)))
#define ossl_sk_OPENSSL_CSTRING_new_null() ((ossl_STACK_OF(ossl_OPENSSL_CSTRING) *)ossl_OPENSSL_sk_new_null())
#define ossl_sk_OPENSSL_CSTRING_new_reserve(cmp, n) ((ossl_STACK_OF(ossl_OPENSSL_CSTRING) *)ossl_OPENSSL_sk_new_reserve(ossl_ossl_check_OPENSSL_CSTRING_compfunc_type(cmp), (n)))
#define ossl_sk_OPENSSL_CSTRING_reserve(sk, n) ossl_OPENSSL_sk_reserve(ossl_ossl_check_OPENSSL_CSTRING_sk_type(sk), (n))
#define ossl_sk_OPENSSL_CSTRING_free(sk) ossl_OPENSSL_sk_free(ossl_ossl_check_OPENSSL_CSTRING_sk_type(sk))
#define ossl_sk_OPENSSL_CSTRING_zero(sk) ossl_OPENSSL_sk_zero(ossl_ossl_check_OPENSSL_CSTRING_sk_type(sk))
#define ossl_sk_OPENSSL_CSTRING_delete(sk, i) ((const char *)ossl_OPENSSL_sk_delete(ossl_ossl_check_OPENSSL_CSTRING_sk_type(sk), (i)))
#define ossl_sk_OPENSSL_CSTRING_delete_ptr(sk, ptr) ((const char *)ossl_OPENSSL_sk_delete_ptr(ossl_ossl_check_OPENSSL_CSTRING_sk_type(sk), ossl_ossl_check_OPENSSL_CSTRING_type(ptr)))
#define ossl_sk_OPENSSL_CSTRING_push(sk, ptr) ossl_OPENSSL_sk_push(ossl_ossl_check_OPENSSL_CSTRING_sk_type(sk), ossl_ossl_check_OPENSSL_CSTRING_type(ptr))
#define ossl_sk_OPENSSL_CSTRING_unshift(sk, ptr) ossl_OPENSSL_sk_unshift(ossl_ossl_check_OPENSSL_CSTRING_sk_type(sk), ossl_ossl_check_OPENSSL_CSTRING_type(ptr))
#define ossl_sk_OPENSSL_CSTRING_pop(sk) ((const char *)ossl_OPENSSL_sk_pop(ossl_ossl_check_OPENSSL_CSTRING_sk_type(sk)))
#define ossl_sk_OPENSSL_CSTRING_shift(sk) ((const char *)ossl_OPENSSL_sk_shift(ossl_ossl_check_OPENSSL_CSTRING_sk_type(sk)))
#define ossl_sk_OPENSSL_CSTRING_pop_free(sk, freefunc) ossl_OPENSSL_sk_pop_free(ossl_ossl_check_OPENSSL_CSTRING_sk_type(sk),ossl_ossl_check_OPENSSL_CSTRING_freefunc_type(freefunc))
#define ossl_sk_OPENSSL_CSTRING_insert(sk, ptr, idx) ossl_OPENSSL_sk_insert(ossl_ossl_check_OPENSSL_CSTRING_sk_type(sk), ossl_ossl_check_OPENSSL_CSTRING_type(ptr), (idx))
#define ossl_sk_OPENSSL_CSTRING_set(sk, idx, ptr) ((const char *)ossl_OPENSSL_sk_set(ossl_ossl_check_OPENSSL_CSTRING_sk_type(sk), (idx), ossl_ossl_check_OPENSSL_CSTRING_type(ptr)))
#define ossl_sk_OPENSSL_CSTRING_find(sk, ptr) ossl_OPENSSL_sk_find(ossl_ossl_check_OPENSSL_CSTRING_sk_type(sk), ossl_ossl_check_OPENSSL_CSTRING_type(ptr))
#define ossl_sk_OPENSSL_CSTRING_find_ex(sk, ptr) ossl_OPENSSL_sk_find_ex(ossl_ossl_check_OPENSSL_CSTRING_sk_type(sk), ossl_ossl_check_OPENSSL_CSTRING_type(ptr))
#define ossl_sk_OPENSSL_CSTRING_find_all(sk, ptr, pnum) ossl_OPENSSL_sk_find_all(ossl_ossl_check_OPENSSL_CSTRING_sk_type(sk), ossl_ossl_check_OPENSSL_CSTRING_type(ptr), pnum)
#define ossl_sk_OPENSSL_CSTRING_sort(sk) ossl_OPENSSL_sk_sort(ossl_ossl_check_OPENSSL_CSTRING_sk_type(sk))
#define ossl_sk_OPENSSL_CSTRING_is_sorted(sk) ossl_OPENSSL_sk_is_sorted(ossl_ossl_check_const_OPENSSL_CSTRING_sk_type(sk))
#define ossl_sk_OPENSSL_CSTRING_dup(sk) ((ossl_STACK_OF(ossl_OPENSSL_CSTRING) *)ossl_OPENSSL_sk_dup(ossl_ossl_check_const_OPENSSL_CSTRING_sk_type(sk)))
#define ossl_sk_OPENSSL_CSTRING_deep_copy(sk, copyfunc, freefunc) ((ossl_STACK_OF(ossl_OPENSSL_CSTRING) *)ossl_OPENSSL_sk_deep_copy(ossl_ossl_check_const_OPENSSL_CSTRING_sk_type(sk), ossl_ossl_check_OPENSSL_CSTRING_copyfunc_type(copyfunc), ossl_ossl_check_OPENSSL_CSTRING_freefunc_type(freefunc)))
#define ossl_sk_OPENSSL_CSTRING_set_cmp_func(sk, cmp) ((ossl_sk_OPENSSL_CSTRING_compfunc)ossl_OPENSSL_sk_set_cmp_func(ossl_ossl_check_OPENSSL_CSTRING_sk_type(sk), ossl_ossl_check_OPENSSL_CSTRING_compfunc_type(cmp)))


#if !defined(ossl_OPENSSL_NO_DEPRECATED_3_0)
/*
 * This is not used by OpenSSL.  A block of bytes,  NOT nul-terminated.
 * These should also be distinguished from "normal" stacks.
 */
typedef void *ossl_OPENSSL_BLOCK;
ossl_SKM_DEFINE_STACK_OF_INTERNAL(ossl_OPENSSL_BLOCK, void, void)
#define ossl_sk_OPENSSL_BLOCK_num(sk) ossl_OPENSSL_sk_num(ossl_ossl_check_const_OPENSSL_BLOCK_sk_type(sk))
#define ossl_sk_OPENSSL_BLOCK_value(sk, idx) ((void *)ossl_OPENSSL_sk_value(ossl_ossl_check_const_OPENSSL_BLOCK_sk_type(sk), (idx)))
#define ossl_sk_OPENSSL_BLOCK_new(cmp) ((ossl_STACK_OF(ossl_OPENSSL_BLOCK) *)ossl_OPENSSL_sk_new(ossl_ossl_check_OPENSSL_BLOCK_compfunc_type(cmp)))
#define ossl_sk_OPENSSL_BLOCK_new_null() ((ossl_STACK_OF(ossl_OPENSSL_BLOCK) *)ossl_OPENSSL_sk_new_null())
#define ossl_sk_OPENSSL_BLOCK_new_reserve(cmp, n) ((ossl_STACK_OF(ossl_OPENSSL_BLOCK) *)ossl_OPENSSL_sk_new_reserve(ossl_ossl_check_OPENSSL_BLOCK_compfunc_type(cmp), (n)))
#define ossl_sk_OPENSSL_BLOCK_reserve(sk, n) ossl_OPENSSL_sk_reserve(ossl_ossl_check_OPENSSL_BLOCK_sk_type(sk), (n))
#define ossl_sk_OPENSSL_BLOCK_free(sk) ossl_OPENSSL_sk_free(ossl_ossl_check_OPENSSL_BLOCK_sk_type(sk))
#define ossl_sk_OPENSSL_BLOCK_zero(sk) ossl_OPENSSL_sk_zero(ossl_ossl_check_OPENSSL_BLOCK_sk_type(sk))
#define ossl_sk_OPENSSL_BLOCK_delete(sk, i) ((void *)ossl_OPENSSL_sk_delete(ossl_ossl_check_OPENSSL_BLOCK_sk_type(sk), (i)))
#define ossl_sk_OPENSSL_BLOCK_delete_ptr(sk, ptr) ((void *)ossl_OPENSSL_sk_delete_ptr(ossl_ossl_check_OPENSSL_BLOCK_sk_type(sk), ossl_ossl_check_OPENSSL_BLOCK_type(ptr)))
#define ossl_sk_OPENSSL_BLOCK_push(sk, ptr) ossl_OPENSSL_sk_push(ossl_ossl_check_OPENSSL_BLOCK_sk_type(sk), ossl_ossl_check_OPENSSL_BLOCK_type(ptr))
#define ossl_sk_OPENSSL_BLOCK_unshift(sk, ptr) ossl_OPENSSL_sk_unshift(ossl_ossl_check_OPENSSL_BLOCK_sk_type(sk), ossl_ossl_check_OPENSSL_BLOCK_type(ptr))
#define ossl_sk_OPENSSL_BLOCK_pop(sk) ((void *)ossl_OPENSSL_sk_pop(ossl_ossl_check_OPENSSL_BLOCK_sk_type(sk)))
#define ossl_sk_OPENSSL_BLOCK_shift(sk) ((void *)ossl_OPENSSL_sk_shift(ossl_ossl_check_OPENSSL_BLOCK_sk_type(sk)))
#define ossl_sk_OPENSSL_BLOCK_pop_free(sk, freefunc) ossl_OPENSSL_sk_pop_free(ossl_ossl_check_OPENSSL_BLOCK_sk_type(sk),ossl_ossl_check_OPENSSL_BLOCK_freefunc_type(freefunc))
#define ossl_sk_OPENSSL_BLOCK_insert(sk, ptr, idx) ossl_OPENSSL_sk_insert(ossl_ossl_check_OPENSSL_BLOCK_sk_type(sk), ossl_ossl_check_OPENSSL_BLOCK_type(ptr), (idx))
#define ossl_sk_OPENSSL_BLOCK_set(sk, idx, ptr) ((void *)ossl_OPENSSL_sk_set(ossl_ossl_check_OPENSSL_BLOCK_sk_type(sk), (idx), ossl_ossl_check_OPENSSL_BLOCK_type(ptr)))
#define ossl_sk_OPENSSL_BLOCK_find(sk, ptr) ossl_OPENSSL_sk_find(ossl_ossl_check_OPENSSL_BLOCK_sk_type(sk), ossl_ossl_check_OPENSSL_BLOCK_type(ptr))
#define ossl_sk_OPENSSL_BLOCK_find_ex(sk, ptr) ossl_OPENSSL_sk_find_ex(ossl_ossl_check_OPENSSL_BLOCK_sk_type(sk), ossl_ossl_check_OPENSSL_BLOCK_type(ptr))
#define ossl_sk_OPENSSL_BLOCK_find_all(sk, ptr, pnum) ossl_OPENSSL_sk_find_all(ossl_ossl_check_OPENSSL_BLOCK_sk_type(sk), ossl_ossl_check_OPENSSL_BLOCK_type(ptr), pnum)
#define ossl_sk_OPENSSL_BLOCK_sort(sk) ossl_OPENSSL_sk_sort(ossl_ossl_check_OPENSSL_BLOCK_sk_type(sk))
#define ossl_sk_OPENSSL_BLOCK_is_sorted(sk) ossl_OPENSSL_sk_is_sorted(ossl_ossl_check_const_OPENSSL_BLOCK_sk_type(sk))
#define ossl_sk_OPENSSL_BLOCK_dup(sk) ((ossl_STACK_OF(ossl_OPENSSL_BLOCK) *)ossl_OPENSSL_sk_dup(ossl_ossl_check_const_OPENSSL_BLOCK_sk_type(sk)))
#define ossl_sk_OPENSSL_BLOCK_deep_copy(sk, copyfunc, freefunc) ((ossl_STACK_OF(ossl_OPENSSL_BLOCK) *)ossl_OPENSSL_sk_deep_copy(ossl_ossl_check_const_OPENSSL_BLOCK_sk_type(sk), ossl_ossl_check_OPENSSL_BLOCK_copyfunc_type(copyfunc), ossl_ossl_check_OPENSSL_BLOCK_freefunc_type(freefunc)))
#define ossl_sk_OPENSSL_BLOCK_set_cmp_func(sk, cmp) ((ossl_sk_OPENSSL_BLOCK_compfunc)ossl_OPENSSL_sk_set_cmp_func(ossl_ossl_check_OPENSSL_BLOCK_sk_type(sk), ossl_ossl_check_OPENSSL_BLOCK_compfunc_type(cmp)))

#endif

# ifdef  __cplusplus
}
# endif
#endif
