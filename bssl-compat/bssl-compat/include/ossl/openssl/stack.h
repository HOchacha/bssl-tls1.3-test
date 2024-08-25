/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_STACK_H
# define ossl_OPENSSL_STACK_H
# pragma once

# include "ossl/openssl/macros.h"
# ifndef ossl_OPENSSL_NO_DEPRECATED_3_0
#  define ossl_HEADER_STACK_H
# endif

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct ossl_stack_st ossl_OPENSSL_STACK; /* Use ossl_STACK_OF(...) instead */

typedef int (*ossl_OPENSSL_sk_compfunc)(const void *, const void *);
typedef void (*ossl_OPENSSL_sk_freefunc)(void *);
typedef void *(*ossl_OPENSSL_sk_copyfunc)(const void *);

int ossl_OPENSSL_sk_num(const ossl_OPENSSL_STACK *);
void *ossl_OPENSSL_sk_value(const ossl_OPENSSL_STACK *, int);

void *ossl_OPENSSL_sk_set(ossl_OPENSSL_STACK *st, int i, const void *data);

ossl_OPENSSL_STACK *ossl_OPENSSL_sk_new(ossl_OPENSSL_sk_compfunc cmp);
ossl_OPENSSL_STACK *ossl_OPENSSL_sk_new_null(void);
ossl_OPENSSL_STACK *ossl_OPENSSL_sk_new_reserve(ossl_OPENSSL_sk_compfunc c, int n);
int ossl_OPENSSL_sk_reserve(ossl_OPENSSL_STACK *st, int n);
void ossl_OPENSSL_sk_free(ossl_OPENSSL_STACK *);
void ossl_OPENSSL_sk_pop_free(ossl_OPENSSL_STACK *st, void (*func) (void *));
ossl_OPENSSL_STACK *ossl_OPENSSL_sk_deep_copy(const ossl_OPENSSL_STACK *,
                                    ossl_OPENSSL_sk_copyfunc c,
                                    ossl_OPENSSL_sk_freefunc f);
int ossl_OPENSSL_sk_insert(ossl_OPENSSL_STACK *sk, const void *data, int where);
void *ossl_OPENSSL_sk_delete(ossl_OPENSSL_STACK *st, int loc);
void *ossl_OPENSSL_sk_delete_ptr(ossl_OPENSSL_STACK *st, const void *p);
int ossl_OPENSSL_sk_find(ossl_OPENSSL_STACK *st, const void *data);
int ossl_OPENSSL_sk_find_ex(ossl_OPENSSL_STACK *st, const void *data);
int ossl_OPENSSL_sk_find_all(ossl_OPENSSL_STACK *st, const void *data, int *pnum);
int ossl_OPENSSL_sk_push(ossl_OPENSSL_STACK *st, const void *data);
int ossl_OPENSSL_sk_unshift(ossl_OPENSSL_STACK *st, const void *data);
void *ossl_OPENSSL_sk_shift(ossl_OPENSSL_STACK *st);
void *ossl_OPENSSL_sk_pop(ossl_OPENSSL_STACK *st);
void ossl_OPENSSL_sk_zero(ossl_OPENSSL_STACK *st);
ossl_OPENSSL_sk_compfunc ossl_OPENSSL_sk_set_cmp_func(ossl_OPENSSL_STACK *sk,
                                            ossl_OPENSSL_sk_compfunc cmp);
ossl_OPENSSL_STACK *ossl_OPENSSL_sk_dup(const ossl_OPENSSL_STACK *st);
void ossl_OPENSSL_sk_sort(ossl_OPENSSL_STACK *st);
int ossl_OPENSSL_sk_is_sorted(const ossl_OPENSSL_STACK *st);

# ifndef ossl_OPENSSL_NO_DEPRECATED_1_1_0
#  define ossl__STACK ossl_OPENSSL_STACK
#  define ossl_sk_num ossl_OPENSSL_sk_num
#  define ossl_sk_value ossl_OPENSSL_sk_value
#  define ossl_sk_set ossl_OPENSSL_sk_set
#  define ossl_sk_new ossl_OPENSSL_sk_new
#  define ossl_sk_new_null ossl_OPENSSL_sk_new_null
#  define ossl_sk_free ossl_OPENSSL_sk_free
#  define ossl_sk_pop_free ossl_OPENSSL_sk_pop_free
#  define ossl_sk_deep_copy ossl_OPENSSL_sk_deep_copy
#  define ossl_sk_insert ossl_OPENSSL_sk_insert
#  define ossl_sk_delete ossl_OPENSSL_sk_delete
#  define ossl_sk_delete_ptr ossl_OPENSSL_sk_delete_ptr
#  define ossl_sk_find ossl_OPENSSL_sk_find
#  define ossl_sk_find_ex ossl_OPENSSL_sk_find_ex
#  define ossl_sk_push ossl_OPENSSL_sk_push
#  define ossl_sk_unshift ossl_OPENSSL_sk_unshift
#  define ossl_sk_shift ossl_OPENSSL_sk_shift
#  define ossl_sk_pop ossl_OPENSSL_sk_pop
#  define ossl_sk_zero ossl_OPENSSL_sk_zero
#  define ossl_sk_set_cmp_func ossl_OPENSSL_sk_set_cmp_func
#  define ossl_sk_dup ossl_OPENSSL_sk_dup
#  define ossl_sk_sort ossl_OPENSSL_sk_sort
#  define ossl_sk_is_sorted ossl_OPENSSL_sk_is_sorted
# endif

#ifdef  __cplusplus
}
#endif

#endif
