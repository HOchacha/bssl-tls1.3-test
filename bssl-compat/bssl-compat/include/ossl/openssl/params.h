/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_PARAMS_H
# define ossl_OPENSSL_PARAMS_H
# pragma once

# include "ossl/openssl/core.h"
# include "ossl/openssl/bn.h"

# ifdef  __cplusplus
extern "C" {
# endif

# define ossl_OSSL_PARAM_UNMODIFIED ((size_t)-1)

# define ossl_OSSL_PARAM_END \
    { NULL, 0, NULL, 0, 0 }

# define ossl_OSSL_PARAM_DEFN(key, type, addr, sz)    \
    { (key), (type), (addr), (sz), ossl_OSSL_PARAM_UNMODIFIED }

/* Basic parameter types without return sizes */
# define ossl_OSSL_PARAM_int(key, addr) \
    ossl_OSSL_PARAM_DEFN((key), ossl_OSSL_PARAM_INTEGER, (addr), sizeof(int))
# define ossl_OSSL_PARAM_uint(key, addr) \
    ossl_OSSL_PARAM_DEFN((key), ossl_OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(unsigned int))
# define ossl_OSSL_PARAM_long(key, addr) \
    ossl_OSSL_PARAM_DEFN((key), ossl_OSSL_PARAM_INTEGER, (addr), sizeof(long int))
# define ossl_OSSL_PARAM_ulong(key, addr) \
    ossl_OSSL_PARAM_DEFN((key), ossl_OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(unsigned long int))
# define ossl_OSSL_PARAM_int32(key, addr) \
    ossl_OSSL_PARAM_DEFN((key), ossl_OSSL_PARAM_INTEGER, (addr), sizeof(int32_t))
# define ossl_OSSL_PARAM_uint32(key, addr) \
    ossl_OSSL_PARAM_DEFN((key), ossl_OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(uint32_t))
# define ossl_OSSL_PARAM_int64(key, addr) \
    ossl_OSSL_PARAM_DEFN((key), ossl_OSSL_PARAM_INTEGER, (addr), sizeof(int64_t))
# define ossl_OSSL_PARAM_uint64(key, addr) \
    ossl_OSSL_PARAM_DEFN((key), ossl_OSSL_PARAM_UNSIGNED_INTEGER, (addr), \
                    sizeof(uint64_t))
# define ossl_OSSL_PARAM_size_t(key, addr) \
    ossl_OSSL_PARAM_DEFN((key), ossl_OSSL_PARAM_UNSIGNED_INTEGER, (addr), sizeof(size_t))
# define ossl_OSSL_PARAM_time_t(key, addr) \
    ossl_OSSL_PARAM_DEFN((key), ossl_OSSL_PARAM_INTEGER, (addr), sizeof(time_t))
# define ossl_OSSL_PARAM_double(key, addr) \
    ossl_OSSL_PARAM_DEFN((key), ossl_OSSL_PARAM_REAL, (addr), sizeof(double))

# define ossl_OSSL_PARAM_BN(key, bn, sz) \
    ossl_OSSL_PARAM_DEFN((key), ossl_OSSL_PARAM_UNSIGNED_INTEGER, (bn), (sz))
# define ossl_OSSL_PARAM_utf8_string(key, addr, sz) \
    ossl_OSSL_PARAM_DEFN((key), ossl_OSSL_PARAM_UTF8_STRING, (addr), sz)
# define ossl_OSSL_PARAM_octet_string(key, addr, sz) \
    ossl_OSSL_PARAM_DEFN((key), ossl_OSSL_PARAM_OCTET_STRING, (addr), sz)

# define ossl_OSSL_PARAM_utf8_ptr(key, addr, sz) \
    ossl_OSSL_PARAM_DEFN((key), ossl_OSSL_PARAM_UTF8_PTR, (addr), sz)
# define ossl_OSSL_PARAM_octet_ptr(key, addr, sz) \
    ossl_OSSL_PARAM_DEFN((key), ossl_OSSL_PARAM_OCTET_PTR, (addr), sz)

/* Search an ossl_OSSL_PARAM array for a matching name */
ossl_OSSL_PARAM *ossl_OSSL_PARAM_locate(ossl_OSSL_PARAM *p, const char *key);
const ossl_OSSL_PARAM *ossl_OSSL_PARAM_locate_const(const ossl_OSSL_PARAM *p, const char *key);

/* Basic parameter type run-time construction */
ossl_OSSL_PARAM ossl_OSSL_PARAM_construct_int(const char *key, int *buf);
ossl_OSSL_PARAM ossl_OSSL_PARAM_construct_uint(const char *key, unsigned int *buf);
ossl_OSSL_PARAM ossl_OSSL_PARAM_construct_long(const char *key, long int *buf);
ossl_OSSL_PARAM ossl_OSSL_PARAM_construct_ulong(const char *key, unsigned long int *buf);
ossl_OSSL_PARAM ossl_OSSL_PARAM_construct_int32(const char *key, int32_t *buf);
ossl_OSSL_PARAM ossl_OSSL_PARAM_construct_uint32(const char *key, uint32_t *buf);
ossl_OSSL_PARAM ossl_OSSL_PARAM_construct_int64(const char *key, int64_t *buf);
ossl_OSSL_PARAM ossl_OSSL_PARAM_construct_uint64(const char *key, uint64_t *buf);
ossl_OSSL_PARAM ossl_OSSL_PARAM_construct_size_t(const char *key, size_t *buf);
ossl_OSSL_PARAM ossl_OSSL_PARAM_construct_time_t(const char *key, time_t *buf);
ossl_OSSL_PARAM ossl_OSSL_PARAM_construct_BN(const char *key, unsigned char *buf,
                                   size_t bsize);
ossl_OSSL_PARAM ossl_OSSL_PARAM_construct_double(const char *key, double *buf);
ossl_OSSL_PARAM ossl_OSSL_PARAM_construct_utf8_string(const char *key, char *buf,
                                            size_t bsize);
ossl_OSSL_PARAM ossl_OSSL_PARAM_construct_utf8_ptr(const char *key, char **buf,
                                         size_t bsize);
ossl_OSSL_PARAM ossl_OSSL_PARAM_construct_octet_string(const char *key, void *buf,
                                             size_t bsize);
ossl_OSSL_PARAM ossl_OSSL_PARAM_construct_octet_ptr(const char *key, void **buf,
                                          size_t bsize);
ossl_OSSL_PARAM ossl_OSSL_PARAM_construct_end(void);

int ossl_OSSL_PARAM_allocate_from_text(ossl_OSSL_PARAM *to,
                                  const ossl_OSSL_PARAM *paramdefs,
                                  const char *key, const char *value,
                                  size_t value_n, int *found);

int ossl_OSSL_PARAM_get_int(const ossl_OSSL_PARAM *p, int *val);
int ossl_OSSL_PARAM_get_uint(const ossl_OSSL_PARAM *p, unsigned int *val);
int ossl_OSSL_PARAM_get_long(const ossl_OSSL_PARAM *p, long int *val);
int ossl_OSSL_PARAM_get_ulong(const ossl_OSSL_PARAM *p, unsigned long int *val);
int ossl_OSSL_PARAM_get_int32(const ossl_OSSL_PARAM *p, int32_t *val);
int ossl_OSSL_PARAM_get_uint32(const ossl_OSSL_PARAM *p, uint32_t *val);
int ossl_OSSL_PARAM_get_int64(const ossl_OSSL_PARAM *p, int64_t *val);
int ossl_OSSL_PARAM_get_uint64(const ossl_OSSL_PARAM *p, uint64_t *val);
int ossl_OSSL_PARAM_get_size_t(const ossl_OSSL_PARAM *p, size_t *val);
int ossl_OSSL_PARAM_get_time_t(const ossl_OSSL_PARAM *p, time_t *val);

int ossl_OSSL_PARAM_set_int(ossl_OSSL_PARAM *p, int val);
int ossl_OSSL_PARAM_set_uint(ossl_OSSL_PARAM *p, unsigned int val);
int ossl_OSSL_PARAM_set_long(ossl_OSSL_PARAM *p, long int val);
int ossl_OSSL_PARAM_set_ulong(ossl_OSSL_PARAM *p, unsigned long int val);
int ossl_OSSL_PARAM_set_int32(ossl_OSSL_PARAM *p, int32_t val);
int ossl_OSSL_PARAM_set_uint32(ossl_OSSL_PARAM *p, uint32_t val);
int ossl_OSSL_PARAM_set_int64(ossl_OSSL_PARAM *p, int64_t val);
int ossl_OSSL_PARAM_set_uint64(ossl_OSSL_PARAM *p, uint64_t val);
int ossl_OSSL_PARAM_set_size_t(ossl_OSSL_PARAM *p, size_t val);
int ossl_OSSL_PARAM_set_time_t(ossl_OSSL_PARAM *p, time_t val);

int ossl_OSSL_PARAM_get_double(const ossl_OSSL_PARAM *p, double *val);
int ossl_OSSL_PARAM_set_double(ossl_OSSL_PARAM *p, double val);

int ossl_OSSL_PARAM_get_BN(const ossl_OSSL_PARAM *p, ossl_BIGNUM **val);
int ossl_OSSL_PARAM_set_BN(ossl_OSSL_PARAM *p, const ossl_BIGNUM *val);

int ossl_OSSL_PARAM_get_utf8_string(const ossl_OSSL_PARAM *p, char **val, size_t max_len);
int ossl_OSSL_PARAM_set_utf8_string(ossl_OSSL_PARAM *p, const char *val);

int ossl_OSSL_PARAM_get_octet_string(const ossl_OSSL_PARAM *p, void **val, size_t max_len,
                                size_t *used_len);
int ossl_OSSL_PARAM_set_octet_string(ossl_OSSL_PARAM *p, const void *val, size_t len);

int ossl_OSSL_PARAM_get_utf8_ptr(const ossl_OSSL_PARAM *p, const char **val);
int ossl_OSSL_PARAM_set_utf8_ptr(ossl_OSSL_PARAM *p, const char *val);

int ossl_OSSL_PARAM_get_octet_ptr(const ossl_OSSL_PARAM *p, const void **val,
                             size_t *used_len);
int ossl_OSSL_PARAM_set_octet_ptr(ossl_OSSL_PARAM *p, const void *val,
                             size_t used_len);

int ossl_OSSL_PARAM_get_utf8_string_ptr(const ossl_OSSL_PARAM *p, const char **val);
int ossl_OSSL_PARAM_get_octet_string_ptr(const ossl_OSSL_PARAM *p, const void **val,
                                    size_t *used_len);

int ossl_OSSL_PARAM_modified(const ossl_OSSL_PARAM *p);
void ossl_OSSL_PARAM_set_all_unmodified(ossl_OSSL_PARAM *p);

ossl_OSSL_PARAM *ossl_OSSL_PARAM_dup(const ossl_OSSL_PARAM *p);
ossl_OSSL_PARAM *ossl_OSSL_PARAM_merge(const ossl_OSSL_PARAM *p1, const ossl_OSSL_PARAM *p2);
void ossl_OSSL_PARAM_free(ossl_OSSL_PARAM *p);

# ifdef  __cplusplus
}
# endif
#endif
