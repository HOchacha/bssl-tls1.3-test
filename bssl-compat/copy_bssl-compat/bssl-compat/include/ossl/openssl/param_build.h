/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef ossl_OPENSSL_PARAM_BUILD_H
# define ossl_OPENSSL_PARAM_BUILD_H
# pragma once

# include "ossl/openssl/params.h"
# include "ossl/openssl/types.h"

# ifdef __cplusplus
extern "C" {
# endif

ossl_OSSL_PARAM_BLD *ossl_OSSL_PARAM_BLD_new(void);
ossl_OSSL_PARAM *ossl_OSSL_PARAM_BLD_to_param(ossl_OSSL_PARAM_BLD *bld);
void ossl_OSSL_PARAM_BLD_free(ossl_OSSL_PARAM_BLD *bld);

int ossl_OSSL_PARAM_BLD_push_int(ossl_OSSL_PARAM_BLD *bld, const char *key, int val);
int ossl_OSSL_PARAM_BLD_push_uint(ossl_OSSL_PARAM_BLD *bld, const char *key,
                             unsigned int val);
int ossl_OSSL_PARAM_BLD_push_long(ossl_OSSL_PARAM_BLD *bld, const char *key,
                             long int val);
int ossl_OSSL_PARAM_BLD_push_ulong(ossl_OSSL_PARAM_BLD *bld, const char *key,
                              unsigned long int val);
int ossl_OSSL_PARAM_BLD_push_int32(ossl_OSSL_PARAM_BLD *bld, const char *key,
                              int32_t val);
int ossl_OSSL_PARAM_BLD_push_uint32(ossl_OSSL_PARAM_BLD *bld, const char *key,
                               uint32_t val);
int ossl_OSSL_PARAM_BLD_push_int64(ossl_OSSL_PARAM_BLD *bld, const char *key,
                              int64_t val);
int ossl_OSSL_PARAM_BLD_push_uint64(ossl_OSSL_PARAM_BLD *bld, const char *key,
                               uint64_t val);
int ossl_OSSL_PARAM_BLD_push_size_t(ossl_OSSL_PARAM_BLD *bld, const char *key,
                               size_t val);
int ossl_OSSL_PARAM_BLD_push_time_t(ossl_OSSL_PARAM_BLD *bld, const char *key,
                               time_t val);
int ossl_OSSL_PARAM_BLD_push_double(ossl_OSSL_PARAM_BLD *bld, const char *key,
                               double val);
int ossl_OSSL_PARAM_BLD_push_BN(ossl_OSSL_PARAM_BLD *bld, const char *key,
                           const ossl_BIGNUM *bn);
int ossl_OSSL_PARAM_BLD_push_BN_pad(ossl_OSSL_PARAM_BLD *bld, const char *key,
                               const ossl_BIGNUM *bn, size_t sz);
int ossl_OSSL_PARAM_BLD_push_utf8_string(ossl_OSSL_PARAM_BLD *bld, const char *key,
                                    const char *buf, size_t bsize);
int ossl_OSSL_PARAM_BLD_push_utf8_ptr(ossl_OSSL_PARAM_BLD *bld, const char *key,
                                 char *buf, size_t bsize);
int ossl_OSSL_PARAM_BLD_push_octet_string(ossl_OSSL_PARAM_BLD *bld, const char *key,
                                     const void *buf, size_t bsize);
int ossl_OSSL_PARAM_BLD_push_octet_ptr(ossl_OSSL_PARAM_BLD *bld, const char *key,
                                  void *buf, size_t bsize);

# ifdef __cplusplus
}
# endif
#endif  /* ossl_OPENSSL_PARAM_BUILD_H */
